from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from .common import report_path, run_cmd, user_can_write, write_text

DETAIL_LIMIT = 100
SECRET_EXTENSIONS = {'.env', '.key', '.p12', '.pfx'}
SENSITIVE_NAME_TOKENS = ('credential', 'secret', 'password', 'passwd', 'private', 'token', 'keystore')
CONFIG_EXTENSIONS = {'.conf', '.cfg', '.ini', '.json', '.yaml', '.yml', '.xml', '.toml', '.txt'}
PRIVILEGED_PREFIXES = ('/etc/', '/usr/bin/', '/usr/sbin/', '/usr/local/bin/', '/etc/systemd/system/', '/usr/lib/systemd/system/')
EXPECTED_STICKY_TEMP_DIRS = {'/tmp', '/var/tmp', '/dev/shm'}


def _may_allow_nonowner_write(path: Path, st: os.stat_result | None = None) -> bool:
    try:
        st = st or path.stat()
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return True
        return "system.posix_acl_access" in os.listxattr(path, follow_symlinks=True)
    except (OSError, TypeError, AttributeError):
        return False


def _mode(meta: dict[str, Any]) -> int:
    try:
        return int(str(meta.get('mode_octal', '0o0')), 8)
    except (ValueError, TypeError):
        return 0


def _parent_write_concerns(path: Path, cache: dict[str, list[str]] | None = None) -> list[str]:
    cache = cache if cache is not None else {}
    key = str(path.parent)
    if key in cache:
        return cache[key]
    concerns: list[str] = []
    current = path.parent
    seen: set[str] = set()
    while str(current) not in seen:
        seen.add(str(current))
        try:
            st = current.stat()
        except OSError:
            break
        expected_sticky_temp = str(current) in EXPECTED_STICKY_TEMP_DIRS and bool(st.st_mode & stat.S_ISVTX)
        if st.st_mode & stat.S_IWOTH and not expected_sticky_temp:
            concerns.append(f'World-writable parent directory: {current}')
        elif (
            not expected_sticky_temp
            and _may_allow_nonowner_write(current, st)
            and user_can_write(current)
            and st.st_uid == 0
        ):
            concerns.append(f'Tester can write root-owned parent directory: {current}')
        if current == current.parent:
            break
        current = current.parent
    cache[key] = concerns
    return concerns


def _acl_write_entries(path: Path) -> list[str]:
    # Most files do not have an extended POSIX ACL. Avoid spawning getfacl for
    # every changed object; the previous implementation spent minutes doing so.
    try:
        attrs = os.listxattr(path, follow_symlinks=True)
    except (OSError, TypeError):
        return []
    if "system.posix_acl_access" not in attrs:
        return []
    result = run_cmd(['getfacl', '-cp', str(path)], timeout=10)
    if result['returncode'] != 0:
        return []
    raw_entries = [line.strip() for line in result['stdout'].splitlines() if line.strip() and not line.startswith('#')]
    mask = None
    for line in raw_entries:
        if line.startswith('mask::'):
            mask = line.split(':', 2)[-1]
            break
    mask_allows_write = mask is None or 'w' in mask
    entries: list[str] = []
    for line in raw_entries:
        if line.startswith('user:') or line.startswith('group:'):
            parts = line.split(':', 2)
            # Only named user/group entries are additional ACL grants; their
            # effective permissions are constrained by the ACL mask.
            if len(parts) == 3 and parts[1] and 'w' in parts[2] and mask_allows_write:
                entries.append(line)
    return entries

def _is_sensitive_read_candidate(path: Path) -> bool:
    """Identify files whose contents, unlike public certificates/config, may be secret."""
    lower_name = path.name.lower()
    if path.suffix.lower() in SECRET_EXTENSIONS:
        return True
    if (
        (path.suffix.lower() in CONFIG_EXTENSIONS or not path.suffix)
        and any(token in lower_name for token in SENSITIVE_NAME_TOKENS)
    ):
        return True
    if path.suffix.lower() == '.pem':
        try:
            sample = path.read_text(encoding='utf-8', errors='replace')[:8192]
        except OSError:
            return False
        return 'PRIVATE KEY' in sample.upper()
    return False


def _classify(
    path_text: str,
    meta: dict[str, Any],
    parent_cache: dict[str, list[str]] | None = None,
) -> dict[str, Any] | None:
    ptype = str(meta.get('type', '?'))
    mode = _mode(meta)
    owner = str(meta.get('owner', '?'))
    group = str(meta.get('group', '?'))
    path = Path(path_text)

    # Symlink mode bits are not a meaningful authorization boundary. Resolve the
    # target and assess the target itself plus its parent chain instead.
    resolved = None
    if ptype == 'symlink':
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            resolved = None

    target = resolved or path
    concerns: list[str] = []
    level = 'REVIEW'

    try:
        target_st = target.stat() if target.exists() else None
    except OSError:
        target_st = None

    if target_st is not None:
        if target_st.st_mode & stat.S_IWOTH:
            concerns.append('Resolved symlink target is world-writable' if ptype == 'symlink' else 'World-writable object')
            level = 'HIGH INTEREST'
        try:
            if target_st.st_uid == 0 and _may_allow_nonowner_write(target, target_st) and user_can_write(target):
                concerns.append(
                    'Current tester has effective write access to root-owned resolved symlink target'
                    if ptype == 'symlink'
                    else 'Current tester has effective write access to root-owned object'
                )
                level = 'HIGH INTEREST'
        except OSError:
            pass

    parent_concerns = _parent_write_concerns(target, parent_cache)
    if parent_concerns:
        concerns.extend(parent_concerns)
        level = 'HIGH INTEREST'

    # The snapshot mode for a symlink describes the link object, not its target.
    # Only interpret SUID/SGID from non-symlink snapshot objects. SGID on a
    # directory is frequently an intentional group-inheritance control and is
    # low-value by itself (for example root-owned mode 2755). Surface it only
    # when another access concern already makes the directory security-relevant.
    if ptype != 'symlink':
        if mode & stat.S_ISUID:
            concerns.append('SUID bit set')
        if mode & stat.S_ISGID and ptype != 'directory':
            concerns.append('SGID bit set')

    # Readability is only surfaced for plausibly sensitive configuration/key files.
    if ptype == 'file' and _is_sensitive_read_candidate(path) and mode & stat.S_IROTH:
        concerns.append('Potentially sensitive configuration/key file is world-readable')

    acl_entries: list[str] = []
    if target_st is not None and (target.is_file() or target.is_dir()):
        acl_entries = _acl_write_entries(target)
        if acl_entries:
            concerns.append('Named ACL grants write permission')

    if ptype == 'directory' and mode & stat.S_ISGID and concerns:
        concerns.append('SGID bit set (relevant because the directory also has an access concern)')

    if not concerns:
        return None

    return {
        'path': path_text,
        'resolved_path': str(resolved) if resolved and str(resolved) != path_text else '',
        'concerns': '; '.join(dict.fromkeys(concerns)),
        'concern_list': list(dict.fromkeys(concerns)),
        'mode': str(meta.get('mode_octal')),
        'mode_text': str(meta.get('mode', '')),
        'owner': owner,
        'group': group,
        'type': ptype,
        'level': level,
        'acl_entries': acl_entries,
    }

def review_permissions(diff: dict[str, Any], output_dir: Path) -> dict[str, list[dict[str, Any]]]:
    post_fs = diff.get('post_filesystem', {})
    changed_paths = sorted(set(diff.get('files_added', [])) | set(diff.get('files_changed', [])))
    candidates: list[dict[str, Any]] = []
    parent_cache: dict[str, list[str]] = {}
    for path in changed_paths:
        item = _classify(path, post_fs.get(path, {}), parent_cache)
        if item:
            candidates.append(item)

    high = [x for x in candidates if x['level'] == 'HIGH INTEREST']
    review = [x for x in candidates if x['level'] != 'HIGH INTEREST']
    cap_lines = diff.get('capabilities_added', [])
    suid_lines = diff.get('suid_sgid_added', [])
    normal_count = max(0, len(changed_paths) - len(candidates))

    lines = [
        'Permissions Review', '=' * 18, '',
        'This report prioritizes permission conditions that may affect an application privilege boundary. Routine ownership/mode entries are summarized rather than listed individually.',
        'Generic root ownership, group write bits, or world readability are not treated as findings without relevant access and application context.',
        '', 'Summary', '-------',
        f'Changed application objects reviewed: {len(changed_paths)}',
        f'High-interest conditions:            {len(high)}',
        f'Review candidates:                   {len(review)}',
        f'Linux capability entries added:      {len(cap_lines)}',
        f'SUID/SGID entries added:             {len(suid_lines)}',
        f'Normal/routine objects omitted:       {normal_count}',
        '',
    ]

    def render(title: str, items: list[dict[str, Any]]) -> None:
        nonlocal lines
        lines.extend([title, '=' * len(title), ''])
        if not items:
            lines.extend(['None identified.', ''])
            return
        for idx, item in enumerate(items[:DETAIL_LIMIT], 1):
            lines += [
                f"[{item['level']}] {idx}",
                f"Path:        {item['path']}",
                f"Type:        {item['type']}",
                f"Owner:       {item['owner']}:{item['group']}",
                f"Permissions: {item['mode']} ({item['mode_text']})",
            ]
            if item.get('resolved_path'):
                lines.append(f"Resolves To: {item['resolved_path']}")
            lines.append(f"Concern:     {item['concerns']}")
            if item.get('acl_entries'):
                lines += ['Relevant ACL entries:'] + [f"  {x}" for x in item['acl_entries']]
            lines += [
                'Tester Action:',
                '  Validate whether an unprivileged test account can modify or replace the affected object/parent path and whether a privileged application component consumes it.',
                '',
            ]
        if len(items) > DETAIL_LIMIT:
            lines += [f'... {len(items) - DETAIL_LIMIT} additional permission candidates suppressed.', '']

    render('High-Interest Permission Conditions', high)
    render('Review Candidates', review)

    lines += ['Linux Capabilities', '==================', '']
    if cap_lines:
        for entry in cap_lines:
            lines += ['[REVIEW]', entry, 'Tester Action: Confirm the capability is required and whether the exposed application functionality permits abuse of that capability.', '']
    else:
        lines += ['None added.', '']

    lines += ['SUID / SGID', '===========', '']
    if suid_lines:
        for entry in suid_lines:
            lines += ['[REVIEW]', entry, 'Tester Action: Review the privileged executable for unsafe argument, environment, path, file, and command handling.', '']
    else:
        lines += ['None added.', '']

    lines += [
        'Normal Permission Summary', '=========================', '',
        f'{normal_count} changed object(s) did not meet the prioritized review criteria and are intentionally omitted from the detailed report.',
        'Raw filesystem metadata remains available to the framework in working/snapshot_post.json.',
    ]

    write_text(report_path(output_dir, 'permissions_review.txt'), '\n'.join(lines))
    return {
        'permission_candidates': candidates,
        'high_interest_candidates': high,
        'review_candidates': review,
        'capability_candidates': [{'entry': x} for x in cap_lines],
        'suid_candidates': [{'entry': x} for x in suid_lines],
    }
