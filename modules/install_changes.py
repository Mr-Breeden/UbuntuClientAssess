from __future__ import annotations

from collections import Counter
import re
from pathlib import Path
from typing import Any, Callable

from .common import human_size, read_json, report_path, write_text
from .path_interest import classify_high_interest
from .snapshot import _normalize_socket_lines

DETAIL_LIMIT = 120
AMBIENT_RUNNING_SERVICES = {'packagekit.service'}


def _set_diff(pre: list[str], post: list[str]) -> tuple[list[str], list[str]]:
    a, b = set(pre), set(post)
    return sorted(b - a), sorted(a - b)


def _timer_name(entry: str) -> str:
    for token in entry.split():
        if token.endswith('.timer'):
            return token
    return entry.strip()


def _legacy_unit_records(entries: list[str], suffix: str) -> dict[str, dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    for raw in entries:
        parts = raw.split()
        if not parts:
            continue
        unit = next((x for x in parts if x.endswith(suffix)), parts[0])
        try:
            idx = parts.index(unit)
        except ValueError:
            idx = 0
        rest = parts[idx + 1:]
        records[unit] = {
            'state': rest[0] if rest else 'unknown',
            'preset': rest[1] if len(rest) > 1 else '',
        }
    return records


def _unit_diff(
    pre: dict[str, Any],
    post: dict[str, Any],
    record_key: str,
    legacy_key: str,
    suffix: str,
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    pre_units = pre.get(record_key) or _legacy_unit_records(pre.get(legacy_key, []), suffix)
    post_units = post.get(record_key) or _legacy_unit_records(post.get(legacy_key, []), suffix)
    pre_names, post_names = set(pre_units), set(post_units)
    added = sorted(post_names - pre_names)
    removed = sorted(pre_names - post_names)
    modified: list[dict[str, Any]] = []
    for unit in sorted(pre_names & post_names):
        before, after = pre_units.get(unit, {}), post_units.get(unit, {})
        if before != after:
            modified.append({'unit': unit, 'before': before, 'after': after})
    return added, removed, modified


def _timer_diff(pre: dict[str, Any], post: dict[str, Any]) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    if pre.get('timer_units') or post.get('timer_units'):
        return _unit_diff(pre, post, 'timer_units', 'timers', '.timer')
    # v0.3.0 and older snapshots stored volatile `list-timers` rows. Reduce
    # those to timer names so NEXT/LAST/LEFT changes do not create false diffs.
    pre_names = {_timer_name(x) for x in pre.get('timers', []) if _timer_name(x)}
    post_names = {_timer_name(x) for x in post.get('timers', []) if _timer_name(x)}
    return sorted(post_names - pre_names), sorted(pre_names - post_names), []


def _identity_diff(
    pre_lines: list[str], post_lines: list[str], key_fn: Callable[[str], str]
) -> tuple[list[str], list[str], list[dict[str, str]]]:
    pre_map = {key_fn(x): x for x in pre_lines if key_fn(x)}
    post_map = {key_fn(x): x for x in post_lines if key_fn(x)}
    pre_keys, post_keys = set(pre_map), set(post_map)
    added = [post_map[k] for k in sorted(post_keys - pre_keys)]
    removed = [pre_map[k] for k in sorted(pre_keys - post_keys)]
    modified = [
        {'identity': k, 'before': pre_map[k], 'after': post_map[k]}
        for k in sorted(pre_keys & post_keys)
        if pre_map[k] != post_map[k]
    ]
    return added, removed, modified



def _package_key(line: str) -> str:
    """Return package identity for both legacy package/version and status/package/version rows."""
    parts = line.split('\t')
    if len(parts) >= 3:
        return parts[1].strip()
    if len(parts) == 2:
        return parts[0].strip()
    return line.split()[0].strip() if line.split() else ''

def _passwd_key(line: str) -> str:
    return line.split(':', 1)[0].strip() if ':' in line else line.strip()


def _mount_key(line: str) -> str:
    return line.split()[0] if line.split() else ''


def _stable_mounts(lines: list[str]) -> list[str]:
    """Remove per-user runtime mounts created by login/sudo session churn."""
    return [line for line in lines if not re.fullmatch(r'/run/user/\d+', _mount_key(line))]


def _is_volatile_filesystem_path(path_text: str) -> bool:
    """Identify desktop-session metadata that is unrelated to application installs."""
    if '/.local/share/gvfs-metadata/' in path_text or path_text.endswith('/.local/share/gvfs-metadata'):
        return True
    return path_text.endswith('/.local/share/gnome-shell') or path_text.endswith(
        '/.local/share/gnome-shell/application_state'
    )


def _running_service_names(lines: list[str]) -> list[str]:
    names: set[str] = set()
    for raw in lines:
        for token in raw.split():
            if token.endswith('.service'):
                names.add(token)
                break
    return sorted(names)


def _stable_running_service_names(lines: list[str]) -> list[str]:
    """Remove package-manager helpers activated as ambient installation activity."""
    return [name for name in _running_service_names(lines) if name not in AMBIENT_RUNNING_SERVICES]


def _install_bucket(path_text: str) -> str:
    p = Path(path_text)
    parts = p.parts
    if len(parts) >= 3 and parts[1] == 'opt':
        return str(Path('/opt') / parts[2])
    if len(parts) >= 4 and parts[1:3] in {('usr', 'lib'), ('usr', 'share'), ('var', 'lib'), ('var', 'opt')}:
        return str(Path('/') / parts[1] / parts[2] / parts[3])
    if len(parts) >= 3 and parts[1] == 'etc' and parts[2] not in {'systemd', 'apt', 'dbus-1', 'polkit-1'}:
        return str(Path('/etc') / parts[2])
    for root in ('/etc/systemd/system', '/usr/lib/systemd/system', '/usr/bin', '/usr/sbin', '/usr/local/bin',
                 '/usr/share/applications', '/etc/apt/sources.list.d', '/etc/sudoers.d', '/etc/dbus-1', '/etc/polkit-1'):
        if path_text == root or path_text.startswith(root + '/'):
            return root
    return str(p.parent)


def _is_high_interest(path_text: str, meta: dict[str, Any]) -> tuple[bool, str]:
    return classify_high_interest(path_text, str(meta.get('type', '')), str(meta.get('mode', '')))


def _summarize_added(lines: list[str], files: list[str], post_fs: dict[str, Any]) -> None:
    lines += ['Filesystem Added', '----------------']
    if not files:
        lines += ['None observed.', '']
        return

    buckets = Counter(_install_bucket(p) for p in files)
    type_counts = Counter(post_fs.get(p, {}).get('type', 'unknown') for p in files)
    high: list[tuple[str, str]] = []
    for p in files:
        interesting, label = _is_high_interest(p, post_fs.get(p, {}))
        if interesting:
            high.append((label, p))

    lines += [
        f'Total filesystem objects added: {len(files)}',
        f"Files: {type_counts.get('file', 0)} | Directories: {type_counts.get('directory', 0)} | Symlinks: {type_counts.get('symlink', 0)}",
        '', 'Primary Installation Locations', '------------------------------',
    ]
    for root, count in buckets.most_common(20):
        lines.append(f'{root:<55} {count:>7} object(s)')
    if len(buckets) > 20:
        lines.append(f'... {len(buckets) - 20} additional locations summarized in the raw working snapshots.')

    lines += ['', 'High-Interest Added Objects', '---------------------------']
    if high:
        for label, p in high[:DETAIL_LIMIT]:
            meta = post_fs.get(p, {})
            suffix = f" -> {meta.get('target')}" if meta.get('type') == 'symlink' and meta.get('target') else ''
            lines.append(f'[{label}] {p}{suffix}')
        if len(high) > DETAIL_LIMIT:
            lines.append(f'... {len(high) - DETAIL_LIMIT} additional high-interest objects omitted from this text report.')
    else:
        lines.append('No high-interest added objects identified by the report filter.')

    suppressed = max(0, len(files) - min(len(high), DETAIL_LIMIT))
    lines += [
        '', 'Detailed Listing', '----------------',
        f'{suppressed} routine/bundled added object(s) are not listed individually.',
        'Complete filesystem state is retained in working/snapshot_post.json for framework comparison and troubleshooting.', '',
    ]


def _summarize_path_list(lines: list[str], title: str, items: list[str], limit: int = DETAIL_LIMIT) -> None:
    lines += [title, '-' * len(title)]
    if not items:
        lines += ['None observed.', '']
        return
    for item in items[:limit]:
        lines.append(item)
    if len(items) > limit:
        lines.append(f'... {len(items) - limit} additional entries suppressed; raw state is retained in working snapshots.')
    lines.append('')


def _application_processes(processes: list[str], files_added: list[str]) -> tuple[list[str], int]:
    """Separate likely installed-application processes from ambient host churn."""
    roots = {
        _install_bucket(path)
        for path in files_added
        if path.startswith(('/opt/', '/usr/lib/', '/var/opt/'))
    }
    related = [line for line in processes if any(root in line for root in roots)]
    return related, max(0, len(processes) - len(related))


def _summarize_processes(lines: list[str], processes: list[str], files_added: list[str]) -> None:
    related, ambient_count = _application_processes(processes, files_added)
    lines += ['Application-Related Processes Added', '-----------------------------------']
    if related:
        lines.extend(related[:DETAIL_LIMIT])
        if len(related) > DETAIL_LIMIT:
            lines.append(f'... {len(related) - DETAIL_LIMIT} additional application-related entries suppressed.')
    else:
        lines.append('None correlated with newly installed application locations.')
    lines += [
        f'Ambient host processes suppressed from this section: {ambient_count}',
        'The complete process differential remains in the returned analysis data and working snapshots.',
        '',
    ]


def _render_modified(lines: list[str], title: str, items: list[dict[str, Any]]) -> None:
    lines += [title, '-' * len(title)]
    if not items:
        lines += ['None observed.', '']
        return
    for item in items[:DETAIL_LIMIT]:
        identity = item.get('unit') or item.get('identity') or 'unknown'
        lines += [identity, f"  Before: {item.get('before')}", f"  After:  {item.get('after')}", '']
    if len(items) > DETAIL_LIMIT:
        lines.append(f'... {len(items) - DETAIL_LIMIT} additional modified entries suppressed.')
        lines.append('')


def compare_snapshots(pre_path: Path, post_path: Path, output_dir: Path) -> dict[str, Any]:
    pre = read_json(pre_path)
    post = read_json(post_path)

    # Raw-state lists that are intrinsically stable enough for set comparison.
    keys = {
        'processes': 'processes',
        'listening_sockets': 'listening_sockets', 'network_connections': 'network_connections', 'unix_sockets': 'unix_sockets',
        'snap_packages': 'snap_packages', 'flatpak_packages': 'flatpak_packages', 'flatpak_remotes': 'flatpak_remotes',
        'user_crontab': 'user_crontab', 'root_crontab': 'root_crontab', 'capabilities': 'capabilities', 'suid_sgid': 'suid_sgid',
    }
    diffs: dict[str, tuple[list[str], list[str]]] = {}
    for out_key, source_key in keys.items():
        pre_values = pre.get(source_key, [])
        post_values = post.get(source_key, [])
        if source_key in {'listening_sockets', 'network_connections', 'unix_sockets'}:
            # Re-normalize at comparison time so snapshots created by older
            # framework revisions also benefit from current volatility rules.
            pre_values = _normalize_socket_lines(pre_values)
            post_values = _normalize_socket_lines(post_values)
        diffs[out_key] = _set_diff(pre_values, post_values)

    packages_added, packages_removed, packages_modified = _identity_diff(
        pre.get('packages', []), post.get('packages', []), _package_key
    )
    services_added, services_removed, services_modified = _unit_diff(pre, post, 'service_units', 'services', '.service')
    timers_added, timers_removed, timers_modified = _timer_diff(pre, post)
    running_added, running_removed = _set_diff(
        _stable_running_service_names(pre.get('running_services', [])),
        _stable_running_service_names(post.get('running_services', [])),
    )
    users_added, users_removed, users_modified = _identity_diff(pre.get('users', []), post.get('users', []), _passwd_key)
    groups_added, groups_removed, groups_modified = _identity_diff(pre.get('groups', []), post.get('groups', []), _passwd_key)
    mounts_added, mounts_removed, mounts_modified = _identity_diff(
        _stable_mounts(pre.get('mounts', [])),
        _stable_mounts(post.get('mounts', [])),
        _mount_key,
    )

    pre_fs = pre.get('filesystem', {})
    post_fs = post.get('filesystem', {})
    pre_paths = {path for path in pre_fs if not _is_volatile_filesystem_path(path)}
    post_paths = {path for path in post_fs if not _is_volatile_filesystem_path(path)}
    files_added = sorted(post_paths - pre_paths)
    files_removed = sorted(pre_paths - post_paths)
    files_changed: list[str] = []
    for path in sorted(pre_paths & post_paths):
        a, b = pre_fs[path], post_fs[path]
        compare_keys = ('type', 'mode_octal', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns', 'sha256', 'target')
        if any(a.get(k) != b.get(k) for k in compare_keys):
            files_changed.append(path)

    diff: dict[str, Any] = {
        'files_added': files_added, 'files_removed': files_removed, 'files_changed': files_changed,
        'post_filesystem': post_fs, 'pre_filesystem': pre_fs,
        'post_processes': post.get('processes', []), 'pre_processes': pre.get('processes', []),
        'packages_added': packages_added, 'packages_removed': packages_removed, 'packages_modified': packages_modified,
        'services_added': services_added, 'services_removed': services_removed, 'services_modified': services_modified,
        'post_service_units': post.get('service_units') or _legacy_unit_records(post.get('services', []), '.service'),
        'running_services_added': running_added, 'running_services_removed': running_removed,
        'timers_added': timers_added, 'timers_removed': timers_removed, 'timers_modified': timers_modified,
        'users_added': users_added, 'users_removed': users_removed, 'users_modified': users_modified,
        'groups_added': groups_added, 'groups_removed': groups_removed, 'groups_modified': groups_modified,
        'mounts_added': mounts_added, 'mounts_removed': mounts_removed, 'mounts_modified': mounts_modified,
    }
    for key, (added, removed) in diffs.items():
        diff[f'{key}_added'] = added
        diff[f'{key}_removed'] = removed

    application_processes, ambient_process_count = _application_processes(diff['processes_added'], files_added)
    lines = [
        'Installation Differential', '=' * 25, '',
        'This report summarizes meaningful system-state changes observed between the pre-installation and post-installation snapshots.',
        'Large application file trees are summarized instead of being dumped line-by-line. Raw state remains in the working snapshots.',
        'systemd services/timers are compared by stable unit identity/state; volatile runtime columns are ignored.',
        '', 'Summary', '-------',
        f"Packages added:             {len(diff['packages_added'])}",
        f"Packages removed:           {len(diff['packages_removed'])}",
        f"Packages modified:          {len(diff['packages_modified'])}",
        f"Snap packages added:        {len(diff['snap_packages_added'])}",
        f"Flatpak packages added:     {len(diff['flatpak_packages_added'])}",
        f"Flatpak remotes added:      {len(diff['flatpak_remotes_added'])}",
        f"Processes added:            {len(diff['processes_added'])}",
        f"Application-related:        {len(application_processes)}",
        f"Ambient process churn:      {ambient_process_count}",
        f'Filesystem added:           {len(files_added)}',
        f'Filesystem removed:         {len(files_removed)}',
        f'Filesystem changed:         {len(files_changed)}',
        f'Services added:             {len(services_added)}',
        f'Services removed:           {len(services_removed)}',
        f'Services modified:          {len(services_modified)}',
        f'Running services added:     {len(running_added)}',
        f'Timers added:               {len(timers_added)}',
        f'Timers removed:             {len(timers_removed)}',
        f'Timers modified:            {len(timers_modified)}',
        f'Users added:                {len(users_added)}',
        f'Groups added:               {len(groups_added)}',
        f'Groups modified:            {len(groups_modified)}',
        f'Mounts added:               {len(mounts_added)}',
        f"User cron entries added:    {len(diff['user_crontab_added'])}",
        f"Root cron entries added:    {len(diff['root_crontab_added'])}",
        f"Listening sockets added:    {len(diff['listening_sockets_added'])}",
        f"Network connections added:  {len(diff['network_connections_added'])}",
        f"Unix sockets added:         {len(diff['unix_sockets_added'])}",
        f"Capabilities added:         {len(diff['capabilities_added'])}",
        f"SUID/SGID entries added:    {len(diff['suid_sgid_added'])}", '',
    ]

    _summarize_path_list(lines, 'Packages Added', diff['packages_added'])
    _summarize_path_list(lines, 'Packages Removed', diff['packages_removed'])
    _render_modified(lines, 'Packages Modified', diff['packages_modified'])
    _summarize_path_list(lines, 'Snap Packages Added', diff['snap_packages_added'])
    _summarize_path_list(lines, 'Snap Packages Removed', diff['snap_packages_removed'])
    _summarize_path_list(lines, 'Flatpak Packages Added', diff['flatpak_packages_added'])
    _summarize_path_list(lines, 'Flatpak Packages Removed', diff['flatpak_packages_removed'])
    _summarize_path_list(lines, 'Flatpak Remotes Added', diff['flatpak_remotes_added'])
    _summarize_path_list(lines, 'Flatpak Remotes Removed', diff['flatpak_remotes_removed'])
    _summarize_processes(lines, diff['processes_added'], files_added)
    _summarize_added(lines, files_added, post_fs)

    lines += ['Filesystem Changed', '------------------']
    if files_changed:
        for p in files_changed[:DETAIL_LIMIT]:
            a, b = pre_fs.get(p, {}), post_fs.get(p, {})
            changes = []
            if a.get('type') != b.get('type'): changes.append(f"type {a.get('type')} -> {b.get('type')}")
            if a.get('mode_octal') != b.get('mode_octal'): changes.append(f"mode {a.get('mode_octal')} -> {b.get('mode_octal')}")
            if (a.get('uid'), a.get('gid')) != (b.get('uid'), b.get('gid')):
                changes.append(f"owner {a.get('owner')}:{a.get('group')} -> {b.get('owner')}:{b.get('group')}")
            if a.get('size') != b.get('size'): changes.append(f"size {human_size(a.get('size'))} -> {human_size(b.get('size'))}")
            if a.get('sha256') != b.get('sha256') and (a.get('sha256') or b.get('sha256')): changes.append('content hash changed')
            if a.get('target') != b.get('target'): changes.append(f"symlink target {a.get('target')} -> {b.get('target')}")
            if not changes: changes.append('metadata timestamp changed')
            lines.append(f'{p}\n    ' + '; '.join(changes))
        if len(files_changed) > DETAIL_LIMIT:
            lines.append(f'... {len(files_changed) - DETAIL_LIMIT} additional changed objects suppressed.')
    else:
        lines.append('None observed.')
    lines.append('')

    _summarize_path_list(lines, 'Filesystem Removed', files_removed)
    _summarize_path_list(lines, 'Services Added', services_added)
    _summarize_path_list(lines, 'Services Removed', services_removed)
    _render_modified(lines, 'Services Modified', services_modified)
    _summarize_path_list(lines, 'Running Services Added', running_added)
    _summarize_path_list(lines, 'Running Services Removed', running_removed)
    _summarize_path_list(lines, 'Timers Added', timers_added)
    _summarize_path_list(lines, 'Timers Removed', timers_removed)
    _render_modified(lines, 'Timers Modified', timers_modified)

    for title, items in [
        ('Users Added', users_added), ('Users Removed', users_removed),
        ('Groups Added', groups_added), ('Groups Removed', groups_removed),
        ('Mounts Added', mounts_added), ('Mounts Removed', mounts_removed),
        ('User Cron Entries Added', diff['user_crontab_added']), ('User Cron Entries Removed', diff['user_crontab_removed']),
        ('Root Cron Entries Added', diff['root_crontab_added']), ('Root Cron Entries Removed', diff['root_crontab_removed']),
        ('Listening Sockets Added', diff['listening_sockets_added']), ('Listening Sockets Removed', diff['listening_sockets_removed']),
        ('Network Connections Added', diff['network_connections_added']), ('Network Connections Removed', diff['network_connections_removed']),
        ('Unix Sockets Added', diff['unix_sockets_added']), ('Unix Sockets Removed', diff['unix_sockets_removed']),
        ('Capabilities Added', diff['capabilities_added']), ('Capabilities Removed', diff['capabilities_removed']),
        ('SUID/SGID Entries Added', diff['suid_sgid_added']), ('SUID/SGID Entries Removed', diff['suid_sgid_removed']),
    ]:
        _summarize_path_list(lines, title, items)
    _render_modified(lines, 'Users Modified', users_modified)
    _render_modified(lines, 'Groups Modified', groups_modified)
    _render_modified(lines, 'Mounts Modified', mounts_modified)

    write_text(report_path(output_dir, 'install_changes.txt'), '\n'.join(lines))
    return diff
