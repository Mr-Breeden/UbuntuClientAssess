from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from .common import get_interactive_home, run_cmd

_BROAD = {
    Path('/'), Path('/etc'), Path('/usr'), Path('/usr/bin'), Path('/usr/sbin'),
    Path('/usr/lib'), Path('/usr/libexec'), Path('/usr/share'), Path('/var'),
    Path('/var/lib'), Path('/var/opt'), Path('/opt'), Path('/run'),
}
_GENERIC_ETC = {'systemd', 'dbus-1', 'polkit-1', 'sudoers.d', 'apt', 'cron.d', 'profile.d', 'xdg'}
_GENERIC_USR_LIB = {'systemd', 'dbus-1.0', 'policykit-1', 'tmpfiles.d', 'udev', 'locale', 'pam', 'python3', 'jvm'}
_GENERIC_USR_SHARE = {'applications', 'dbus-1', 'polkit-1', 'icons', 'pixmaps', 'mime', 'doc', 'man', 'locale', 'systemd'}


def _clean_slug(value: str) -> str:
    value = Path(value).name.strip().casefold()
    value = re.sub(r'\.(?:service|desktop|sh|py|bin)$', '', value)
    value = re.sub(r'[^a-z0-9._+-]+', '-', value).strip('-._')
    return value


def _candidate_root(path: Path) -> Path | None:
    parts = path.parts
    if len(parts) >= 3 and parts[1] == 'opt':
        return Path('/opt') / parts[2]
    if len(parts) >= 3 and parts[1] == 'etc':
        return None if parts[2] in _GENERIC_ETC else Path('/etc') / parts[2]
    if len(parts) >= 4 and parts[1:3] in {('usr', 'lib'), ('usr', 'share'), ('var', 'lib'), ('var', 'opt')}:
        leaf = parts[3]
        if parts[1:3] == ('usr', 'lib') and (leaf in _GENERIC_USR_LIB or leaf.endswith('-linux-gnu') or leaf.startswith('python3.')):
            return None
        if parts[1:3] == ('usr', 'share') and leaf in _GENERIC_USR_SHARE:
            return None
        return Path('/') / parts[1] / parts[2] / leaf
    if len(parts) >= 4 and parts[1:3] == ('usr', 'libexec'):
        return Path('/usr/libexec') / parts[3]
    return None


def infer_debian_application_scope(installer: Path | None, declared_paths: Iterable[Path]) -> dict[str, Any]:
    """Infer conservative application roots/launcher from a Debian manifest.

    The function intentionally favors application-specific roots and never returns
    broad operating-system directories such as /usr/share or /etc.
    """
    paths = sorted({Path(p) for p in declared_paths}, key=str)
    package = ''
    if installer is not None and installer.is_file() and installer.name.lower().endswith('.deb'):
        result = run_cmd(['dpkg-deb', '-f', str(installer), 'Package'])
        if result['returncode'] == 0:
            package = result['stdout'].strip()

    roots = sorted({root for p in paths if (root := _candidate_root(p)) and root not in _BROAD}, key=str)

    # Prefer /opt as the primary installation root, then an application-specific
    # /usr/lib or /usr/libexec root. Configuration/state roots stay supplemental.
    def root_rank(root: Path) -> tuple[int, int, str]:
        text = str(root)
        if text.startswith('/opt/'):
            rank = 5
        elif text.startswith('/usr/libexec/'):
            rank = 4
        elif text.startswith('/usr/lib/'):
            rank = 3
        elif text.startswith('/var/lib/'):
            rank = 2
        else:
            rank = 1
        return (rank, -len(root.parts), text)

    primary_root = max(roots, key=root_rank) if roots else None
    root_slug = _clean_slug(primary_root.name) if primary_root else ''
    package_slug = _clean_slug(package)
    package_tokens = {token for token in re.split(r'[-_.+]+', package_slug) if len(token) >= 3}
    root_tokens = {token for token in re.split(r'[-_.+]+', root_slug) if len(token) >= 2}

    launchers = [p for p in paths if p.parent in {Path('/usr/bin'), Path('/usr/sbin'), Path('/usr/local/bin')}]
    def launcher_rank(path: Path) -> tuple[int, int, str]:
        name = _clean_slug(path.name)
        score = 0
        if root_slug and (name == root_slug or root_slug in name or name in root_slug):
            score += 10
        score += 2 * len((package_tokens | root_tokens).intersection(set(re.split(r'[-_.+]+', name))))
        if path.parent == Path('/usr/bin'):
            score += 2
        return (score, -len(name), str(path))
    launcher = max(launchers, key=launcher_rank) if launchers else None

    slug = root_slug or (_clean_slug(launcher.name) if launcher else package_slug)
    return {
        'package': package or None,
        'application_root': str(primary_root) if primary_root else None,
        'application_path': str(launcher) if launcher else None,
        'application_roots': [str(root) for root in roots],
        'application_slug': slug or None,
    }



def infer_application_roots_from_evidence(paths: Iterable[Path], process_lines: Iterable[str] = ()) -> list[Path]:
    """Infer application-specific roots from post-install filesystem and process evidence.

    This is intentionally conservative and is useful for non-package installers
    whose installed location is learned only after setup.
    """
    roots = {root for p in paths if (root := _candidate_root(Path(p))) and root not in _BROAD}
    for line in process_lines:
        for match in re.findall(r"/(?:opt|usr/local|usr/libexec|usr/lib|var/opt|var/lib)/[^\s'\"]+", str(line)):
            token = match.rstrip(",;:)]")
            path = Path(token)
            root = _candidate_root(path)
            if root is None and len(path.parts) >= 4 and path.parts[1:3] == ("usr", "local"):
                root = Path("/usr/local") / path.parts[3]
            if root and root not in _BROAD:
                roots.add(root)
    return sorted(roots, key=str)

def discover_runtime_roots(scope: dict[str, Any] | None, *, existing_only: bool = True) -> list[Path]:
    """Return application-specific runtime/user-data roots without scanning whole profiles."""
    scope = scope or {}
    roots: set[Path] = set()
    for value in scope.get('application_roots', []) or []:
        path = Path(str(value)).expanduser().resolve(strict=False)
        roots.add(path)

    slug = _clean_slug(str(scope.get('application_slug') or ''))
    home = get_interactive_home().resolve(strict=False)
    if slug:
        candidates = [
            Path('/run') / slug,
            home / '.config' / slug,
            home / '.local' / 'share' / slug,
            home / '.cache' / slug,
        ]
        for candidate in candidates:
            if not existing_only or candidate.exists() or candidate.is_symlink():
                roots.add(candidate.resolve(strict=False))

    return sorted(roots, key=str)


def path_within_scope(path: Path | str, roots: Iterable[Path | str]) -> bool:
    try:
        target = Path(path).expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        target = Path(str(path)).expanduser()
    for raw in roots:
        try:
            root = Path(raw).expanduser().resolve(strict=False)
        except (OSError, RuntimeError):
            root = Path(str(raw)).expanduser()
        if target == root or root in target.parents:
            return True
    return False
