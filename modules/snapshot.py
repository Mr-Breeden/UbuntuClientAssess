from __future__ import annotations

import grp
import os
import pwd
import re
import stat
import time
from pathlib import Path
from typing import Any

from .common import VERSION, command_exists, get_interactive_home, get_interactive_user, mode_string, now_iso, redact_sensitive_text, run_cmd, sha256_file, write_json

MAX_HASH_SIZE = 50 * 1024 * 1024
HASH_CACHE_LIMIT = 250000
_HASH_CACHE: dict[tuple[int, int, int, int, int], str | None] = {}
_VERBOSITY = 0


def configure_progress(*, verbose: bool = False, debug: bool = False) -> None:
    """Configure snapshot detail without changing captured evidence."""
    global _VERBOSITY
    _VERBOSITY = 2 if debug else 1 if verbose else 0


def _detail(message: str, level: int = 1) -> None:
    if _VERBOSITY >= level:
        print(message, flush=True)


def default_tracked_paths() -> list[Path]:
    home = get_interactive_home()
    return [
        Path("/opt"),
        Path("/usr/local"),
        Path("/etc/systemd/system"),
        Path("/usr/lib/systemd/system"),
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/var/spool/cron/crontabs"),
        Path("/etc/profile"),
        Path("/etc/profile.d"),
        Path("/etc/rc.local"),
        Path("/etc/ld.so.conf.d"),
        # Common certificate/key locations are tracked so a post-install script
        # that generates or installs local CA material is visible even when the
        # files were not declared in the package manifest. /usr/local is already
        # covered above, including /usr/local/share/ca-certificates.
        Path("/etc/ssl"),
        Path("/etc/pki"),
        Path("/etc/ca-certificates"),
        Path("/etc/apt/sources.list.d"),
        Path("/etc/sudoers"),
        Path("/etc/sudoers.d"),
        Path("/etc/dbus-1/system.d"),
        Path("/usr/share/dbus-1/system-services"),
        Path("/usr/share/dbus-1/system.d"),
        Path("/etc/polkit-1/rules.d"),
        Path("/usr/share/polkit-1/actions"),
        Path("/usr/share/applications"),
        home / ".bashrc",
        home / ".profile",
        home / ".zshrc",
        home / ".config",
        home / ".config" / "autostart",
        home / ".local" / "share",
    ]


def merge_tracked_paths(extra_paths: list[Path] | None = None) -> list[Path]:
    # Collapse descendant roots so a package containing /usr/lib/vendor plus
    # hundreds of files beneath it is traversed once rather than once per file.
    candidates = {Path(p) for p in default_tracked_paths()}
    candidates.update(Path(p) for p in (extra_paths or []))
    selected: list[Path] = []
    for path in sorted(candidates, key=lambda p: (len(p.parts), str(p))):
        if any(parent == path or parent in path.parents for parent in selected):
            continue
        selected.append(path)
    return sorted(selected, key=str)


def _command_lines(cmd: list[str], timeout: int = 45) -> list[str]:
    result = run_cmd(cmd, timeout=timeout)
    return sorted(line.rstrip() for line in result["stdout"].splitlines() if line.strip())


def _safe_owner(st: os.stat_result) -> tuple[str, str]:
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return owner, group


def _file_type(p: Path, st: os.stat_result) -> str:
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "char-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "other"


def _is_excluded(path: Path, excluded_paths: list[Path]) -> bool:
    return any(path == excluded or excluded in path.parents for excluded in excluded_paths)


def _snapshot_hash(path: Path, st: os.stat_result) -> str | None:
    """Reuse hashes for unchanged inodes between pre/post snapshots.

    Size, modification time, and change time are part of the cache identity so
    content/metadata changes invalidate the entry. This substantially reduces
    repeated I/O for large application trees while retaining differential
    integrity within one framework process.
    """
    if st.st_size > MAX_HASH_SIZE:
        return None
    key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if key in _HASH_CACHE:
        return _HASH_CACHE[key]
    digest = sha256_file(path, MAX_HASH_SIZE)
    if len(_HASH_CACHE) >= HASH_CACHE_LIMIT:
        _HASH_CACHE.pop(next(iter(_HASH_CACHE)))
    _HASH_CACHE[key] = digest
    return digest


def _walk_snapshot_paths(root: Path, excluded_paths: list[Path], collection_gaps: list[dict[str, Any]] | None = None):
    """Stream entries and prune excluded trees before opening them."""
    if _is_excluded(root, excluded_paths):
        return
    yield root
    if not root.is_dir() or root.is_symlink():
        return
    collection_gaps = collection_gaps if collection_gaps is not None else []
    def onerror(exc: OSError) -> None:
        collection_gaps.append({"path": str(getattr(exc, "filename", None) or root), "operation": "walk", "errno": getattr(exc, "errno", None), "error": str(exc)})
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        base = Path(directory)
        dirs[:] = [name for name in dirs if not _is_excluded(base / name, excluded_paths)]
        for name in dirs + files:
            path = base / name
            if not _is_excluded(path, excluded_paths):
                yield path


def _collect_filesystem(paths: list[Path], excluded_paths: list[Path] | None = None, collection_gaps: list[dict[str, Any]] | None = None) -> dict[str, dict[str, Any]]:
    excluded_paths = excluded_paths or []
    collection_gaps = collection_gaps if collection_gaps is not None else []
    result: dict[str, dict[str, Any]] = {}
    owners: dict[tuple[int, int], tuple[str, str]] = {}
    last_progress = time.monotonic()
    for root in paths:
        if _is_excluded(root, excluded_paths):
            continue
        if not root.exists() and not root.is_symlink():
            continue
        _detail(f"    Scanning files: {root}")
        for p in _walk_snapshot_paths(root, excluded_paths, collection_gaps):
            try:
                st = p.lstat()
                owner_key = (st.st_uid, st.st_gid)
                if owner_key not in owners:
                    owners[owner_key] = _safe_owner(st)
                owner, group = owners[owner_key]
                ptype = _file_type(p, st)
                item: dict[str, Any] = {
                    "type": ptype,
                    "mode": mode_string(st.st_mode),
                    "mode_octal": oct(stat.S_IMODE(st.st_mode)),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "owner": owner,
                    "group": group,
                    "size": st.st_size,
                    "mtime_ns": st.st_mtime_ns,
                    "ctime_ns": st.st_ctime_ns,
                    "sha256": _snapshot_hash(p, st) if ptype == "file" else None,
                }
                if ptype == "symlink":
                    try:
                        item["target"] = os.readlink(p)
                    except OSError:
                        item["target"] = None
                result[str(p)] = item
                if _VERBOSITY and time.monotonic() - last_progress >= 5:
                    _detail(f"    Scanned {len(result):,} entries; current file: {p}", 1)
                    last_progress = time.monotonic()
            except (OSError, PermissionError) as exc:
                collection_gaps.append({"path": str(p), "operation": "metadata", "errno": getattr(exc, "errno", None), "error": str(exc)})
                continue
    return result


def _normalize_socket_lines(lines: list[str]) -> list[str]:
    normalized: set[str] = set()
    for line in lines:
        # Preserve process names/endpoints while removing volatile identifiers
        # that otherwise make a service restart look like a new socket.
        # `ss -H -lxnp` emits unlabeled Recv-Q, Send-Q, inode, and peer-inode
        # columns for Unix sockets. These values can change between otherwise
        # identical snapshots, so normalize the stable eight-column prefix.
        parts = line.split()
        if len(parts) >= 8 and parts[0].startswith("u_"):
            parts[2] = "<RECV-Q>"
            parts[3] = "<SEND-Q>"
            parts[5] = "<INO>"
            parts[7] = "<PEER-INO>"
            line = " ".join(parts)
        elif len(parts) >= 5 and parts[0] in {"tcp", "udp"}:
            # Recv-Q/Send-Q are volatile and should not make an otherwise
            # identical listener/connection appear added and removed.
            parts[2] = "<RECV-Q>"
            parts[3] = "<SEND-Q>"
            line = " ".join(parts)
        line = re.sub(r"pid=\d+", "pid=<PID>", line)
        line = re.sub(r"fd=\d+", "fd=<FD>", line)
        line = re.sub(r"ino:\d+", "ino:<INO>", line)
        line = re.sub(r"sk:[0-9a-fA-F]+", "sk:<SK>", line)
        line = re.sub(r"cgroup:[^\s,)]+", "cgroup:<CGROUP>", line)
        normalized.add(line)
    return sorted(normalized)


def _collect_unit_files(unit_type: str) -> tuple[list[str], dict[str, dict[str, str]]]:
    """Collect stable unit identity/state without volatile runtime columns."""
    result = run_cmd(["systemctl", "list-unit-files", f"--type={unit_type}", "--no-pager", "--no-legend"])
    inventory: list[str] = []
    records: dict[str, dict[str, str]] = {}
    if result["returncode"] != 0:
        return inventory, records
    suffix = f".{unit_type}"
    for raw in result["stdout"].splitlines():
        parts = raw.split()
        if not parts or not parts[0].endswith(suffix):
            continue
        unit = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        preset = parts[2] if len(parts) > 2 else ""
        inventory.append(" ".join(x for x in (unit, state, preset) if x))
        records[unit] = {"state": state, "preset": preset}
    return sorted(inventory), records


def _collect_timer_units() -> tuple[list[str], dict[str, dict[str, str]]]:
    """Collect stable timer identity/configuration without volatile NEXT/LAST fields."""
    inventory, records = _collect_unit_files("timer")
    for unit in list(records):
        _detail(f"    Reading timer: {unit}", 2)
        cat = run_cmd(["systemctl", "cat", unit], timeout=20)
        unit_text = cat["stdout"].strip() if cat["returncode"] == 0 else ""
        stable_text = "\n".join(
            line.rstrip() for line in unit_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        records[unit]["unit_text"] = stable_text
    return inventory, records


def _collect_service_units() -> tuple[list[str], dict[str, dict[str, str]]]:
    # Service configuration changes are already covered by filesystem snapshot
    # metadata. Here we need stable service identity/state so enabled/disabled
    # changes are classified as modifications instead of add/remove pairs.
    return _collect_unit_files("service")


def _running_service_names() -> list[str]:
    result = run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
    names: set[str] = set()
    if result["returncode"] == 0:
        for raw in result["stdout"].splitlines():
            parts = raw.split()
            if parts and parts[0].endswith(".service"):
                names.add(parts[0])
    return sorted(names)


def _user_crontab() -> list[str]:
    user = get_interactive_user()
    result = run_cmd(["crontab", "-l", "-u", user])
    if result["returncode"] != 0:
        return []
    return sorted(line.rstrip() for line in result["stdout"].splitlines() if line.strip() and not line.lstrip().startswith("#"))



def _root_crontab() -> list[str]:
    if not command_exists("sudo") or not command_exists("crontab"):
        return []
    result = run_cmd(["sudo", "-n", "crontab", "-l", "-u", "root"], timeout=10)
    if result["returncode"] != 0:
        return []
    return sorted(line.rstrip() for line in result["stdout"].splitlines() if line.strip() and not line.lstrip().startswith("#"))

def _snap_inventory() -> list[str]:
    if not command_exists("snap"):
        return []
    result = run_cmd(["snap", "list"])
    if result["returncode"] != 0:
        return []
    lines = [line.rstrip() for line in result["stdout"].splitlines() if line.strip()]
    return sorted(lines[1:] if lines and lines[0].lower().startswith("name ") else lines)


def _flatpak_inventory() -> list[str]:
    if not command_exists("flatpak"):
        return []
    return _command_lines([
        "flatpak", "list", "--columns=application,ref,version,branch,origin,installation",
    ])


def _flatpak_remotes() -> list[str]:
    if not command_exists("flatpak"):
        return []
    return _command_lines(["flatpak", "remotes", "--columns=name,url,collection,filter,options,installation"])


def _network_connections() -> list[str]:
    """Collect process-correlated non-listening INET connections."""
    lines = _command_lines(["ss", "-H", "-ntupn"])
    active = []
    for line in lines:
        parts = line.split()
        state = parts[1].upper() if len(parts) > 1 and parts[0].lower() in {"tcp", "udp"} else parts[0].upper() if parts else ""
        if state not in {"LISTEN", "UNCONN"}:
            active.append(line)
    return _normalize_socket_lines(active)


def _collect_network_state(observation_seconds: float = 0) -> tuple[list[str], list[str], list[str]]:
    """Union socket observations over a short window to reduce timing misses."""
    listeners: set[str] = set()
    connections: set[str] = set()
    unix_sockets: set[str] = set()
    duration = max(0.0, min(float(observation_seconds or 0), 60.0))
    deadline = time.monotonic() + duration
    while True:
        listeners.update(_normalize_socket_lines(_command_lines(["ss", "-H", "-lntupn"])))
        connections.update(_network_connections())
        unix_sockets.update(_normalize_socket_lines(_command_lines(["ss", "-H", "-lxnp"])))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1.0, remaining))
    return sorted(listeners), sorted(connections), sorted(unix_sockets)


def _security_scan_paths(tracked_paths: list[Path]) -> list[Path]:
    """Return deduplicated paths relevant to capabilities/SUID checks."""
    roots: set[Path] = {Path("/opt"), Path("/usr/local"), Path("/usr/bin"), Path("/usr/sbin")}
    for p in tracked_paths:
        # Exact/package-specific paths outside the broad default roots matter,
        # especially /usr/lib/<vendor> helpers.
        if any(parent == p or parent in p.parents for parent in roots):
            continue
        if p.exists() or p.is_symlink():
            roots.add(p)
    selected: list[Path] = []
    for path in sorted(roots, key=lambda p: (len(p.parts), str(p))):
        if any(parent == path or parent in path.parents for parent in selected):
            continue
        selected.append(path)
    return selected


def _find_prune_args(excluded_paths: list[Path]) -> list[str]:
    if not excluded_paths:
        return []
    terms: list[str] = []
    for path in excluded_paths:
        if terms:
            terms.append("-o")
        # find -path interprets glob characters even without a shell.
        literal = "".join("\\" + c if c in "\\*?[]" else c for c in str(path))
        terms.extend(["-path", literal])
    return ["(", *terms, ")", "-prune", "-o"]


def _collect_capabilities(tracked_paths: list[Path], excluded_paths: list[Path] | None = None) -> list[str]:
    if not command_exists("getcap"):
        return []
    found: set[str] = set()
    for path in _security_scan_paths(tracked_paths):
        if _is_excluded(path, excluded_paths or []):
            continue
        _detail(f"    Checking security attributes: {path}", 2)
        if not path.exists() and not path.is_symlink():
            continue
        cmd = ["getcap", "-r", str(path)] if path.is_dir() else ["getcap", str(path)]
        if path.is_dir() and excluded_paths:
            cmd = ["find", str(path), *_find_prune_args(excluded_paths), "-type", "f", "-exec", "getcap", "{}", "+"]
        result = run_cmd(cmd, timeout=60)
        if result["returncode"] in {0, 1}:
            found.update(line.rstrip() for line in result["stdout"].splitlines() if line.strip())
    return sorted(found)


def _collect_suid_sgid(tracked_paths: list[Path], excluded_paths: list[Path] | None = None) -> list[str]:
    found: set[str] = set()
    for path in _security_scan_paths(tracked_paths):
        if _is_excluded(path, excluded_paths or []):
            continue
        _detail(f"    Checking security attributes: {path}", 2)
        if not path.exists() or path.is_symlink():
            continue
        if path.is_file():
            try:
                if path.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
                    found.add(str(path))
            except OSError:
                pass
            continue
        result = run_cmd([
            "find", str(path), "-xdev", *_find_prune_args(excluded_paths or []), "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print"
        ], timeout=60)
        found.update(line.rstrip() for line in result["stdout"].splitlines() if line.strip())
    return sorted(found)


def collect_snapshot(
    output_path: Path,
    label: str,
    tracked_paths: list[Path] | None = None,
    excluded_paths: list[Path] | None = None,
    network_observation_seconds: float = 0,
    progress_callback=None,
) -> dict[str, Any]:
    tracked_paths = merge_tracked_paths(tracked_paths)
    excluded_paths = sorted(
        {Path(p).expanduser().resolve() for p in (excluded_paths or [])},
        key=str,
    )
    timings: dict[str, float] = {}

    def capture(stage, collector, *args):
        if progress_callback:
            try:
                progress_callback({"stage": stage, "status": "running"})
            except Exception:
                pass
        _detail(f"  Snapshot: {stage}...")
        started = time.monotonic()
        value = collector(*args)
        elapsed = time.monotonic() - started
        timings[stage] = round(elapsed, 3)
        print(f"  Snapshot: {stage} complete ({elapsed:.1f}s)", flush=True)
        if progress_callback:
            try:
                progress_callback({"stage": stage, "status": "completed", "elapsed_seconds": round(elapsed, 3)})
            except Exception:
                pass
        return value

    packages = capture("Debian packages", _command_lines, ["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Package}\t${Version}\n"])
    processes = [redact_sensitive_text(line) for line in capture("processes", _command_lines, ["ps", "-eo", "user,group,comm,args", "--no-headers"])]
    services, service_units = capture("service configuration", _collect_service_units)
    running_services = capture("running services", _running_service_names)
    timers, timer_units = capture("timer configuration", _collect_timer_units)
    network_stage = "network activity" + (f" ({network_observation_seconds:g}s observation)" if network_observation_seconds > 0 else "")
    sockets, network_connections, unix_sockets = capture(network_stage, _collect_network_state, network_observation_seconds)
    mounts = capture("mounts", _command_lines, ["findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
    users = capture("users", _command_lines, ["getent", "passwd"])
    groups = capture("groups", _command_lines, ["getent", "group"])
    capabilities = capture("file capabilities", _collect_capabilities, tracked_paths, excluded_paths)
    suid_sgid = capture("SUID/SGID files", _collect_suid_sgid, tracked_paths, excluded_paths)

    snapshot = {
        "schema_version": 6,
        "framework_version": VERSION,
        "label": label,
        "captured_at": now_iso(),
        "tracked_paths": [str(p) for p in tracked_paths],
        "excluded_paths": [str(p) for p in excluded_paths],
        "packages": packages,
        "processes": processes,
        "services": services,
        "service_units": service_units,
        "running_services": running_services,
        "timers": timers,
        "timer_units": timer_units,
        "listening_sockets": sockets,
        "network_connections": network_connections,
        "unix_sockets": unix_sockets,
        "snap_packages": capture("Snap packages", _snap_inventory),
        "flatpak_packages": capture("Flatpak packages", _flatpak_inventory),
        "flatpak_remotes": capture("Flatpak remotes", _flatpak_remotes),
        "mounts": mounts,
        "users": users,
        "groups": groups,
        "user_crontab": capture("user crontab", _user_crontab),
        "root_crontab": capture("root crontab", _root_crontab),
        "capabilities": capabilities,
        "suid_sgid": suid_sgid,
    }
    filesystem_collection_gaps: list[dict[str, Any]] = []
    snapshot["filesystem"] = capture("filesystem metadata and hashes", _collect_filesystem, tracked_paths, excluded_paths, filesystem_collection_gaps)
    snapshot["filesystem_collection_gaps"] = filesystem_collection_gaps
    snapshot["collection_timings_seconds"] = timings
    capture("saving snapshot", write_json, output_path, snapshot)
    return snapshot
