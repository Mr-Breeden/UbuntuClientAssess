from __future__ import annotations

import ipaddress
import os
import re
import shlex
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .common import get_interactive_user, now_iso, redact_sensitive_text, run_cmd, working_dir, write_json
from .ipc import analyze_socket_line, _socket_path
from .app_scope import path_within_scope

DEFAULT_POLL_INTERVAL = 0.35
FAST_NETWORK_POLL_INTERVAL = 0.10
FILE_PROGRESS_INTERVAL = 1.0
MAX_OBSERVATION_SECONDS = 3600.0
MAX_TRACKED_FILES = 25000
MAX_REPORTED_FILE_EVENTS = 500
MAX_REPORTED_ROWS = 500
SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh", "fish", "python", "python3", "perl", "ruby"}


def _display_user(user: str) -> str:
    if user == "root":
        return "root"
    try:
        return "interactive-user" if user == get_interactive_user() else user
    except Exception:
        return user


def _processes() -> list[dict[str, Any]]:
    result = run_cmd(["ps", "-eo", "pid=,ppid=,user=,group=,comm=,args="], timeout=10)
    if result["returncode"] != 0:
        return []
    records: list[dict[str, Any]] = []
    for raw in result["stdout"].splitlines():
        parts = raw.strip().split(maxsplit=5)
        if len(parts) < 5:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        user = _display_user(parts[2])
        group = "interactive-user" if parts[3] == get_interactive_user() else parts[3]
        records.append({
            "pid": pid,
            "ppid": ppid,
            "user": user,
            "group": group,
            "comm": parts[4],
            "args": redact_sensitive_text(parts[5] if len(parts) > 5 else parts[4]),
        })
    return records


def _command_lines(cmd: list[str], *, elevated: bool = False) -> list[str]:
    actual = (["sudo", "-n"] + cmd) if elevated else cmd
    result = run_cmd(actual, timeout=10)
    if result["returncode"] != 0:
        return []
    return [redact_sensitive_text(line.rstrip()) for line in result["stdout"].splitlines() if line.strip()]


def _connection_lines(*, elevated: bool = False) -> list[str]:
    # -a explicitly includes recently closed TIME-WAIT rows. Exclude listeners
    # here because they are collected separately and should not inflate the
    # connection count.
    rows = _command_lines(["ss", "-H", "-antupn"], elevated=elevated)
    return [line for line in rows if not re.search(r"\b(?:LISTEN|UNCONN)\b", line)]


def _sample(*, elevated: bool = False) -> dict[str, Any]:
    return {
        "captured_at": now_iso(),
        "processes": _processes(),
        "listeners": _command_lines(["ss", "-H", "-lntupn"], elevated=elevated),
        "connections": _connection_lines(elevated=elevated),
        "unix_sockets": _command_lines(["ss", "-H", "-lxnp"], elevated=elevated),
    }


def _invoke_sample(elevated: bool) -> dict[str, Any]:
    # Keep monkeypatch/test compatibility with the v1.3 no-argument sampler.
    try:
        return _sample(elevated=elevated)
    except TypeError as exc:
        if "unexpected keyword argument" not in str(exc):
            raise
        return _sample()


def _normalize_hints(hints: list[str] | None) -> list[str]:
    normalized: set[str] = set()
    for raw in hints or []:
        text = str(raw).strip()
        if not text or text == "/":
            continue
        normalized.add(text)
        try:
            path = Path(text)
            if path.name:
                normalized.add(path.name)
        except Exception:
            pass
    return sorted(normalized, key=lambda value: (-len(value), value.casefold()))


def _argv_tokens(args: str, comm: str = "") -> list[str]:
    try:
        tokens = shlex.split(args, posix=True)
    except ValueError:
        tokens = args.split()
    if not tokens:
        return []
    # A shell's -c/-lc payload is free-form command text, not process identity.
    shell = Path(comm or tokens[0]).name.casefold() in {"sh", "bash", "dash", "zsh", "ksh", "fish"}
    if shell:
        for idx, token in enumerate(tokens[1:], 1):
            if token.startswith("-") and "c" in token[1:]:
                return tokens[:idx + 1]
    return tokens[:5]


def _root_like_path(path_hint: Path, hints: list[str]) -> bool:
    try:
        if path_hint.is_dir():
            return True
    except OSError:
        pass
    prefix = str(path_hint).rstrip("/") + "/"
    if any(str(other).startswith(prefix) for other in hints if str(other) != str(path_hint) and Path(str(other)).is_absolute()):
        return True
    # Extensionless path hints are commonly application roots or executables.
    # If they are not exact argv tokens, prefix matching below will decide.
    return path_hint.suffix == ""


def _process_direct_match(proc: dict[str, Any], hints: list[str]) -> bool:
    """Match process identity while ignoring incidental shell command text."""
    if not hints:
        return False
    comm = str(proc.get("comm") or "").casefold()
    tokens = _argv_tokens(str(proc.get("args") or ""), str(proc.get("comm") or ""))
    token_folded = [token.casefold() for token in tokens]

    for hint in hints:
        raw = str(hint).strip()
        if not raw:
            continue
        folded = raw.casefold()
        path_hint = Path(raw).expanduser()
        if path_hint.is_absolute():
            # Exact executable/script path behind interpreter/launcher.
            if any(token == folded for token in token_folded):
                return True
            if _root_like_path(path_hint, hints):
                try:
                    root_folded = str(path_hint.resolve(strict=False)).rstrip("/").casefold() + "/"
                except OSError:
                    root_folded = str(path_hint).rstrip("/").casefold() + "/"
                for token in tokens:
                    if not token.startswith("/"):
                        continue
                    try:
                        candidate = str(Path(token).resolve(strict=False)).casefold()
                    except OSError:
                        candidate = token.casefold()
                    if candidate.startswith(root_folded):
                        return True
            continue

        # Name hints must match executable/process identity rather than arbitrary args.
        if comm == folded:
            return True
        for token in tokens[:3]:
            if Path(token).name.casefold() == folded:
                return True
    return False


def _process_sets(processes: list[dict[str, Any]], hints: list[str]) -> tuple[set[int], set[int]]:
    """Return (related, children), giving ancestry precedence over path matches.

    A helper inside the application root may itself satisfy direct path matching,
    but if it descends from another directly matched application process it is
    still classified as a child. This keeps the process tree meaningful.
    """
    if not hints:
        return set(), set()
    by_pid = {int(p["pid"]): p for p in processes}
    candidates = {int(p["pid"]) for p in processes if _process_direct_match(p, hints)}

    def has_candidate_ancestor(pid: int) -> bool:
        seen: set[int] = set()
        current = by_pid.get(pid)
        while current:
            ppid = int(current.get("ppid", 0) or 0)
            if ppid <= 0 or ppid in seen:
                return False
            if ppid in candidates:
                return True
            seen.add(ppid)
            current = by_pid.get(ppid)
        return False

    seeds = {pid for pid in candidates if not has_candidate_ancestor(pid)}
    related = set(seeds)
    changed = True
    while changed:
        changed = False
        for proc in processes:
            pid = int(proc["pid"])
            ppid = int(proc.get("ppid", 0) or 0)
            if pid not in related and ppid in related:
                related.add(pid)
                changed = True
    return related, related - seeds


def _socket_pids(line: str) -> set[int]:
    return {int(value) for value in re.findall(r"\bpid=(\d+)", line)}


def _socket_related(line: str, pids: set[int], hints: list[str]) -> bool:
    if _socket_pids(line).intersection(pids):
        return True
    names = {Path(hint).name.casefold() for hint in hints if Path(hint).name}
    for proc_name in re.findall(r'\(\("([^\"]+)"\s*,pid=', line):
        if proc_name.casefold() in names:
            return True
    return False


def _listener_host(line: str) -> str | None:
    parts = line.split()
    # ss -H -lntupn usually places local endpoint at index 4, but tolerate protocol prefixes.
    candidates = [part for part in parts if ":" in part and not part.startswith("users:")]
    if not candidates:
        return None
    endpoint = candidates[0] if len(parts) < 5 else parts[4]
    if endpoint.startswith("[") and "]" in endpoint:
        return endpoint[1:endpoint.index("]")].split("%", 1)[0]
    if ":" in endpoint:
        return endpoint.rsplit(":", 1)[0].split("%", 1)[0]
    return None


def _endpoint_port(line: str) -> str | None:
    parts = line.split()
    if len(parts) < 5:
        return None
    endpoint = parts[4]
    if endpoint.startswith("[") and "]:" in endpoint:
        return endpoint.rsplit(":", 1)[-1]
    if ":" in endpoint:
        return endpoint.rsplit(":", 1)[-1]
    return None


def _externally_bound(line: str) -> bool:
    host = _listener_host(line)
    if not host:
        return False
    if host in {"*", "0.0.0.0", "::"}:
        return True
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() not in {"localhost", "localhost.localdomain"}


def _file_state(roots: list[Path]) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    count = 0
    for root in roots:
        if count >= MAX_TRACKED_FILES:
            break
        try:
            candidates = [root] if root.is_file() or root.is_symlink() else root.rglob("*") if root.is_dir() else []
            for path in candidates:
                if count >= MAX_TRACKED_FILES:
                    break
                try:
                    st = path.lstat()
                except OSError:
                    continue
                if path.is_dir() and not path.is_symlink():
                    continue
                kind = "symlink" if path.is_symlink() else "file" if path.is_file() else "other"
                state[str(path)] = {"type": kind, "size": st.st_size, "mtime_ns": st.st_mtime_ns, "mode": f"{stat.S_IMODE(st.st_mode):04o}"}
                count += 1
        except (OSError, PermissionError):
            continue
    return state


def _diff_files(before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]) -> dict[str, Any]:
    before_keys, after_keys = set(before), set(after)
    created = sorted(after_keys - before_keys)
    deleted = sorted(before_keys - after_keys)
    modified = sorted(path for path in before_keys & after_keys if before[path] != after[path])
    return {
        "created": created[:MAX_REPORTED_FILE_EVENTS],
        "modified": modified[:MAX_REPORTED_FILE_EVENTS],
        "deleted": deleted[:MAX_REPORTED_FILE_EVENTS],
        "suppressed": max(0, len(created) - MAX_REPORTED_FILE_EVENTS) + max(0, len(modified) - MAX_REPORTED_FILE_EVENTS) + max(0, len(deleted) - MAX_REPORTED_FILE_EVENTS),
    }


def analyze_samples(samples: list[dict[str, Any]], application_hints: list[str] | None = None, filesystem_roots: list[Path] | None = None) -> dict[str, Any]:
    hints = _normalize_hints(application_hints)
    scope_roots = [Path(root) for root in (filesystem_roots or [])]
    app_processes: dict[int, dict[str, Any]] = {}
    child_processes: dict[int, dict[str, Any]] = {}
    listeners: set[str] = set()
    connections: set[str] = set()
    unix_sockets: set[str] = set()
    privileged_pids: set[int] = set()
    sample_related: list[set[int]] = []

    # First pass establishes the application process set and persistent listener
    # ports across the whole observation window. This lets a later fast network
    # sample correlate a short-lived/TIME-WAIT connection even when the owning
    # client process has already exited.
    for sample in samples:
        processes = list(sample.get("processes", []))
        related, children = _process_sets(processes, hints)
        sample_related.append(related)
        for proc in processes:
            pid = int(proc["pid"])
            if pid not in related:
                continue
            app_processes[pid] = proc
            if str(proc.get("user")) == "root":
                privileged_pids.add(pid)
            if pid in children:
                child_processes[pid] = proc
        related_listeners = [str(line) for line in sample.get("listeners", []) if _socket_related(str(line), related, hints)]
        listeners.update(related_listeners)

    listener_ports = {port for line in listeners if (port := _endpoint_port(line))}

    # Second pass correlates transient connections and local sockets using the
    # full-window application/listener context rather than only same-sample data.
    known_pids = set(app_processes)
    for index, sample in enumerate(samples):
        related = sample_related[index] if index < len(sample_related) else set()
        relation_pids = related.union(known_pids)
        for raw_line in sample.get("connections", []):
            line = str(raw_line)
            if _socket_related(line, relation_pids, hints) or any(re.search(rf":{re.escape(port)}(?:\s|$)", line) for port in listener_ports):
                connections.add(line)
        for raw_line in sample.get("unix_sockets", []):
            line = str(raw_line)
            socket_path = _socket_path(line)
            if _socket_related(line, relation_pids, hints) or (socket_path and scope_roots and path_within_scope(socket_path, scope_roots)):
                unix_sockets.add(line)

    process_users: dict[str, set[str]] = {}
    for proc in app_processes.values():
        process_users.setdefault(str(proc.get("comm") or ""), set()).add(str(proc.get("user") or ""))
    socket_analysis = [analyze_socket_line(line, process_users) for line in sorted(unix_sockets)]
    shell_children = [proc for proc in child_processes.values() if str(proc.get("comm") or "").casefold() in SHELL_NAMES]
    return {
        "application_hints": hints,
        "application_processes": sorted(app_processes.values(), key=lambda item: (str(item.get("comm")), int(item.get("pid", 0))))[:MAX_REPORTED_ROWS],
        "child_processes": sorted(child_processes.values(), key=lambda item: (str(item.get("comm")), int(item.get("pid", 0))))[:MAX_REPORTED_ROWS],
        "privileged_process_count": len(privileged_pids),
        "listeners": sorted(listeners)[:MAX_REPORTED_ROWS],
        "externally_bound_listeners": sorted(line for line in listeners if _externally_bound(line))[:MAX_REPORTED_ROWS],
        "connections": sorted(connections)[:MAX_REPORTED_ROWS],
        "unix_sockets": sorted(unix_sockets)[:MAX_REPORTED_ROWS],
        "socket_analysis": socket_analysis[:MAX_REPORTED_ROWS],
        "shell_children": shell_children[:MAX_REPORTED_ROWS],
    }


def _fifo_paths(roots: list[Path]) -> list[str]:
    found: set[str] = set()
    for root in roots:
        try:
            candidates = [root] if root.exists() and not root.is_dir() else root.rglob("*") if root.is_dir() else []
            for path in candidates:
                try:
                    if stat.S_ISFIFO(path.lstat().st_mode):
                        found.add(str(path))
                except OSError:
                    continue
        except (OSError, PermissionError):
            continue
    return sorted(found)


def collect_runtime_observation(
    output_dir: Path,
    *,
    application_hints: list[str] | None = None,
    filesystem_roots: list[Path] | None = None,
    duration_seconds: float | None = None,
    wait_for_stop: Callable[[], None] | None = None,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    elevated_visibility: bool = False,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Collect tester-controlled runtime observations without launching the target."""
    if duration_seconds is None and wait_for_stop is None:
        raise ValueError("Runtime observation requires a duration or an interactive stop callback")
    if duration_seconds is not None and (duration_seconds < 0 or duration_seconds > MAX_OBSERVATION_SECONDS):
        raise ValueError(f"Runtime observation duration must be between 0 and {int(MAX_OBSERVATION_SECONDS)} seconds")

    # Keep expected roots even when absent at observation start so creation of
    # an application-specific runtime/user-data directory can be captured.
    roots = sorted({Path(path).expanduser().resolve(strict=False) for path in (filesystem_roots or [])}, key=str)
    start_files = _file_state(roots)
    samples: list[dict[str, Any]] = []
    fast_connections: set[str] = set()
    fast_network_samples = 0
    started = time.monotonic()
    interrupted = False
    last_file_progress = 0.0
    cached_file_activity = {"created": [], "modified": [], "deleted": [], "suppressed": 0}

    def emit_progress(*, force_file_scan: bool = False) -> None:
        nonlocal last_file_progress, cached_file_activity
        if not progress_callback:
            return
        partial_samples = list(samples)
        if fast_connections:
            partial_samples.append({"captured_at": now_iso(), "processes": [], "listeners": [], "connections": sorted(fast_connections), "unix_sockets": []})
        partial = analyze_samples(partial_samples, application_hints, roots)
        partial["sample_count"] = len(samples)
        partial["duration_seconds"] = round(max(0.0, time.monotonic() - started), 2)
        partial["fifo_paths"] = _fifo_paths(roots)
        now = time.monotonic()
        if force_file_scan or now - last_file_progress >= FILE_PROGRESS_INTERVAL:
            cached_file_activity = _diff_files(start_files, _file_state(roots))
            last_file_progress = now
        partial["file_activity"] = cached_file_activity
        progress_callback(partial)

    fast_stop = threading.Event()

    def fast_network_worker() -> None:
        nonlocal fast_network_samples
        while not fast_stop.is_set():
            try:
                fast_connections.update(_connection_lines(elevated=elevated_visibility))
                fast_network_samples += 1
            except Exception:
                pass
            fast_stop.wait(FAST_NETWORK_POLL_INTERVAL)

    fast_thread = threading.Thread(target=fast_network_worker, name="uca-fast-network-observer", daemon=True)
    fast_thread.start()

    if duration_seconds is not None:
        if duration_seconds == 0:
            samples.append(_invoke_sample(elevated_visibility))
            emit_progress()
        else:
            deadline = started + duration_seconds
            while True:
                samples.append(_invoke_sample(elevated_visibility))
                emit_progress()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(max(0.1, poll_interval), remaining))
    else:
        stop_event = threading.Event()

        def worker() -> None:
            while not stop_event.is_set():
                samples.append(_invoke_sample(elevated_visibility))
                emit_progress()
                stop_event.wait(max(0.1, poll_interval))

        thread = threading.Thread(target=worker, name="uca-runtime-observer", daemon=True)
        thread.start()
        try:
            assert wait_for_stop is not None
            wait_for_stop()
        except KeyboardInterrupt:
            interrupted = True
        finally:
            stop_event.set()
            thread.join(timeout=max(2.0, poll_interval + 1.0))
            if not samples:
                samples.append(_invoke_sample(elevated_visibility))

    fast_stop.set()
    fast_thread.join(timeout=2.0)
    # Fast network polling supplements analysis without changing the meaning of
    # sample_count, which tracks the full runtime observation samples only.
    analysis_samples = list(samples)
    if fast_connections:
        analysis_samples.append({"captured_at": now_iso(), "processes": [], "listeners": [], "connections": sorted(fast_connections), "unix_sockets": []})
    end_files = _file_state(roots)
    analyzed = analyze_samples(analysis_samples, application_hints, roots)
    analyzed.update({
        "schema_version": 1,
        "captured_at": now_iso(),
        "duration_seconds": round(time.monotonic() - started, 2),
        "sample_count": len(samples),
        "fast_network_sample_count": fast_network_samples,
        "poll_interval_seconds": poll_interval,
        "fast_network_poll_interval_seconds": FAST_NETWORK_POLL_INTERVAL,
        "interrupted": interrupted,
        "filesystem_roots": [str(path) for path in roots],
        "file_activity": _diff_files(start_files, end_files),
        "fifo_paths": _fifo_paths(roots),
        "elevated_visibility": bool(elevated_visibility),
    })
    if progress_callback:
        progress_callback(analyzed)
    if persist:
        write_json(working_dir(output_dir) / "runtime_observation.json", analyzed)
    return analyzed
