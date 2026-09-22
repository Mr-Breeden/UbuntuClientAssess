from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from .app_scope import path_within_scope
from .common import command_exists, get_interactive_user, report_path, run_cmd, user_can_write, write_text

STANDARD_STICKY_TEMP = {"/tmp", "/var/tmp", "/dev/shm"}
MAX_DBUS_OBJECTS = 20
MAX_DBUS_TEXT = 12000


def _read_text(path: Path, limit: int = 512 * 1024) -> str:
    try:
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _display_identity(name: str) -> str:
    if name == "root":
        return "root"
    try:
        return "interactive-user" if name == get_interactive_user() else name
    except Exception:
        return name


def _socket_path(line: str) -> str | None:
    for token in line.split():
        token = token.strip()
        if token.startswith("/"):
            return token
        if token.startswith("@") and len(token) > 1:
            return token
    return None


def _socket_process_names(line: str) -> list[str]:
    return sorted(set(re.findall(r'\(\("([^\"]+)"\s*,pid=', line)))


def _path_context(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {"exists": False}
    try:
        st = path.lstat()
    except OSError:
        return data
    mode = stat.S_IMODE(st.st_mode)
    data.update({
        "exists": True,
        "mode": f"{mode:04o}",
        "uid": st.st_uid,
        "gid": st.st_gid,
        "world_write": bool(mode & stat.S_IWOTH),
        "group_write": bool(mode & stat.S_IWGRP),
        "interactive_write": user_can_write(path),
    })
    parent = path.parent
    try:
        pst = parent.stat()
        pmode = stat.S_IMODE(pst.st_mode)
        sticky = bool(pmode & stat.S_ISVTX)
        data["parent"] = {
            "path": str(parent),
            "mode": f"{pmode:04o}",
            "world_write": bool(pmode & stat.S_IWOTH),
            "group_write": bool(pmode & stat.S_IWGRP),
            "sticky": sticky,
            "standard_sticky_temp": str(parent) in STANDARD_STICKY_TEMP and sticky,
            "interactive_write": user_can_write(parent),
        }
    except OSError:
        data["parent"] = {"path": str(parent), "exists": False}
    return data


def analyze_socket_line(line: str, process_users: dict[str, set[str]] | None = None) -> dict[str, Any]:
    """Analyze one ss Unix-socket line without interacting with the socket."""
    process_users = process_users or {}
    path_text = _socket_path(line)
    names = _socket_process_names(line)
    users = sorted({_display_identity(user) for name in names for user in process_users.get(name, set()) if user})
    privileged = "root" in users
    abstract = bool(path_text and path_text.startswith("@"))
    filesystem: dict[str, Any] = {}
    if path_text and not abstract:
        filesystem = _path_context(Path(path_text))

    writable_boundary = False
    if filesystem:
        parent = filesystem.get("parent") or {}
        writable_boundary = bool(
            filesystem.get("world_write")
            or filesystem.get("interactive_write")
            or (
                parent.get("interactive_write")
                and not parent.get("standard_sticky_temp")
            )
        )
    if privileged and writable_boundary:
        level = "HIGH"
    elif privileged or writable_boundary or abstract:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {
        "line": line,
        "path": path_text,
        "abstract": abstract,
        "process_names": names,
        "process_users": users,
        "privileged_process": privileged,
        "filesystem": filesystem,
        "review_level": level,
    }


def _policykit_details(path: Path, text: str) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    if path.suffix == ".policy" or "<policyconfig" in text:
        try:
            root = ET.fromstring(text)
            for action in root.findall(".//action"):
                action_id = action.attrib.get("id", "unknown")
                defaults: dict[str, str] = {}
                d = action.find("defaults")
                if d is not None:
                    for key in ("allow_any", "allow_inactive", "allow_active"):
                        node = d.find(key)
                        if node is not None and node.text:
                            defaults[key] = node.text.strip()
                permissive = any(value.casefold() in {"yes", "auth_self", "auth_self_keep"} for value in defaults.values())
                details.append({"path": str(path), "action": action_id, "defaults": defaults, "permissive_review": permissive})
        except ET.ParseError:
            pass
    if path.suffix == ".rules" or "/rules.d/" in str(path):
        result_yes = bool(re.search(r"polkit\.Result\.YES", text))
        broad_subject = bool(re.search(r"subject\.(?:isInGroup|user)\s*\(", text)) or "unix-group:" in text
        details.append({
            "path": str(path),
            "action": "JavaScript rule",
            "defaults": {},
            "permissive_review": result_yes,
            "rule_returns_yes": result_yes,
            "subject_constraint_observed": broad_subject,
        })
    return details


def _dbus_list(bus: str) -> str:
    result = run_cmd(["busctl", bus, "list", "--no-pager"], timeout=15)
    return result["stdout"] if result["returncode"] == 0 else ""


def _introspect_name(bus: str, name: str) -> dict[str, Any]:
    result: dict[str, Any] = {"bus": bus[2:], "name": name, "objects": [], "introspection": []}
    tree = run_cmd(["busctl", bus, "tree", name, "--no-pager"], timeout=15)
    if tree["returncode"] != 0:
        result["error"] = (tree["stderr"] or tree["stdout"]).strip()[:1000]
        return result
    objects: list[str] = []
    for line in tree["stdout"].splitlines():
        match = re.search(r"(/[^\s]*)\s*$", line.strip())
        if match:
            objects.append(match.group(1))
    if "/" not in objects:
        objects.insert(0, "/")
    objects = list(dict.fromkeys(objects))[:MAX_DBUS_OBJECTS]
    result["objects"] = objects
    for obj in objects:
        intro = run_cmd(["busctl", bus, "introspect", name, obj, "--no-pager"], timeout=15)
        if intro["returncode"] == 0 and intro["stdout"].strip():
            result["introspection"].append({"object": obj, "detail": intro["stdout"].strip()[:MAX_DBUS_TEXT]})
    return result


def review_ipc(diff: dict[str, Any], output_dir: Path, extra_roots: list[Path] | None = None) -> dict[str, Any]:
    scope_roots = [Path(root) for root in (extra_roots or [])]
    raw_unix_added = diff.get("unix_sockets_added", [])
    unix_added = []
    for line in raw_unix_added:
        socket_path = _socket_path(str(line))
        # Static snapshot rows without a usable endpoint pathname cannot be
        # reliably attributed to the assessed application. Keep only sockets
        # whose pathname is within the inferred application scope. Abstract or
        # pathless host sockets require runtime process correlation instead.
        if not scope_roots:
            if socket_path:
                unix_added.append(line)
        elif socket_path and path_within_scope(socket_path, scope_roots):
            unix_added.append(line)
    changed = sorted(set(diff.get("files_added", [])) | set(diff.get("files_changed", [])))
    dbus_files = [p for p in changed if "/dbus-1/" in p or "/polkit-1/" in p]
    fifo_files = [p for p in changed if diff.get("post_filesystem", {}).get(p, {}).get("type") == "fifo"]
    dbus_names: set[str] = set()
    policy_indicators: list[str] = []
    polkit_details: list[dict[str, Any]] = []

    for path_text in dbus_files:
        p = Path(path_text)
        if not p.is_file():
            continue
        text = _read_text(p)
        for match in re.findall(r"(?:name|own|send_destination|destination)=[\"']([^\"']+)[\"']", text, re.I):
            if "." in match:
                dbus_names.add(match)
        for match in re.findall(r"^Name\s*=\s*([^#;\s]+)", text, re.I | re.M):
            if "." in match:
                dbus_names.add(match.strip())
        if re.search(r"<allow\b[^>]*(?:own=|send_destination=)", text, re.I):
            policy_indicators.append(f"Allow rule observed: {path_text}")
        if re.search(r"<policy\s+context=[\"']default[\"']", text, re.I):
            policy_indicators.append(f"Default D-Bus policy block observed: {path_text}")
        for detail in _policykit_details(p, text):
            polkit_details.append(detail)
            if detail.get("permissive_review"):
                policy_indicators.append(f"PolicyKit authorization requires review: {path_text} ({detail.get('action')})")

    # Static snapshot socket lines often omit a reliable process-user map, so
    # permission correlation here is filesystem-focused. Runtime observation
    # enriches this with process privilege.
    socket_analysis = [analyze_socket_line(str(line), {}) for line in unix_added]

    active_bus_matches: list[str] = []
    dbus_introspection: list[dict[str, Any]] = []
    if command_exists("busctl") and dbus_names:
        for bus in ("--system", "--user"):
            listing = _dbus_list(bus)
            if not listing:
                continue
            for name in sorted(dbus_names):
                if re.search(rf"^{re.escape(name)}\s", listing, re.M):
                    active_bus_matches.append(f"{bus[2:]}: {name}")
                    dbus_introspection.append(_introspect_name(bus, name))

    lines = [
        "IPC Review", "=" * 10, "",
        "This report highlights Unix domain sockets, D-Bus service/policy definitions, PolicyKit-related changes, and named FIFOs introduced during installation.",
        "", "New Unix Domain Sockets", "-----------------------",
    ]
    if socket_analysis:
        for item in socket_analysis:
            lines.append(f"[{item['review_level']} REVIEW] {item['line']}")
            if item.get("path"):
                lines.append(f"  Path: {item['path']}")
            fs = item.get("filesystem") or {}
            if fs.get("exists"):
                lines.append(f"  Socket mode: {fs.get('mode')} | tester-write: {'yes' if fs.get('interactive_write') else 'no'}")
                parent = fs.get("parent") or {}
                if parent:
                    suffix = " (standard sticky temporary directory)" if parent.get("standard_sticky_temp") else ""
                    lines.append(f"  Parent: {parent.get('path')} mode {parent.get('mode')}{suffix}")
            if item.get("abstract"):
                lines.append("  Abstract socket: no filesystem permissions protect the endpoint; validate peer authorization in the service.")
    else:
        lines.append("None observed.")

    lines += ["", "Changed D-Bus / PolicyKit Files", "-------------------------------"]
    lines += dbus_files or ["None observed within tracked paths."]
    lines += ["", "D-Bus Names Referenced", "---------------------"]
    lines += sorted(dbus_names) or ["None automatically identified."]
    lines += ["", "Referenced Names Currently Active", "---------------------------------"]
    lines += active_bus_matches or ["No matching names were observed on the accessible system/user buses."]
    lines += ["", "Read-Only D-Bus Introspection", "----------------------------"]
    if dbus_introspection:
        for item in dbus_introspection:
            lines.append(f"[{item.get('bus')}] {item.get('name')}")
            if item.get("error"):
                lines.append(f"  Introspection unavailable: {item['error']}")
                continue
            for obj in item.get("introspection", []):
                lines.append(f"  Object: {obj['object']}")
                for detail_line in obj["detail"].splitlines()[:80]:
                    lines.append(f"    {detail_line}")
    else:
        lines.append("No active referenced D-Bus service was available for read-only introspection.")

    lines += ["", "D-Bus / PolicyKit Policy Indicators", "-----------------------------------"]
    lines += policy_indicators or ["No simple allow/default-policy indicators identified."]
    if polkit_details:
        lines += ["", "PolicyKit Action / Rule Details", "-------------------------------"]
        for item in polkit_details:
            lines.append(f"- {item.get('action')} | {item.get('path')} | review={'yes' if item.get('permissive_review') else 'no'}")
            if item.get("defaults"):
                lines.append("  defaults: " + ", ".join(f"{k}={v}" for k, v in item["defaults"].items()))

    lines += ["", "Changed Named FIFOs", "-------------------"]
    lines += fifo_files or ["None observed within tracked paths."]
    lines += [
        "", "Tester Guidance", "---------------",
        "Validate Unix-socket/FIFO filesystem permissions and peer authorization. For D-Bus/PolicyKit, use the read-only object/method inventory to plan tests, then validate caller authorization before invoking any state-changing method.",
    ]
    write_text(report_path(output_dir, "ipc_review.txt"), "\n".join(lines))
    return {
        "unix_sockets": unix_added,
        "socket_analysis": socket_analysis,
        "dbus_files": dbus_files,
        "dbus_names": sorted(dbus_names),
        "active_bus_matches": active_bus_matches,
        "dbus_introspection": dbus_introspection,
        "policy_indicators": policy_indicators,
        "polkit_details": polkit_details,
        "fifo_candidates": fifo_files,
    }


def update_ipc_with_runtime(output_dir: Path, runtime_data: dict[str, Any], profile_data: dict[str, Any] | None = None) -> None:
    """Append/refresh a bounded runtime IPC section in the authoritative report."""
    profile_data = profile_data or {}
    path = report_path(output_dir, "ipc_review.txt")
    existing = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else "IPC Review\n==========\n"
    marker = "\nGuided Runtime IPC Observation\n==============================\n"
    if marker in existing:
        existing = existing.split(marker, 1)[0].rstrip() + "\n"
    lines = [
        marker.strip("\n"),
        "",
        f"Observation duration: {runtime_data.get('duration_seconds', 0)} seconds",
        f"Primary technology: {profile_data.get('primary_technology') or 'not confidently identified'}",
        "",
        "Observed Application Unix Sockets",
        "---------------------------------",
    ]
    analyses = runtime_data.get("socket_analysis", []) or []
    if analyses:
        for item in analyses:
            lines.append(f"[{item.get('review_level', 'MEDIUM')} REVIEW] {item.get('line', '')}")
            if item.get("path"):
                lines.append(f"  Path: {item['path']}")
            if item.get("process_users"):
                lines.append(f"  Process privilege: {', '.join(item['process_users'])}")
            fs = item.get("filesystem") or {}
            if fs.get("exists"):
                lines.append(f"  Mode: {fs.get('mode')} | tester-write: {'yes' if fs.get('interactive_write') else 'no'}")
                parent = fs.get("parent") or {}
                if parent:
                    lines.append(f"  Parent: {parent.get('path')} mode {parent.get('mode')}")
            if item.get("abstract"):
                lines.append("  Abstract socket: validate application-level peer authorization; no pathname permissions apply.")
    else:
        lines.append("No application-correlated Unix sockets observed during this runtime window.")
    lines += ["", "Observed Application FIFOs", "--------------------------"]
    fifos = runtime_data.get("fifo_paths", []) or []
    lines += [f"- {value}" for value in fifos] or ["No application FIFO observed within scoped runtime roots."]
    techs = profile_data.get("technologies", []) or []
    focus = [line for tech in techs for line in tech.get("ipc_focus", [])]
    if focus:
        lines += ["", "Technology-Specific IPC Focus", "-----------------------------"] + [f"- {entry}" for entry in focus[:12]]
    write_text(path, existing.rstrip() + "\n\n" + "\n".join(lines) + "\n")
