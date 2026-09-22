from __future__ import annotations

import re
import shlex
import stat
from pathlib import Path
from typing import Any

from .common import report_path, run_cmd, user_can_write, write_text

HARDENING_KEYS = ["NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "CapabilityBoundingSet"]
SHOW_PROPERTIES = [
    "User", "Group", "DynamicUser", "ExecStart", "EnvironmentFiles", "WorkingDirectory",
    "FragmentPath", "DropInPaths", *HARDENING_KEYS,
]


def _unit_name(line: str) -> str:
    return line.split()[0] if line.split() else line


def _directive_values(text: str, name: str) -> list[str]:
    return [v.strip() for v in re.findall(rf"^{re.escape(name)}=(.*)$", text, re.M) if v.strip()]


def _extract_exec_path(value: str) -> str | None:
    cleaned = value.strip()
    # systemctl show ExecStart commonly renders a structure containing path=.
    m = re.search(r"(?:^|[;{]\s*)path=([^; }]+)", cleaned)
    if m:
        return m.group(1).strip()
    while cleaned and cleaned[0] in "-+!:@":
        cleaned = cleaned[1:].lstrip()
    try:
        parts = shlex.split(cleaned)
    except ValueError:
        parts = cleaned.split()
    return parts[0] if parts else None


def _show_effective(unit: str) -> dict[str, str]:
    cmd = ["systemctl", "show", unit, "--no-pager"] + [f"--property={p}" for p in SHOW_PROPERTIES]
    result = run_cmd(cmd, timeout=20)
    if result["returncode"] != 0:
        return {}
    values: dict[str, str] = {}
    for line in result["stdout"].splitlines():
        key, sep, value = line.partition("=")
        if sep and key in SHOW_PROPERTIES:
            values[key] = value.strip()
    return values


def _paths_from_property(value: str) -> list[str]:
    if not value:
        return []
    # EnvironmentFiles/DropInPaths can contain multiple path-like values and
    # annotations. Preserve the actual path tokens without annotations.
    paths = re.findall(r"(?<![A-Za-z0-9_.-])(-?/(?:[^\s;{}()])+)", value)
    return list(dict.fromkeys(p.lstrip("-") for p in paths))


def _is_executable_reference(path: Path) -> bool:
    try:
        if not path.is_file():
            return False
        mode = path.stat().st_mode
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            return True
        with path.open("rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return False


def _classify_referenced_path(path: Path) -> str:
    lower_parts = {part.casefold() for part in path.parts}
    suffix = path.suffix.casefold()
    if suffix in {".conf", ".config", ".ini", ".json", ".yaml", ".yml", ".toml", ".properties", ".xml", ".cfg"} or "config" in lower_parts or "configuration" in lower_parts:
        return "ConfigurationDependency"
    return "ReferencedPath"


def _wrapper_referenced_paths(path_text: str | None) -> list[dict[str, str]]:
    """Return absolute non-executable paths referenced by a small script/wrapper.

    This is intentionally conservative. Executable references belong in the
    execution chain; configuration/data paths are recorded separately so they
    are never mislabeled as ExecStart executables.
    """
    if not path_text or path_text.startswith("$") or "%" in path_text:
        return []
    try:
        path = Path(path_text).resolve(strict=True)
    except OSError:
        return []
    try:
        if not path.is_file() or path.stat().st_size > 256 * 1024:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    first = text.splitlines()[0] if text.splitlines() else ""
    if not (first.startswith("#!") or path.suffix.casefold() in {".sh", ".py", ".pl", ".rb"}):
        return []
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines()[1:240]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for candidate in re.findall(r"(?<![A-Za-z0-9_.-])(/(?:opt|etc|var|run|usr/local|usr/bin|usr/sbin|usr/lib|usr/share)/[^\s\"';&|()]+)", stripped):
            cp = Path(candidate.rstrip(",)]}"))
            if not cp.exists() or _is_executable_reference(cp):
                continue
            normalized = str(cp.resolve(strict=False))
            if normalized in seen:
                continue
            seen.add(normalized)
            found.append({"path_type": _classify_referenced_path(cp), "path": normalized})
    return found


def _resolve_exec_chain(path_text: str | None) -> list[str]:
    if not path_text or path_text.startswith("$") or "%" in path_text:
        return []
    p = Path(path_text)
    chain = [str(p)]
    try:
        resolved = p.resolve(strict=True)
        if resolved != p:
            chain.append(str(resolved))
        p = resolved
    except OSError:
        return chain

    # If the resolved target is a small shell/Python wrapper, show the first
    # executable application command it launches. Configuration/data references
    # are recorded separately by _wrapper_referenced_paths().
    try:
        if p.is_file() and p.stat().st_size <= 256 * 1024:
            text = p.read_text(encoding="utf-8", errors="replace")
            first = text.splitlines()[0] if text.splitlines() else ""
            if first.startswith("#!") or p.suffix.lower() in {".sh", ".py", ".pl", ".rb"}:
                for line in text.splitlines()[1:240]:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    matches = re.findall(r"(?<![A-Za-z0-9_.-])(/(?:opt|usr/local|usr/bin|usr/sbin|usr/lib)/[^\s\"';&|()]+)", stripped)
                    for candidate in matches:
                        cp = Path(candidate.rstrip(",)]}"))
                        if cp.exists() and _is_executable_reference(cp):
                            resolved_candidate = str(cp.resolve(strict=False))
                            if resolved_candidate not in chain:
                                chain.append(resolved_candidate)
                                return chain
    except (OSError, UnicodeDecodeError):
        pass
    return chain


def _write_concerns(path_text: str | None) -> list[str]:
    if not path_text or path_text.startswith("$") or "%" in path_text:
        return []
    p = Path(path_text.lstrip("-"))
    try:
        if p.is_symlink():
            p = p.resolve(strict=True)
    except OSError:
        pass
    if not p.exists():
        return []

    concerns: list[str] = []
    try:
        st = p.stat()
        if st.st_mode & stat.S_IWOTH:
            concerns.append("world-writable target")
        if st.st_uid == 0 and user_can_write(p):
            concerns.append("current tester has write access to root-owned target")
    except OSError:
        return []

    current = p.parent
    seen: set[str] = set()
    while str(current) not in seen:
        seen.add(str(current))
        try:
            st = current.stat()
        except OSError:
            break
        if st.st_mode & stat.S_IWOTH and str(current) not in {"/tmp", "/var/tmp"}:
            concerns.append(f"world-writable parent: {current}")
        elif st.st_uid == 0 and user_can_write(current) and str(current) not in {"/tmp", "/var/tmp"}:
            concerns.append(f"tester-writable root-owned parent: {current}")
        if current == current.parent:
            break
        current = current.parent
    return list(dict.fromkeys(concerns))


def _timer_details(unit: str) -> dict[str, Any]:
    cat = run_cmd(["systemctl", "cat", unit], timeout=20)
    text = cat["stdout"].strip() if cat["returncode"] == 0 else ""
    schedule = []
    for key in ("OnCalendar", "OnBootSec", "OnStartupSec", "OnUnitActiveSec", "OnUnitInactiveSec", "Persistent"):
        for value in _directive_values(text, key):
            schedule.append(f"{key}={value}")
    units = _directive_values(text, "Unit")
    activates = units[-1] if units else unit.replace(".timer", ".service")
    return {"unit": unit, "unit_text": text, "schedule": schedule, "activates": activates}


def _fallback_effective(text: str) -> dict[str, Any]:
    """Best-effort fallback when systemctl show is unavailable."""
    users = _directive_values(text, "User")
    groups = _directive_values(text, "Group")
    exec_values = _directive_values(text, "ExecStart")
    env_values = [x.lstrip("-") for x in _directive_values(text, "EnvironmentFile")]
    wd_values = _directive_values(text, "WorkingDirectory")
    dynamic_values = _directive_values(text, "DynamicUser")
    return {
        "user": users[-1] if users else "",
        "group": groups[-1] if groups else "",
        "dynamic_user": dynamic_values[-1] if dynamic_values else "no",
        "exec_start": exec_values,
        "environment_files": env_values,
        "working_directory": wd_values[-1:] if wd_values else [],
        "fragment_path": "",
        "drop_in_paths": [],
        "hardening": {key: (_directive_values(text, key)[-1] if _directive_values(text, key) else "Not configured") for key in HARDENING_KEYS},
    }


def _effective_service(unit: str, text: str) -> dict[str, Any]:
    show = _show_effective(unit)
    if not show:
        return _fallback_effective(text)

    exec_value = show.get("ExecStart", "")
    exec_paths: list[str] = []
    # Usually one path= entry, but tolerate multiple rendered structures.
    for match in re.findall(r"path=([^; }]+)", exec_value):
        if match and match not in exec_paths:
            exec_paths.append(match)
    if not exec_paths:
        p = _extract_exec_path(exec_value)
        if p:
            exec_paths.append(p)

    user = show.get("User", "")
    group = show.get("Group", "")
    dynamic_user = show.get("DynamicUser", "no")
    return {
        "user": user,
        "group": group,
        "dynamic_user": dynamic_user,
        "exec_start": [exec_value] if exec_value else [],
        "exec_paths": exec_paths,
        "environment_files": _paths_from_property(show.get("EnvironmentFiles", "")),
        "working_directory": [show["WorkingDirectory"]] if show.get("WorkingDirectory") and show.get("WorkingDirectory") != "~" else [],
        "fragment_path": show.get("FragmentPath", ""),
        "drop_in_paths": _paths_from_property(show.get("DropInPaths", "")),
        "hardening": {key: (show.get(key) or "Not configured") for key in HARDENING_KEYS},
    }


def _service_units_from_changed_paths(diff: dict[str, Any]) -> set[str]:
    units: set[str] = set()
    for raw in set(diff.get("files_added", [])) | set(diff.get("files_changed", [])):
        path = Path(raw)
        if path.name.endswith(".service"):
            units.add(path.name)
        elif path.parent.name.endswith(".service.d"):
            units.add(path.parent.name[:-2])
    return units


def review_services(diff: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    added = diff.get("services_added", [])
    modified = diff.get("services_modified", [])
    timer_units = [_unit_name(x) for x in diff.get("timers_added", [])]
    records: list[dict[str, Any]] = []
    risk_candidates: list[dict[str, Any]] = []
    timer_records = [_timer_details(x) for x in timer_units if x.endswith(".timer")]
    post_service_units = diff.get("post_service_units", {})
    added_by_unit = {_unit_name(entry): entry for entry in added}
    modified_units = {str(item.get("unit")) for item in modified if item.get("unit")}
    modified_units.update(_service_units_from_changed_paths(diff) - set(added_by_unit))
    review_units = sorted(set(added_by_unit) | modified_units)

    for unit in review_units:
        entry = added_by_unit.get(unit, unit)
        cat = run_cmd(["systemctl", "cat", unit], timeout=20)
        text = cat["stdout"].strip() if cat["returncode"] == 0 else ""
        effective = _effective_service(unit, text)
        legacy_parts = str(entry).split()
        legacy_state = legacy_parts[1] if len(legacy_parts) > 1 else "unknown"
        legacy_preset = legacy_parts[2] if len(legacy_parts) > 2 else ""
        unit_state = post_service_units.get(unit, {})
        record: dict[str, Any] = {
            "unit": unit,
            "change_type": "added" if unit in added_by_unit else "modified",
            "state": unit_state.get("state", legacy_state),
            "preset": unit_state.get("preset", legacy_preset),
            "unit_text": text,
            **effective,
        }

        user = str(effective.get("user") or "")
        dynamic_user = str(effective.get("dynamic_user") or "no").lower() in {"yes", "true", "1"}
        privileged = (not user and not dynamic_user) or user in {"root", "0"}
        exec_paths = effective.get("exec_paths", [])
        execution_chains = [_resolve_exec_chain(p) for p in exec_paths]
        record["execution_chains"] = execution_chains
        wrapper_references: list[dict[str, str]] = []
        seen_wrapper_refs: set[tuple[str, str]] = set()
        for exec_path in exec_paths:
            for ref in _wrapper_referenced_paths(exec_path):
                key = (str(ref.get("path_type")), str(ref.get("path")))
                if key not in seen_wrapper_refs:
                    seen_wrapper_refs.add(key)
                    wrapper_references.append(ref)
        record["wrapper_references"] = wrapper_references
        record["privileged"] = privileged

        checks: list[tuple[str, str]] = []
        fragment = str(effective.get("fragment_path") or "")
        if fragment:
            checks.append(("UnitFile", fragment))
        checks.extend(("DropIn", p) for p in effective.get("drop_in_paths", []))
        for chain in execution_chains:
            for path in chain:
                checks.append(("ExecStart", path))
        checks.extend(("EnvironmentFile", p) for p in effective.get("environment_files", []))
        checks.extend(("WorkingDirectory", p) for p in effective.get("working_directory", []))
        checks.extend((str(ref.get("path_type") or "ReferencedPath"), str(ref.get("path") or "")) for ref in wrapper_references if ref.get("path"))

        permission_results = []
        for kind, path_text in checks:
            concerns = _write_concerns(path_text)
            permission_results.append({"path_type": kind, "path": path_text, "concerns": concerns})
            if concerns:
                risk_candidates.append({
                    "unit": unit, "privileged": privileged, "path_type": kind,
                    "path": path_text, "concerns": ", ".join(concerns),
                })
        record["permission_results"] = permission_results
        records.append(record)

    privileged_count = sum(1 for x in records if x.get("privileged"))
    high_count = sum(1 for x in risk_candidates if x.get("privileged"))
    review_count = sum(1 for x in risk_candidates if not x.get("privileged")) + privileged_count

    lines = [
        "systemd Service Review", "=" * 22, "",
        "This report analyzes application services introduced or modified during installation and correlates effective systemd execution settings with referenced filesystem paths.",
        "Effective User/Group/ExecStart values are read from systemctl show so drop-in overrides and reset directives do not leave obsolete values in the analysis.",
        "The change inventory itself remains in install_changes.txt; unrelated operating-system timers are not repeated here.",
        "", "Summary", "-------",
        f"Application services reviewed:    {len(records)}",
        f"New services introduced:          {sum(1 for r in records if r.get('change_type') == 'added')}",
        f"Pre-existing services modified:   {sum(1 for r in records if r.get('change_type') == 'modified')}",
        f"Application timers identified:   {len(timer_records)}",
        f"Services running as root:         {privileged_count}",
        f"High-interest path conditions:    {high_count}",
        f"Other review conditions:          {max(0, review_count - high_count)}",
        "", "Application Services", "====================", "",
    ]

    if not records:
        lines += ["No new or modified application systemd services were identified.", ""]

    for record in records:
        unit = record.get("unit", "unknown.service")
        lines += [f"Service: {unit}", "-" * (9 + len(unit))]
        user = str(record.get("user") or "")
        group = str(record.get("group") or "")
        dynamic = str(record.get("dynamic_user") or "no")
        if user:
            runs_as = user
        elif dynamic.lower() in {"yes", "true", "1"}:
            runs_as = "dynamic systemd user (DynamicUser=yes)"
        else:
            runs_as = "root (implicit; no User= directive)"
        lines += [
            f"Change:    {str(record.get('change_type') or 'review').title()}",
            f"Unit File: {record.get('fragment_path') or 'Not resolved'}",
            f"Drop-Ins:  {', '.join(record.get('drop_in_paths', [])) or 'None'}",
            f"State:     {record.get('state') or 'unknown'}",
            f"Preset:    {record.get('preset') or 'Not reported'}",
            f"Runs As:   {runs_as}",
            f"Group:     {group or 'default'}",
            f"DynamicUser: {dynamic}",
            "", "Execution", "---------",
        ]
        for value in record.get("exec_start", []):
            lines.append(f"ExecStart: {value}")
        if not record.get("exec_start"):
            lines.append("ExecStart: Not identified")
        chains = record.get("execution_chains", [])
        if chains:
            lines += ["", "Execution Chain", "---------------"]
            for chain in chains:
                if chain:
                    lines.append("  " + "\n    -> ".join(chain))
        lines += [
            "", "Environment / Working Paths", "---------------------------",
            f"EnvironmentFile: {', '.join(record.get('environment_files', [])) or 'None'}",
            f"WorkingDirectory: {', '.join(record.get('working_directory', [])) or 'Not configured'}",
            "", "Filesystem Correlation", "----------------------",
        ]
        permission_results = record.get("permission_results", [])
        if permission_results:
            for item in permission_results:
                state = "REVIEW" if item.get("concerns") else "OK"
                lines.append(f"[{state}] {item['path_type']}: {item['path']}")
                for concern in item.get("concerns", []):
                    lines.append(f"    - {concern}")
        else:
            lines.append("No resolvable referenced paths were available for permission correlation.")

        lines += ["", "Systemd Hardening", "-----------------"]
        for key in HARDENING_KEYS:
            lines.append(f"{key:<24} {record.get('hardening', {}).get(key, 'Not configured')}")
        lines += ["", "Assessment", "----------"]
        if record.get("privileged"):
            verb = "installs" if record.get("change_type") == "added" else "modifies"
            lines.append(f"[REVIEW] The application {verb} a persistent system service that runs with elevated privileges.")
        else:
            lines.append("[INFORMATIONAL] The service runs under an explicitly configured or dynamic non-root account.")
        if not any(x.get("concerns") for x in permission_results):
            lines.append("No immediately exploitable writable referenced path was identified by the automated correlation.")
        lines += [
            "Missing systemd sandboxing directives are informational and are not treated as vulnerabilities by themselves.",
            "", "Tester Actions", "--------------",
            "1. Validate the complete ExecStart execution chain and any privileged helper behavior.",
            "2. Determine whether configuration, environment, working directories, IPC, or command arguments can be influenced by an unprivileged user.",
            "3. Exercise the client while observing privileged service child processes and filesystem/network activity.", "",
        ]

    if modified:
        lines += ["Pre-Existing Service State Changes", "==================================", ""]
        for item in modified:
            lines += [f"Service: {item.get('unit')}", f"Before:  {item.get('before')}", f"After:   {item.get('after')}", ""]
        lines += ["These units existed before installation and are not described as newly introduced services.", ""]

    lines += ["Application Timers", "==================", ""]
    if timer_records:
        for timer in timer_records:
            lines += [
                f"Timer: {timer['unit']}", "-" * (7 + len(timer['unit'])),
                f"Activates: {timer['activates']}", "Schedule:",
            ]
            lines += [f"  {x}" for x in timer["schedule"]] or ["  Not automatically resolved"]
            lines += [
                "Assessment: [REVIEW] Determine whether the associated service executes with elevated privileges and whether its executable/configuration/update source can be influenced by an unprivileged user.", "",
            ]
    else:
        lines += ["No application timers were introduced during installation.", ""]

    write_text(report_path(output_dir, "service_review.txt"), "\n".join(lines))
    return {"services": records, "timers": timer_records, "risk_candidates": risk_candidates, "modified_services": modified}
