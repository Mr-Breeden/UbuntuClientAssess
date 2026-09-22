from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .common import get_interactive_user, report_path, run_cmd, write_text


SUDOERS_FILE = "/etc/sudoers"
SUDOERS_DIRECTORY = "/etc/sudoers.d/"
SUDO_TAG_RE = re.compile(
    r"\b(NOPASSWD|PASSWD|SETENV|NOSETENV|EXEC|NOEXEC|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT):"
)
COMMAND_PATH_RE = re.compile(r"(?<!\\)(/[^\s,]+)")
WILDCARD_RE = re.compile(r"(?<!\\)[*?[]")
DANGEROUS_PROGRAMS = {
    "ash", "awk", "bash", "busybox", "chmod", "chown", "cp", "csh", "dash",
    "dd", "dnf", "dpkg", "ed", "emacs", "env", "expect", "find", "fish", "ftp",
    "gdb", "irb", "ksh", "less", "lua", "make", "more", "mv", "nano", "nc",
    "ncat", "netcat", "node", "npm", "perl", "php", "pip", "pip3", "python",
    "python3", "rbash", "rsync", "ruby", "scp", "sed", "setcap", "sh", "socat",
    "ssh", "systemctl", "tar", "tee", "vi", "vim", "wget", "yum", "zsh",
}


def _is_sudoers_path(path_text: str) -> bool:
    return path_text == SUDOERS_FILE or path_text.startswith(SUDOERS_DIRECTORY)


def _policy_paths(diff: dict[str, Any]) -> list[str]:
    changed = sorted(set(diff.get("files_added", [])) | set(diff.get("files_changed", [])))
    post_fs = diff.get("post_filesystem", {})
    paths: list[str] = []
    for path_text in changed:
        if not _is_sudoers_path(path_text):
            continue
        meta = post_fs.get(path_text, {})
        # Do not report the sudoers.d directory itself as a policy file. A
        # symlink is retained because it is independently security-relevant.
        if meta.get("type") == "directory" or path_text.rstrip("/") == "/etc/sudoers.d":
            continue
        paths.append(path_text)
    return paths


def _split_unescaped_commas(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    escaped = False
    for index, char in enumerate(text):
        if char == "\\" and not escaped:
            escaped = True
            continue
        if char == "," and not escaped:
            parts.append(text[start:index])
            start = index + 1
        escaped = False
    parts.append(text[start:])
    return parts


def _extract_command_path(command: str) -> str:
    match = COMMAND_PATH_RE.search(command)
    if not match:
        return ""
    return match.group(1).replace("\\ ", " ").replace("\\,", ",")


def _parse_sudo_policy(text: str) -> list[dict[str, Any]]:
    """Parse command specifications from stable, C-locale ``sudo -l`` output.

    The parser intentionally ignores Defaults entries and descriptive text. It
    tracks tag state across comma-separated command specifications on the same
    output line, which handles rules such as ``NOPASSWD: /a, PASSWD: /b``.
    """
    records: list[dict[str, Any]] = []
    normalized = text.replace("\\\n", " ")
    for raw_line in normalized.splitlines():
        match = re.match(r"^\s*\((?P<runas>[^)]+)\)\s+(?P<body>.+?)\s*$", raw_line)
        if not match:
            continue
        runas = match.group("runas").strip()
        state: dict[str, bool | None] = {"nopasswd": False, "setenv": None}
        for raw_spec in _split_unescaped_commas(match.group("body")):
            tags = SUDO_TAG_RE.findall(raw_spec)
            for tag in tags:
                if tag == "NOPASSWD":
                    state["nopasswd"] = True
                elif tag == "PASSWD":
                    state["nopasswd"] = False
                elif tag == "SETENV":
                    state["setenv"] = True
                elif tag == "NOSETENV":
                    state["setenv"] = False
            command = SUDO_TAG_RE.sub("", raw_spec).strip()
            if not command:
                continue
            all_commands = command == "ALL"
            records.append({
                "runas": runas,
                "command": command,
                "command_path": _extract_command_path(command),
                "nopasswd": state["nopasswd"],
                # sudoers implies SETENV for an ALL command unless explicitly
                # disabled. Record that effective behavior for review.
                "setenv": state["setenv"] is True or (all_commands and state["setenv"] is not False),
                "all_commands": all_commands,
                "wildcards": bool(WILDCARD_RE.search(command)),
                "raw": raw_line.strip(),
            })
    return records


def _correlates_with_install(command_path: str, changed_paths: set[str]) -> bool:
    if not command_path:
        return False
    if command_path in changed_paths:
        return True
    # A sudoers command may itself contain a path wildcard. Correlate its
    # literal prefix with newly installed files without expanding the pattern.
    prefix = re.split(r"(?<!\\)[*?[]", command_path, maxsplit=1)[0]
    return bool(prefix and any(path.startswith(prefix) for path in changed_paths))


def _dynamic_elf_paths(elf_data: dict[str, Any]) -> set[str]:
    dynamic: set[str] = set()
    for record in elf_data.get("elf_files", []):
        if record.get("interpreter") or (record.get("dynamic") or {}).get("needed"):
            path = str(record.get("path") or "")
            if path:
                dynamic.add(path)
    return dynamic


def _assess_sudo_records(
    records: list[dict[str, Any]],
    diff: dict[str, Any],
    elf_data: dict[str, Any],
) -> list[dict[str, Any]]:
    changed_paths = set(diff.get("files_added", [])) | set(diff.get("files_changed", []))
    dynamic_paths = _dynamic_elf_paths(elf_data)
    candidates: list[dict[str, Any]] = []
    for record in records:
        runas_text = str(record["runas"])
        privileged = bool(re.search(r"(?:^|[\s,:])(?:root|ALL)(?:$|[\s,:])", runas_text, re.I))
        command_path = str(record.get("command_path") or "")
        # Do not attribute a tester's pre-existing broad sudo access to the
        # application merely because some sudoers file changed. Automatic
        # promotion requires a command/path correlation with this install.
        correlated = _correlates_with_install(command_path, changed_paths)
        dynamic_executable = command_path in dynamic_paths
        program = Path(command_path).name.lower() if command_path else ""
        program_family = re.sub(r"\d+(?:\.\d+)*$", "", program)
        dangerous_program = program in DANGEROUS_PROGRAMS or program_family in DANGEROUS_PROGRAMS

        concerns: list[str] = []
        if record["nopasswd"]:
            concerns.append("NOPASSWD allows use without re-authentication")
        if record["setenv"]:
            concerns.append("SETENV permits caller-controlled environment variables")
        if record["wildcards"]:
            concerns.append("wildcards broaden caller-controlled arguments or paths")
        if record["all_commands"]:
            concerns.append("ALL permits unrestricted command selection")
        if dangerous_program:
            concerns.append(f"{program} can commonly execute commands or modify privileged files")
        if dynamic_executable and record["setenv"]:
            concerns.append("the permitted executable is dynamically linked, increasing loader-environment risk")
        if correlated and not record["all_commands"]:
            concerns.append("the permitted executable was introduced or changed during installation")

        finding_candidate = bool(
            privileged
            and correlated
            and (
                record["all_commands"]
                or dangerous_program
                or (record["setenv"] and dynamic_executable)
                or (record["nopasswd"] and record["wildcards"])
            )
        )
        if record["all_commands"] or dangerous_program or (record["setenv"] and dynamic_executable):
            severity = "High"
        else:
            severity = "Medium"

        # Retain application-correlated privileged rules in the persistence
        # report even when they need tester validation before promotion to
        # findings.txt. Unrelated baseline sudo privileges are intentionally
        # suppressed.
        if privileged and correlated:
            candidates.append({
                **record,
                "privileged": privileged,
                "application_correlated": correlated,
                "dynamic_executable": dynamic_executable,
                "dangerous_program": dangerous_program,
                "concerns": concerns,
                "finding_candidate": finding_candidate,
                "severity": severity,
            })
    return candidates


def _collect_effective_policy() -> dict[str, Any]:
    command = ["sudo", "-n", "-l"]
    tester = get_interactive_user()
    if os.geteuid() == 0 and tester != "root":
        command.extend(["-U", tester])
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "LANG": "C"})
    result = run_cmd(command, timeout=20, env=environment)
    return {
        "status": "captured" if result["returncode"] == 0 else "unavailable",
        "returncode": result["returncode"],
        "command": command,
        "stdout": result["stdout"] if result["returncode"] == 0 else "",
    }


def review_persistence(
    diff: dict[str, Any],
    output_dir: Path,
    elf_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    elf_data = elf_data or {}
    changed = sorted(set(diff.get("files_added", [])) | set(diff.get("files_changed", [])))
    indicators = []
    patterns = (
        "/etc/systemd/system/",
        "/usr/lib/systemd/system/",
        "/etc/cron.",
        "/etc/cron.d/",
        "/.config/autostart/",
        "/usr/share/applications/",
        "/.local/share/applications/",
        "/etc/ld.so.conf.d/",
        "/etc/profile.d/",
        "/etc/sudoers",
        "/etc/polkit-1/rules.d/",
    )
    for path in changed:
        if any(p in path for p in patterns) or path.endswith(("/.bashrc", "/.profile", "/.zshrc", "/rc.local")):
            indicators.append(path)

    sudoers_paths = _policy_paths(diff)
    policy_result = {"status": "not-applicable", "returncode": None, "command": [], "stdout": ""}
    sudo_candidates: list[dict[str, Any]] = []
    if sudoers_paths:
        policy_result = _collect_effective_policy()
        if policy_result["status"] == "captured":
            records = _parse_sudo_policy(policy_result["stdout"])
            sudo_candidates = _assess_sudo_records(records, diff, elf_data)

    post_fs = diff.get("post_filesystem", {})
    review_required: list[dict[str, str]] = []
    for path_text in sudoers_paths:
        meta = post_fs.get(path_text, {})
        state = "added" if path_text in diff.get("files_added", []) else "modified"
        mode = meta.get("mode_octal") or "unknown mode"
        owner = f"{meta.get('owner', '?')}:{meta.get('group', '?')}"
        reason = (
            f"{path_text} was {state} ({owner}, {mode}). Effective policy was inspected for the current tester, "
            "but the root-managed policy file itself still requires syntax and scope validation."
            if policy_result["status"] == "captured"
            else
            f"{path_text} was {state} ({owner}, {mode}), but non-interactive effective-policy collection was unavailable."
        )
        review_required.append({
            "identity": f"sudoers-review:{path_text}",
            "title": "Changed sudoers Policy Requires Manual Review",
            "evidence": reason,
            "action": "Inspect the exact policy with administrative read access, validate it with visudo, and review effective privileges for each affected user or group.",
        })

    lines = [
        "Persistence and Privileged Policy Review",
        "=" * 40,
        "",
        "This report identifies installation changes that may establish startup, service, scheduled, shell, desktop, loader, or privileged-policy persistence.",
        "Changed sudoers policy files are always marked for manual review. When possible, the framework also performs a non-interactive, read-only sudo policy listing and correlates risky rules with installed executables; it never executes a permitted command.",
        "",
        "systemd Persistence Summary",
        "---------------------------",
        f"Services added:    {len(diff.get('services_added', []))}",
        f"Services modified: {len(diff.get('services_modified', []))}",
        f"Timers added:      {len(diff.get('timers_added', []))}",
        "Detailed service/timer inventory is kept in install_changes.txt; security analysis is kept in service_review.txt.",
        "",
        "New User Crontab Entries", "-------------------------"]
    lines += diff.get("user_crontab_added", []) or ["None observed."]
    lines += ["", "New Root Crontab Entries", "-------------------------"]
    lines += diff.get("root_crontab_added", []) or ["None observed."]
    lines += ["", "Persistence-Related File Changes", "--------------------------------"]
    lines += indicators or ["None observed within tracked paths."]

    lines += ["", "sudoers Policy Changes", "----------------------"]
    if review_required:
        for item in review_required:
            lines += [
                "[REVIEW REQUIRED]",
                f"Evidence: {item['evidence']}",
                f"Action:   {item['action']}",
                "",
            ]
    else:
        lines += ["None observed.", ""]

    lines += ["Effective sudo Policy Correlation", "---------------------------------"]
    if not sudoers_paths:
        lines += ["Not applicable: no sudoers policy file was added or modified.", ""]
    elif policy_result["status"] != "captured":
        lines += [
            "[ATTENTION] Effective policy could not be listed non-interactively.",
            "The changed sudoers policy remains unresolved and must be inspected manually before assessment closeout.",
            "",
        ]
    elif not sudo_candidates:
        lines += [
            "No risky effective rule was automatically correlated with newly installed or changed application files for the current tester.",
            "This does not clear the changed policy file; rules applying to other users/groups and sudoers alias expansion still require manual validation.",
            "",
        ]
    else:
        for candidate in sudo_candidates:
            marker = "HIGH ATTENTION / FINDING CANDIDATE" if candidate["finding_candidate"] else "REVIEW"
            lines += [
                f"[{marker}]",
                f"Rule:     {candidate['raw']}",
                f"Run as:   {candidate['runas']}",
                f"Command:  {candidate['command']}",
                f"Concerns: {'; '.join(candidate['concerns']) or 'Privileged rule requires contextual review'}",
                "",
            ]

    lines += [
        "Tester Guidance",
        "---------------",
        "Determine whether each startup or privileged-policy mechanism is required, what privilege it receives, and whether lower-privileged users can manipulate the executable, arguments, environment, policy, configuration, or parent directory it relies upon.",
        "Treat SETENV, NOPASSWD, ALL, command/path wildcards, interpreters, shells, editors, package managers, and dynamically linked privileged helpers as priority review conditions.",
    ]
    write_text(report_path(output_dir, "persistence_review.txt"), "\n".join(lines))
    return {
        "persistence_paths": indicators,
        "user_crontab_added": diff.get("user_crontab_added", []),
        "root_crontab_added": diff.get("root_crontab_added", []),
        "sudoers_paths": sudoers_paths,
        "sudo_policy_status": policy_result["status"],
        "sudo_policy_candidates": sudo_candidates,
        "review_required": review_required,
    }
