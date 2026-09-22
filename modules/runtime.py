from __future__ import annotations

from pathlib import Path
from .common import VERSION, report_path, write_text


def _process_line(proc: dict) -> str:
    return (
        f"PID {proc.get('pid')} PPID {proc.get('ppid')} {proc.get('user')} "
        f"{proc.get('comm')} | {proc.get('args')}"
    )


def write_runtime_guidance(
    output_dir: Path,
    application_path: str | None = None,
    profile_data: dict | None = None,
    observation: dict | None = None,
) -> None:
    target = application_path or "/path/to/application"
    profile_data = profile_data or {}
    observation = observation or {}
    technologies = profile_data.get("technologies", []) or []
    primary = profile_data.get("primary_technology") or "not confidently identified"
    supporting = ", ".join(profile_data.get("supporting_technologies", []) or []) or "none identified"
    detected = ", ".join(f"{item['technology']} ({item['confidence']})" for item in technologies) or "No framework-specific profile available"
    monitor_roots = []
    for value in (observation.get("filesystem_roots", []) or profile_data.get("analysis_roots", []) or []):
        if str(value) not in monitor_roots:
            monitor_roots.append(str(value))
    monitor_command = "inotifywait -mr " + " ".join(repr(value) for value in monitor_roots) if monitor_roots else "inotifywait -mr <application-root> <application-data-root>"
    framework_lines: list[str] = []
    for item in technologies:
        role = "PRIMARY" if item.get("technology") == profile_data.get("primary_technology") else "SUPPORTING"
        if item.get("kind") == "packaging":
            role = "PACKAGING"
        framework_lines.append(f"[{item['technology']} - {item['confidence']} - {role}]")
        focus = item.get("runtime_focus") or item.get("guidance") or []
        framework_lines.extend(f"- {entry}" for entry in focus)
        framework_lines.append("")
    framework_text = "\n".join(framework_lines).rstrip() or "Use the generic runtime procedures below and application_profile.txt to refine the plan."

    lines = [
        "Runtime Review", "==============", "",
        f"UbuntuClientAssess v{VERSION} does not automatically launch or exploit the target application. Runtime observation is tester-controlled and is intended to correlate application behavior with the static/differential evidence.",
        "",
        "Detected Application Technologies", "---------------------------------", "",
        f"Primary technology:       {primary}",
        f"Supporting technologies: {supporting}",
        f"Detected evidence:        {detected}",
        "",
    ]

    if observation:
        lines += [
            "Guided Runtime Observation", "--------------------------", "",
            f"Observation duration:     {observation.get('duration_seconds', 0)} seconds",
            f"Samples captured:         {observation.get('sample_count', 0)}",
            f"Application processes:    {len(observation.get('application_processes', []))}",
            f"Child processes:          {len(observation.get('child_processes', []))}",
            f"Privileged processes:     {observation.get('privileged_process_count', 0)}",
            f"Active/recent connections: {len(observation.get('connections', []))}",
            f"Unix sockets observed:    {len(observation.get('unix_sockets', []))}",
            f"Named FIFOs observed:     {len(observation.get('fifo_paths', []))}",
            f"Elevated endpoint view:   {'yes' if observation.get('elevated_visibility') else 'no'}",
            "",
            "Application / Related Processes",
            "-------------------------------",
        ]
        processes = observation.get("application_processes", []) or []
        lines += [f"- {_process_line(proc)}" for proc in processes] or ["None attributed during the observation window."]
        children = observation.get("child_processes", []) or []
        lines += ["", "Observed Child Processes", "------------------------"]
        lines += [f"- {_process_line(proc)}" for proc in children] or ["None observed."]
        lines += ["", "Observed Network Listeners", "--------------------------"]
        lines += [f"- {line}" for line in observation.get("listeners", [])] or ["None attributed."]
        lines += ["", "Externally Bound Listeners", "--------------------------"]
        lines += [f"- {line}" for line in observation.get("externally_bound_listeners", [])] or ["None observed."]
        lines += ["", "Observed Active / Recent Connections", "------------------------------------"]
        lines += [f"- {line}" for line in observation.get("connections", [])] or ["None attributed."]
        lines += ["", "Observed Unix Sockets", "---------------------"]
        socket_rows = observation.get("socket_analysis", []) or []
        if socket_rows:
            for item in socket_rows:
                lines.append(f"[{item.get('review_level', 'MEDIUM')} REVIEW] {item.get('line', '')}")
        else:
            lines.append("None attributed.")
        lines += ["", "Observed Named FIFOs", "--------------------"]
        lines += [f"- {value}" for value in observation.get("fifo_paths", [])] or ["None observed within application-specific runtime roots."]
        activity = observation.get("file_activity", {}) or {}
        lines += ["", "Scoped Filesystem Activity", "--------------------------"]
        for key, title in (("created", "Created"), ("modified", "Modified"), ("deleted", "Deleted")):
            values = activity.get(key, []) or []
            lines.append(f"{title}: {len(values)}")
            lines.extend(f"  - {value}" for value in values[:50])
        if activity.get("suppressed"):
            lines.append(f"Additional file events suppressed: {activity['suppressed']}")
        lines += [
            "",
            "Runtime Interpretation",
            "----------------------",
            "These observations identify application-correlated activity, not automatically exploitable behavior. Validate authorization, privilege, input handling, and concrete security impact before reporting a finding.",
            "",
        ]

    lines += [
        "Recommended Commands", "--------------------", "",
        "Trace file, network, and process activity:", "",
        f"    strace -ff -e trace=file,network,process -o runtime_strace {target}", "",
        "Trace library calls where appropriate:", "",
        f"    ltrace -f -o runtime_ltrace.txt {target}", "",
        "Inspect files and sockets used by a running process:", "",
        "    lsof -p <PID>",
        "    lsof -i -n -P",
        "    ss -lntupn",
        "    ss -ntupn",
        "    ss -lxnp", "",
        "Monitor application-specific filesystem locations:", "",
        f"    {monitor_command}", "",
        "Review systemd logs:", "",
        '    journalctl --since "10 minutes ago"', "",
        "Review D-Bus activity / interfaces:", "",
        "    busctl --system list",
        "    busctl --user list",
        "    gdbus introspect --system --dest <BUS.NAME> --object-path <OBJECT_PATH>", "",
        "Capture scoped network traffic and proxy behavior where authorized:", "",
        "    sudo tcpdump -i any -nn -s0 -w client-runtime.pcap",
        "    env | grep -iE '^(http|https|all|no)_proxy='", "",
        "Framework-Specific Runtime Focus", "--------------------------------", "",
        framework_text, "",
        "Tester Review Areas", "-------------------", "",
        "- Files created or modified at runtime",
        "- Temporary files and unsafe temporary-file handling",
        "- Child process creation and shell execution",
        "- Network connections and listening ports",
        "- Unix domain sockets and D-Bus activity",
        "- Shared libraries loaded at runtime",
        "- Local credentials, tokens, and session material",
        "- Log files containing sensitive information",
        "- Privileged helper processes",
        "- Updater/download behavior and signature verification",
        "- Direct versus proxy communication and certificate-validation failure behavior",
        "",
    ]
    write_text(report_path(output_dir, "runtime_review.txt"), "\n".join(lines))
