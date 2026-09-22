from __future__ import annotations

from pathlib import Path
from .common import command_exists, report_path, write_text

TOOLS = {
    "REQUIRED": ["python3", "file", "dpkg-deb", "readelf", "objdump", "ss", "stat"],
    "RECOMMENDED": [
        "checksec", "strace", "ltrace", "getfacl", "getcap", "lsof", "inotifywait",
        "sqlite3", "busctl", "gdbus", "strings", "unsquashfs", "gpgv", "debsig-verify"
    ],
    "OPTIONAL": [
        "gdb", "auditctl", "yara", "binwalk", "tcpdump", "nmap",
        "desktop-file-validate", "debsums", "debsigs", "snap", "flatpak"
    ],
}


def detect_tools(output_dir: Path) -> tuple[dict, bool]:
    results: dict[str, dict[str, dict[str, str | bool | None]]] = {}
    lines = ["UbuntuClientAssess Tool Detection", "=" * 33, ""]
    ready = True
    for level, names in TOOLS.items():
        lines += [level, "-" * len(level)]
        results[level] = {}
        for name in names:
            path = command_exists(name)
            present = bool(path)
            results[level][name] = {"present": present, "path": path}
            if level == "REQUIRED" and not present:
                ready = False
            status = "PASS" if present else ("FAIL" if level == "REQUIRED" else "WARN")
            lines.append(f"[{status}] {name:<22} {path or 'Not detected'}")
        lines.append("")

    lines += ["Summary", "-------"]
    for level, names in TOOLS.items():
        count = sum(1 for name in names if results[level][name]["present"])
        lines.append(f"{level.title():<12}: {count}/{len(names)}")
    lines += ["", "Assessment environment is ready." if ready else "One or more required tools are missing."]
    write_text(report_path(output_dir, "tool_detection.txt"), "\n".join(lines))
    return results, ready
