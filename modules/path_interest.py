from __future__ import annotations

from pathlib import Path


ROUTINE_EXECUTABLE_DATA_SUFFIXES = {
    ".bmp", ".dat", ".gif", ".html", ".icns", ".ico", ".jpg", ".jpeg",
    ".md", ".pak", ".png", ".txt", ".webp",
}


def classify_high_interest(path_text: str, ptype: str, mode: str) -> tuple[bool, str]:
    """Classify tester-relevant installed/package paths with one shared policy."""
    path = Path(path_text)
    lower = path_text.lower()
    name = path.name.lower()
    bundled_runtime = (
        ("/lib/" in lower and ("/opt/" in lower or "/usr/lib/" in lower))
        or "/_internal/" in lower
        or ".dist-info/" in lower
        or ".egg-info/" in lower
        or "/share/tk" in lower
    )

    if lower == "/etc/sudoers" or any(
        marker in lower
        for marker in (
            "/systemd/system/", "/sudoers.d/", "/dbus-1/", "/polkit-1/",
            "/apt/sources.list.d/",
        )
    ):
        return True, "SYSTEM CONFIG"
    if ptype == "symlink":
        # Internal runtime symlinks are represented in the package/object
        # counts and raw payload, but do not need repetitive report entries.
        return False, ""
    if bundled_runtime or name.endswith((".pyc", ".pyo")):
        return False, ""
    if "/usr/share/applications/" in lower or name.endswith(".desktop"):
        return True, "DESKTOP ENTRY"
    if name.endswith((".service", ".timer")):
        return True, "SYSTEMD UNIT"
    if name in {"package-lock.json", "npm-shrinkwrap.json"} or any(part.lower() in {"locales", "translations"} for part in path.parts):
        return False, ""
    if name.endswith((".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".xml", ".env", ".properties")):
        return True, "CONFIGURATION"
    if name.endswith((".sh", ".bash", ".py", ".pl")) and ("x" in mode or "/bin/" in lower):
        return True, "SCRIPT"
    if name.endswith((".pem", ".key", ".p12", ".pfx", ".crt", ".cer")):
        return True, "KEY/CERTIFICATE"
    if any(token in name for token in ("update", "updater", "upgrade")):
        return True, "UPDATE COMPONENT"
    if ".so" in name:
        return False, ""
    if name in {"license", "version"} or path.suffix.lower() in ROUTINE_EXECUTABLE_DATA_SUFFIXES:
        # Some vendor archives mark whole resource trees executable. Report
        # permissions separately instead of flooding the high-interest list.
        return False, ""
    if ptype == "file" and ("x" in mode or str(path.parent) in {"/usr/bin", "/usr/sbin", "/usr/local/bin"}):
        return True, "EXECUTABLE"
    return False, ""
