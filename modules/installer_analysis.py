from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import tarfile
import tempfile
import zipfile
import math
from pathlib import Path
from typing import Any

from .common import command_exists, human_size, redact_sensitive_text, report_path, run_cmd, sanitize_url, sha256_file, write_text
from .path_interest import classify_high_interest

SCRIPT_NAMES = ["preinst", "postinst", "prerm", "postrm", "config", "triggers"]
SCRIPT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Network download", re.compile(r"\b(?:curl|wget)\b", re.I)),
    ("Service management", re.compile(r"\b(?:systemctl|service)\b", re.I)),
    ("User/group creation", re.compile(r"\b(?:useradd|adduser|groupadd|addgroup|usermod)\b", re.I)),
    ("Permission change", re.compile(r"\b(?:chmod|chown|setfacl|setcap)\b", re.I)),
    ("Broad permissions", re.compile(r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rw|a\+rwx|o\+w)\b", re.I)),
    ("Scheduled execution", re.compile(r"\b(?:cron|crontab|at)\b", re.I)),
    ("Privilege configuration", re.compile(r"(?:/etc/sudoers|sudoers\.d|pkexec|polkit)", re.I)),
    ("Dynamic loader change", re.compile(r"(?:ldconfig|ld\.so\.conf|LD_PRELOAD|LD_LIBRARY_PATH)", re.I)),
    ("Shell execution", re.compile(r"\b(?:sh|bash|dash)\s+-c\b", re.I)),
]
ARCHIVE_ENTRY_LIMIT = 20000
ARCHIVE_REPORT_LIMIT = 160
SCRIPT_SCAN_LIMIT = 5 * 1024 * 1024
SQUASHFS_SIZE_LIMIT = 4 * 1024 * 1024 * 1024
SQUASHFS_FILE_LIMIT = 100000
MAX_PACKAGE_COMMAND_TIMEOUT = 900
_DEB_CONTENTS_CACHE: dict[tuple[str, int, int], dict[str, Any]] = {}


def _package_command_timeout(size_bytes: int, base: int = 120) -> int:
    """Scale parser/extraction time for large packages within a hard ceiling."""
    additional = math.ceil(max(0, size_bytes) / (8 * 1024 * 1024))
    return min(MAX_PACKAGE_COMMAND_TIMEOUT, base + additional)
URL_RE = re.compile(r"(?:https?|wss?)://[^\s\"'<>]+", re.I)
INSTALL_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])/(?:opt|usr|etc|var|home|tmp)/[A-Za-z0-9_./@%+,:=-]+")


def _deb_contents_result(installer: Path, timeout: int) -> dict[str, Any]:
    """Enumerate a Debian archive once per process and reuse the output."""
    try:
        st = installer.stat()
        key = (str(installer.resolve()), st.st_size, st.st_mtime_ns)
    except OSError:
        return run_cmd(["dpkg-deb", "--contents", str(installer)], timeout=timeout)
    if key not in _DEB_CONTENTS_CACHE:
        _DEB_CONTENTS_CACHE[key] = run_cmd(["dpkg-deb", "--contents", str(installer)], timeout=timeout)
    return _DEB_CONTENTS_CACHE[key]


def _append_cmd(lines: list[str], title: str, cmd: list[str], timeout: int = 45) -> dict[str, Any]:
    result = run_cmd(cmd, timeout=timeout)
    lines += [title, "-" * len(title), f"Command: {' '.join(shlex.quote(x) for x in cmd)}", ""]
    output = redact_sensitive_text((result["stdout"] or result["stderr"] or "(no output)").rstrip())
    lines += [output, ""]
    return result


def _parse_deb_field(installer: Path, field: str) -> str | None:
    result = run_cmd(["dpkg-deb", "-f", str(installer), field])
    value = result["stdout"].strip()
    return value or None


def discover_installer_paths(installer: Path | None) -> list[Path]:
    """Return useful package-declared paths without broad OS roots.

    Debian archives contain directory entries such as ./usr/ and ./etc/. Those
    are intentionally ignored. We retain exact package files and add selected
    application-specific directory roots so maintainer-script-created siblings
    can still be detected without recursively snapshotting all of /usr or /etc.
    """
    if installer is None or not installer.is_file() or not installer.name.lower().endswith(".deb"):
        return []

    try:
        timeout = _package_command_timeout(installer.stat().st_size, base=90)
    except OSError:
        timeout = 90
    result = _deb_contents_result(installer, timeout)
    if result["returncode"] != 0:
        return []

    paths: set[Path] = set()
    broad_dirs = {
        Path("/etc"), Path("/usr"), Path("/usr/bin"), Path("/usr/sbin"),
        Path("/usr/lib"), Path("/usr/share"), Path("/var"), Path("/var/lib"),
        Path("/lib"), Path("/bin"), Path("/sbin"),
    }
    generic_etc = {
        "apt", "cron.d", "cron.daily", "cron.hourly", "cron.weekly", "dbus-1",
        "default", "init.d", "ld.so.conf.d", "logrotate.d", "pam.d", "polkit-1",
        "profile.d", "security", "sudoers.d", "systemd", "udev", "xdg",
    }
    generic_usr_lib = {
        "aarch64-linux-gnu", "arm-linux-gnueabihf", "dbus-1.0", "i386-linux-gnu",
        "jvm", "locale", "modules", "pam", "policykit-1", "python3", "systemd",
        "tmpfiles.d", "udev", "x86_64-linux-gnu",
    }
    generic_usr_share = {
        "applications", "bash-completion", "dbus-1", "doc", "icons", "locale",
        "man", "mime", "pixmaps", "polkit-1", "systemd", "themes",
    }

    def add_vendor_root(p: Path) -> None:
        parts = p.parts
        if len(parts) >= 4 and parts[1:3] in {("usr", "lib"), ("usr", "share"), ("var", "lib"), ("var", "opt")}:
            leaf = parts[3]
            if parts[1:3] == ("usr", "lib") and (leaf in generic_usr_lib or leaf.endswith("-linux-gnu") or leaf.startswith("python3.")):
                return
            if parts[1:3] == ("usr", "share") and leaf in generic_usr_share:
                return
            root = Path("/") / parts[1] / parts[2] / leaf
            if root not in broad_dirs:
                paths.add(root)
        elif len(parts) >= 3 and parts[1] == "opt":
            root = Path("/opt") / parts[2]
            paths.add(root)
        elif len(parts) >= 3 and parts[1] == "etc" and parts[2] not in generic_etc:
            root = Path("/etc") / parts[2]
            if root not in broad_dirs:
                paths.add(root)

    for line in result["stdout"].splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 6:
            continue
        mode = parts[0]
        raw = parts[-1].strip()
        if " -> " in raw:
            raw = raw.split(" -> ", 1)[0]
        raw = raw.lstrip(".")
        if not raw.startswith("/"):
            raw = "/" + raw.lstrip("/")
        p = Path(raw)
        if ".." in p.parts or str(p) == "/":
            continue

        is_dir = mode.startswith("d")
        if not is_dir:
            paths.add(p)
            add_vendor_root(p)
        else:
            # Keep only application-specific roots, not package boilerplate
            # directory entries such as /usr, /usr/lib, or /etc.
            add_vendor_root(p)

    # Maintainer scripts may create application state/configuration outside the
    # package payload (for example /etc/vendor or /var/lib/vendor). Extract the
    # control area to a temporary directory and add obvious absolute paths to
    # pre-snapshot coverage without persisting another inventory artifact.
    try:
        with tempfile.TemporaryDirectory(prefix="uca-deb-control-") as td:
            control = Path(td) / "control"
            result = run_cmd(["dpkg-deb", "--control", str(installer), str(control)], timeout=timeout)
            if result["returncode"] == 0:
                for name in SCRIPT_NAMES:
                    script = control / name
                    if not script.is_file():
                        continue
                    text = script.read_text(encoding="utf-8", errors="replace")[:SCRIPT_SCAN_LIMIT]
                    for raw in INSTALL_PATH_RE.findall(text):
                        candidate = Path(raw.rstrip(".,);]}"))
                        if candidate in broad_dirs or ".." in candidate.parts:
                            continue
                        paths.add(candidate)
                        add_vendor_root(candidate)
    except (OSError, PermissionError):
        pass

    return sorted((p for p in paths if p not in broad_dirs), key=str)



def _content_bucket(path_text: str) -> str:
    p = Path(path_text)
    parts = p.parts
    if len(parts) >= 3 and parts[1] == "opt":
        return str(Path("/opt") / parts[2])
    if len(parts) >= 4 and parts[1:3] in {("usr", "lib"), ("usr", "share"), ("var", "lib"), ("var", "opt")}:
        return str(Path("/") / parts[1] / parts[2] / parts[3])
    for root in ("/etc/systemd/system", "/usr/lib/systemd/system", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/share/applications", "/etc/apt/sources.list.d", "/etc/sudoers.d", "/etc/dbus-1", "/etc/polkit-1"):
        if path_text == root or path_text.startswith(root + "/"):
            return root
    if len(parts) >= 3 and parts[1] == "etc":
        return str(Path("/etc") / parts[2])
    return str(p.parent)


def _content_interest(path_text: str, mode: str) -> tuple[bool, str]:
    if mode.startswith("d"):
        return False, ""
    ptype = "symlink" if mode.startswith("l") else "file"
    return classify_high_interest(path_text, ptype, mode)


def _deb_contents_summary(installer: Path) -> tuple[list[str], dict[str, Any]]:
    from collections import Counter

    result = _deb_contents_result(installer, 90)
    if result["returncode"] != 0:
        return [result["stderr"].strip() or "Unable to enumerate Debian package contents."], {}

    entries: list[dict[str, str]] = []
    for line in result["stdout"].splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 6:
            continue
        mode = parts[0]
        raw = parts[-1].strip()
        target = ""
        if " -> " in raw:
            raw, target = raw.split(" -> ", 1)
        raw = raw.lstrip(".")
        if not raw.startswith("/"):
            raw = "/" + raw.lstrip("/")
        entries.append({"mode": mode, "path": raw, "target": target})

    files = [e for e in entries if e["mode"].startswith("-")]
    dirs = [e for e in entries if e["mode"].startswith("d")]
    symlinks = [e for e in entries if e["mode"].startswith("l")]
    executables = [e for e in files if "x" in e["mode"]]
    shared = [e for e in files if ".so" in Path(e["path"]).name]
    configs = [e for e in files if Path(e["path"]).suffix.lower() in {".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".xml", ".env", ".properties"} or e["path"].startswith("/etc/")]
    boilerplate = {"/", "/usr", "/usr/bin", "/opt", "/etc", "/etc/systemd"}
    buckets = Counter(_content_bucket(e["path"]) for e in entries if e["path"].rstrip("/") not in boilerplate)
    buckets.pop("/", None)
    high: list[tuple[str, dict[str, str]]] = []
    for e in entries:
        interesting, label = _content_interest(e["path"], e["mode"])
        if interesting:
            high.append((label, e))

    lines = [
        "Debian Package Contents",
        "-----------------------",
        f"Total package entries: {len(entries)}",
        f"Files:                 {len(files)}",
        f"Directories:           {len(dirs)}",
        f"Symlinks:              {len(symlinks)}",
        f"Executables:           {len(executables)}",
        f"Shared libraries:      {len(shared)}",
        f"Configuration files:   {len(configs)}",
        "",
        "Primary Installation Locations",
        "------------------------------",
    ]
    for root, count in buckets.most_common(20):
        lines.append(f"{root:<55} {count:>7} entry/entries")
    if len(buckets) > 20:
        lines.append(f"... {len(buckets) - 20} additional locations omitted from the text summary.")

    lines += ["", "High-Interest Package Files", "---------------------------"]
    for label, e in high[:150]:
        suffix = f" -> {e['target']}" if e["target"] else ""
        lines.append(f"[{label}] {e['path']}{suffix}")
    if not high:
        lines.append("No high-interest package paths identified by the summary filter.")
    elif len(high) > 150:
        lines.append(f"... {len(high) - 150} additional high-interest package entries omitted from this text report.")

    routine = max(0, len(entries) - min(len(high), 150))
    lines += [
        "",
        "Bundled / Routine Content",
        "-------------------------",
        f"{routine} routine package entry/entries are summarized rather than listed individually.",
        "The extracted package payload is retained under working/deb_payload for manual inspection when needed.",
        "",
    ]
    return lines, {
        "total_entries": len(entries), "files": len(files), "directories": len(dirs), "symlinks": len(symlinks),
        "executables": len(executables), "shared_libraries": len(shared), "configuration_files": len(configs),
        "high_interest": [{"label": label, **e} for label, e in high],
    }


def _script_review(script_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        text = script_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for label, pattern in SCRIPT_PATTERNS:
            if pattern.search(stripped):
                findings.append({"type": label, "line": line_no, "text": redact_sensitive_text(stripped[:500])})
    return findings


def _safe_member_name(name: str) -> tuple[bool, str]:
    normalized = name.replace("\\", "/")
    path = Path(normalized)
    if normalized.startswith("/") or path.is_absolute():
        return False, "absolute path"
    if ".." in path.parts:
        return False, "parent-directory traversal"
    return True, ""


def _archive_review(installer: Path) -> tuple[list[str], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    suffix = installer.name.lower()
    try:
        if suffix.endswith(".7z"):
            if not command_exists("7z"):
                raise OSError("7z is not installed")
            result = run_cmd(["7z", "l", "-slt", "--", str(installer)], timeout=90)
            if result["returncode"] != 0:
                raise OSError((result["stderr"] or result["stdout"]).strip())
            records: list[dict[str, str]] = []
            current: dict[str, str] = {}
            in_members = False
            for raw in result["stdout"].splitlines():
                if raw.startswith("----------"):
                    in_members = True
                    current = {}
                    continue
                if not in_members:
                    continue
                if not raw.strip():
                    if current.get("Path"):
                        records.append(current)
                    current = {}
                    continue
                if " = " in raw:
                    key, value = raw.split(" = ", 1)
                    current[key] = value
            if current.get("Path"):
                records.append(current)
            for item in records[:ARCHIVE_ENTRY_LIMIT]:
                name = item.get("Path", "")
                safe, concern = _safe_member_name(name)
                entries.append({
                    "name": name,
                    "type": "directory" if item.get("Folder") == "+" else "file",
                    "size": int(item.get("Size", "0") or 0),
                    "safe": safe,
                    "concern": concern,
                })
            truncated = len(records) > ARCHIVE_ENTRY_LIMIT
        elif suffix.endswith(".zip"):
            with zipfile.ZipFile(installer) as archive:
                infos = archive.infolist()
                for item in infos[:ARCHIVE_ENTRY_LIMIT]:
                    safe, concern = _safe_member_name(item.filename)
                    member_type = "directory" if item.is_dir() else "file"
                    if stat.S_ISLNK(item.external_attr >> 16):
                        member_type = "symlink"
                        try:
                            target = archive.read(item)[:4096].decode("utf-8", errors="replace")
                        except (OSError, RuntimeError, zipfile.BadZipFile):
                            target = ""
                        target_safe, target_concern = _safe_member_name(target)
                        if not target_safe:
                            safe, concern = False, f"unsafe link target ({target_concern})"
                    entries.append({
                        "name": item.filename,
                        "type": member_type,
                        "size": item.file_size,
                        "safe": safe,
                        "concern": concern,
                    })
                truncated = len(infos) > ARCHIVE_ENTRY_LIMIT
        else:
            with tarfile.open(installer, mode="r:*") as archive:
                member_count = 0
                for item in archive:
                    member_count += 1
                    if member_count > ARCHIVE_ENTRY_LIMIT:
                        break
                    safe, concern = _safe_member_name(item.name)
                    if item.isdev():
                        safe, concern = False, "device-node member"
                    elif item.issym() or item.islnk():
                        target_safe, target_concern = _safe_member_name(item.linkname)
                        if not target_safe:
                            safe, concern = False, f"unsafe link target ({target_concern})"
                    entries.append({
                        "name": item.name,
                        "type": "directory" if item.isdir() else "symlink" if item.issym() or item.islnk() else "file",
                        "size": item.size,
                        "safe": safe,
                        "concern": concern,
                    })
                truncated = member_count > ARCHIVE_ENTRY_LIMIT
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        truncated = False
        errors.append(str(exc))

    unsafe = [entry for entry in entries if not entry["safe"]]
    names = [entry["name"] for entry in entries]
    high = [
        entry for entry in entries
        if any(token in entry["name"].lower() for token in (
            "app.asar", "meta-inf/manifest.mf", ".service", ".desktop", "sudoers",
            "polkit", "update", "install", "runtimeconfig.json", "snap.yaml",
        )) or entry["name"].lower().endswith((".sh", ".run", ".jar", ".py", ".so", ".dll", ".exe"))
    ]
    lines = [
        "Archive Structure Review", "------------------------",
        f"Entries inspected: {len(entries)}",
        f"Total declared uncompressed size: {human_size(sum(int(x['size']) for x in entries))}",
        f"Unsafe member paths/types: {len(unsafe)}",
        f"High-interest members: {len(high)}",
    ]
    if truncated:
        lines.append(f"Entry review stopped at the safety limit of {ARCHIVE_ENTRY_LIMIT} entries.")
    if errors:
        lines += [f"Unable to parse archive safely: {'; '.join(errors)}", ""]
    else:
        lines += ["", "Unsafe Members", "--------------"]
        lines += [f"[REVIEW] {item['name']} - {item['concern']}" for item in unsafe[:ARCHIVE_REPORT_LIMIT]] or ["None identified."]
        lines += ["", "High-Interest Members", "---------------------"]
        lines += [f"{item['type']}: {item['name']}" for item in high[:ARCHIVE_REPORT_LIMIT]] or ["None identified by the static path filter."]
        if len(high) > ARCHIVE_REPORT_LIMIT:
            lines.append(f"... {len(high) - ARCHIVE_REPORT_LIMIT} additional high-interest entries suppressed.")
        lines += [
            "",
            "Safety behavior: archive members are validated and inventoried without extraction. This avoids path traversal, unsafe links, device nodes, and archive-expansion side effects.",
            "",
        ]
    return lines, {"entries": entries, "member_paths": names, "unsafe_members": unsafe, "truncated": truncated, "errors": errors}


def _find_squashfs_offsets(path: Path, limit: int = 64 * 1024 * 1024) -> list[int]:
    """Find candidate embedded SquashFS offsets used by AppImage type 2 files."""
    found: list[int] = []
    try:
        with path.open("rb") as handle:
            offset = 0
            carry = b""
            while offset < limit:
                chunk = handle.read(min(1024 * 1024, limit - offset))
                if not chunk:
                    break
                data = carry + chunk
                start = 0
                while True:
                    pos = data.find(b"hsqs", start)
                    if pos < 0:
                        break
                    candidate = max(0, offset - len(carry) + pos)
                    if candidate not in found:
                        found.append(candidate)
                    start = pos + 4
                carry = data[-3:]
                offset += len(chunk)
    except OSError:
        return []
    return found


def _find_squashfs_offset(path: Path, limit: int = 64 * 1024 * 1024) -> int | None:
    offsets = _find_squashfs_offsets(path, limit)
    return offsets[0] if offsets else None


def _extract_embedded_squashfs(installer: Path, destination: Path) -> tuple[int | None, dict[str, Any]]:
    offsets = _find_squashfs_offsets(installer)
    if not offsets:
        return None, {"status": "failed", "error": "SquashFS magic not identified within the scan limit", "root": None, "files": 0}
    last: dict[str, Any] = {"status": "failed", "error": "No valid SquashFS candidate", "root": None, "files": 0}
    for offset in offsets[:16]:
        last = _extract_squashfs(installer, destination, offset)
        if last.get("status") != "failed":
            return offset, last
    return offsets[0], last


def _extract_squashfs(installer: Path, destination: Path, offset: int | None) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not command_exists("unsquashfs"):
        return {"status": "unavailable", "error": "unsquashfs is not installed", "root": None, "files": 0}
    summary_cmd = ["unsquashfs", "-s"]
    if offset:
        summary_cmd += ["-o", str(offset)]
    summary_cmd.append(str(installer))
    summary = run_cmd(summary_cmd, timeout=60)
    if summary["returncode"] != 0:
        return {"status": "failed", "error": (summary["stderr"] or summary["stdout"]).strip(), "root": None, "files": 0}
    filesystem_size_match = re.search(r"Filesystem size\s+(\d+)\s+bytes", summary["stdout"], re.I)
    file_count_match = re.search(r"Number of files\s+(\d+)", summary["stdout"], re.I)
    filesystem_size = int(filesystem_size_match.group(1)) if filesystem_size_match else None
    declared_files = int(file_count_match.group(1)) if file_count_match else None
    if filesystem_size is not None and filesystem_size > SQUASHFS_SIZE_LIMIT:
        return {"status": "safety-limit", "error": f"declared filesystem exceeds {human_size(SQUASHFS_SIZE_LIMIT)}", "root": None, "files": 0, "filesystem_size": filesystem_size, "declared_files": declared_files}
    if declared_files is not None and declared_files > SQUASHFS_FILE_LIMIT:
        return {"status": "safety-limit", "error": f"filesystem exceeds {SQUASHFS_FILE_LIMIT} files", "root": None, "files": 0, "filesystem_size": filesystem_size, "declared_files": declared_files}
    cmd = ["unsquashfs", "-f", "-d", str(destination)]
    if offset:
        cmd += ["-o", str(offset)]
    cmd.append(str(installer))
    result = run_cmd(cmd, timeout=240)
    if result["returncode"] != 0:
        return {"status": "failed", "error": (result["stderr"] or result["stdout"]).strip(), "root": None, "files": 0, "filesystem_size": filesystem_size, "declared_files": declared_files}
    count = sum(1 for item in destination.rglob("*") if item.is_file() or item.is_symlink())
    return {"status": "extracted", "error": "", "root": str(destination), "files": count, "filesystem_size": filesystem_size, "declared_files": declared_files}


def _script_static_analysis(installer: Path) -> dict[str, Any]:
    try:
        data = installer.read_bytes()[:SCRIPT_SCAN_LIMIT]
    except OSError:
        return {"syntax": "not checked", "urls": [], "install_paths": [], "embedded_archive": [], "truncated": False}
    text = data.decode("utf-8", errors="replace")
    syntax = run_cmd(["bash", "-n", str(installer)], timeout=30) if command_exists("bash") else None
    archive_markers = sorted({
        marker for marker in ("__ARCHIVE_BELOW__", "__ARCHIVE_FOLLOWS__", "Makeself", "skip=", "tail -n +")
        if marker.lower() in text.lower()
    })
    return {
        "syntax": "valid" if syntax and syntax["returncode"] == 0 else "invalid/review required" if syntax else "not checked",
        "syntax_error": (syntax["stderr"].strip() if syntax and syntax["returncode"] else ""),
        "urls": sorted({sanitize_url(url) for url in URL_RE.findall(text)}),
        "install_paths": sorted(set(INSTALL_PATH_RE.findall(text))),
        "embedded_archive": archive_markers,
        "truncated": installer.stat().st_size > SCRIPT_SCAN_LIMIT,
    }


def _flatpak_text_review(installer: Path) -> dict[str, list[str]]:
    try:
        text = installer.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"entries": [], "concerns": []}
    entries: list[str] = []
    concerns: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            if key.lower() in {"name", "url", "branch", "title", "gpgkey", "runtime", "suggestremotename", "isruntime"}:
                entries.append(f"{key}={sanitize_url(value[:500]) if key.lower() == 'url' else redact_sensitive_text(value[:500])}")
            if key.lower() == "url" and value.lower().startswith("http://"):
                concerns.append("Flatpak repository/reference uses cleartext HTTP")
        if "--filesystem=host" in line or "--socket=system-bus" in line or "--device=all" in line:
            concerns.append(f"Broad Flatpak permission: {line[:300]}")
    return {"entries": entries, "concerns": sorted(set(concerns))}


def analyze_installer(installer: Path, output_dir: Path, retain_payload: bool = False) -> dict[str, Any]:
    info: dict[str, Any] = {
        "path": str(installer),
        "exists": installer.exists(),
        "name": installer.name,
        "size": installer.stat().st_size if installer.exists() else None,
        "sha256": sha256_file(installer) if installer.exists() and installer.is_file() else None,
        "type": "unknown",
        "declared_path_count": 0,
        "coverage_roots": [],
        "maintainer_script_indicators": [],
    }
    lines = ["Installer / Package Analysis", "=" * 28, ""]
    if not installer.exists():
        lines += [f"Installer not found: {installer}"]
        write_text(report_path(output_dir, "installer_analysis.txt"), "\n".join(lines))
        return info

    lines += [
        f"File:   {installer}",
        f"Size:   {human_size(info['size'])}",
        f"SHA256: {info['sha256']}",
        "",
    ]
    _append_cmd(lines, "File Identification", ["file", "-b", str(installer)])

    suffix = installer.name.lower()
    if suffix.endswith(".deb"):
        info["type"] = "deb"
        for field in ("Package", "Version", "Architecture", "Maintainer", "Depends", "Pre-Depends"):
            info[field.lower().replace("-", "_")] = _parse_deb_field(installer, field)

        lines += ["Parsed Package Metadata", "-----------------------"]
        for field in ("package", "version", "architecture", "maintainer", "depends", "pre_depends"):
            lines.append(f"{field.replace('_', ' ').title():<14}: {info.get(field) or 'Not declared'}")
        lines.append("")

        _append_cmd(lines, "Debian Package Information", ["dpkg-deb", "--info", str(installer)])
        content_lines, content_summary = _deb_contents_summary(installer)
        lines += content_lines
        info["content_summary"] = content_summary

        declared = discover_installer_paths(installer)
        info["declared_path_count"] = len(declared)
        compact: list[Path] = []
        for path in sorted(set(declared), key=lambda p: (len(p.parts), str(p))):
            if not any(root == path or root in path.parents for root in compact):
                compact.append(path)
        info["coverage_roots"] = [str(path) for path in sorted(compact, key=str)]
        lines += ["Declared Filesystem Coverage", "----------------------------"]
        lines += [f"Package paths added to snapshot coverage: {len(declared)}", ""]

        control_dir = output_dir / "working" / "deb_control"
        payload_dir = output_dir / "working" / "deb_payload"
        # Extraction directories must represent only the package analyzed in
        # this run. Reusing an assessment directory must never preserve a
        # previous package's maintainer scripts or payload files.
        for stale_dir in (control_dir, payload_dir):
            if stale_dir.exists() or stale_dir.is_symlink():
                if stale_dir.is_dir() and not stale_dir.is_symlink():
                    shutil.rmtree(stale_dir)
                else:
                    stale_dir.unlink()
        control_dir.mkdir(parents=True, exist_ok=True)
        package_timeout = _package_command_timeout(int(info.get("size") or 0))
        control_result = run_cmd(["dpkg-deb", "--control", str(installer), str(control_dir)], timeout=package_timeout)
        extract_result = {"returncode": 0, "stdout": "", "stderr": ""}
        if retain_payload:
            payload_dir.mkdir(parents=True, exist_ok=True)
            extract_result = run_cmd(["dpkg-deb", "--extract", str(installer), str(payload_dir)], timeout=package_timeout)

        lines += ["Maintainer Scripts", "------------------"]
        if control_result["returncode"] == 0:
            found = False
            indicators: list[dict[str, Any]] = []
            for script in SCRIPT_NAMES:
                p = control_dir / script
                if not p.exists():
                    continue
                found = True
                lines += [f"\n[{script}]", redact_sensitive_text(p.read_text(encoding="utf-8", errors="replace").rstrip())]
                for item in _script_review(p):
                    item["script"] = script
                    indicators.append(item)
            if not found:
                lines.append("No lifecycle scripts detected.")
            info["maintainer_script_indicators"] = indicators
            lines += ["", "Maintainer-Script Security Indicators", "-------------------------------------"]
            if indicators:
                for item in indicators:
                    lines.append(f"[REVIEW] {item['script']}:{item['line']} - {item['type']}: {item['text']}")
            else:
                lines.append("No high-interest script patterns identified by the automated review.")
        else:
            lines.append(control_result["stderr"].strip() or "Unable to extract control metadata.")
        lines.append("")

        lines += ["Extracted Package Payload", "-------------------------"]
        if not retain_payload:
            lines.append("Not retained for this full assessment. Use --retain-payload when manual payload inspection is required.")
        elif extract_result["returncode"] == 0:
            count = sum(1 for p in payload_dir.rglob("*") if p.is_file() or p.is_symlink())
            lines += [f"Location: {payload_dir}", f"Payload files/symlinks extracted: {count}"]
            info["extracted_root"] = str(payload_dir)
        else:
            lines.append(extract_result["stderr"].strip() or "Unable to extract package payload.")
        lines.append("")

    elif suffix.endswith(".appimage"):
        info["type"] = "appimage"
        lines += ["Package Type", "------------", "AppImage", ""]
        offset, extraction = _extract_embedded_squashfs(installer, output_dir / "working" / "appimage_payload")
        info.update({"squashfs_offset": offset, "extraction": extraction})
        if extraction.get("root"):
            info["extracted_root"] = extraction["root"]
        lines += [
            "Static Extraction", "-----------------",
            f"Embedded SquashFS offset: {offset if offset is not None else 'Not identified'}",
            f"Status: {extraction['status']}",
            f"Declared filesystem size: {human_size(extraction.get('filesystem_size'))}",
            f"Declared file count: {extraction.get('declared_files') if extraction.get('declared_files') is not None else 'Unknown'}",
            f"Extracted root: {extraction.get('root') or 'Not available'}",
            f"Extracted files/symlinks: {extraction.get('files', 0)}",
        ]
        if extraction.get("error"):
            lines.append(f"Detail: {extraction['error'][:1000]}")
        lines += [
            "Safety behavior: UbuntuClientAssess parses the embedded SquashFS with unsquashfs and never invokes the AppImage or its runtime extraction switch.",
            "",
        ]
    elif suffix.endswith(".snap"):
        info["type"] = "snap"
        lines += ["Package Type", "------------", "Snap package", ""]
        offset, extraction = _extract_embedded_squashfs(installer, output_dir / "working" / "snap_payload")
        info["extraction"] = extraction
        if extraction.get("root"):
            info["extracted_root"] = extraction["root"]
        lines += [
            "Static Extraction", "-----------------",
            f"Status: {extraction['status']}",
            f"Declared filesystem size: {human_size(extraction.get('filesystem_size'))}",
            f"Declared file count: {extraction.get('declared_files') if extraction.get('declared_files') is not None else 'Unknown'}",
            f"Extracted root: {extraction.get('root') or 'Not available'}",
            f"Extracted files/symlinks: {extraction.get('files', 0)}",
        ]
        snap_yaml = Path(extraction["root"]) / "meta" / "snap.yaml" if extraction.get("root") else None
        if snap_yaml and snap_yaml.is_file():
            lines += ["", "Snap Metadata", "-------------", redact_sensitive_text(snap_yaml.read_text(encoding="utf-8", errors="replace")[:20000])]
        if extraction.get("error"):
            lines.append(f"Detail: {extraction['error'][:1000]}")
        lines += ["", "Safety behavior: the Snap filesystem is parsed without executing package hooks or applications.", ""]
    elif suffix.endswith((".flatpakref", ".flatpakrepo", ".flatpak")):
        info["type"] = "flatpak"
        review = _flatpak_text_review(installer) if suffix.endswith((".flatpakref", ".flatpakrepo")) else {"entries": [], "concerns": []}
        info["flatpak_metadata"] = review
        lines += [
            "Package Type", "------------", "Flatpak bundle/reference", "",
            "Flatpak Metadata", "----------------",
        ]
        lines += review["entries"] or ["Binary Flatpak bundles require Flatpak/OSTree tooling for deeper repository-object inspection."]
        lines += ["", "Security-Relevant Metadata", "--------------------------"]
        lines += [f"[REVIEW] {item}" for item in review["concerns"]] or ["No cleartext repository or broad permission indicator identified in the reference metadata."]
        lines += [
            "",
            "Safety behavior: the framework does not import or install the bundle. During Full Assessment, Snap/Flatpak inventory and effective Flatpak permissions are compared separately.",
            "",
        ]
    elif suffix.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tbz", ".zip", ".7z")):
        info["type"] = "archive"
        lines += ["Package Type", "------------", "Archive", ""]
        archive_lines, archive_data = _archive_review(installer)
        lines += archive_lines
        info["archive"] = archive_data
        info["member_paths"] = archive_data.get("member_paths", [])
    elif suffix.endswith((".run", ".sh")):
        info["type"] = "script"
        lines += ["Package Type", "------------", "Installer script", ""]
        _append_cmd(lines, "Script Header", ["head", "-n", "120", str(installer)])
        indicators = _script_review(installer)
        info["maintainer_script_indicators"] = indicators
        lines += ["Script Security Indicators", "--------------------------"]
        if indicators:
            for item in indicators:
                lines.append(f"[REVIEW] line {item['line']} - {item['type']}: {item['text']}")
        else:
            lines.append("No high-interest script patterns identified by the automated review.")
        static = _script_static_analysis(installer)
        info["script_analysis"] = static
        lines += [
            "", "Script Structure", "----------------",
            f"Bash syntax check (no execution): {static['syntax']}",
            f"Embedded archive markers: {', '.join(static['embedded_archive']) if static['embedded_archive'] else 'None identified'}",
            f"URLs identified: {len(static['urls'])}",
            f"Installation/configuration paths identified: {len(static['install_paths'])}",
        ]
        if static.get("syntax_error"):
            lines.append(f"Syntax detail: {static['syntax_error'][:1000]}")
        if static["truncated"]:
            lines.append(f"Static text scanning was limited to the first {human_size(SCRIPT_SCAN_LIMIT)}.")
        lines += ["", "Referenced Endpoints"] + [f"- {url}" for url in static["urls"][:80]]
        if not static["urls"]:
            lines.append("None identified.")
        lines += ["", "Referenced Installation Paths"] + [f"- {path}" for path in static["install_paths"][:80]]
        if not static["install_paths"]:
            lines.append("None identified.")
        lines += [
            "",
            "Safety behavior: shell syntax and content are analyzed without executing the installer. Embedded self-extracting payloads are identified for isolated manual handling.",
            "",
        ]
    else:
        lines += [
            "Package Type", "------------", "Unrecognized package format", "",
            "The file was hashed and identified, but no format-specific parser was selected. Use an isolated environment for manual inspection.", "",
        ]

    write_text(report_path(output_dir, "installer_analysis.txt"), "\n".join(lines))
    return info
