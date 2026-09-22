from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import pwd
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

VERSION = "2.0.6"
METHODOLOGY_VERSION = "2.4"
TEST_CASE_CATALOG_VERSION = "1.1"


GENERATED_REPORTS = {
    "installer_analysis.txt",
    "application_profile.txt",
    "install_changes.txt",
    "permissions_review.txt",
    "binary_security_review.txt",
    "service_review.txt",
    "persistence_review.txt",
    "network_surface_review.txt",
    "ipc_review.txt",
    "local_storage_review.txt",
    "update_review.txt",
    "runtime_review.txt",
    "findings.txt",
    "findings_summary.txt",
    "module_status.txt",
    "tool_detection.txt",
    "assessment_coverage.txt",
    "tester_review.txt",
    "evidence_guide.txt",
    "assessment_report.html",
    "artifact_manifest.txt",
}

INSTALLER_ONLY_REPORTS = {
    "installer_analysis.txt",
    "application_profile.txt",
    "runtime_review.txt",
    "module_status.txt",
    "tool_detection.txt",
    "assessment_coverage.txt",
    "assessment_report.html",
    "artifact_manifest.txt",
}

FULL_ASSESSMENT_REPORTS = set(GENERATED_REPORTS)
EXPECTED_REPORTS_BY_MODE = {
    "full": FULL_ASSESSMENT_REPORTS,
    "installer-analysis-only": INSTALLER_ONLY_REPORTS,
}


def clean_generated_artifacts(assessment_dir: Path, *, full_run: bool = False) -> None:
    """Remove artifacts that can otherwise survive a rerun and look current.

    Tester-facing reports and pre/post snapshots are always cleared before a
    new attempt. Full runs require a fresh baseline; Installer Analysis Only
    must not inherit stale snapshots from a prior Full Assessment. Installer
    extraction directories are recreated for every package analysis.
    """
    reports = assessment_dir / "reports"
    root_manifest = assessment_dir / "assessment_manifest.json"
    try:
        if root_manifest.is_file() or root_manifest.is_symlink():
            root_manifest.unlink()
    except OSError:
        pass
    for name in (set(GENERATED_REPORTS) | {"test_cases.txt"}):
        for candidate in (reports / name, assessment_dir / name):
            try:
                if candidate.is_file() or candidate.is_symlink():
                    candidate.unlink()
            except OSError:
                pass

    work = working_dir(assessment_dir)
    interrupted_marker = work / "INTERRUPTED_RUN.txt"
    try:
        if interrupted_marker.is_file() or interrupted_marker.is_symlink():
            interrupted_marker.unlink()
    except OSError:
        pass
    transaction_dir = work / ".state_transaction"
    try:
        if transaction_dir.is_dir() and not transaction_dir.is_symlink():
            shutil.rmtree(transaction_dir)
        elif transaction_dir.exists() or transaction_dir.is_symlink():
            transaction_dir.unlink()
    except OSError:
        pass
    for dirname in ("deb_control", "deb_payload", "appimage_payload", "snap_payload", "archive_payload"):
        stale_dir = work / dirname
        try:
            if stale_dir.is_dir() and not stale_dir.is_symlink():
                shutil.rmtree(stale_dir)
            elif stale_dir.exists() or stale_dir.is_symlink():
                stale_dir.unlink()
        except OSError:
            pass

    # Clean legacy root-level snapshot files from pre-v0.3.1 layouts.
    for name in ("snapshot_pre.json", "snapshot_post.json"):
        legacy = assessment_dir / name
        try:
            if legacy.is_file() or legacy.is_symlink():
                legacy.unlink()
        except OSError:
            pass

    for name in ("snapshot_pre.json", "snapshot_post.json", "tester_review_state.json", "finding_candidates.json", "application_profile.json", "runtime_observation.json", "security_model.json"):
        candidate = work / name
        try:
            if candidate.is_file() or candidate.is_symlink():
                candidate.unlink()
        except OSError:
            pass

    # Atomic report/metadata writes use same-directory temporary files. A
    # killed process cannot expose a partial final file, and the next run can
    # safely remove any orphaned staging files left before os.replace().
    for directory in (assessment_dir, reports, work):
        try:
            for candidate in directory.glob(".*.tmp"):
                if candidate.is_file() or candidate.is_symlink():
                    candidate.unlink()
        except OSError:
            pass


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def reports_dir(assessment_dir: Path) -> Path:
    return ensure_dir(assessment_dir / "reports")


def working_dir(assessment_dir: Path) -> Path:
    return ensure_dir(assessment_dir / "working")


def report_path(assessment_dir: Path, filename: str) -> Path:
    return reports_dir(assessment_dir) / filename


def ensure_assessment_layout(assessment_dir: Path) -> None:
    ensure_dir(assessment_dir)
    reports_dir(assessment_dir)
    work = working_dir(assessment_dir)
    readme = work / "README.txt"
    if not readme.exists():
        write_text(
            readme,
            """UbuntuClientAssess Working Data
================================

This directory contains internal UbuntuClientAssess working data used for differential analysis and troubleshooting.

These files are not intended as primary tester-facing or client-facing assessment artifacts. Tester-facing reports are stored in the ../reports directory.

Contents may include:
- pre-installation and post-installation snapshots
- extracted installer/package control metadata
- extracted package payloads
- safely extracted AppImage, Snap, or archive payloads when supported
- tester review state used by the guided post-assessment review workflow
- machine-readable application technology profile used for runtime correlation
- structured security model containing canonical objects, observations, relationships, and correlation links
- guided runtime observation data when that optional workflow is performed
- other temporary analysis material required by framework modules
""",
        )


def run_cmd(cmd: list[str], timeout: int = 45, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=env,
        )
        return {"cmd": cmd, "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except FileNotFoundError as exc:
        return {"cmd": cmd, "returncode": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {"cmd": cmd, "returncode": 124, "stdout": stdout, "stderr": stderr or f"Command timed out after {timeout}s"}


def command_exists(name: str) -> str | None:
    return shutil.which(name)


def _atomic_write(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    existing_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, existing_mode)
        os.replace(temporary, path)
        # Persist the directory entry as well as the file contents. This keeps
        # state/report replacement durable across an abrupt process or host stop.
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def write_json(path: Path, data: Any) -> None:
    _atomic_write(path, json.dumps(data, indent=2, sort_keys=True, default=str) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_text(path: Path, text: str) -> None:
    _atomic_write(path, text.rstrip() + "\n")


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", text)


def human_size(value: int | float | None) -> str:
    if value is None:
        return "Unknown"
    size = float(value)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if abs(size) < 1024 or unit == units[-1]:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def sha256_file(path: Path, max_bytes: int | None = None) -> str | None:
    try:
        if max_bytes is not None and path.stat().st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def mode_string(mode: int) -> str:
    return stat.filemode(mode)


def get_interactive_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        result = run_cmd(["getent", "passwd", sudo_user])
        if result["returncode"] == 0 and result["stdout"].strip():
            fields = result["stdout"].strip().split(":")
            if len(fields) >= 6:
                return Path(fields[5])
    return Path.home()


def get_interactive_user() -> str:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user
    return os.environ.get("USER") or Path.home().name



def sanitize_url(raw: str) -> str:
    """Remove credentials and sensitive query values from a URL before persistence."""
    raw = raw.rstrip(".,);]}")
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host + (f":{parts.port}" if parts.port else "")
        sensitive = re.compile(
            r"(?i)(?:^|[_-])(?:token|access[_-]?token|refresh[_-]?token|auth|authorization|auth[_-]?code|"
            r"authorization[_-]?code|code|credential|secret|client[_-]?secret|password|passwd|api[_-]?key|apikey|key|signature|sig|sas[_-]?token|session|sessionid|session[_-]?id)(?:$|[_-])"
        )
        query = urlencode([
            (key, "[REDACTED]" if sensitive.search(key) else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ])
        query = query.replace("%5BREDACTED%5D", "[REDACTED]")
        return urlunsplit((parts.scheme, netloc, parts.path, query, ""))
    except (ValueError, UnicodeError):
        return raw


def redact_sensitive_text(text: str) -> str:
    """Best-effort redaction for command lines/config snippets before persistence."""
    key = r"(?:password|passwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer[_-]?token|authorization|auth[_-]?code|authorization[_-]?code|code|credential|token|signature|sig|sas[_-]?token|sessionid|session[_-]?id)"
    generic_key = r"(?:password|passwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer[_-]?token|auth[_-]?code|authorization[_-]?code|code|credential|token|signature|sig|sas[_-]?token|sessionid|session[_-]?id)"

    # Protect URLs from the generic assignment regexes; sanitize them independently.
    url_re = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>]+", re.I)
    sanitized_urls: list[str] = []
    def _url_placeholder(match: re.Match[str]) -> str:
        sanitized_urls.append(sanitize_url(match.group(0)))
        return f"__UCA_URL_{len(sanitized_urls) - 1}__"
    text = url_re.sub(_url_placeholder, text)

    # Authorization headers must be handled before generic key:value patterns.
    text = re.sub(
        r"(?i)(\bauthorization\b\s*:\s*(?:bearer|basic)\s+)([^\s,;]+)",
        r"\1[REDACTED]",
        text,
    )
    # JSON/YAML-style quoted keys and values, e.g. "token": "abc".
    quoted = re.compile(
        rf"(?i)([\"'])(?P<key>{key})\1\s*:\s*([\"'])(?P<value>.*?)\3"
    )
    text = quoted.sub(
        lambda m: f'{m.group(1)}{m.group("key")}{m.group(1)}: {m.group(3)}[REDACTED]{m.group(3)}',
        text,
    )
    # Unquoted/common assignment forms. Authorization is handled separately so
    # an Authorization: Bearer header cannot be partially redacted.
    text = re.sub(r"(?i)(\bauthorization\b\s*[:=]\s*)(?!bearer\b|basic\b)([^\s,;]+)", r"\1[REDACTED]", text)
    assign = re.compile(rf"(?i)(\b{generic_key}\b\s*[:=]\s*)([\"']?)([^\s,;}}\]]+?)(?:\2)(?=$|\s|[,;}}\]])")
    text = assign.sub(lambda m: m.group(1) + (m.group(2) or "") + "[REDACTED]" + (m.group(2) or ""), text)
    text = re.sub(rf"(?i)((?:--|-){key}\s+)([^\s]+)", r"\1[REDACTED]", text)
    text = re.sub(rf"(?i)(\b{generic_key}\b\s+)(Bearer\s+)?([^\s]+)", lambda m: m.group(1) + (m.group(2) or "") + "[REDACTED]", text)
    text = re.sub(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=-]{6,})", r"\1[REDACTED]", text)

    for index, url in enumerate(sanitized_urls):
        text = text.replace(f"__UCA_URL_{index}__", url)
    return text

def _acl_allows_write(path: Path, user: str, uid: int, groups: set[int]) -> bool | None:
    """Return ACL write result when an extended ACL can be read, else None."""
    if not command_exists("getfacl"):
        return None
    try:
        if "system.posix_acl_access" not in os.listxattr(path, follow_symlinks=True):
            return None
    except (OSError, TypeError, AttributeError):
        # Filesystems without xattr introspection fall back to getfacl.
        pass
    result = run_cmd(["getfacl", "-cpn", str(path)], timeout=10)
    if result["returncode"] != 0:
        return None
    owner_perms = other_perms = mask_perms = None
    named_user = None
    group_perms: list[str] = []
    saw_acl = False
    for raw in result["stdout"].splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("default:"):
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        kind, ident, perms = parts
        if kind == "user" and ident == "":
            owner_perms = perms
        elif kind == "user" and ident.isdigit():
            saw_acl = True
            if int(ident) == uid:
                named_user = perms
        elif kind == "group" and ident == "":
            try:
                if path.stat().st_gid in groups:
                    group_perms.append(perms)
            except OSError:
                pass
        elif kind == "group" and ident.isdigit():
            saw_acl = True
            if int(ident) in groups:
                group_perms.append(perms)
        elif kind == "mask" and ident == "":
            saw_acl = True
            mask_perms = perms
        elif kind == "other" and ident == "":
            other_perms = perms
    if not saw_acl:
        return None
    try:
        st = path.stat()
    except OSError:
        return False
    if st.st_uid == uid:
        return bool(owner_perms and "w" in owner_perms)
    mask_write = mask_perms is None or "w" in mask_perms
    if named_user is not None:
        return "w" in named_user and mask_write
    if group_perms:
        return any("w" in perms for perms in group_perms) and mask_write
    return bool(other_perms and "w" in other_perms)


def user_can_write(path: Path, user: str | None = None) -> bool:
    """Evaluate effective write permission for the interactive tester, including POSIX ACLs."""
    user = user or get_interactive_user()
    try:
        pw = pwd.getpwnam(user)
        st = path.stat()
    except (KeyError, OSError):
        return False
    try:
        groups = set(os.getgrouplist(user, pw.pw_gid))
    except OSError:
        groups = {pw.pw_gid}
    acl_result = _acl_allows_write(path, user, pw.pw_uid, groups)
    if acl_result is not None:
        return acl_result
    mode = st.st_mode
    if st.st_uid == pw.pw_uid:
        return bool(mode & stat.S_IWUSR)
    if st.st_gid in groups:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)

def normalize_user_path(path: str, home: Path | None = None) -> str:
    home = home or get_interactive_home()
    try:
        s = str(Path(path))
        h = str(home)
        if s == h:
            return "~"
        if s.startswith(h + os.sep):
            return "~" + s[len(h):]
        return s
    except Exception:
        return str(path)


def stable_lines(text: str) -> list[str]:
    return sorted({line.strip() for line in text.splitlines() if line.strip()})


def section(title: str, body: Iterable[str] | str = "") -> str:
    underline = "=" * len(title)
    if isinstance(body, str):
        payload = body.rstrip()
    else:
        payload = "\n".join(body).rstrip()
    return f"{title}\n{underline}\n\n{payload}\n" if payload else f"{title}\n{underline}\n"
