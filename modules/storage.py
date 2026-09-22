from __future__ import annotations

import os
import re
import stat
from collections import defaultdict
from pathlib import Path
from typing import Any

from .app_scope import path_within_scope
from .common import command_exists, get_interactive_home, human_size, report_path, run_cmd, write_text

MAX_SCAN_SIZE = 5 * 1024 * 1024
TEXT_EXTENSIONS = {
    ".conf", ".config", ".ini", ".json", ".yaml", ".yml", ".xml", ".toml",
    ".properties", ".env", ".txt", ".log", ".pem", ".key", ".p12", ".pfx",
}
SENSITIVE_NAMES = {
    ".env", "credentials", "credentials.json", "secrets", "secrets.json", "token", "tokens",
    "cookies", "login data", "keychain", "keystore", "auth.db", "credentials.db",
}
STORAGE_DIR_NAMES = {"local storage", "session storage", "indexeddb", "leveldb", "databases", "storage", "data", "config", "settings"}
CHROMIUM_FILE_NAMES = {"cookies", "login data", "web data", "history", "preferences", "secure preferences", "transportsecurity", "network persistent state"}
EXCLUDED_DIR_NAMES = {
    "node_modules", "site-packages", "dist-packages", "__pycache__", ".git", ".svn",
    "dist-info", "egg-info", "sboms", "docs", "documentation", "botocore", "boto3", "locales", "translations",
}
EXCLUDED_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
EXCLUDED_SUFFIXES = {
    ".pyc", ".pyo", ".class", ".o", ".a", ".h", ".hpp", ".c", ".cpp", ".map", ".min.js",
}

ASSIGNMENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("password", re.compile(r"(?i)(?:[\"']?pass(?:word|wd)?[\"']?\s*[:=]\s*)(?![\s,}\]]*$)")),
    ("client secret", re.compile(r"(?i)(?:[\"']?client[_-]?secret[\"']?\s*[:=]\s*)(?![\s,}\]]*$)")),
    ("token", re.compile(r"(?i)(?:[\"']?(?:access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer[_-]?token|token)[\"']?\s*[:=]\s*)(?![\s,}\]]*$)")),
    ("api key", re.compile(r"(?i)(?:[\"']?(?:api[_-]?key|apikey)[\"']?\s*[:=]\s*)(?![\s,}\]]*$)")),
    ("authorization", re.compile(r"(?i)(?:[\"']?authorization[\"']?\s*[:=]\s*)(?![\s,}\]]*$)")),
    ("connection string", re.compile(r"(?i)(?:[\"']?connection[_-]?string[\"']?\s*[:=]\s*|jdbc:|postgres(?:ql)?://|mysql://|mongodb(?:\+srv)?://)")),
    ("private key", re.compile(r"(?i)(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|[\"']?(?:ca[_-]?private[_-]?key|private[_-]?key|privatekey|signing[_-]?key|certificate[_-]?key|key[_-]?material)[\"']?\s*[:=]\s*)(?![\s,}\]]*$)")),
]

CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key", re.compile(r"(?i)(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|[\"']?(?:ca[_-]?private[_-]?key|private[_-]?key|privatekey|signing[_-]?key|certificate[_-]?key|key[_-]?material)[\"']?\s*[:=]\s*)(?![\s,}\]]*$)")),
    ("cryptographic salt", re.compile(r"(?i)[\"']?(?:crypto[_-]?salt|encryption[_-]?salt|password[_-]?salt|key[_-]?salt|kdf[_-]?salt|salt)[\"']?\s*[:=]\s*(?![\s,}\]]*$)")),
]

CERTIFICATE_SUFFIXES = {".crt", ".cer", ".pem"}


INSECURE_CONFIG_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("TLS/certificate verification disabled", re.compile(r"(?i)\b(?:rejectUnauthorized|verify[_-]?(?:ssl|tls|certificate)|ssl[_-]?verify|tls[_-]?verify)\b\s*[:=]\s*(?:false|0|no|off)\b")),
    ("Insecure transport explicitly allowed", re.compile(r"(?i)\b(?:allow[_-]?insecure|insecure[_-]?(?:tls|transport|channel))\b\s*[:=]\s*(?:true|1|yes|on)\b")),
    ("Debug/development mode enabled", re.compile(r"(?i)\b(?:debug|development[_-]?mode|devtools)\b\s*[:=]\s*(?:true|1|yes|on)\b")),
]


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def _excluded(path: Path) -> bool:
    lower_parts = [x.lower() for x in path.parts]
    if any(part in EXCLUDED_DIR_NAMES or part.endswith(".dist-info") or part.endswith(".egg-info") for part in lower_parts):
        return True
    lower_name = path.name.lower()
    if lower_name in EXCLUDED_NAMES or lower_name.endswith(".min.js"):
        return True
    return path.suffix.lower() in EXCLUDED_SUFFIXES


def _bundled_runtime_path(path: Path) -> bool:
    """Identify known third-party/runtime trees without excluding generic app lib/ paths."""
    lower_parts = [x.lower() for x in path.parts]
    runtime_parts = {"_internal", "lib-dynload", "jsmodules"}
    dependency_parts = {"dukpy", "cffi", "setuptools", "tldextract", "keyring", "cryptography", "botocore", "boto3"}
    if any(part in runtime_parts or part.endswith(".dist-info") or part.endswith(".egg-info") for part in lower_parts):
        return True
    if "lib" in lower_parts and any(part in dependency_parts for part in lower_parts):
        return True
    return False

def _other_can_traverse(path: Path) -> bool:
    current = path
    seen: set[str] = set()
    while str(current) not in seen:
        seen.add(str(current))
        try:
            if not current.stat().st_mode & stat.S_IXOTH:
                return False
        except OSError:
            return False
        if current == current.parent:
            return True
        current = current.parent
    return False


def _text_candidate(path: Path) -> bool:
    if _excluded(path):
        return False
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in SENSITIVE_NAMES:
        return True
    lower_parts = {x.lower() for x in path.parts}
    if lower_parts.intersection(STORAGE_DIR_NAMES) and path.suffix.lower() not in EXCLUDED_SUFFIXES:
        try:
            with path.open("rb") as f:
                sample = f.read(4096)
            return b"\x00" not in sample
        except OSError:
            return False
    return False


def _permission_note(path: Path) -> str | None:
    try:
        st = path.stat()
    except OSError:
        return None
    externally_reachable = _other_can_traverse(path.parent)
    if externally_reachable and st.st_mode & stat.S_IWOTH:
        return "world-writable"
    if externally_reachable and st.st_mode & stat.S_IROTH:
        return "world-readable"
    return None


def _chromium_storage_kind(path: Path) -> str | None:
    name = path.name.lower()
    parts = [part.lower() for part in path.parts]
    if name in CHROMIUM_FILE_NAMES:
        return f"Chromium profile database/configuration ({path.name})"
    if "local storage" in parts:
        return "Chromium Local Storage"
    if "session storage" in parts:
        return "Chromium Session Storage"
    if "indexeddb" in parts:
        return "Chromium IndexedDB"
    if "leveldb" in parts or name.startswith("manifest-") or suffix_is_leveldb(path):
        return "LevelDB storage"
    if name in {"quota manager", "sharedstorage", "sharedstorage-wal"}:
        return "Chromium origin/storage metadata"
    return None


def suffix_is_leveldb(path: Path) -> bool:
    return path.suffix.lower() in {".ldb", ".sst"} or path.name.lower() in {"current", "lock", "log", "log.old"}


def _temporary_or_log_kind(path: Path) -> str | None:
    parts = [part.lower() for part in path.parts]
    name = path.name.lower()
    if "/tmp/" in str(path) or any(part in {"tmp", "temp", "temporary"} for part in parts):
        return "temporary file"
    if path.suffix.lower() == ".log" or any(part in {"log", "logs"} for part in parts):
        return "log file"
    if path.suffix.lower() in {".tmp", ".temp"}:
        return "temporary file"
    if any(part in {"cache", "cachedata", "gpucache", "code cache"} for part in parts):
        return "cache artifact"
    if name.endswith((".log.1", ".log.old")):
        return "rotated log file"
    return None


def _runtime_storage_location(path: Path) -> bool:
    """Prefer mutable user/system data over bundled installation resources."""
    try:
        path.resolve().relative_to(get_interactive_home().resolve())
        return True
    except (OSError, ValueError):
        pass
    text = str(path)
    return text.startswith(("/var/lib/", "/var/opt/", "/var/cache/", "/var/log/"))


def _schema_or_placeholder_assignment(line: str) -> bool:
    """Suppress field definitions that name secrets but do not contain values."""
    _, separator, value = line.partition(":" if ":" in line else "=")
    if not separator:
        return False
    value = value.strip().rstrip(",")
    return value in {"", "{}", "[]", "null", "None"} or value.startswith(("{", "["))


def _certificate_record(path: Path) -> dict[str, Any] | None:
    if path.suffix.casefold() not in CERTIFICATE_SUFFIXES:
        return None
    try:
        if path.stat().st_size > MAX_SCAN_SIZE:
            return None
        sample = path.read_text(encoding="utf-8", errors="replace")[:65536]
    except OSError:
        return None
    if "BEGIN CERTIFICATE" not in sample:
        return None
    record: dict[str, Any] = {
        "path": str(path), "is_ca": False, "self_signed": False,
        "subject": "", "issuer": "", "permission": _permission_note(path) or "",
    }
    if not command_exists("openssl"):
        return record
    result = run_cmd(["openssl", "x509", "-in", str(path), "-noout", "-subject", "-issuer", "-text"], timeout=15)
    if result["returncode"] != 0:
        return record
    text = result["stdout"]
    record["is_ca"] = bool(re.search(r"CA\s*:\s*TRUE", text, re.I))
    subject = re.search(r"^subject\s*=\s*(.+)$", text, re.M | re.I)
    issuer = re.search(r"^issuer\s*=\s*(.+)$", text, re.M | re.I)
    record["subject"] = subject.group(1).strip() if subject else ""
    record["issuer"] = issuer.group(1).strip() if issuer else ""
    record["self_signed"] = bool(record["subject"] and record["subject"] == record["issuer"] )
    return record


def _related_ca_certificates(crypto_path: Path, ca_records: list[dict[str, Any]]) -> list[str]:
    related: list[str] = []
    for record in ca_records:
        cert = Path(str(record.get("path") or ""))
        if not cert:
            continue
        try:
            common = Path(os.path.commonpath([str(crypto_path), str(cert)]))
            if len(common.parts) >= 3:
                related.append(str(cert))
        except (ValueError, OSError):
            continue
    if not related and len(ca_records) == 1:
        # A single locally generated CA in the scoped application tree is useful
        # correlation context even when config/key and certificate roots differ.
        related.append(str(ca_records[0].get("path") or ""))
    return sorted(set(x for x in related if x))




def _cryptographic_path_candidate(path: Path) -> bool:
    """Retain installation-changed key/certificate material even outside app roots.

    System trust stores and key directories are intentionally shared OS paths, so
    application-root scoping alone would hide a CA certificate installed there.
    Only explicitly changed cryptographic-looking paths receive this exception;
    ambient unchanged trust-store content is not recursively scanned.
    """
    suffix = path.suffix.casefold()
    if suffix in {".crt", ".cer", ".pem", ".key", ".p12", ".pfx"}:
        return True
    text = str(path).casefold()
    return text.startswith((
        "/etc/ssl/", "/etc/pki/", "/etc/ca-certificates/",
        "/usr/local/share/ca-certificates/", "/usr/share/ca-certificates/",
    ))

def review_storage(diff: dict[str, Any], output_dir: Path, extra_roots: list[Path] | None = None) -> dict[str, Any]:
    changed = set(diff.get("files_added", [])) | set(diff.get("files_changed", []))
    scope_roots = [Path(root) for root in (extra_roots or [])]
    candidates: set[Path] = {
        Path(p) for p in changed
        if Path(p).is_file() and (
            not scope_roots
            or path_within_scope(Path(p), scope_roots)
            or _cryptographic_path_candidate(Path(p))
        )
    }
    for root in scope_roots:
        if not root.exists():
            continue
        if root.is_file():
            candidates.add(root)
            continue
        try:
            for p in root.rglob("*"):
                if p.is_file():
                    candidates.add(p)
        except (OSError, PermissionError):
            pass

    secret_by_file: dict[str, dict[str, Any]] = {}
    sqlite_records: list[dict[str, Any]] = []
    storage_candidates: list[dict[str, str]] = []
    chromium_records: list[dict[str, Any]] = []
    temp_log_records: list[dict[str, Any]] = []
    config_risks: list[dict[str, Any]] = []
    crypto_by_file: dict[str, dict[str, Any]] = {}
    certificate_records: list[dict[str, Any]] = []
    skipped_large = 0
    excluded_bundled = 0
    scanned_text = 0

    for path in sorted(candidates, key=str):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        lower_parts = {x.lower() for x in path.parts}
        permission = _permission_note(path)
        cert_record = _certificate_record(path)
        if cert_record:
            certificate_records.append(cert_record)
        chromium_kind = _chromium_storage_kind(path)
        if chromium_kind:
            chromium_records.append({"path": str(path), "kind": chromium_kind, "size": size, "permission": permission or ""})
        temp_kind = _temporary_or_log_kind(path)
        if temp_kind and not _excluded(path) and not _bundled_runtime_path(path):
            temp_log_records.append({"path": str(path), "kind": temp_kind, "size": size, "permission": permission or ""})

        if _is_sqlite(path):
            tables: list[str] = []
            quick_check = "not checked"
            if command_exists("sqlite3"):
                result = run_cmd(["sqlite3", "-readonly", str(path), ".tables"], timeout=10)
                if result["returncode"] == 0:
                    tables = result["stdout"].split()
                integrity = run_cmd(["sqlite3", "-readonly", str(path), "PRAGMA quick_check;"], timeout=15)
                if integrity["returncode"] == 0:
                    quick_check = integrity["stdout"].strip()[:500] or "no result"
                else:
                    quick_check = "unable to check (locked, encrypted, or unreadable)"
            sidecars = [str(Path(str(path) + suffix)) for suffix in ("-wal", "-shm", "-journal") if Path(str(path) + suffix).exists()]
            sqlite_records.append({
                "path": str(path), "size": size, "tables": tables, "permission": permission or "",
                "quick_check": quick_check, "sidecars": sidecars,
            })
            continue

        if _excluded(path) or _bundled_runtime_path(path):
            excluded_bundled += 1
            continue

        if path.name.lower() in SENSITIVE_NAMES or (
            lower_parts.intersection(STORAGE_DIR_NAMES) and _runtime_storage_location(path)
        ):
            storage_candidates.append({
                "path": str(path),
                "reason": "Sensitive/storage-oriented filename or directory",
                "permission": permission or "",
            })

        if size > MAX_SCAN_SIZE:
            skipped_large += 1
            continue
        if not _text_candidate(path):
            continue

        scanned_text += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        indicators: set[str] = set()
        crypto_indicators: set[str] = set()
        crypto_first_lines: dict[str, int] = {}
        occurrence_count = 0
        first_lines: dict[str, int] = {}
        for line_no, line in enumerate(text.splitlines(), 1):
            if _schema_or_placeholder_assignment(line):
                continue
            for label, pattern in ASSIGNMENT_PATTERNS:
                if pattern.search(line):
                    indicators.add(label)
                    occurrence_count += 1
                    first_lines.setdefault(label, line_no)
            for label, pattern in CRYPTO_PATTERNS:
                if pattern.search(line):
                    crypto_indicators.add(label)
                    crypto_first_lines.setdefault(label, line_no)
            for label, pattern in INSECURE_CONFIG_PATTERNS:
                if pattern.search(line):
                    config_risks.append({"path": str(path), "line": line_no, "indicator": label})
        if indicators:
            secret_by_file[str(path)] = {
                "path": str(path),
                "indicators": sorted(indicators),
                "occurrences": occurrence_count,
                "first_lines": first_lines,
                "permission": permission or "",
            }
        if crypto_indicators:
            crypto_by_file[str(path)] = {
                "path": str(path),
                "indicators": sorted(crypto_indicators),
                "first_lines": crypto_first_lines,
                "permission": permission or "",
                "private_key": "private key" in crypto_indicators,
                "salt": "cryptographic salt" in crypto_indicators,
                "values_redacted": True,
            }

    secret_hits = list(secret_by_file.values())
    ca_records = [item for item in certificate_records if item.get("is_ca")]
    crypto_material = list(crypto_by_file.values())
    for item in crypto_material:
        item["related_ca_certificates"] = _related_ca_certificates(Path(item["path"]), ca_records) if item.get("private_key") else []
        item["ca_private_key_context"] = bool(item.get("private_key") and item.get("related_ca_certificates"))
    high_table_words = re.compile(r"(?i)(token|secret|credential|password|session|auth|cookie|key)")

    lines = [
        "Local Storage Review", "=" * 20, "",
        "This report prioritizes application configuration/data stores and potential secret assignments without copying secret values into assessment output.",
        "Bundled runtime/library content and repetitive source-code keyword matches are intentionally suppressed.",
        "",
        "Summary", "-------",
        f"Application files considered:          {len(candidates)}",
        f"Text/configuration files scanned:      {scanned_text}",
        f"Bundled/runtime files excluded:        {excluded_bundled}",
        f"Files skipped over {human_size(MAX_SCAN_SIZE)}:       {skipped_large}",
        f"Credential-storage candidates:         {len(secret_hits)}",
        f"SQLite databases:                      {len(sqlite_records)}",
        f"Chromium/Electron storage artifacts:   {len(chromium_records)}",
        f"Storage-oriented artifacts:            {len(storage_candidates)}",
        f"Temporary/log/cache artifacts:         {len(temp_log_records)}",
        f"Sensitive configuration candidates:    {len(config_risks)}",
        f"Cryptographic-material candidates:      {len(crypto_material)}",
        f"Certificate files identified:           {len(certificate_records)}",
        f"CA certificates identified:             {len(ca_records)}",
        "",
        "Potential Sensitive Storage", "---------------------------",
    ]

    if secret_hits:
        for hit in secret_hits:
            lines += [
                "[REVIEW]",
                f"Path:        {hit['path']}",
                f"Indicators:  {', '.join(hit['indicators'])}",
                f"Occurrences: {hit['occurrences']}",
                "Values:      [REDACTED]",
            ]
            if hit["permission"]:
                lines.append(f"Permissions: {hit['permission']}")
            lines.append("")
    else:
        lines += ["No credential-style assignments were identified in the prioritized text/configuration files.", ""]

    lines += ["Cryptographic Material Context", "------------------------------"]
    if crypto_material or certificate_records:
        if certificate_records:
            for cert in certificate_records[:80]:
                role = "CA certificate" if cert.get("is_ca") else "certificate"
                self_signed = "; self-signed/local" if cert.get("self_signed") else ""
                perm = f"; permissions: {cert['permission']}" if cert.get("permission") else ""
                lines.append(f"[CERT] {cert['path']} - {role}{self_signed}{perm}")
        for item in crypto_material[:80]:
            perm = f"; permissions: {item['permission']}" if item.get("permission") else ""
            related = ", ".join(item.get("related_ca_certificates", [])) or "None automatically correlated"
            lines += [
                f"[CRYPTO REVIEW] {item['path']} - indicators: {', '.join(item['indicators'])}; values: [REDACTED]{perm}",
                f"  Related CA certificate(s): {related}",
            ]
        lines.append("Note: salts are normally non-secret KDF inputs and are not vulnerabilities by themselves. Validate whether recoverable private-key/key-protection material and a meaningful trust boundary are present.")
    else:
        lines.append("No private-key/salt/certificate material was identified in prioritized application files.")
    lines.append("")

    lines += ["SQLite Storage", "--------------"]
    if sqlite_records:
        for item in sqlite_records:
            interesting_tables = [t for t in item["tables"] if high_table_words.search(t)]
            tables = ", ".join(item["tables"][:50]) if item["tables"] else "Not enumerated / no tables returned"
            lines += [
                f"Database: {item['path']}",
                f"Size:     {human_size(item['size'])}",
                f"Tables:   {tables}",
                f"High-interest table names: {', '.join(interesting_tables) if interesting_tables else 'None automatically identified'}",
                f"SQLite quick_check: {item['quick_check']}",
                f"WAL/SHM/journal sidecars: {', '.join(item['sidecars']) if item['sidecars'] else 'None present at review time'}",
                "",
            ]
    else:
        lines += ["No SQLite databases identified among prioritized application files.", ""]

    lines += ["Chromium / Electron Storage", "-----------------------------"]
    if chromium_records:
        for item in chromium_records[:160]:
            perm = f"; permissions: {item['permission']}" if item["permission"] else ""
            lines.append(f"{item['path']} - {item['kind']}; size: {human_size(item['size'])}{perm}")
        if len(chromium_records) > 160:
            lines.append(f"... {len(chromium_records) - 160} additional Chromium/Electron storage artifacts suppressed.")
    else:
        lines.append("No Chromium/Electron profile-storage artifacts identified.")

    lines += ["", "Sensitive Configuration Indicators", "----------------------------------"]
    if config_risks:
        for item in config_risks[:120]:
            lines.append(f"[REVIEW] {item['path']}:{item['line']} - {item['indicator']}")
    else:
        lines.append("No explicit disabled-verification, insecure-transport, or debug-mode settings identified.")

    lines += ["", "Temporary Files, Logs, and Caches", "---------------------------------"]
    if temp_log_records:
        for item in temp_log_records[:160]:
            marker = "[REVIEW] " if item["permission"] else ""
            perm = f"; permissions: {item['permission']}" if item["permission"] else ""
            lines.append(f"{marker}{item['path']} - {item['kind']}; size: {human_size(item['size'])}{perm}")
        if len(temp_log_records) > 160:
            lines.append(f"... {len(temp_log_records) - 160} additional temporary/log/cache artifacts suppressed.")
    else:
        lines.append("No changed temporary, log, or cache artifacts identified in snapshot coverage.")

    lines += ["", "Storage-Oriented Artifacts", "--------------------------"]
    if storage_candidates:
        for item in storage_candidates[:120]:
            perm = f"; permissions: {item['permission']}" if item["permission"] else ""
            lines.append(f"{item['path']} - {item['reason']}{perm}")
        if len(storage_candidates) > 120:
            lines.append(f"... {len(storage_candidates) - 120} additional storage-oriented artifacts suppressed.")
    else:
        lines.append("No additional storage-oriented filename/directory indicators identified.")

    lines += [
        "", "Tester Guidance", "---------------",
        "Validate whether highlighted files actually contain authentication material, session data, private signing/key material, personal data, or other sensitive values. Review SQLite WAL/journal sidecars and LevelDB/IndexedDB records because deleted or transient values may persist there. A salt or certificate by itself is not treated as a secret vulnerability; assess private-key recoverability, trust scope, data sensitivity, and which users can access the material.",
    ]
    write_text(report_path(output_dir, "local_storage_review.txt"), "\n".join(lines))
    return {
        "secret_hits": secret_hits,
        "sqlite_databases": sqlite_records,
        "storage_candidates": storage_candidates,
        "chromium_storage": chromium_records,
        "temporary_log_artifacts": temp_log_records,
        "configuration_risks": config_risks,
        "crypto_material": crypto_material,
        "certificate_records": certificate_records,
        "ca_certificates": ca_records,
    }
