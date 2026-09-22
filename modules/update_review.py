from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .common import command_exists, report_path, run_cmd, sanitize_url, write_text

MAX_TEXT_SIZE = 3 * 1024 * 1024
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
STRONG_UPDATER_NAME_RE = re.compile(r"(?i)(?:^|[-_.])(updater|update[-_]?client|update[-_]?agent|software[-_]?update|auto[-_]?update|self[-_]?update|upgrade|patch|disable[-_]?updates?)(?:[-_.]|$)")
UPDATE_KEY_RE = re.compile(r"(?i)\b(update[_-]?(?:url|server|endpoint|manifest|package)|download[_-]?url|manifest[_-]?url|release[_-]?url|package[_-]?url|repository[_-]?url)\b")
VERIFY_RE = re.compile(r"(?i)\b(gpg|pgp|signature|signed|verify|verification|sha256|sha512|checksum|digest|public[_-]?key)\b")
EXCLUDED_DIRS = {"node_modules", "site-packages", "dist-packages", "__pycache__", "sboms", "docs", "documentation", "botocore", "boto3"}
EXCLUDED_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".class", ".map", ".h", ".hpp", ".c", ".cpp", ".svg", ".svgz", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp"}
CHECKSUM_NAME_RE = re.compile(r"(?i)(?:^|[-_.])(?:sha(?:256|512)?sums?|checksums?|md5sums?)(?:[-_.]|$)|\.(?:sha256|sha512|md5)$")
REPOSITORY_RISK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("cleartext repository URL", re.compile(r"(?i)\b(?:deb\s+(?:\[[^]]*\]\s*)?|url\s*=\s*)http://")),
    ("repository signature verification disabled", re.compile(r"(?i)\b(?:trusted\s*=\s*yes|allow[_-]?insecure\s*=\s*(?:yes|true|1)|gpgcheck\s*=\s*0|repo_gpgcheck\s*=\s*0|gpgverify\s*=\s*false)\b")),
    ("repository TLS verification disabled", re.compile(r"(?i)\b(?:sslverify|tlsverify|verify[_-]?(?:ssl|tls))\s*=\s*(?:false|no|0)\b")),
]


def _excluded(path: Path) -> bool:
    parts = [x.lower() for x in path.parts]
    if any(x in EXCLUDED_DIRS or x.endswith('.dist-info') or x.endswith('.egg-info') for x in parts):
        return True
    if path.name.lower() in EXCLUDED_NAMES or path.name.lower().endswith('.min.js'):
        return True
    return path.suffix.lower() in EXCLUDED_SUFFIXES


def _read_small_text(path: Path) -> str:
    try:
        if _excluded(path) or not path.is_file() or path.stat().st_size > MAX_TEXT_SIZE:
            return ""
        data = path.read_bytes()
        if b"\x00" in data[:4096]:
            return ""
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _strong_updater_candidate(path: Path) -> bool:
    if _excluded(path):
        return False
    name = path.name.lower()
    if STRONG_UPDATER_NAME_RE.search(name):
        return True
    if any(x in str(path).lower() for x in ('/updater/', '/update-agent/', '/software-update/', '/auto-update/')):
        return True
    return False


def _digest(path: Path, algorithm: str) -> str | None:
    try:
        digest = hashlib.new(algorithm)
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def _inside(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except (OSError, ValueError):
        return False


def _validate_checksum_manifest(manifest: Path, base: Path | None = None) -> dict[str, Any]:
    base = base or manifest.parent
    record: dict[str, Any] = {"manifest": str(manifest), "checked": 0, "matched": 0, "mismatched": [], "missing": [], "unsafe": []}
    try:
        lines = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        record["error"] = "unable to read manifest"
        return record
    digest_re = re.compile(r"^([0-9a-fA-F]{32}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})\s+[* ]?(.+?)\s*$")
    for raw in lines:
        match = digest_re.match(raw)
        if not match:
            continue
        expected, name = match.groups()
        relative_name = name[2:] if name.startswith("./") else name
        target = base / relative_name
        if not _inside(base, target):
            record["unsafe"].append(name)
            continue
        if not target.is_file():
            record["missing"].append(name)
            continue
        algorithm = {32: "md5", 64: "sha256", 128: "sha512"}[len(expected)]
        actual = _digest(target, algorithm)
        record["checked"] += 1
        if actual and actual.lower() == expected.lower():
            record["matched"] += 1
        else:
            record["mismatched"].append(name)
    record["status"] = "PASS" if record["checked"] and not record["mismatched"] and not record["missing"] and not record["unsafe"] else "FAIL" if record["mismatched"] or record["unsafe"] else "INCOMPLETE"
    return record


def _validate_deb_md5(control_dir: Path, payload_dir: Path | None = None) -> dict[str, Any] | None:
    manifest = control_dir / "md5sums"
    if not manifest.is_file():
        return None
    base = payload_dir if payload_dir and payload_dir.is_dir() else Path("/")
    record = _validate_checksum_manifest(manifest, base)
    record["validation_base"] = str(base)
    return record


def _debsig_status(returncode: int) -> tuple[str, str]:
    """Map debsig-verify exit codes without conflating trust-policy gaps with bad signatures."""
    return {
        0: ("VALID", "Package signature verified successfully using the locally configured debsig policy/keyring."),
        10: ("NO SIGNATURE", "No embedded Debian package signature/origin signature was found."),
        11: ("NO POLICY", "An origin signature was found, but no corresponding local debsig policy directory is installed."),
        12: ("NO MATCHING POLICY", "The origin was recognized, but no installed debsig policy passed selection; verification was not performed."),
        13: ("VERIFICATION FAILED", "The package failed debsig verification; the signature or policy verification criteria did not validate."),
        14: ("ERROR", "debsig-verify encountered an internal/backend error or the package could not be processed."),
    }.get(returncode, ("ERROR", f"debsig-verify returned unexpected exit code {returncode}."))


def _signature_checks(paths: list[Path], installer_data: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    installer = Path(str(installer_data.get("path") or ""))
    if installer_data.get("type") == "deb" and installer.is_file():
        signature_inventory = ""
        if command_exists("debsigs"):
            listed = run_cmd(["debsigs", "--list", str(installer)], timeout=30)
            listing = (listed["stdout"] or listed["stderr"]).strip()
            if listing:
                signature_inventory = f" Embedded signature inventory (debsigs --list): {listing[:600]}"

        if command_exists("debsig-verify"):
            result = run_cmd(["debsig-verify", str(installer)], timeout=30)
            status, explanation = _debsig_status(int(result["returncode"]))
            output = (result["stdout"] or result["stderr"]).strip()
            detail = explanation
            if output:
                detail += f" Diagnostic: {output[:700]}"
            detail += signature_inventory
            records.append({
                "signature": str(installer),
                "target": str(installer),
                "tool": "debsig-verify",
                "status": status,
                "returncode": int(result["returncode"]),
                "detail": detail[:1400],
            })
        else:
            detail = (
                "debsig-verify is not installed; embedded Debian package signatures were not independently verified. "
                "APT repository authentication may establish a separate archive-level trust chain, but it is not package-level signature verification."
            ) + signature_inventory
            records.append({
                "signature": str(installer),
                "target": str(installer),
                "tool": "debsig-verify",
                "status": "NOT CHECKED",
                "detail": detail[:1400],
            })

    if not command_exists("gpgv"):
        return records
    for signature in paths:
        if signature.suffix.lower() not in {".sig", ".asc"}:
            continue
        target = signature.with_suffix("")
        if not target.is_file():
            continue
        result = run_cmd(["gpgv", str(signature), str(target)], timeout=30)
        output = (result["stdout"] or result["stderr"]).strip()
        records.append({
            "signature": str(signature), "target": str(target), "tool": "gpgv",
            "status": "VALID" if result["returncode"] == 0 else "NOT VERIFIED",
            "detail": output[:1000],
        })
    return records


def review_updates(diff: dict[str, Any], output_dir: Path, installer_data: dict[str, Any] | None = None) -> dict[str, Any]:
    installer_data = installer_data or {}
    changed = sorted(set(diff.get("files_added", [])) | set(diff.get("files_changed", [])))
    changed_paths = [Path(p) for p in changed if Path(p).is_file()]

    lifecycle_sources: list[Path] = []
    control_dir = output_dir / "working" / "deb_control"
    if control_dir.exists():
        for name in ("preinst", "postinst", "prerm", "postrm", "config"):
            p = control_dir / name
            if p.is_file():
                lifecycle_sources.append(p)

    updater_paths = sorted({str(p) for p in changed_paths if _strong_updater_candidate(p)})
    apt_source_paths = sorted({str(p) for p in changed_paths if '/etc/apt/sources.list.d/' in str(p) or p.name == 'sources.list'})
    browser_update_config = [p for p in changed_paths if '/opt/google/chrome/extensions/' in str(p) and p.suffix.lower() == '.json']
    flatpak_remotes_added = diff.get("flatpak_remotes_added", [])
    snap_packages_added = diff.get("snap_packages_added", [])
    flatpak_packages_added = diff.get("flatpak_packages_added", [])

    endpoint_candidates: list[dict[str, Any]] = []
    verification: list[dict[str, Any]] = []
    repository_risks: list[dict[str, Any]] = []

    source_paths = changed_paths + lifecycle_sources
    for path in source_paths:
        text = _read_small_text(path)
        if not text:
            continue
        strong_file = str(path) in updater_paths or str(path) in apt_source_paths
        for line_no, line in enumerate(text.splitlines(), 1):
            urls = [sanitize_url(u.rstrip("\\.,);]}")) for u in URL_RE.findall(line)]
            has_update_key = bool(UPDATE_KEY_RE.search(line))
            if urls and (strong_file or has_update_key):
                for url in urls:
                    endpoint_candidates.append({
                        "path": str(path), "line": line_no, "url": url,
                        "confidence": "HIGH" if has_update_key else "MEDIUM",
                        "reason": "update configuration key" if has_update_key else "probable updater component",
                    })
            if VERIFY_RE.search(line) and (strong_file or has_update_key):
                indicators = sorted({m.group(0).lower() for m in VERIFY_RE.finditer(line)})
                if indicators:
                    verification.append({"path": str(path), "line": line_no, "indicators": indicators})
            if strong_file or str(path) in apt_source_paths or path.suffix.lower() in {".repo", ".flatpakrepo", ".flatpakref"}:
                for label, pattern in REPOSITORY_RISK_PATTERNS:
                    if pattern.search(line):
                        repository_risks.append({"path": str(path), "line": line_no, "indicator": label})
    for remote in flatpak_remotes_added:
        if "http://" in remote.lower():
            repository_risks.append({"path": "[Flatpak remote inventory]", "line": 0, "indicator": "cleartext repository URL"})

    # One endpoint is one review item; preserve all evidence locations without
    # multiplying the tester's workload.
    unique_endpoints: list[dict[str, Any]] = []
    by_url: dict[str, dict[str, Any]] = {}
    for item in endpoint_candidates:
        key = item['url']
        evidence = {"path": item["path"], "line": item["line"]}
        if key not in by_url:
            item["evidence"] = [evidence]
            by_url[key] = item
            unique_endpoints.append(item)
        elif evidence not in by_url[key]["evidence"]:
            by_url[key]["evidence"].append(evidence)

    verification_by_file: dict[str, set[str]] = {}
    for item in verification:
        verification_by_file.setdefault(item['path'], set()).update(item['indicators'])

    browser_records: list[dict[str, str]] = []
    for path in browser_update_config:
        text = _read_small_text(path)
        for url in URL_RE.findall(text):
            if 'clients2.google.com/service/update2/crx' in url:
                browser_records.append({"path": str(path), "url": sanitize_url(url)})
                break

    insecure = [x for x in unique_endpoints if x['url'].lower().startswith('http://') and x['confidence'] in {'HIGH', 'MEDIUM'}]
    md5_present = (control_dir / 'md5sums').exists()
    payload_dir = output_dir / "working" / "deb_payload"
    checksum_validations: list[dict[str, Any]] = []
    deb_md5 = _validate_deb_md5(control_dir, payload_dir)
    if deb_md5:
        checksum_validations.append(deb_md5)
    manifests = [path for path in changed_paths if CHECKSUM_NAME_RE.search(path.name)]
    for manifest in manifests[:80]:
        checksum_validations.append(_validate_checksum_manifest(manifest))
    signature_paths = list(changed_paths)
    extracted_root = installer_data.get("extracted_root")
    if extracted_root and Path(extracted_root).is_dir():
        try:
            for path in Path(extracted_root).rglob("*"):
                if path.is_file() and (CHECKSUM_NAME_RE.search(path.name) or path.suffix.lower() in {".sig", ".asc"}):
                    signature_paths.append(path)
                    if CHECKSUM_NAME_RE.search(path.name) and len(checksum_validations) < 80:
                        checksum_validations.append(_validate_checksum_manifest(path))
        except (OSError, PermissionError):
            pass
    signature_validations = _signature_checks(sorted(set(signature_paths), key=str), installer_data)

    lines = [
        "Update Mechanism Review", "=" * 23, "",
        "This report prioritizes probable application software-update components and update-specific configuration. Generic source-code uses of the word 'update', third-party documentation URLs, and bundled library metadata are suppressed.",
        "", "Summary", "-------",
        f"Probable updater components:          {len(updater_paths)}",
        f"Application update endpoints:         {len(unique_endpoints)}",
        f"APT repositories/sources introduced:  {len(apt_source_paths)}",
        f"Snap packages introduced:              {len(snap_packages_added)}",
        f"Flatpak packages/remotes introduced:   {len(flatpak_packages_added) + len(flatpak_remotes_added)}",
        f"Verification/signing candidates:       {len(verification_by_file)}",
        f"Checksum manifests validated:          {len(checksum_validations)}",
        f"Signature checks attempted:            {len(signature_validations)}",
        f"Cleartext update endpoint candidates:  {len(insecure)}",
        f"Insecure repository settings:          {len(repository_risks)}",
        "",
        "Probable Update Components", "==========================",
    ]
    if updater_paths:
        for path in updater_paths:
            lines += [
                "[REVIEW]",
                f"Path: {path}",
                "Reason: Filename/location is consistent with software-update control or execution.",
                "Tester Action: Determine which process/service invokes this component and what update source, package format, verification, and privilege it uses.",
                "",
            ]
    else:
        lines += ["No probable application updater component was identified by static file analysis.", ""]

    lines += ["Package Repository Changes", "==========================", ""]
    if apt_source_paths:
        lines += apt_source_paths + [""]
    else:
        lines += ["No application-specific APT repository/source changes identified.", ""]
    lines += ["Snap / Flatpak Inventory Changes", "---------------------------------"]
    lines += [f"[SNAP] {item}" for item in snap_packages_added]
    lines += [f"[FLATPAK] {item}" for item in flatpak_packages_added]
    lines += [f"[FLATPAK REMOTE] {item}" for item in flatpak_remotes_added]
    if not (snap_packages_added or flatpak_packages_added or flatpak_remotes_added):
        lines.append("No Snap/Flatpak package or remote additions identified.")
    lines += ["", "Repository Security Configuration", "---------------------------------"]
    lines += [f"[REVIEW] {item['path']}:{item['line']} - {item['indicator']}" for item in repository_risks] or ["No explicit cleartext repository or disabled repository-verification setting identified."]
    lines.append("")

    lines += ["Application Update Endpoints", "============================", ""]
    if unique_endpoints:
        for item in unique_endpoints:
            marker = "[HIGH INTEREST]" if item['url'].lower().startswith('http://') else "[REVIEW]"
            lines += [
                marker,
                f"URL:        {item['url']}",
                f"Source:     {item['path']}:{item['line']}",
                f"Confidence: {item['confidence']} ({item['reason']})",
                "",
            ]
    else:
        lines += ["No probable application software-update endpoints identified from prioritized static analysis.", ""]

    lines += ["Signing / Verification", "======================", ""]
    lines += [f"Debian package md5sums metadata: {'Present' if md5_present else 'Not identified'}"]
    if verification_by_file:
        for path, indicators in sorted(verification_by_file.items()):
            lines += [f"[REVIEW] {path}", f"  Indicators: {', '.join(sorted(indicators))}"]
    else:
        lines.append("No application-specific updater signature/checksum verification mechanism was confidently identified.")
    lines += ["", "Checksum Validation Results", "---------------------------"]
    if checksum_validations:
        for item in checksum_validations:
            lines += [
                f"[{item.get('status', 'UNKNOWN')}] {item['manifest']}",
                f"  Checked: {item.get('checked', 0)} | Matched: {item.get('matched', 0)} | Mismatched: {len(item.get('mismatched', []))} | Missing: {len(item.get('missing', []))} | Unsafe paths: {len(item.get('unsafe', []))}",
            ]
            for name in item.get("mismatched", [])[:20]:
                lines.append(f"  [MISMATCH] {name}")
            for name in item.get("unsafe", [])[:20]:
                lines.append(f"  [UNSAFE PATH] {name}")
    else:
        lines.append("No checksum manifest with locally available referenced files was identified.")
    lines += ["", "Signature Validation Results", "----------------------------"]
    if signature_validations:
        for item in signature_validations:
            lines += [
                f"[{item['status']}] {item['signature']}",
                f"  Target: {item['target']}",
                f"  Tool: {item['tool']}",
                f"  Detail: {item['detail'] or 'No diagnostic output'}",
            ]
    else:
        lines.append("No detached/package signature pairing was available for automatic verification.")
    lines.append("")

    lines += ["Browser / Extension Update Configuration", "========================================", ""]
    if browser_records:
        for item in browser_records:
            lines += [
                "[INFORMATIONAL]",
                f"Endpoint: {item['url']}",
                f"Source:   {item['path']}",
                "This appears to be a browser-extension update mechanism. Confirm that the assessed application installed/depends on the extension before spending additional testing time on it.",
                "",
            ]
    else:
        lines += ["No browser-extension update configuration identified among changed files.", ""]

    lines += [
        "Tester Guidance", "===============", "",
        "If an application update function is available:",
        "1. Exercise the update workflow through the normal client interface.",
        "2. Identify the update service/process and capture its network traffic.",
        "3. Determine the update source and validate TLS/transport protections.",
        "4. Determine whether update packages/manifests are cryptographically authenticated before privileged installation.",
        "5. Review updater executable, configuration, and parent-directory permissions.",
        "6. Assess downgrade/rollback behavior where appropriate.",
    ]

    write_text(report_path(output_dir, "update_review.txt"), "\n".join(lines))
    return {
        "updater_paths": updater_paths,
        "apt_source_paths": apt_source_paths,
        "urls": unique_endpoints,
        "insecure_update_url_candidates": insecure,
        "verification_indicators": [{"path": p, "indicators": sorted(v)} for p, v in verification_by_file.items()],
        "browser_update_records": browser_records,
        "checksum_validations": checksum_validations,
        "signature_validations": signature_validations,
        "repository_security_candidates": repository_risks,
        "snap_packages_added": snap_packages_added,
        "flatpak_packages_added": flatpak_packages_added,
        "flatpak_remotes_added": flatpak_remotes_added,
    }
