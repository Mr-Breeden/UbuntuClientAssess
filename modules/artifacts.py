from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .common import (
    EXPECTED_REPORTS_BY_MODE,
    METHODOLOGY_VERSION,
    TEST_CASE_CATALOG_VERSION,
    VERSION,
    human_size,
    now_iso,
    read_json,
    report_path,
    sha256_file,
    write_json,
    write_text,
)

MANIFEST_SCHEMA_VERSION = 1
EXTRACTION_DIRECTORIES = (
    "deb_control",
    "deb_payload",
    "appimage_payload",
    "snap_payload",
    "archive_payload",
)


def manifest_inventory_revision(data: dict[str, Any]) -> str:
    """Return a stable fingerprint of the integrity inventory, excluding timestamps."""
    canonical = {
        "schema_version": data.get("schema_version"),
        "framework_version": data.get("framework_version"),
        "methodology_version": data.get("methodology_version"),
        "test_case_catalog_version": data.get("test_case_catalog_version"),
        "mode": data.get("mode"),
        "inventory_status": data.get("inventory_status"),
        "expected_reports": data.get("expected_reports", []),
        "reports": data.get("reports", []),
        "supporting_files": data.get("supporting_files", []),
        "extraction_directories": data.get("extraction_directories", []),
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _file_entry(assessment_dir: Path, path: Path) -> dict[str, Any]:
    return {
        "path": str(path.relative_to(assessment_dir)),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _directory_entry(assessment_dir: Path, directory: Path) -> dict[str, Any]:
    tree = hashlib.sha256()
    objects = 0
    files = 0
    total_size = 0
    for path in sorted(directory.rglob("*"), key=lambda item: str(item.relative_to(directory))):
        try:
            relative = str(path.relative_to(directory))
            st = path.lstat()
        except OSError:
            continue
        objects += 1
        kind = "symlink" if path.is_symlink() else "directory" if path.is_dir() else "file" if path.is_file() else "other"
        target = os.readlink(path) if kind == "symlink" else ""
        digest = ""
        if kind == "file":
            files += 1
            total_size += st.st_size
            digest = sha256_file(path) or "UNREADABLE"
        record = f"{kind}\0{relative}\0{st.st_size}\0{target}\0{digest}\n"
        tree.update(record.encode("utf-8", errors="surrogateescape"))
    return {
        "path": str(directory.relative_to(assessment_dir)),
        "objects": objects,
        "files": files,
        "size": total_size,
        "tree_sha256": tree.hexdigest(),
    }


def finalize_artifact_manifest(assessment_dir: Path, mode: str) -> dict[str, Any]:
    if mode not in EXPECTED_REPORTS_BY_MODE:
        raise ValueError(f"Unsupported artifact-manifest mode: {mode}")

    reports_dir = assessment_dir / "reports"
    expected = set(EXPECTED_REPORTS_BY_MODE[mode])
    manifest_name = "artifact_manifest.txt"
    expected_before_manifest = expected - {manifest_name}
    actual_before_manifest = {
        path.name for path in reports_dir.iterdir()
        if path.is_file() and path.name != manifest_name
    }
    missing = sorted(expected_before_manifest - actual_before_manifest)
    unexpected = sorted(actual_before_manifest - expected_before_manifest)
    if missing or unexpected:
        raise RuntimeError(f"Artifact inventory mismatch; missing={missing or 'none'}, unexpected={unexpected or 'none'}")

    required_supporting = [assessment_dir / "assessment_metadata.json", assessment_dir / "working" / "README.txt"]
    snapshot_paths = [assessment_dir / "working" / "snapshot_pre.json", assessment_dir / "working" / "snapshot_post.json"]
    if mode == "full":
        required_supporting.extend(snapshot_paths)
        required_supporting.append(assessment_dir / "working" / "tester_review_state.json")
    elif any(path.exists() for path in snapshot_paths):
        raise RuntimeError("Installer Analysis Only contains stale pre/post snapshots")
    missing_supporting = [str(path.relative_to(assessment_dir)) for path in required_supporting if not path.is_file()]
    if missing_supporting:
        raise RuntimeError(f"Required supporting artifacts are missing: {', '.join(missing_supporting)}")

    optional_supporting = [
        assessment_dir / "working" / "application_profile.json",
        assessment_dir / "working" / "application_file_coverage.json",
        assessment_dir / "working" / "runtime_observation.json",
        assessment_dir / "working" / "finding_candidates.json",
        assessment_dir / "working" / "security_model.json",
    ]
    reports = [_file_entry(assessment_dir, reports_dir / name) for name in sorted(expected_before_manifest)]
    supporting = [_file_entry(assessment_dir, path) for path in required_supporting]
    supporting.extend(_file_entry(assessment_dir, path) for path in optional_supporting if path.is_file())
    directories = [
        _directory_entry(assessment_dir, directory)
        for name in EXTRACTION_DIRECTORIES
        if (directory := assessment_dir / "working" / name).is_dir()
    ]
    data = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "framework_version": VERSION,
        "methodology_version": METHODOLOGY_VERSION,
        "test_case_catalog_version": TEST_CASE_CATALOG_VERSION,
        "mode": mode,
        "generated_at": now_iso(),
        "inventory_status": "COMPLETE",
        "expected_reports": sorted(expected),
        "reports": reports,
        "supporting_files": supporting,
        "extraction_directories": directories,
    }
    title = "UbuntuClientAssess Artifact Manifest"
    lines = [
        title,
        "=" * len(title),
        "",
        f"Framework Version:        {VERSION}",
        f"Methodology Version:      {METHODOLOGY_VERSION}",
        f"Test-Case Catalog Version: {TEST_CASE_CATALOG_VERSION}",
        f"Execution Mode:           {mode}",
        "Inventory Status:         COMPLETE",
        f"Expected Tester Reports:  {len(expected)}",
        "",
        "Machine-Readable Manifest",
        "-------------------------",
        "assessment_manifest.json | authoritative machine-readable inventory (self-hash intentionally omitted)",
        "",
        "Tester Reports",
        "--------------",
    ]
    for entry in reports:
        lines.append(f"{entry['path']} | {human_size(entry['size'])} | SHA256 {entry['sha256']}")
    lines.append("reports/artifact_manifest.txt | this human-readable inventory (self-hash intentionally omitted)")

    lines += ["", "Supporting Files", "----------------"]
    for entry in supporting:
        lines.append(f"{entry['path']} | {human_size(entry['size'])} | SHA256 {entry['sha256']}")

    lines += ["", "Extracted Payload Inventories", "-----------------------------"]
    if directories:
        for entry in directories:
            lines.append(
                f"{entry['path']} | objects {entry['objects']} | files {entry['files']} | "
                f"content {human_size(entry['size'])} | TREE-SHA256 {entry['tree_sha256']}"
            )
    else:
        lines.append("No extracted payload directory was retained for this installer format.")

    lines += [
        "",
        "Verification",
        "------------",
        f"Run: python3 ubuntuclientassess.py --verify-assessment {assessment_dir}",
        "A successful verification confirms the finalized report set and all recorded hashes/tree hashes.",
    ]
    human_manifest = report_path(assessment_dir, manifest_name)
    write_text(human_manifest, "\n".join(lines))
    data["reports"].append(_file_entry(assessment_dir, human_manifest))
    data["reports"] = sorted(data["reports"], key=lambda entry: entry["path"])
    # The timestamp remains useful operational metadata, while this fingerprint
    # proves that regenerating from unchanged authoritative state produced the
    # same inventory regardless of when regeneration occurred.
    data["inventory_revision"] = manifest_inventory_revision(data)
    write_json(assessment_dir / "assessment_manifest.json", data)
    return data



def _manifest_path(assessment_dir: Path, raw: str) -> Path | None:
    """Resolve a recorded manifest path only when it remains inside the assessment root."""
    try:
        relative = Path(raw)
        if relative.is_absolute() or ".." in relative.parts:
            return None
        root = assessment_dir.resolve()
        candidate = (assessment_dir / relative).resolve(strict=False)
        candidate.relative_to(root)
        return candidate
    except (OSError, ValueError):
        return None

def verify_artifact_manifest(
    assessment_dir: Path,
    *,
    allow_framework_version_mismatch: bool = False,
    allow_methodology_version_mismatch: bool = False,
) -> list[str]:
    issues: list[str] = []
    machine_manifest = assessment_dir / "assessment_manifest.json"
    if not machine_manifest.is_file():
        return ["assessment_manifest.json is missing"]
    try:
        data = read_json(machine_manifest)
    except Exception as exc:
        return [f"assessment_manifest.json cannot be read: {exc}"]

    if data.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        issues.append(f"Unsupported manifest schema: {data.get('schema_version')}")
    if data.get("framework_version") != VERSION and not allow_framework_version_mismatch:
        issues.append(f"Framework version mismatch: manifest={data.get('framework_version')} verifier={VERSION}")
    if data.get("methodology_version") != METHODOLOGY_VERSION and not allow_methodology_version_mismatch:
        issues.append(f"Methodology version mismatch: {data.get('methodology_version')}")
    recorded_revision = str(data.get("inventory_revision") or "")
    if data.get("framework_version") == VERSION:
        if not recorded_revision:
            issues.append("Manifest inventory revision is missing")
        elif recorded_revision != manifest_inventory_revision(data):
            issues.append("Manifest inventory revision mismatch")
    mode = data.get("mode")
    if allow_framework_version_mismatch:
        expected = set(str(name) for name in data.get("expected_reports", []) if name)
    else:
        expected = set(EXPECTED_REPORTS_BY_MODE.get(str(mode), set()))
    actual = {path.name for path in (assessment_dir / "reports").iterdir() if path.is_file()} if (assessment_dir / "reports").is_dir() else set()
    if actual != expected:
        issues.append(f"Tester report set mismatch: missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")

    for collection in ("reports", "supporting_files"):
        for entry in data.get(collection, []):
            raw_path = str(entry.get("path", ""))
            path = _manifest_path(assessment_dir, raw_path)
            if path is None:
                issues.append(f"Unsafe recorded path outside assessment root: {raw_path}")
                continue
            if not path.is_file():
                issues.append(f"Missing recorded file: {entry.get('path')}")
                continue
            if path.stat().st_size != entry.get("size"):
                issues.append(f"Size mismatch: {entry.get('path')}")
            if sha256_file(path) != entry.get("sha256"):
                issues.append(f"SHA256 mismatch: {entry.get('path')}")

    for entry in data.get("extraction_directories", []):
        raw_path = str(entry.get("path", ""))
        directory = _manifest_path(assessment_dir, raw_path)
        if directory is None:
            issues.append(f"Unsafe extraction path outside assessment root: {raw_path}")
            continue
        if not directory.is_dir():
            issues.append(f"Missing extraction directory: {entry.get('path')}")
            continue
        current = _directory_entry(assessment_dir, directory)
        for field in ("objects", "files", "size", "tree_sha256"):
            if current.get(field) != entry.get(field):
                issues.append(f"Extraction inventory mismatch ({field}): {entry.get('path')}")

    if not (assessment_dir / "reports" / "artifact_manifest.txt").is_file():
        issues.append("reports/artifact_manifest.txt is missing")
    staging = []
    for directory in (assessment_dir, assessment_dir / "reports", assessment_dir / "working"):
        if directory.is_dir():
            staging.extend(directory.glob(".*.tmp"))
    if staging:
        issues.append("Orphaned atomic-write staging files are present")
    return issues


def assessment_verification_summary(
    assessment_dir: Path,
    *,
    allow_framework_version_mismatch: bool = False,
    allow_methodology_version_mismatch: bool = False,
) -> dict[str, Any]:
    """Return a transparent integrity-verification result for CLI/dashboard use."""
    issues = verify_artifact_manifest(
        assessment_dir,
        allow_framework_version_mismatch=allow_framework_version_mismatch,
        allow_methodology_version_mismatch=allow_methodology_version_mismatch,
    )
    checks: list[dict[str, Any]] = []
    manifest_path = assessment_dir / "assessment_manifest.json"
    manifest: dict[str, Any] = {}
    if manifest_path.is_file():
        try:
            manifest = read_json(manifest_path)
        except Exception:
            manifest = {}
    reports = list(manifest.get("reports", []) or [])
    supporting = list(manifest.get("supporting_files", []) or [])
    extracted = list(manifest.get("extraction_directories", []) or [])
    issue_text = "\n".join(issues).casefold()
    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})
    add("Assessment manifest", manifest_path.is_file() and "assessment_manifest.json" not in issue_text, "Machine-readable integrity inventory is present and readable")
    add("Report artifact integrity", not any(x in issue_text for x in ("tester report set mismatch", "missing recorded file: reports/", "sha256 mismatch: reports/", "size mismatch: reports/")), f"{len(reports)} recorded report artifact(s)")
    add("Supporting state integrity", not any(x in issue_text for x in ("missing recorded file: working/", "missing recorded file: assessment_metadata", "sha256 mismatch: working/", "sha256 mismatch: assessment_metadata")), f"{len(supporting)} recorded supporting file(s)")
    add("Extracted payload integrity", not any("extraction" in x.casefold() for x in issues), f"{len(extracted)} retained extraction director{'y' if len(extracted)==1 else 'ies'}")
    add("Artifact inventory consistency", not any("report set mismatch" in x.casefold() for x in issues), f"Mode: {manifest.get('mode') or 'unknown'}")
    add("Atomic-write cleanup", not any("staging" in x.casefold() for x in issues), "No orphaned temporary write artifacts")
    return {
        "passed": not issues,
        "issues": issues,
        "checks": checks,
        "framework_version": manifest.get("framework_version"),
        "methodology_version": manifest.get("methodology_version"),
        "coverage_catalog_version": manifest.get("test_case_catalog_version"),
        "mode": manifest.get("mode"),
        "report_count": len(reports),
        "supporting_count": len(supporting),
        "extraction_count": len(extracted),
        "inventory_revision": manifest.get("inventory_revision"),
    }
