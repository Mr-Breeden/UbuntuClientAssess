from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


def _finalized_assessment(tmp_path: Path, mode: str = "full") -> Path:
    import ubuntuclientassess as uca
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout, report_path, write_json, write_text

    ensure_assessment_layout(tmp_path)
    metadata_path = tmp_path / "assessment_metadata.json"
    metadata = {
        "framework": "UbuntuClientAssess",
        "version": "1.2.0",
        "assessment_name": "Client Appendix Test",
        "installer": "/tmp/vendor.deb",
        "mode": mode,
    }
    write_json(metadata_path, metadata)
    if mode == "full":
        write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 6})
        write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "tester_review_state.json", {"schema_version": 1, "framework_version": "1.2.0", "items": []})

    generated = {"assessment_report.html", "artifact_manifest.txt", "module_status.txt"}
    for name in EXPECTED_REPORTS_BY_MODE[mode] - generated:
        body = f"client technical evidence for {name}\n"
        if name == "findings.txt":
            body = "Findings\n========\n\nNo automatic finding candidates generated.\n"
        write_text(report_path(tmp_path, name), body)

    assert uca.finalize_assessment(tmp_path, mode, metadata_path, metadata, {}) is True
    return tmp_path


def test_client_appendix_full_exports_only_approved_files(tmp_path):
    from modules.client_appendix import FULL_CLIENT_REPORTS, create_client_appendix

    assessment = _finalized_assessment(tmp_path, "full")
    result = create_client_appendix(assessment)
    appendix = assessment / "ClientAppendix"

    assert result["path"] == appendix
    for name in FULL_CLIENT_REPORTS:
        assert (appendix / name).is_file()
    for name in (
        "findings.txt", "findings_summary.txt", "assessment_coverage.txt", "module_status.txt",
        "tool_detection.txt", "artifact_manifest.txt", "assessment_manifest.json",
        "snapshot_pre.json", "snapshot_post.json",
    ):
        assert not (appendix / name).exists()
    assert not (appendix / "working").exists()
    assert (appendix / "README.txt").is_file()
    assert (appendix / "SHA256SUMS.txt").is_file()
    assert (appendix / "assessment_report.html").is_file()


def test_client_appendix_html_is_client_safe_and_links_only_exported_files(tmp_path):
    from modules.client_appendix import create_client_appendix

    assessment = _finalized_assessment(tmp_path, "full")
    create_client_appendix(assessment)
    report = (assessment / "ClientAppendix" / "assessment_report.html").read_text(encoding="utf-8")

    assert "Automatic Finding Candidates" not in report
    assert "findings.txt" not in report
    assert "assessment_coverage.txt" not in report
    assert "module_status.txt" not in report
    assert "tool_detection.txt" not in report
    assert "Confirmed vulnerabilities" in report
    assert 'href="permissions_review.txt"' in report
    assert 'href="ipc_review.txt"' in report


def test_client_appendix_checksums_match_every_exported_file(tmp_path):
    from modules.client_appendix import create_client_appendix

    assessment = _finalized_assessment(tmp_path, "full")
    create_client_appendix(assessment)
    appendix = assessment / "ClientAppendix"
    checksum_lines = (appendix / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    recorded = {}
    for line in checksum_lines:
        digest, name = line.split("  ", 1)
        recorded[name] = digest
    expected_names = {p.name for p in appendix.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt"}
    assert set(recorded) == expected_names
    for name, digest in recorded.items():
        assert hashlib.sha256((appendix / name).read_bytes()).hexdigest() == digest


def test_client_appendix_refresh_removes_stale_files(tmp_path):
    from modules.client_appendix import create_client_appendix

    assessment = _finalized_assessment(tmp_path, "full")
    create_client_appendix(assessment)
    stale = assessment / "ClientAppendix" / "OLD-DO-NOT-DELIVER.txt"
    stale.write_text("stale", encoding="utf-8")
    assert stale.exists()
    create_client_appendix(assessment)
    assert not stale.exists()


def test_client_appendix_installer_only_uses_reduced_client_set(tmp_path):
    from modules.client_appendix import INSTALLER_ONLY_CLIENT_REPORTS, create_client_appendix

    assessment = _finalized_assessment(tmp_path, "installer-analysis-only")
    create_client_appendix(assessment)
    appendix = assessment / "ClientAppendix"
    assert {name for name in INSTALLER_ONLY_CLIENT_REPORTS} <= {p.name for p in appendix.iterdir() if p.is_file()}
    assert not (appendix / "install_changes.txt").exists()
    assert not (appendix / "permissions_review.txt").exists()


def test_client_appendix_refuses_modified_source_report(tmp_path):
    from modules.client_appendix import create_client_appendix

    assessment = _finalized_assessment(tmp_path, "full")
    (assessment / "reports" / "permissions_review.txt").write_text("modified after finalization\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="integrity verification failed"):
        create_client_appendix(assessment)
    assert not (assessment / "ClientAppendix").exists()


def test_client_appendix_can_export_compatible_previous_patch_assessment(tmp_path):
    from modules.artifacts import verify_artifact_manifest
    from modules.client_appendix import create_client_appendix
    from modules.common import read_json, write_json

    assessment = _finalized_assessment(tmp_path, "full")
    manifest_path = assessment / "assessment_manifest.json"
    manifest = read_json(manifest_path)
    manifest["framework_version"] = "1.1.3"
    write_json(manifest_path, manifest)

    strict = verify_artifact_manifest(assessment)
    assert any("Framework version mismatch" in item for item in strict)
    result = create_client_appendix(assessment)
    assert result["source_version"] == "1.1.3"
    assert (assessment / "ClientAppendix" / "README.txt").is_file()


def test_client_appendix_refuses_symlink_destination(tmp_path):
    from modules.client_appendix import create_client_appendix

    assessment = _finalized_assessment(tmp_path, "full")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir(exist_ok=True)
    (assessment / "ClientAppendix").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match="symbolic link"):
        create_client_appendix(assessment)


def test_source_assessment_still_verifies_after_client_appendix_export(tmp_path):
    from modules.artifacts import verify_artifact_manifest
    from modules.client_appendix import create_client_appendix

    assessment = _finalized_assessment(tmp_path, "full")
    assert verify_artifact_manifest(assessment) == []
    create_client_appendix(assessment)
    assert verify_artifact_manifest(assessment) == []


def test_cli_help_exposes_client_appendix_flag():
    import subprocess
    import sys

    script = Path(__file__).resolve().parents[1] / "ubuntuclientassess.py"
    help_text = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "--create-client-appendix" in help_text
