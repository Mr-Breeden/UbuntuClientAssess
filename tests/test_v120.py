from __future__ import annotations

from pathlib import Path


def test_review_queue_prioritizes_privileged_service_and_deduplicates_path(tmp_path):
    from modules.tester_review import generate_tester_review

    path = "/opt/vendor/bin/helper"
    service = {"risk_candidates": [{"unit": "vendor.service", "privileged": True, "path_type": "ExecStart", "path": path, "concerns": "tester-writable root-owned target"}]}
    permissions = {"high_interest_candidates": [{"path": path, "concerns": "world-writable", "level": "HIGH INTEREST"}], "review_candidates": []}
    state = generate_tester_review(tmp_path, permission_data=permissions, service_data=service)
    assert len(state["items"]) == 1
    item = state["items"][0]
    assert item["priority"] == "HIGH"
    assert item["category"] == "SVC"
    assert "privilege boundary" in item["why_it_matters"].lower()
    assert (tmp_path / "reports" / "tester_review.txt").is_file()
    assert (tmp_path / "reports" / "evidence_guide.txt").is_file()


def test_storage_secret_is_review_item_not_automatic_finding(tmp_path):
    from modules.findings import generate_findings
    from modules.tester_review import generate_tester_review

    storage = {"secret_hits": [{"path": "/etc/vendor/client.conf", "indicators": ["client secret"], "permission": "world-readable"}]}
    findings = generate_findings(tmp_path, {}, {}, {}, {}, storage)
    assert findings == []
    state = generate_tester_review(tmp_path, storage_data=storage)
    assert len(state["items"]) == 1
    assert state["items"][0]["priority"] == "HIGH"
    assert "Potential Credential" in state["items"][0]["title"]


def test_review_state_preserves_status_and_redacts_notes(tmp_path):
    from modules.tester_review import generate_tester_review, update_review_item

    network = {"exposed_listener_candidates": ['tcp LISTEN 0 128 0.0.0.0:8443 users:(("vendor",pid=<PID>,fd=<FD>))']}
    state = generate_tester_review(tmp_path, network_data=network)
    identity = state["items"][0]["identity"]
    updated = update_review_item(tmp_path, identity, status="VALIDATED", notes="api_key=super-secret-value")
    assert updated["items"][0]["status"] == "VALIDATED"
    assert "super-secret-value" not in updated["items"][0]["notes"]
    assert "[REDACTED]" in updated["items"][0]["notes"]
    regenerated = generate_tester_review(tmp_path, network_data=network)
    assert regenerated["items"][0]["status"] == "VALIDATED"
    assert "super-secret-value" not in (tmp_path / "reports" / "tester_review.txt").read_text()


def test_review_queue_empty_is_still_valid_artifact(tmp_path):
    from modules.tester_review import generate_tester_review

    state = generate_tester_review(tmp_path)
    assert state["items"] == []
    text = (tmp_path / "reports" / "tester_review.txt").read_text()
    assert "No prioritized review candidates" in text


def test_evidence_guide_does_not_embed_screenshot_placeholder(tmp_path):
    from modules.tester_review import generate_tester_review

    storage = {"secret_hits": [{"path": "/etc/vendor/client.conf", "indicators": ["token"], "permission": ""}]}
    generate_tester_review(tmp_path, storage_data=storage)
    text = (tmp_path / "reports" / "evidence_guide.txt").read_text()
    assert "<SCREENSHOT>" not in text
    assert "final Word report" in text


def test_full_manifest_requires_review_state(tmp_path):
    import pytest
    from modules.artifacts import finalize_artifact_manifest
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout, report_path, write_json, write_text

    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "assessment_metadata.json", {"version": "1.2.0", "mode": "full"})
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 6})
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"artifact_manifest.txt"}:
        write_text(report_path(tmp_path, name), "ok")
    with pytest.raises(RuntimeError, match="tester_review_state.json"):
        finalize_artifact_manifest(tmp_path, "full")


def test_consolidated_report_links_review_queue(tmp_path):
    from modules.common import ensure_assessment_layout, report_path, write_text
    from modules.consolidated_report import generate_consolidated_report

    ensure_assessment_layout(tmp_path)
    write_text(report_path(tmp_path, "tester_review.txt"), "queue")
    write_text(report_path(tmp_path, "evidence_guide.txt"), "guide")
    write_text(report_path(tmp_path, "findings.txt"), "Findings\n========\n\nManual Review Required\n----------------------\nNone generated.\n")
    generate_consolidated_report(tmp_path, "Review Test", None, "full", "1.2.0", {})
    html = report_path(tmp_path, "assessment_report.html").read_text()
    assert 'href="tester_review.txt"' in html
    assert 'href="evidence_guide.txt"' in html
    assert 'id="tester-review"' in html


def test_client_appendix_excludes_tester_review_artifacts():
    from modules.client_appendix import FULL_CLIENT_REPORTS, INTERNAL_EXCLUSIONS

    assert "tester_review.txt" not in FULL_CLIENT_REPORTS
    assert "evidence_guide.txt" not in FULL_CLIENT_REPORTS
    assert "tester_review.txt" in INTERNAL_EXCLUSIONS
    assert "evidence_guide.txt" in INTERNAL_EXCLUSIONS


def test_cli_exposes_review_mode():
    import subprocess, sys
    script = Path(__file__).resolve().parents[1] / "ubuntuclientassess.py"
    out = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True, check=True).stdout
    assert "--review" in out


def test_previous_methodology_assessment_can_still_export_client_appendix(tmp_path):
    import ubuntuclientassess as uca
    from modules.client_appendix import create_client_appendix
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout, report_path, write_json, write_text, read_json

    # Build a current assessment first, then mutate its manifest contract to
    # mimic a prior 1.1.x report set/methodology while retaining valid hashes.
    ensure_assessment_layout(tmp_path)
    metadata = {"framework": "UbuntuClientAssess", "version": "1.2.0", "assessment_name": "Compat", "mode": "full"}
    metadata_path = tmp_path / "assessment_metadata.json"
    write_json(metadata_path, metadata)
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "tester_review_state.json", {"schema_version": 1, "framework_version": "1.2.0", "items": []})
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"assessment_report.html", "artifact_manifest.txt", "module_status.txt"}:
        write_text(report_path(tmp_path, name), "ok")
    assert uca.finalize_assessment(tmp_path, "full", metadata_path, metadata, {})

    manifest_path = tmp_path / "assessment_manifest.json"
    manifest = read_json(manifest_path)
    # Simulate a prior version's methodology identity. Export verification is
    # intentionally compatible while strict --verify remains version-bound.
    manifest["framework_version"] = "1.1.5"
    manifest["methodology_version"] = "1.0"
    write_json(manifest_path, manifest)
    result = create_client_appendix(tmp_path)
    assert result["source_version"] == "1.1.5"


def test_client_appendix_blocks_pending_v120_review_items(tmp_path):
    import pytest
    import ubuntuclientassess as uca
    from modules.client_appendix import create_client_appendix
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout, report_path, write_json, write_text

    ensure_assessment_layout(tmp_path)
    metadata = {"framework": "UbuntuClientAssess", "version": "1.2.0", "assessment_name": "Pending Review", "mode": "full"}
    metadata_path = tmp_path / "assessment_metadata.json"
    write_json(metadata_path, metadata)
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "tester_review_state.json", {
        "schema_version": 1,
        "framework_version": "1.2.0",
        "items": [{"identity": "TEST-1", "id": "TRQ-001", "priority": "MEDIUM", "title": "Review me", "status": "PENDING", "notes": ""}],
    })
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"assessment_report.html", "artifact_manifest.txt", "module_status.txt"}:
        write_text(report_path(tmp_path, name), "ok")
    assert uca.finalize_assessment(tmp_path, "full", metadata_path, metadata, {})
    with pytest.raises(RuntimeError, match="pending item"):
        create_client_appendix(tmp_path)
