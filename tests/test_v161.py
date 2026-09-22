from pathlib import Path

from modules.assessment_coverage import build_assessment_coverage, generate_assessment_coverage, refresh_assessment_coverage
from modules.common import EXPECTED_REPORTS_BY_MODE, VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, ensure_assessment_layout, write_json
from modules.security_model import MODEL_SCHEMA_VERSION
from modules.consolidated_report import generate_consolidated_report


def test_v161_release_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10
    assert "assessment_coverage.txt" in EXPECTED_REPORTS_BY_MODE["full"]
    assert "test_cases.txt" not in EXPECTED_REPORTS_BY_MODE["full"]


def test_coverage_maps_review_categories_without_duplicating_validation(tmp_path):
    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "working" / "tester_review_state.json", {
        "items": [
            {"id": "TRQ-004", "category": "PERM", "status": "PENDING"},
            {"id": "TRQ-005", "category": "PERM", "status": "VALIDATED"},
            {"id": "TRQ-029", "category": "DBUS", "status": "INFORMATIONAL"},
        ]
    })
    records = build_assessment_coverage(tmp_path, "full", {})
    perm = next(x for x in records if x["id"] == "TC-PERM-001")
    ipc = next(x for x in records if x["id"] == "TC-IPC-001")
    assert perm["related_review_ids"] == ["TRQ-004", "TRQ-005"]
    assert perm["pending_review_count"] == 1
    assert ipc["related_review_ids"] == ["TRQ-029"]
    generate_assessment_coverage(tmp_path, "full", {})
    text = (tmp_path / "reports" / "assessment_coverage.txt").read_text()
    assert "Detailed Validation Procedure" not in text
    assert "No specific review candidate" in text


def test_coverage_reflects_runtime_observation(tmp_path):
    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "working" / "runtime_observation.json", {"application_processes": [{"pid": 123}]})
    records = build_assessment_coverage(tmp_path, "full", {})
    assert next(x for x in records if x["id"] == "TC-RUN-001")["runtime_state"] == "OBSERVED"
    assert next(x for x in records if x["id"] == "TC-PERM-001")["runtime_state"] == "NOT REQUIRED BY THIS COVERAGE ROW"


def test_refresh_coverage_uses_authoritative_review_and_metadata(tmp_path):
    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "assessment_metadata.json", {"mode": "full"})
    write_json(tmp_path / "working" / "application_profile.json", {"technologies": [{"technology": "Native ELF"}]})
    write_json(tmp_path / "working" / "tester_review_state.json", {"items": [{"id": "TRQ-012", "category": "STOR", "status": "VALIDATED"}]})
    refresh_assessment_coverage(tmp_path)
    text = (tmp_path / "reports" / "assessment_coverage.txt").read_text()
    assert "TRQ-012" in text
    assert "Review state: RESOLVED" in text


def test_dashboard_contains_coverage_view_and_links_generated_artifact(tmp_path):
    ensure_assessment_layout(tmp_path)
    generate_assessment_coverage(tmp_path, "full", {})
    generate_consolidated_report(tmp_path, "Coverage Test", None, "full", VERSION, {})
    html = (tmp_path / "reports" / "assessment_report.html").read_text()
    assert 'id="assessment-coverage"' in html
    assert '>Coverage</a>' in html
    assert "A row with no specific candidate still requires" in html
    assert 'href="assessment_coverage.txt"' in html
    assert "test_cases.txt" not in html


def test_coverage_artifact_is_read_only_integrity_guidance(tmp_path):
    generate_assessment_coverage(tmp_path, "full", {})
    text = (tmp_path / "reports" / "assessment_coverage.txt").read_text()
    assert "Manual edits intentionally invalidate assessment integrity." in text
    assert "Use Guided Review for condition-specific validation." in text
    assert "[ ] COMPLETED" not in text
