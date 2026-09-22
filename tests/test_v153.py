from pathlib import Path

from modules.common import ensure_assessment_layout, report_path, write_json, write_text
from modules.consolidated_report import generate_consolidated_report


def test_v153_version_contract():
    from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION
    from modules.security_model import MODEL_SCHEMA_VERSION
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_v153_dashboard_has_tester_workspace_filters_and_read_only_contract(tmp_path: Path):
    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "working" / "tester_review_state.json", {
        "items": [{
            "id": "TRQ-001", "identity": "demo", "category": "SVC", "priority": "HIGH",
            "title": "Privileged Service Path Requires Validation", "status": "PENDING",
            "condition": "demo.service consumes /opt/demo/config", "why_it_matters": "Privilege boundary",
            "generation_source": "correlation_engine", "correlation_id": "COR-demo",
            "correlation_rule": "CORR-SVC-WRITABLE-PATH", "correlation_strength": "STRONG",
            "supporting_observation_ids": ["OBS-service", "OBS-perm"],
            "runtime_confirmed": True, "runtime_observations": ["runtime confirmed"],
            "validation": ["Validate the service"], "evidence": ["systemctl cat demo.service"],
            "related_reports": ["service_review.txt"],
        }]
    })
    write_json(tmp_path / "working" / "security_model.json", {
        "schema_version": 3,
        "objects": [
            {"id": "service:demo.service", "kind": "service", "identity": "demo.service", "attributes": {}},
            {"id": "file:/opt/demo/config", "kind": "file", "identity": "/opt/demo/config", "attributes": {}},
        ],
        "observations": [
            {"id": "OBS-service", "category": "service_dependency", "object_id": "service:demo.service", "source_module": "systemd_service_review", "summary": "Root service consumes config"},
            {"id": "OBS-perm", "category": "filesystem_permission", "object_id": "file:/opt/demo/config", "source_module": "permissions_review", "summary": "Tester-writable config"},
            {"id": "OBS-runtime", "category": "runtime_listener", "object_id": "network_endpoint:tcp:0.0.0.0:9000", "source_module": "guided_runtime_observation", "summary": "tcp listener"},
        ],
        "relationships": [],
        "correlations": [{
            "id": "COR-demo", "kind": "privileged_service_writable_path", "rule_id": "CORR-SVC-WRITABLE-PATH",
            "strength": "STRONG", "generation_source": "correlation_engine", "object_ids": ["service:demo.service", "file:/opt/demo/config"],
            "observation_ids": ["OBS-service", "OBS-perm"],
        }],
    })
    write_json(tmp_path / "working" / "finding_candidates.json", {"findings": [], "manual_review": []})
    write_text(report_path(tmp_path, "service_review.txt"), "service")
    write_text(report_path(tmp_path, "runtime_review.txt"), "runtime")
    generate_consolidated_report(tmp_path, "Dashboard", "/tmp/demo.deb", "full", "1.5.4", {"Security Correlation Model": ("PASS", "")})
    html = report_path(tmp_path, "assessment_report.html").read_text(encoding="utf-8")
    assert 'id="review-search"' in html
    assert 'id="filter-status"' in html and 'id="filter-source"' in html and 'id="filter-runtime"' in html
    assert 'id="next-pending"' in html
    assert "Read-only dashboard" in html and "Guided Review" in html
    assert "CORR-SVC-WRITABLE-PATH" in html and "OBS-service" in html and "Root service consumes config" in html
    assert "Runtime Activity" in html and "Listeners" in html
    assert "script-src 'unsafe-inline'" in html
    assert "https://" not in html and "http://" not in html


def test_v153_dashboard_preserves_legacy_item_context(tmp_path: Path):
    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "working" / "tester_review_state.json", {"items": [{
        "id": "TRQ-002", "identity": "legacy", "category": "PERS", "priority": "MEDIUM",
        "title": "Persistence Review", "status": "INFORMATIONAL", "condition": "timer introduced",
        "why_it_matters": "Persistence context", "notes": "Reviewed",
    }]})
    write_json(tmp_path / "working" / "security_model.json", {"schema_version": 3, "objects": [], "observations": [], "relationships": [], "correlations": []})
    generate_consolidated_report(tmp_path, "Legacy", None, "full", "1.5.4", {})
    html = report_path(tmp_path, "assessment_report.html").read_text(encoding="utf-8")
    assert "Legacy Analysis" in html
    assert "structured correlation ownership has not migrated" in html
    assert "Reviewed" in html
