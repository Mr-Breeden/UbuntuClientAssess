from pathlib import Path

from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, write_json
from modules.security_model import MODEL_SCHEMA_VERSION
from modules.technical_summary import build_technical_summary
from modules.client_appendix import _client_index
from modules.artifacts import assessment_verification_summary


def test_v170_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_structured_technical_summary_is_client_safe(tmp_path: Path):
    work = tmp_path / "working"; work.mkdir(parents=True)
    write_json(work / "security_model.json", {
        "schema_version": 9,
        "objects": [
            {"id":"service:a","kind":"service","identity":"a.service","attributes":{}},
            {"id":"network_endpoint:tcp:0.0.0.0:9000","kind":"network_endpoint","identity":"tcp:0.0.0.0:9000","attributes":{}},
            {"id":"application_endpoint:http://example.test","kind":"application_endpoint","identity":"http://example.test","attributes":{}},
        ],
        "observations": [
            {"id":"OBS-secret","category":"cleartext_application_endpoint","object_id":"application_endpoint:http://example.test","source_module":"network_surface_review","summary":"x","attributes":{},"evidence_bookmarks":[]},
            {"id":"OBS-runtime","category":"runtime_listener","object_id":"network_endpoint:tcp:0.0.0.0:9000","source_module":"guided_runtime_observation","summary":"x","attributes":{},"evidence_bookmarks":[]},
        ],
        "relationships": [], "correlations": [{"id":"COR-secret"}],
    })
    summary = build_technical_summary(tmp_path)
    assert summary["service_count"] == 1
    assert summary["network_listener_count"] == 1
    assert summary["cleartext_endpoint_count"] == 1
    assert "OBS-secret" not in repr(summary)
    assert "COR-secret" not in repr(summary)


def test_client_dashboard_has_summary_but_no_internal_workflow_tokens():
    html = _client_index("Example", "2.0.6", "full", ["network_surface_review.txt", "runtime_review.txt"], {
        "model_schema": 9, "service_count": 2, "network_listener_count": 1,
        "application_endpoint_count": 3, "cleartext_endpoint_count": 2,
        "credential_storage_count": 1, "update_endpoint_count": 1,
        "unix_socket_count": 1, "fifo_count": 1, "dbus_count": 1, "polkit_count": 1,
        "runtime_process_count": 2, "privileged_process_count": 1, "runtime_listener_count": 1,
        "runtime_connection_observation_count": 1, "runtime_socket_count": 1, "runtime_fifo_count": 1,
        "permission_observation_count": 3, "suid_helper_count": 1, "capability_count": 1,
        "cleartext_update_count": 1, "listeners": ["tcp:0.0.0.0:9000"], "update_endpoints": ["http://updates.test"],
    })
    assert "Technical Surface at a Glance" in html
    assert "Network & Communications" in html
    assert "Confirmed vulnerabilities" in html
    for token in ("TRQ-", "UAF-", "OBS-", "CORR-", "Tester notes", "Correlation Engine", "working/"):
        assert token not in html


def test_verification_summary_explains_missing_manifest(tmp_path: Path):
    result = assessment_verification_summary(tmp_path)
    assert result["passed"] is False
    assert result["checks"]
    assert any(x["name"] == "Assessment manifest" and x["status"] == "FAIL" for x in result["checks"])
