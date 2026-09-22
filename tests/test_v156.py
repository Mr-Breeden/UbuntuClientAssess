from pathlib import Path

from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, ensure_assessment_layout, write_json
from modules.security_model import MODEL_SCHEMA_VERSION, build_security_model, merge_runtime_security_model
from modules.tester_review import generate_tester_review, stable_review_identity
from modules.findings import generate_findings


def _setup(tmp_path: Path) -> None:
    ensure_assessment_layout(tmp_path)


def test_v156_version_and_model_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_credential_storage_review_is_correlation_owned_and_redacted(tmp_path: Path):
    _setup(tmp_path)
    path = "/etc/vendor/credentials.conf"
    storage_data = {"secret_hits": [{
        "path": path,
        "indicators": ["api key", "password"],
        "occurrences": 2,
        "first_lines": {"api key": 3, "password": 7},
        "permission": "world-readable",
    }]}
    model = build_security_model(tmp_path, storage_data=storage_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "credential_token_storage")
    assert corr["rule_id"] == "CORR-STOR-CREDENTIAL"
    assert corr["generation_source"] == "correlation_engine"
    assert corr["drives_review"] is True and corr["drives_finding"] is False
    obs = next(x for x in model["observations"] if x["category"] == "credential_token_storage")
    assert obs["attributes"]["values_redacted"] is True
    assert "secret-value" not in str(model)

    state = generate_tester_review(tmp_path, storage_data=storage_data)
    item = next(x for x in state["items"] if x["identity"] == stable_review_identity("STOR", path))
    assert item["generation_source"] == "correlation_engine"
    assert item["priority"] == "HIGH"
    assert "value intentionally redacted" in item["condition"]


def test_credential_storage_non_world_access_remains_medium(tmp_path: Path):
    _setup(tmp_path)
    path = "/opt/vendor/config/auth.ini"
    storage_data = {"secret_hits": [{"path": path, "indicators": ["token"], "permission": ""}]}
    build_security_model(tmp_path, storage_data=storage_data)
    state = generate_tester_review(tmp_path, storage_data=storage_data)
    item = next(x for x in state["items"] if x["identity"] == stable_review_identity("STOR", path))
    assert item["priority"] == "MEDIUM"


def test_cleartext_application_endpoint_review_is_correlation_owned(tmp_path: Path):
    _setup(tmp_path)
    endpoint = "http://127.0.0.1:8080/api"
    network_data = {"cleartext_endpoint_candidates": [{
        "endpoint": endpoint,
        "path": "/opt/vendor/config/client.conf",
        "line": 9,
        "source": "configuration/text",
        "evidence": [{"path": "/opt/vendor/config/client.conf", "line": 9, "source": "configuration/text"}],
    }]}
    model = build_security_model(tmp_path, network_data=network_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "cleartext_application_endpoint")
    assert corr["rule_id"] == "CORR-COMM-CLEARTEXT"
    assert corr["generation_source"] == "correlation_engine"
    assert corr["drives_review"] is True and corr["drives_finding"] is False
    assert any(x["id"] == f"application_endpoint:{endpoint}" for x in model["objects"])

    state = generate_tester_review(tmp_path, network_data=network_data)
    item = next(x for x in state["items"] if x["identity"] == stable_review_identity("COMM", endpoint))
    assert item["generation_source"] == "correlation_engine"
    assert item["priority"] == "MEDIUM"
    assert item["condition"] == f"Static/config endpoint indicator: {endpoint}"


def test_cleartext_application_endpoint_does_not_create_automatic_finding(tmp_path: Path):
    _setup(tmp_path)
    endpoint = "http://vendor.invalid/api"
    network_data = {"cleartext_endpoint_candidates": [{"endpoint": endpoint}]}
    build_security_model(tmp_path, network_data=network_data)
    findings = generate_findings(tmp_path, {}, {}, {}, network_data, {}, {}, {})
    assert not [x for x in findings if x.get("generation_source") == "correlation_engine" and x.get("category") == "COMM"]


def test_v156_migration_preserves_technology_plan_and_runtime_listener_as_legacy(tmp_path: Path):
    _setup(tmp_path)
    endpoint = "http://127.0.0.1:8080"
    network_data = {
        "cleartext_endpoint_candidates": [{"endpoint": endpoint}],
        "exposed_listener_candidates": ["tcp LISTEN 0 8 0.0.0.0:8080 0.0.0.0:*"],
    }
    profile_data = {"primary_technology": "Python"}
    build_security_model(tmp_path, network_data=network_data, profile_data=profile_data)
    state = generate_tester_review(tmp_path, network_data=network_data, profile_data=profile_data)
    comm = next(x for x in state["items"] if x["identity"] == stable_review_identity("COMM", endpoint))
    assert comm["generation_source"] == "correlation_engine"
    listener = next(x for x in state["items"] if x["category"] == "NET")
    assert listener.get("generation_source") != "correlation_engine"
    tech = next(x for x in state["items"] if x["category"] == "TECH")
    assert tech.get("generation_source") != "correlation_engine"


def test_schema5_new_review_kinds_migrate_to_v156_ownership(tmp_path: Path):
    _setup(tmp_path)
    endpoint = "http://127.0.0.1:8080/api"
    path = "/etc/vendor/credentials.conf"
    stor_rid = stable_review_identity("STOR", path)
    comm_rid = stable_review_identity("COMM", endpoint)
    write_json(tmp_path / "working" / "security_model.json", {
        "schema_version": 5,
        "objects": [
            {"id": f"file:{path}", "kind": "file", "identity": path, "attributes": {}},
            {"id": f"application_endpoint:{endpoint}", "kind": "application_endpoint", "identity": endpoint, "attributes": {}},
        ],
        "observations": [], "relationships": [],
        "correlations": [
            {"id": "COR-old-storage", "kind": "credential_token_storage", "strength": "REVIEW", "title": "old", "summary": "old", "object_ids": [f"file:{path}"], "observation_ids": [], "review_identity": stor_rid, "generation_source": "legacy_bridge", "drives_review": False, "drives_finding": False},
            {"id": "COR-old-comm", "kind": "cleartext_application_endpoint", "strength": "REVIEW", "title": "old", "summary": "old", "object_ids": [f"application_endpoint:{endpoint}"], "observation_ids": [], "review_identity": comm_rid, "generation_source": "legacy_bridge", "drives_review": False, "drives_finding": False},
        ],
    })
    merged = merge_runtime_security_model(tmp_path, {})
    assert merged["schema_version"] == 10
    rules = {x["kind"]: x for x in merged["correlations"]}
    assert rules["credential_token_storage"]["rule_id"] == "CORR-STOR-CREDENTIAL"
    assert rules["credential_token_storage"]["drives_review"] is True
    assert rules["cleartext_application_endpoint"]["rule_id"] == "CORR-COMM-CLEARTEXT"
    assert rules["cleartext_application_endpoint"]["drives_review"] is True
    assert not rules["credential_token_storage"]["drives_finding"]
    assert not rules["cleartext_application_endpoint"]["drives_finding"]
