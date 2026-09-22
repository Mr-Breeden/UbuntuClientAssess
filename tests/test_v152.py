from pathlib import Path

from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, ensure_assessment_layout, read_json
from modules.findings import generate_findings
from modules.security_model import MODEL_SCHEMA_VERSION, build_security_model
from modules.tester_review import generate_tester_review, stable_review_identity


def _setup(tmp_path: Path) -> None:
    ensure_assessment_layout(tmp_path)


def test_v152_version_and_model_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_service_candidate_is_owned_by_correlation_engine(tmp_path: Path):
    _setup(tmp_path)
    path = "/opt/vendor/config/client.conf"
    permission_data = {
        "high_interest_candidates": [{
            "path": path, "type": "file", "owner": "root", "group": "root", "mode": "0666",
            "level": "HIGH INTEREST", "concerns": "world-writable", "concern_list": ["world-writable"],
        }]
    }
    service_data = {"risk_candidates": [{
        "unit": "vendor.service", "path": path, "path_type": "EnvironmentFile",
        "privileged": True, "concerns": "world-writable",
    }]}
    build_security_model(tmp_path, permission_data=permission_data, service_data=service_data)
    state = generate_tester_review(tmp_path, permission_data=permission_data, service_data=service_data)
    findings = generate_findings(tmp_path, permission_data, {}, service_data, {}, {}, {}, {})

    rid = stable_review_identity("SVC", f"vendor.service:EnvironmentFile:{path}")
    matches = [x for x in state["items"] if x["identity"] == rid]
    assert len(matches) == 1
    assert matches[0]["generation_source"] == "correlation_engine"
    assert matches[0]["correlation_rule"] == "CORR-SVC-WRITABLE-PATH"
    assert matches[0]["supporting_observation_ids"]

    f = next(x for x in findings if x["identity"] == f"service:vendor.service:EnvironmentFile:{path}")
    assert f["generation_source"] == "correlation_engine"
    assert f["review_identity"] == rid


def test_equivalent_elf_candidate_is_owned_and_consolidated(tmp_path: Path):
    _setup(tmp_path)
    elf_data = {"finding_candidates": [
        {"binary": "/opt/vendor/a", "kind": "RPATH", "path": "/opt/vendor/lib", "concern": "writable search path", "finding_candidate": True},
        {"binary": "/opt/vendor/b", "kind": "RPATH", "path": "/opt/vendor/lib", "concern": "writable search path", "finding_candidate": True},
    ]}
    build_security_model(tmp_path, elf_data=elf_data)
    state = generate_tester_review(tmp_path, elf_data=elf_data)
    findings = generate_findings(tmp_path, {}, {}, {}, elf_data, {}, {}, {})

    owned_reviews = [x for x in state["items"] if x.get("generation_source") == "correlation_engine" and x["category"] == "ELF"]
    assert len(owned_reviews) == 1
    assert owned_reviews[0]["validation_targets"] == ["/opt/vendor/a", "/opt/vendor/b"]
    owned_findings = [x for x in findings if x.get("generation_source") == "correlation_engine" and x["category"] == "ELF"]
    assert len(owned_findings) == 1
    assert owned_findings[0]["validation_targets"] == ["/opt/vendor/a", "/opt/vendor/b"]


def test_cleartext_update_correlation_preserves_multiple_locations(tmp_path: Path):
    _setup(tmp_path)
    url = "http://updates.vendor.test/latest"
    update_data = {"insecure_update_url_candidates": [
        {"url": url, "path": "/opt/vendor/a.conf", "line": 3, "confidence": "high"},
        {"url": url, "path": "/etc/vendor/b.conf", "line": 8, "confidence": "medium"},
    ]}
    model = build_security_model(tmp_path, update_data=update_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "cleartext_update_path")
    assert corr["generation_source"] == "correlation_engine"
    assert corr["drives_review"] is True and corr["drives_finding"] is True
    assert len(corr["observation_ids"]) == 2

    state = generate_tester_review(tmp_path, update_data=update_data)
    findings = generate_findings(tmp_path, {}, {}, {}, {}, {}, update_data, {})
    review = next(x for x in state["items"] if x["identity"] == stable_review_identity("UPD", url))
    assert review["generation_source"] == "correlation_engine"
    finding = next(x for x in findings if x["identity"] == f"update:{url}")
    assert "/opt/vendor/a.conf:3" in finding["evidence"]
    assert "/etc/vendor/b.conf:8" in finding["evidence"]


def test_sudo_candidate_migrates_review_and_finding_ownership(tmp_path: Path):
    _setup(tmp_path)
    persistence_data = {"sudo_policy_candidates": [{
        "finding_candidate": True, "command": "/opt/vendor/bin/helper *", "runas": "root",
        "concerns": ["broad privileged command"], "severity": "High",
    }]}
    model = build_security_model(tmp_path, persistence_data=persistence_data)
    sudo_corr = next(x for x in model["correlations"] if x["kind"] == "unsafe_sudo_policy")
    assert sudo_corr["generation_source"] == "correlation_engine"
    assert sudo_corr["drives_review"] is True
    assert sudo_corr["drives_finding"] is True

    state = generate_tester_review(tmp_path, persistence_data=persistence_data)
    sudo_reviews = [x for x in state["items"] if x["category"] == "PERS" and "sudo" in x["title"].casefold()]
    assert sudo_reviews
    assert all(x.get("generation_source") == "correlation_engine" for x in sudo_reviews)
    sudo_findings = [x for x in generate_findings(tmp_path, {}, {}, {}, {}, {}, {}, persistence_data) if x["category"] == "PERS"]
    assert sudo_findings
    assert all(x.get("generation_source") == "correlation_engine" for x in sudo_findings)

def test_correlation_provenance_is_rendered_for_tester(tmp_path: Path):
    _setup(tmp_path)
    url = "http://updates.vendor.test/latest"
    update_data = {"insecure_update_url_candidates": [{"url": url, "path": "/opt/vendor/update.conf", "line": 4, "confidence": "high"}]}
    build_security_model(tmp_path, update_data=update_data)
    generate_tester_review(tmp_path, update_data=update_data)
    generate_findings(tmp_path, {}, {}, {}, {}, {}, update_data, {})

    review_text = (tmp_path / "reports" / "tester_review.txt").read_text(encoding="utf-8")
    finding_text = (tmp_path / "reports" / "findings.txt").read_text(encoding="utf-8")
    assert "Generation:  Correlation Engine" in review_text
    assert "CORR-UPD-CLEARTEXT" in review_text
    assert "Supporting Observations:" in review_text
    assert "Generation:     Correlation Engine" in finding_text
    assert "CORR-UPD-CLEARTEXT" in finding_text
    assert "Observations:" in finding_text


def test_correlation_model_is_synchronized_after_candidates(tmp_path: Path):
    from modules.security_model import synchronize_security_model
    _setup(tmp_path)
    url = "http://updates.vendor.test/latest"
    update_data = {"insecure_update_url_candidates": [{"url": url, "path": "/opt/vendor/update.conf", "line": 4, "confidence": "high"}]}
    build_security_model(tmp_path, update_data=update_data)
    generate_tester_review(tmp_path, update_data=update_data)
    generate_findings(tmp_path, {}, {}, {}, {}, {}, update_data, {})
    synced = synchronize_security_model(tmp_path)
    corr = next(x for x in synced["correlations"] if x["kind"] == "cleartext_update_path")
    assert corr["review_id"].startswith("TRQ-")
    assert corr["finding_id"].startswith("UAF-")
    assert corr["review_status"] == "PENDING"

def test_schema2_correlation_migrates_to_v152_authoritative_metadata(tmp_path: Path):
    from modules.common import write_json
    from modules.security_model import merge_runtime_security_model
    _setup(tmp_path)
    review_identity = stable_review_identity("UPD", "http://updates.vendor.test/latest")
    write_json(tmp_path / "working" / "security_model.json", {
        "schema_version": 2,
        "objects": [{"id": "update_endpoint:http://updates.vendor.test/latest", "kind": "update_endpoint", "identity": "http://updates.vendor.test/latest", "attributes": {}}],
        "observations": [], "relationships": [],
        "correlations": [{
            "id": "COR-old", "kind": "cleartext_update_path", "strength": "REVIEW",
            "title": "old", "summary": "old",
            "object_ids": ["update_endpoint:http://updates.vendor.test/latest"], "observation_ids": [],
            "review_identity": review_identity, "finding_identity": "update:http://updates.vendor.test/latest",
        }],
    })
    merged = merge_runtime_security_model(tmp_path, {})
    corr = next(x for x in merged["correlations"] if x["kind"] == "cleartext_update_path")
    assert merged["schema_version"] == 10
    assert corr["generation_source"] == "correlation_engine"
    assert corr["rule_id"] == "CORR-UPD-CLEARTEXT"
    assert corr["drives_review"] is True and corr["drives_finding"] is True
