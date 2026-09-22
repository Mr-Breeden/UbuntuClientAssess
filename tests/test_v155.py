from pathlib import Path

from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, ensure_assessment_layout
from modules.security_model import MODEL_SCHEMA_VERSION, build_security_model
from modules.tester_review import generate_tester_review, stable_review_identity
from modules.findings import generate_findings


def _setup(tmp_path: Path) -> None:
    ensure_assessment_layout(tmp_path)


def test_v155_version_and_model_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_permission_boundary_review_is_correlation_owned(tmp_path: Path):
    _setup(tmp_path)
    path = "/opt/vendor/config"
    permission_data = {"high_interest_candidates": [{
        "path": path, "type": "directory", "owner": "root", "group": "root", "mode": "0777",
        "level": "HIGH INTEREST", "concerns": "World-writable object; Current tester has effective write access to root-owned object",
        "concern_list": ["World-writable object", "Current tester has effective write access to root-owned object"],
    }]}
    model = build_security_model(tmp_path, permission_data=permission_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "permission_boundary")
    assert corr["rule_id"] == "CORR-PERM-BOUNDARY"
    assert corr["generation_source"] == "correlation_engine"
    assert corr["drives_review"] is True and corr["drives_finding"] is False

    state = generate_tester_review(tmp_path, permission_data=permission_data)
    item = next(x for x in state["items"] if x["identity"] == stable_review_identity("PERM", path))
    assert item["generation_source"] == "correlation_engine"
    assert item["priority"] == "HIGH"
    assert item["object_identity"] == path


def test_service_consumed_permission_does_not_create_generic_permission_correlation(tmp_path: Path):
    _setup(tmp_path)
    path = "/etc/vendor/client.conf"
    permission_data = {"high_interest_candidates": [{
        "path": path, "type": "file", "owner": "root", "group": "root", "mode": "0666",
        "level": "HIGH INTEREST", "concerns": "World-writable object", "concern_list": ["World-writable object"],
    }]}
    service_data = {"risk_candidates": [{
        "unit": "vendor.service", "path": path, "path_type": "EnvironmentFile", "privileged": True,
        "concerns": "World-writable object",
    }]}
    model = build_security_model(tmp_path, permission_data=permission_data, service_data=service_data)
    assert not [x for x in model["correlations"] if x["kind"] == "permission_boundary" and x["review_identity"] == stable_review_identity("PERM", path)]
    assert [x for x in model["correlations"] if x["kind"] == "privileged_service_writable_path"]
    state = generate_tester_review(tmp_path, permission_data=permission_data, service_data=service_data)
    assert not [x for x in state["items"] if x["identity"] == stable_review_identity("PERM", path)]


def test_file_capability_review_is_correlation_owned(tmp_path: Path):
    _setup(tmp_path)
    raw = "/opt/vendor/bin/helper cap_net_bind_service=ep"
    permission_data = {"capability_candidates": [{"entry": raw}]}
    model = build_security_model(tmp_path, permission_data=permission_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "file_capability_boundary")
    assert corr["rule_id"] == "CORR-CAP-FILE"
    assert corr["drives_review"] is True and corr["drives_finding"] is False
    state = generate_tester_review(tmp_path, permission_data=permission_data)
    item = next(x for x in state["items"] if x["identity"] == stable_review_identity("CAP", raw))
    assert item["generation_source"] == "correlation_engine"


def test_suid_helper_review_is_correlation_owned(tmp_path: Path):
    _setup(tmp_path)
    raw = "/opt/vendor/bin/suid-helper"
    permission_data = {"suid_candidates": [{"entry": raw}]}
    model = build_security_model(tmp_path, permission_data=permission_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "suid_sgid_helper_boundary")
    assert corr["rule_id"] == "CORR-SUID-HELPER"
    assert corr["drives_review"] is True and corr["drives_finding"] is False
    state = generate_tester_review(tmp_path, permission_data=permission_data)
    item = next(x for x in state["items"] if x["identity"] == stable_review_identity("SUID", raw))
    assert item["generation_source"] == "correlation_engine"
    assert item["priority"] == "HIGH"


def test_changed_sudoers_policy_review_is_correlation_owned(tmp_path: Path):
    _setup(tmp_path)
    path = "/etc/sudoers.d/vendor"
    identity = f"sudoers-review:{path}"
    persistence_data = {"review_required": [{
        "identity": identity,
        "title": "Changed sudoers Policy Requires Manual Review",
        "evidence": f"{path} was added (root:root, 0o440).",
        "action": "Inspect the exact policy with administrative read access and validate it with visudo.",
    }]}
    model = build_security_model(tmp_path, persistence_data=persistence_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "sudoers_policy_change")
    assert corr["rule_id"] == "CORR-SUDO-POLICY"
    assert corr["drives_review"] is True and corr["drives_finding"] is False
    state = generate_tester_review(tmp_path, persistence_data=persistence_data)
    item = next(x for x in state["items"] if x["identity"] == stable_review_identity("PERS", identity))
    assert item["generation_source"] == "correlation_engine"


def test_risky_sudo_rule_review_and_finding_are_correlation_owned(tmp_path: Path):
    _setup(tmp_path)
    command = "/opt/vendor/bin/helper *"
    persistence_data = {"sudo_policy_candidates": [{
        "finding_candidate": True, "command": command, "runas": "root",
        "concerns": ["wildcards broaden caller-controlled arguments or paths"], "severity": "High",
    }]}
    model = build_security_model(tmp_path, persistence_data=persistence_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "unsafe_sudo_policy")
    assert corr["rule_id"] == "CORR-SUDO-RULE"
    assert corr["generation_source"] == "correlation_engine"
    assert corr["drives_review"] is True
    assert corr["drives_finding"] is True

    state = generate_tester_review(tmp_path, persistence_data=persistence_data)
    rid = stable_review_identity("PERS", f"sudo-candidate:root:{command}")
    item = next(x for x in state["items"] if x["identity"] == rid)
    assert item["generation_source"] == "correlation_engine"

    findings = generate_findings(tmp_path, {}, {}, {}, {}, {}, {}, persistence_data)
    sudo_findings = [x for x in findings if x.get("category") == "PERS"]
    assert sudo_findings
    assert all(x.get("generation_source") == "correlation_engine" for x in sudo_findings)


def test_schema4_sudo_correlation_migrates_to_v155_review_ownership(tmp_path: Path):
    from modules.common import write_json
    from modules.security_model import merge_runtime_security_model
    _setup(tmp_path)
    command = "/opt/vendor/bin/helper *"
    rid = stable_review_identity("PERS", f"sudo-candidate:root:{command}")
    write_json(tmp_path / "working" / "security_model.json", {
        "schema_version": 4,
        "objects": [{"id": f"sudo_rule:root:{command}", "kind": "sudo_rule", "identity": f"root:{command}", "attributes": {"runas": "root", "command": command}}],
        "observations": [], "relationships": [],
        "correlations": [{
            "id": "COR-old-sudo", "kind": "unsafe_sudo_policy", "strength": "STRONG",
            "title": "old", "summary": "old", "object_ids": [f"sudo_rule:root:{command}"], "observation_ids": [],
            "review_identity": rid, "finding_identity": f"sudo:root:{command}",
            "generation_source": "legacy_bridge", "drives_review": False, "drives_finding": False,
        }],
    })
    merged = merge_runtime_security_model(tmp_path, {})
    corr = next(x for x in merged["correlations"] if x["kind"] == "unsafe_sudo_policy")
    assert merged["schema_version"] == 10
    assert corr["generation_source"] == "correlation_engine"
    assert corr["rule_id"] == "CORR-SUDO-RULE"
    assert corr["drives_review"] is True
    assert corr["drives_finding"] is True
