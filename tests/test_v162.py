from pathlib import Path

from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, write_json
from modules.security_model import MODEL_SCHEMA_VERSION, build_security_model
from modules.tester_review import build_review_items, generate_tester_review, merge_additional_review_items
from modules.assessment_coverage import generate_assessment_coverage
from modules.client_appendix import _readme


def test_v162_release_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_structured_queue_uses_correlation_source_and_workflow_guidance(tmp_path: Path):
    permission_data = {"review_candidates": [{"path": "/opt/app/config", "concerns": "world-writable object", "level": "REVIEW", "type": "file"}]}
    profile_data = {"application_name": "Example", "primary_technology": "Python", "supporting_technologies": [], "technologies": [{"technology": "Python", "guidance": ["Review Python-specific behavior."]}]}
    model = build_security_model(tmp_path, permission_data=permission_data, profile_data=profile_data)
    items = build_review_items(permission_data=permission_data, profile_data=profile_data, correlation_model=model)
    perm = next(x for x in items if x["category"] == "PERM")
    tech = next(x for x in items if x["category"] == "TECH")
    assert perm["generation_source"] == "correlation_engine"
    assert tech["generation_source"] == "workflow_guidance"
    assert len([x for x in items if x["category"] == "PERM"]) == 1


def test_missing_structured_model_keeps_compatibility_generation(tmp_path: Path):
    items = build_review_items(permission_data={"review_candidates": [{"path": "/opt/app/config", "concerns": "writable", "level": "REVIEW"}]})
    assert any(x["category"] == "PERM" for x in items)


def test_runtime_correlation_supersedes_equivalent_fallback_and_preserves_id(tmp_path: Path):
    initial = generate_tester_review(tmp_path, network_data={"exposed_listener_candidates": ["tcp LISTEN 0 8 0.0.0.0:9000 0.0.0.0:*"]})
    old = initial["items"][0]
    old_id = old["id"]
    old["status"] = "VALIDATED"
    write_json(tmp_path / "working" / "tester_review_state.json", initial)
    runtime = {"listeners": ["tcp LISTEN 0 8 0.0.0.0:9000 0.0.0.0:*"], "externally_bound_listeners": ["tcp LISTEN 0 8 0.0.0.0:9000 0.0.0.0:*"]}
    build_security_model(tmp_path, profile_data={"application_name": "Example"}, runtime_data=runtime)
    merged = merge_additional_review_items(tmp_path, runtime_data=runtime)
    item = next(x for x in merged["items"] if x.get("object_type") == "listener")
    assert item["id"] == old_id
    assert item["status"] == "VALIDATED"
    assert item["generation_source"] == "correlation_engine"
    assert item["runtime_confirmed"] is True


def test_coverage_summary_does_not_truncate_long_privilege_title(tmp_path: Path):
    (tmp_path / "working").mkdir(parents=True, exist_ok=True)
    write_json(tmp_path / "working" / "tester_review_state.json", {"items": []})
    generate_assessment_coverage(tmp_path, "full", {})
    text = (tmp_path / "reports" / "assessment_coverage.txt").read_text(encoding="utf-8")
    assert "Privileged Helpers / Local Privilege Boundaries" in text


def test_client_appendix_readme_uses_coverage_wording():
    text = _readme("Example", "2.0.6", "full", [])
    assert "tester workflow and assessment-coverage artifacts" in text
    assert "tester test cases" not in text
