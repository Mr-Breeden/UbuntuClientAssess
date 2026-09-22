from pathlib import Path

from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, ensure_assessment_layout, report_path, write_json
from modules.security_model import MODEL_SCHEMA_VERSION, build_security_model, merge_runtime_security_model
from modules.tester_review import generate_tester_review, merge_additional_review_items, stable_review_identity
from modules.consolidated_report import generate_consolidated_report


def _setup(tmp_path: Path) -> None:
    ensure_assessment_layout(tmp_path)


def test_v160_version_and_schema_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_runtime_external_listener_is_correlation_owned_and_review_only(tmp_path: Path):
    _setup(tmp_path)
    profile = {"primary_technology": "Python"}
    build_security_model(tmp_path, profile_data=profile)
    generate_tester_review(tmp_path, profile_data=profile)
    line = "tcp LISTEN 0 8 0.0.0.0:18080 0.0.0.0:* users:((\"python3\",pid=1234,fd=3))"
    runtime = {
        "listeners": [line],
        "externally_bound_listeners": [line],
        "application_processes": [{"pid": 1234, "command": "python3 /opt/vendor/service.py", "user": "root"}],
    }
    model = merge_runtime_security_model(tmp_path, runtime, profile)
    corr = next(x for x in model["correlations"] if x["kind"] == "runtime_application_listener")
    assert corr["rule_id"] == "CORR-NET-RUNTIME-LISTENER"
    assert corr["generation_source"] == "correlation_engine"
    assert corr["drives_review"] is True
    assert corr["drives_finding"] is False
    state = merge_additional_review_items(tmp_path, profile_data=profile, runtime_data=runtime)
    expected = stable_review_identity("RUNTIME", f"runtime-listener:{line}")
    item = next(x for x in state["items"] if x["identity"] == expected)
    assert item["generation_source"] == "correlation_engine"
    assert item["correlation_rule"] == "CORR-NET-RUNTIME-LISTENER"
    assert item["runtime_confirmed"] is True
    assert item["priority"] == "MEDIUM"


def test_runtime_listener_does_not_create_duplicate_legacy_item(tmp_path: Path):
    _setup(tmp_path)
    profile = {"primary_technology": "Python"}
    build_security_model(tmp_path, profile_data=profile)
    generate_tester_review(tmp_path, profile_data=profile)
    line = "tcp LISTEN 0 8 0.0.0.0:9000 0.0.0.0:*"
    runtime = {"listeners": [line], "externally_bound_listeners": [line]}
    merge_runtime_security_model(tmp_path, runtime, profile)
    state = merge_additional_review_items(tmp_path, profile_data=profile, runtime_data=runtime)
    matches = [x for x in state["items"] if x["title"] == "Runtime Application Listener Requires Validation"]
    assert len(matches) == 1
    assert matches[0]["generation_source"] == "correlation_engine"


def test_technology_plan_remains_workflow_generated(tmp_path: Path):
    _setup(tmp_path)
    profile = {"primary_technology": "Python", "supporting_technologies": []}
    build_security_model(tmp_path, profile_data=profile)
    state = generate_tester_review(tmp_path, profile_data=profile)
    tech = next(x for x in state["items"] if x["category"] == "TECH")
    assert tech.get("generation_source") != "correlation_engine"


def test_dashboard_filters_hide_nonmatches_reorder_and_scroll_to_top(tmp_path: Path):
    _setup(tmp_path)
    write_json(tmp_path / "working" / "tester_review_state.json", {"items": [
        {"id": "TRQ-001", "identity": "one", "category": "ELF", "priority": "HIGH", "title": "One", "status": "VALIDATED", "condition": "one", "why_it_matters": "one", "generation_source": "correlation_engine"},
        {"id": "TRQ-002", "identity": "two", "category": "TECH", "priority": "LOW", "title": "Two", "status": "PENDING", "condition": "two", "why_it_matters": "two"},
    ]})
    write_json(tmp_path / "working" / "security_model.json", {"schema_version": 7, "objects": [], "observations": [], "relationships": [], "correlations": []})
    write_json(tmp_path / "working" / "finding_candidates.json", {"findings": [], "manual_review": []})
    generate_consolidated_report(tmp_path, "Dashboard", None, "full", VERSION, {})
    html = report_path(tmp_path, "assessment_report.html").read_text(encoding="utf-8")
    assert '.queue-item[hidden]{display:none!important}' in html
    assert 'data-order="0"' in html and 'data-order="1"' in html
    assert 'const matched=[],unmatched=[]' in html
    assert '[...matched,...unmatched].forEach(el=>queue.appendChild(el))' in html
    assert 'queue.scrollTop=0' in html
    assert 'select(matched[0]||null)' in html


def test_guided_review_source_contains_compact_progress_counter():
    source = (Path(__file__).resolve().parents[1] / "ubuntuclientassess.py").read_text(encoding="utf-8")
    assert 'Review progress: {completed} / {len(fresh_items)} completed | {remaining} pending' in source
