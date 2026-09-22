import json
from datetime import datetime, timezone
from pathlib import Path

import modules.application_service as application_service
from modules.application_service import ServiceResult, UbuntuClientAssessService
from modules.common import VERSION
from modules.web_gui import INDEX_HTML


def test_v202_release_contract():
    assert VERSION == "2.0.6"


def test_service_result_recursively_normalizes_non_json_values(tmp_path: Path):
    result = ServiceResult(True, "ok", data={
        "path": tmp_path / "ClientAppendix",
        "nested": {"paths": (tmp_path / "a", tmp_path / "b")},
        "set_value": {"b", "a"},
        "when": datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc),
    }).as_dict()
    encoded = json.dumps(result)
    assert str(tmp_path / "ClientAppendix") in encoded
    assert result["data"]["path"] == str(tmp_path / "ClientAppendix")
    assert isinstance(result["data"]["nested"]["paths"], list)
    assert isinstance(result["data"]["set_value"], list)
    assert result["data"]["when"].startswith("2026-09-21T12:00:00")



def test_client_appendix_service_result_is_json_serializable(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(application_service, "create_client_appendix", lambda assessment: {
        "path": assessment / "ClientAppendix",
        "generated": ("README.txt", "SHA256SUMS.txt"),
    })
    monkeypatch.setattr(application_service, "assessment_revision", lambda assessment: "revision-token")
    result = UbuntuClientAssessService().create_client_appendix(tmp_path)
    assert result.ok is True
    payload = result.as_dict()
    assert payload["data"]["path"] == str(tmp_path / "ClientAppendix")
    assert payload["data"]["generated"] == ["README.txt", "SHA256SUMS.txt"]
    json.dumps(payload)

def test_guided_review_has_independent_scrolling_and_status_filters():
    assert 'class="split reviewSplit"' in INDEX_HTML
    assert 'class="reviewList"' in INDEX_HTML
    assert '.reviewList{overflow-y:auto' in INDEX_HTML
    assert '.reviewGuide{flex:1' in INDEX_HTML
    assert 'id="statusFilter"' in INDEX_HTML
    for value in ("PENDING", "VALIDATED", "NOT APPLICABLE", "INFORMATIONAL"):
        assert value in INDEX_HTML


def test_guided_review_has_disposition_highlighting_and_combined_filtering():
    for css_class in (
        "review-item-pending",
        "review-item-validated",
        "review-item-na",
        "review-item-informational",
    ):
        assert css_class in INDEX_HTML
    assert "filteredReviewItems()" in INDEX_HTML
    assert "x.status===status" in INDEX_HTML
    assert "x.category===category" in INDEX_HTML


def test_review_actions_remain_outside_scrolling_guidance():
    assert '<div class="reviewGuide">' in INDEX_HTML
    assert '<div class="reviewActions">' in INDEX_HTML
    assert '.reviewActions{flex:none' in INDEX_HTML
