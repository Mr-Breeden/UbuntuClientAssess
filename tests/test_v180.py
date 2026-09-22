from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION
from modules.security_model import MODEL_SCHEMA_VERSION
from modules.tester_review import decorate_review_items, category_progress, review_category
from modules.consolidated_report import _review_workspace
from pathlib import Path


def test_v180_contract_keeps_engine_schema_stable():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_review_items_receive_security_area_group_and_shared_context():
    items = decorate_review_items([
        {"id":"TRQ-001","category":"SVC","priority":"HIGH","title":"Service path","service_unit":"demo.service","status":"PENDING"},
        {"id":"TRQ-002","category":"SVC","priority":"HIGH","title":"Service path 2","service_unit":"demo.service","status":"VALIDATED"},
        {"id":"TRQ-003","category":"COMM","priority":"MEDIUM","title":"HTTP endpoint","status":"PENDING"},
    ])
    assert items[0]["review_category"] == "Services"
    assert items[0]["review_group"] == items[1]["review_group"]
    assert "demo.service" in items[0]["review_group_label"]
    assert items[0]["shared_validation"]
    assert review_category(items[2]) == "Network & Communications"
    progress = {x["category"]: x for x in category_progress(items)}
    assert progress["Services"] == {"category":"Services","total":2,"completed":1,"pending":1}


def test_runtime_ipc_maps_to_ipc_area():
    item = decorate_review_items([{"category":"RUNTIME-IPC","priority":"MEDIUM","title":"Runtime IPC","status":"PENDING"}])[0]
    assert item["review_category"] == "IPC & Authorization"


def test_tester_html_workspace_mirrors_category_and_group(tmp_path: Path):
    items = decorate_review_items([
        {"id":"TRQ-001","category":"SVC","priority":"HIGH","title":"Service path","service_unit":"demo.service","status":"PENDING","condition":"/opt/demo","why_it_matters":"boundary"},
        {"id":"TRQ-002","category":"SVC","priority":"HIGH","title":"Service path 2","service_unit":"demo.service","status":"VALIDATED","condition":"/opt/demo/lib","why_it_matters":"boundary"},
    ])
    html = _review_workspace(items, tmp_path, {})
    assert "Services" in html
    assert "Service: demo.service" in html
    assert "Shared validation context" in html
    assert "Related review items" in html
    assert 'id="filter-category"' in html
