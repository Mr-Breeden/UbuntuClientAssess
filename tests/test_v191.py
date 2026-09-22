from pathlib import Path

from modules.application_service import ServiceResult, UbuntuClientAssessService
from modules.common import METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, VERSION, write_json
from modules.security_model import MODEL_SCHEMA_VERSION


def test_v191_release_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_application_service_is_presentation_neutral():
    source = Path("modules/application_service.py").read_text(encoding="utf-8")
    assert "rich." not in source
    assert "prompt_toolkit" not in source
    assert "Console(" not in source
    assert "Prompt." not in source
    assert "Confirm." not in source


def test_service_result_has_stable_serializable_shape():
    result = ServiceResult(True, "ok", "message", data={"count": 2}, errors=[])
    assert result.as_dict() == {
        "ok": True,
        "code": "ok",
        "message": "message",
        "data": {"count": 2},
        "errors": [],
    }


def test_review_snapshot_returns_categories_groups_and_progress(monkeypatch, tmp_path: Path):
    import modules.application_service as svc

    write_json(tmp_path / "assessment_metadata.json", {"mode": "full", "assessment_name": "Example"})
    monkeypatch.setattr(svc, "verify_artifact_manifest", lambda path: [])
    state = {
        "items": [
            {
                "id": "TRQ-001", "identity": "a", "status": "PENDING", "priority": "HIGH",
                "category": "ELF", "title": "One", "condition": "c", "review_category": "Privilege & Permissions",
                "review_group": "library:/opt/example/lib", "review_group_label": "Library: /opt/example/lib",
                "shared_validation": ["Reuse common directory evidence."],
            },
            {
                "id": "TRQ-002", "identity": "b", "status": "VALIDATED", "priority": "HIGH",
                "category": "ELF", "title": "Two", "condition": "c", "review_category": "Privilege & Permissions",
                "review_group": "library:/opt/example/lib", "review_group_label": "Library: /opt/example/lib",
                "shared_validation": ["Reuse common directory evidence."],
            },
        ]
    }
    monkeypatch.setattr(svc, "load_review_state", lambda path: state)

    result = UbuntuClientAssessService().review_snapshot(tmp_path)
    assert result.ok is True
    assert result.code == "review-ready"
    assert result.data["progress"] == {"total": 2, "completed": 1, "pending": 1}
    assert len(result.data["groups"]) == 1
    assert result.data["groups"][0]["item_ids"] == ["TRQ-001", "TRQ-002"]
    assert result.data["categories"][0]["total"] == 2


def test_save_review_item_owns_write_and_refresh_transaction(monkeypatch, tmp_path: Path):
    import modules.application_service as svc

    service = UbuntuClientAssessService()
    before = ServiceResult(True, "review-ready", data={"state": {"items": []}})
    monkeypatch.setattr(service, "_review_snapshot_unlocked", lambda path: before)
    state = {"items": [{
        "id": "TRQ-001", "identity": "abc", "status": "VALIDATED", "priority": "HIGH",
        "category": "ELF", "review_category": "Privilege & Permissions", "title": "Example", "condition": "c",
    }]}
    calls = []
    monkeypatch.setattr(svc, "update_review_item", lambda *a, **k: state)
    monkeypatch.setattr(service, "_refresh_review_outputs", lambda path: calls.append(Path(path)))

    result = service.save_review_item(tmp_path, "abc", status="VALIDATED", notes="checked")
    assert result.ok is True
    assert result.code == "review-saved"
    assert calls == [tmp_path.resolve()]
    assert result.data["progress"] == {"total": 1, "completed": 1, "pending": 0}
    assert result.data["category_progress"]["total"] == 1


def test_runtime_finalization_is_reusable_without_cli_prompts(monkeypatch, tmp_path: Path):
    import modules.application_service as svc

    write_json(tmp_path / "assessment_metadata.json", {"mode": "full", "application_path": "/opt/example/app"})
    calls = []
    for name in (
        "write_runtime_guidance", "update_ipc_with_runtime", "merge_runtime_security_model",
        "refresh_findings_dispositions", "synchronize_security_model", "refresh_assessment_coverage",
        "refresh_consolidated_report", "finalize_artifact_manifest",
    ):
        monkeypatch.setattr(svc, name, lambda *a, _name=name, **k: calls.append(_name))
    monkeypatch.setattr(svc, "merge_additional_review_items", lambda *a, **k: {"items": [{"status": "PENDING"}]})
    monkeypatch.setattr(svc, "verify_artifact_manifest", lambda path: [])

    observation = {
        "sample_count": 3,
        "application_processes": [{"pid": 1}],
        "connections": [{"remote": "127.0.0.1"}],
        "unix_sockets": ["/run/example.sock"],
        "fifo_paths": ["/run/example.fifo"],
    }
    result = UbuntuClientAssessService().finalize_runtime_observation(tmp_path, observation, {})
    assert result.ok is True
    assert result.data["pending_review_items"] == 1
    assert result.data["sample_count"] == 3
    assert "merge_runtime_security_model" in calls
    assert "finalize_artifact_manifest" in calls


def test_cli_consumes_shared_application_service():
    source = Path("ubuntuclientassess.py").read_text(encoding="utf-8")
    assert "service = UbuntuClientAssessService()" in source
    assert "service.review_snapshot(" in source
    assert "service.save_review_item(" in source
    assert "service.finalize_runtime_observation(" in source
    assert "service.create_client_appendix(" in source
    assert "service.verify_assessment(" in source
    assert "service.assessment_status(" in source
