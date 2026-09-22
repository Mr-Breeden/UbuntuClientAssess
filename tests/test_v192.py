from pathlib import Path

import pytest

from modules.application_service import ServiceResult, UbuntuClientAssessService
from modules.common import (
    EXPECTED_REPORTS_BY_MODE,
    METHODOLOGY_VERSION,
    TEST_CASE_CATALOG_VERSION,
    VERSION,
    ensure_assessment_layout,
    report_path,
    write_json,
    write_text,
)
from modules.security_model import MODEL_SCHEMA_VERSION
from modules.state_guard import (
    AssessmentBusyError,
    StateTransaction,
    assessment_lock,
    pending_transaction,
    recover_interrupted_transaction,
)


def test_v192_release_contract_keeps_assessment_semantics_stable():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_assessment_lock_rejects_concurrent_incompatible_access(tmp_path: Path):
    with assessment_lock(tmp_path, "writer-one", exclusive=True):
        with pytest.raises(AssessmentBusyError):
            with assessment_lock(tmp_path, "reader-two", exclusive=False):
                pass


def test_state_transaction_rolls_back_modified_and_created_files(tmp_path: Path):
    original = tmp_path / "working" / "state.json"
    created = tmp_path / "reports" / "new.txt"
    original.parent.mkdir(parents=True)
    created.parent.mkdir(parents=True)
    original.write_text("before\n", encoding="utf-8")

    with pytest.raises(RuntimeError):
        with StateTransaction(tmp_path, "test rollback", [original, created], base_revision="abc"):
            original.write_text("after\n", encoding="utf-8")
            created.write_text("created\n", encoding="utf-8")
            raise RuntimeError("simulated failure")

    assert original.read_text(encoding="utf-8") == "before\n"
    assert not created.exists()
    assert pending_transaction(tmp_path) is None


def test_hard_interruption_journal_can_restore_last_consistent_state(tmp_path: Path):
    original = tmp_path / "working" / "state.json"
    original.parent.mkdir(parents=True)
    original.write_text("before\n", encoding="utf-8")

    tx = StateTransaction(tmp_path, "simulated interrupted write", [original], base_revision="base")
    tx.__enter__()
    original.write_text("partial\n", encoding="utf-8")
    assert pending_transaction(tmp_path)["operation"] == "simulated interrupted write"

    recovered = recover_interrupted_transaction(tmp_path)
    assert recovered["operation"] == "simulated interrupted write"
    assert original.read_text(encoding="utf-8") == "before\n"
    assert pending_transaction(tmp_path) is None


def test_service_rejects_stale_review_revision(monkeypatch, tmp_path: Path):
    import modules.application_service as svc

    write_json(tmp_path / "assessment_metadata.json", {"mode": "full", "marker": 1})
    service = UbuntuClientAssessService()
    revision = service.state_revision(tmp_path).data["revision"]
    write_json(tmp_path / "assessment_metadata.json", {"mode": "full", "marker": 2})

    # A stale token must be rejected before any review write executes.
    monkeypatch.setattr(svc, "update_review_item", lambda *a, **k: pytest.fail("stale write reached update_review_item"))
    result = service.save_review_item(tmp_path, "identity", status="VALIDATED", expected_revision=revision)
    assert result.ok is False
    assert result.code == "stale-state"
    assert result.data["current_revision"] != revision


def test_status_surfaces_interrupted_transaction_recovery(tmp_path: Path):
    write_json(tmp_path / "assessment_metadata.json", {"mode": "full", "assessment_name": "Example"})
    state = tmp_path / "working" / "state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text("before\n", encoding="utf-8")
    tx = StateTransaction(tmp_path, "review save", [state], base_revision="base")
    tx.__enter__()
    state.write_text("partial\n", encoding="utf-8")

    result = UbuntuClientAssessService().assessment_status(tmp_path)
    assert result.ok is False
    assert result.code == "status-interrupted-write"
    assert result.data["action"] == "recover-transaction"
    recover_interrupted_transaction(tmp_path)


def test_manifest_inventory_revision_is_stable_for_unchanged_state(tmp_path: Path):
    from modules.artifacts import finalize_artifact_manifest, verify_artifact_manifest

    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "assessment_metadata.json", {"version": VERSION, "mode": "full"})
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 5})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 5})
    write_json(tmp_path / "working" / "tester_review_state.json", {"schema_version": 1, "framework_version": VERSION, "items": []})
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"artifact_manifest.txt"}:
        write_text(report_path(tmp_path, name), f"complete {name}")

    first = finalize_artifact_manifest(tmp_path, "full")
    second = finalize_artifact_manifest(tmp_path, "full")
    assert first["inventory_revision"] == second["inventory_revision"]
    assert verify_artifact_manifest(tmp_path) == []


def test_runtime_collector_can_defer_persistence_to_service(monkeypatch, tmp_path: Path):
    import modules.runtime_observation as runtime

    monkeypatch.setattr(runtime, "_invoke_sample", lambda elevated=False: {"processes": [], "listeners": [], "connections": [], "unix_sockets": []})
    monkeypatch.setattr(runtime, "_connection_lines", lambda elevated=False: [])
    result = runtime.collect_runtime_observation(tmp_path, duration_seconds=0, persist=False)
    assert result["sample_count"] == 1
    assert not (tmp_path / "working" / "runtime_observation.json").exists()


def test_cli_uses_revision_tokens_and_exposes_recovery_command():
    source = Path("ubuntuclientassess.py").read_text(encoding="utf-8")
    assert "expected_revision=review_revision or None" in source
    assert "expected_revision=runtime_base_revision or None" in source
    assert "persist=False" in source
    assert "--recover-interrupted-operation" in source
