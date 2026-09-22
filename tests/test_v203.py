from pathlib import Path

from modules.common import VERSION
from modules.web_gui import INDEX_HTML


def test_v203_release_contract():
    assert VERSION == "2.0.6"


def test_runtime_gui_is_manual_start_stop_not_timer_driven():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert "Stop & Save Observation" in INDEX_HTML
    assert "Cancel Observation" in INDEX_HTML
    assert 'id="runtimeSeconds"' not in INDEX_HTML
    assert "/api/runtime/stop" in source
    assert "/api/runtime/cancel" in source
    assert "duration_seconds=None" in source
    assert "wait_for_stop=wait_for_stop" in source


def test_runtime_gui_keeps_live_elapsed_counters_and_safety_limit():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert '"elapsed_seconds"' in source
    assert '"sample_count"' in source
    assert '"application_processes"' in source
    assert '"connections"' in source
    assert '"listeners"' in source
    assert 'job.stop_event.wait(MAX_OBSERVATION_SECONDS)' in source
    assert "safety_limit_reached" in source


def test_runtime_cancel_discards_before_service_finalization():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    cancel = source.index('if job and job.cancel_requested:')
    finalize = source.index('result = self.service.finalize_runtime_observation', cancel)
    assert cancel < finalize
    assert '"runtime-cancelled"' in source


def test_runtime_partial_progress_includes_sample_count():
    source = Path("modules/runtime_observation.py").read_text(encoding="utf-8")
    assert 'partial["sample_count"] = len(samples)' in source
    assert 'partial["duration_seconds"]' in source

from modules.web_gui import GuiJob, GuiState


def test_runtime_stop_and_cancel_controls_signal_active_job(tmp_path: Path):
    state = GuiState(tmp_path)
    stop_job = GuiJob(id="stop-job", kind="runtime-observation", assessment=str(tmp_path), status="running")
    cancel_job = GuiJob(id="cancel-job", kind="runtime-observation", assessment=str(tmp_path / "other"), status="running")
    state.jobs[stop_job.id] = stop_job
    state.jobs[cancel_job.id] = cancel_job

    returned = state.stop_runtime_job(stop_job.id, cancel=False)
    assert returned.status == "stopping"
    assert returned.stop_event.is_set()
    assert returned.cancel_requested is False

    returned = state.stop_runtime_job(cancel_job.id, cancel=True)
    assert returned.status == "cancelling"
    assert returned.stop_event.is_set()
    assert returned.cancel_requested is True


def test_runtime_job_dict_does_not_expose_threading_event(tmp_path: Path):
    job = GuiJob(id="job", kind="runtime-observation", assessment=str(tmp_path))
    payload = job.as_dict()
    assert "stop_event" not in payload
    assert "cancel_requested" not in payload


def test_runtime_active_job_can_be_rediscovered_after_page_navigation(tmp_path: Path):
    state = GuiState(tmp_path)
    assessment = (tmp_path / "assessment").resolve()
    job = GuiJob(id="active", kind="runtime-observation", assessment=str(assessment), status="running")
    state.jobs[job.id] = job
    assert state.active_runtime_job(assessment) is job
    assert "/api/runtime/active" in Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert "active.data.job" in INDEX_HTML
