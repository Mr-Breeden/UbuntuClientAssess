from pathlib import Path

from modules.common import VERSION
from modules.web_gui import INDEX_HTML


def test_v201_release_contract():
    assert VERSION == "2.0.6"


def test_assessment_name_is_placeholder():
    assert 'id="newName" placeholder="Ubuntu Client Assessment"' in INDEX_HTML
    assert 'id="newName" value="Ubuntu Client Assessment"' not in INDEX_HTML


def test_guided_review_has_complete_scrollable_validation_guidance():
    service = Path("modules/application_service.py").read_text(encoding="utf-8")
    assert 'item["validation_procedure"]' in service
    assert 'render_playbook_lines(playbook)' in service
    assert '.reviewGuide{flex:1' in INDEX_HTML
    assert 'overflow-y:auto' in INDEX_HTML
    assert '<div class="reviewGuide">' in INDEX_HTML


def test_runtime_observation_has_live_progress_and_fresh_commit_revision():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert '"elapsed_seconds"' in source
    assert '"duration_seconds"' in source
    assert 'commit_verify = self.service.verify_assessment(assessment)' in source
    assert 'expected_revision=commit_revision or None' in source
    assert "p.phase==='runtime-observation'" in INDEX_HTML
