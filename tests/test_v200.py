import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from modules.common import VERSION
from modules.web_gui import (
    DEFAULT_GUI_HOST,
    DEFAULT_GUI_PORT,
    GuiState,
    INDEX_HTML,
    UcaGuiServer,
    validate_gui_port,
)


def test_v200_release_and_default_gui_port():
    assert VERSION == "2.0.6"
    assert DEFAULT_GUI_HOST == "127.0.0.1"
    assert DEFAULT_GUI_PORT == 9001


def test_gui_port_override_validation():
    assert validate_gui_port(8765) == 8765
    assert validate_gui_port(1) == 1
    assert validate_gui_port(65535) == 65535
    with pytest.raises(ValueError):
        validate_gui_port(0)
    with pytest.raises(ValueError):
        validate_gui_port(65536)


def test_gui_html_exposes_major_workflows_without_external_assets():
    for phrase in (
        "Dashboard", "Guided Review", "Runtime Observation", "Reports",
        "Integrity & Recovery", "Client Appendix",
    ):
        assert phrase in INDEX_HTML
    assert "http://" not in INDEX_HTML
    assert "https://" not in INDEX_HTML


def test_gui_state_discovers_assessments(tmp_path: Path):
    assessment = tmp_path / "example"
    assessment.mkdir()
    (assessment / "assessment_metadata.json").write_text(json.dumps({
        "assessment_name": "Example",
        "mode": "full",
        "framework_version": VERSION,
        "methodology_version": "2.4",
        "run_state": {"status": "completed", "stage": "complete"},
        "installation": {"status": "completed"},
    }), encoding="utf-8")
    state = GuiState(tmp_path, token="test-token")
    found = state.discover_assessments()
    assert len(found) == 1
    assert found[0]["assessment_name"] == "Example"


def _serve(state: GuiState):
    server = UcaGuiServer((DEFAULT_GUI_HOST, 0), state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_gui_requires_launch_token_for_page_and_api(tmp_path: Path):
    state = GuiState(tmp_path, token="known-token")
    server, thread = _serve(state)
    host, port = server.server_address
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"http://{host}:{port}/", timeout=2)
        assert exc.value.code == 403

        req = urllib.request.Request(
            f"http://{host}:{port}/api/capabilities",
            headers={"X-UCA-Token": "known-token"},
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["ok"] is True
        assert payload["data"]["framework_version"] == "2.0.6"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_gui_page_contains_token_only_after_authorized_launch_url(tmp_path: Path):
    state = GuiState(tmp_path, token="known-token")
    server, thread = _serve(state)
    host, port = server.server_address
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/?token=known-token", timeout=2) as response:
            html = response.read().decode("utf-8")
        assert "const TOKEN='known-token'" in html
        assert "UbuntuClientAssess" in html
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_gui_source_is_loopback_only_and_has_security_headers_contract():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert 'DEFAULT_GUI_HOST = "127.0.0.1"' in source
    assert "X-Frame-Options" in source
    assert "Content-Security-Policy" in source
    assert "X-UCA-Token" in source
    assert "ThreadingHTTPServer" in source


def test_gui_v200_supports_browsing_and_new_assessment_workflow():
    for phrase in (
        "New Assessment", "Browse Filesystem", "Installer / Package",
        "Start Assessment", "Installation and Setup Complete — Continue",
        "Copy Command",
    ):
        assert phrase in INDEX_HTML
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert '"/api/fs/list"' in source
    assert '"/api/assessment/start"' in source
    assert '"/api/assessment/continue"' in source


def test_service_contract_exposes_gui_assessment_orchestration():
    from modules.application_service import UbuntuClientAssessService
    result = UbuntuClientAssessService().capabilities()
    names = {item["name"] for item in result.data["operations"]}
    assert "start_assessment" in names
    assert "continue_assessment" in names


def test_gui_auto_browser_launch_suppresses_child_output():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert 'subprocess.Popen(["xdg-open", url]' in source
    assert "stdout=subprocess.DEVNULL" in source
    assert "stderr=subprocess.DEVNULL" in source
    assert "webbrowser.open" not in source


def test_gui_filesystem_browser_lists_directories_and_deb_files(tmp_path: Path):
    (tmp_path / "folder").mkdir()
    (tmp_path / "package.deb").write_bytes(b"deb")
    (tmp_path / "ignore.txt").write_text("x", encoding="utf-8")
    state = GuiState(tmp_path, token="known-token")
    server, thread = _serve(state)
    host, port = server.server_address
    try:
        url = f"http://{host}:{port}/api/fs/list?path={urllib.parse.quote(str(tmp_path))}&mode=installer"
        req = urllib.request.Request(url, headers={"X-UCA-Token": "known-token"})
        with urllib.request.urlopen(req, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["ok"] is True
        assert {x["name"] for x in payload["data"]["directories"]} == {"folder"}
        assert {x["name"] for x in payload["data"]["files"]} == {"package.deb"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_gui_operational_tabs_share_selected_assessment_context():
    for phrase in (
        'id="assessmentPicker"',
        "ucaSelectedAssessment",
        "Selected Assessment",
        "reloadSelected()",
        "updateSelectedCards()",
    ):
        assert phrase in INDEX_HTML


def test_gui_client_appendix_is_separate_top_level_tab():
    assert '<button data-view="appendix">Client Appendix</button>' in INDEX_HTML
    assert '<section id="appendix"' in INDEX_HTML
    recovery = INDEX_HTML.split('<section id="recovery"', 1)[1].split('</section>', 1)[0]
    assert "Client Appendix" not in recovery


def test_gui_installer_only_review_is_presented_as_not_applicable():
    assert "Guided Review is not applicable to Installer Analysis Only assessments." in INDEX_HTML
    assert "Review is not applicable" not in INDEX_HTML or "Installer Analysis Only" in INDEX_HTML
    assert "return 'N/A'" in INDEX_HTML


def test_gui_dashboard_and_jobs_have_refresh_and_live_progress_contract():
    for phrase in (
        "Refresh",
        "progressbar",
        "progressHtml",
        "phase",
        "module",
        "Assessment Completed",
        "Technical Details",
    ):
        assert phrase in INDEX_HTML


def test_assessment_listing_does_not_mutate_configured_server_root(tmp_path: Path):
    configured = tmp_path / "configured"
    alternate = tmp_path / "alternate"
    configured.mkdir(); alternate.mkdir()
    state = GuiState(configured, token="known-token")
    server, thread = _serve(state)
    host, port = server.server_address
    try:
        url = f"http://{host}:{port}/api/assessments?root={urllib.parse.quote(str(alternate))}"
        req = urllib.request.Request(url, headers={"X-UCA-Token": "known-token"})
        with urllib.request.urlopen(req, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["ok"] is True
        assert payload["data"]["root"] == str(alternate.resolve())
        assert state.assessment_root == configured.resolve()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_snapshot_progress_callback_reports_substages_contract():
    source = Path("modules/snapshot.py").read_text(encoding="utf-8")
    assert "progress_callback" in source
    assert '{"stage": stage, "status": "running"}' in source
    assert '{"stage": stage, "status": "completed"' in source


def test_gui_assessment_jobs_forward_structured_progress_callbacks():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert "progress_callback=progress" in source
    workflow = Path("modules/assessment_workflow.py").read_text(encoding="utf-8")
    assert 'phase="pre-install-snapshot"' in workflow
    assert 'phase="post-install-snapshot"' in workflow
    assert 'phase="correlating"' in workflow
    assert 'module="Artifact Inventory & Integrity"' in workflow
