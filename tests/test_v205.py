import os
from pathlib import Path

import pytest

from modules.common import VERSION, read_json, write_json
from modules.coverage_limits import enrich_analysis_roots
from modules.privileged_review import privileged_roots, collect_protected_application_roots
from modules.web_gui import INDEX_HTML


def test_v205_release_contract():
    assert VERSION == "2.0.6"


def test_readme_authorized_use_and_no_roadmap():
    text = Path("README.md").read_text(encoding="utf-8")
    assert "## Authorized Use" in text
    assert "explicit permission to test" in text
    assert "## Roadmap" not in text


def test_gui_exposes_privileged_collection_without_browser_password_field():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert "Run Privileged Collection" in INDEX_HTML
    assert "/api/privileged-review/launch" in source
    assert 'type="password"' not in INDEX_HTML.lower()
    assert "never requests your sudo password" in INDEX_HTML.lower()
    assert "--privileged-static-review" in source


def test_ambient_shared_system_process_root_requires_filesystem_corroboration():
    roots = enrich_analysis_roots([], {
        "files_added": ["/opt/ExampleAgent"],
        "files_changed": [],
        "processes_added": [
            "tester tester unrelated /usr/lib/ExampleBrowser/browser --background",
            "root root agent /opt/ExampleAgent/bin/agent",
        ],
    })
    assert Path("/opt/ExampleAgent") in roots
    assert Path("/usr/lib/ExampleBrowser") not in roots


def test_privileged_roots_only_uses_recorded_coverage_gaps(tmp_path: Path):
    write_json(tmp_path / "assessment_metadata.json", {
        "mode": "full",
        "application_file_coverage": {
            "limited": True,
            "gaps": [
                {"path": "/opt/ExampleAgent"},
                {"path": "/tmp/not-allowed"},
            ],
        },
    })
    assert privileged_roots(tmp_path) == [Path("/opt/ExampleAgent")]


def test_privileged_collection_requires_root(monkeypatch, tmp_path: Path):
    (tmp_path / "working").mkdir()
    write_json(tmp_path / "assessment_metadata.json", {
        "mode": "full",
        "application_file_coverage": {"limited": True, "gaps": [{"path": "/opt/ExampleAgent"}]},
    })
    write_json(tmp_path / "working" / "snapshot_post.json", {"filesystem": {}, "filesystem_collection_gaps": []})
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError):
        collect_protected_application_roots(tmp_path)


def test_hidden_privileged_cli_action_is_not_advertised_as_normal_user_option():
    source = Path("ubuntuclientassess.py").read_text(encoding="utf-8")
    assert '"--privileged-static-review"' in source
    assert "help=argparse.SUPPRESS" in source
