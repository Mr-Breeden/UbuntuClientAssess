from pathlib import Path

from modules.app_scope import infer_application_roots_from_evidence
from modules.common import VERSION
from modules.coverage_limits import (
    apply_coverage_attention,
    detect_application_file_coverage_gaps,
    enrich_analysis_roots,
)
from modules.web_gui import INDEX_HTML


def test_v204_release_contract():
    assert VERSION == "2.0.6"


def test_gui_installer_browser_includes_script_and_current_flatpak_extensions():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    for suffix in (".sh", ".run", ".flatpak", ".flatpakref", ".flatpakrepo", ".bz2", ".txz", ".tbz", ".tbz2"):
        assert f'"{suffix}"' in source


def test_gui_full_assessment_no_longer_requires_deb_only():
    source = Path("modules/assessment_workflow.py").read_text(encoding="utf-8")
    assert "GUI Full Assessment currently requires a Debian .deb package" not in source
    assert 'elif suffix == ".sh"' in source
    assert 'elif suffix in {".run", ".appimage"}' in source
    assert "if is_deb and not _deb_installation_complete" in source
    assert "Manual Installation Confirmation" in source


def test_dashboard_distinguishes_valid_zero_item_review_from_not_ready():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert "if(!rv.available)return 'Not ready'" in source
    assert "'No review items'" in source
    service = Path("modules/application_service.py").read_text(encoding="utf-8")
    assert '"available": False' in service
    assert '"available": True' in service


def test_post_install_root_inference_uses_filesystem_and_process_evidence():
    roots = infer_application_roots_from_evidence(
        [Path("/opt/ExampleAgent")],
        ["root root java /opt/ExampleAgent/jre/bin/java -jar /opt/ExampleAgent/lib/agent.jar"],
    )
    assert Path("/opt/ExampleAgent") in roots
    enriched = enrich_analysis_roots([], {"files_added": ["/opt/ExampleAgent"], "files_changed": [], "processes_added": []})
    assert Path("/opt/ExampleAgent") in enriched


def test_inaccessible_application_root_becomes_explicit_coverage_gap():
    snapshot = {
        "filesystem": {
            "/opt/ExampleAgent": {
                "type": "directory", "owner": "root", "group": "example-agent", "mode_octal": "0o770"
            }
        },
        "filesystem_collection_gaps": [
            {"path": "/opt/ExampleAgent", "operation": "walk", "errno": 13, "error": "Permission denied"}
        ],
    }
    gaps = detect_application_file_coverage_gaps(snapshot, [Path("/opt/ExampleAgent")])
    assert len(gaps) == 1
    assert gaps[0]["path"] == "/opt/ExampleAgent"
    assert "ELF/binary security review" in gaps[0]["affected_coverage"]


def test_coverage_gap_marks_static_modules_attention_without_failure():
    statuses = {
        "ELF Security Review": ("PASS", ""),
        "Network Surface Review": ("ATTN", "No active connection observed"),
    }
    gaps = [{"path": "/opt/ExampleAgent", "owner": "root", "group": "example-agent", "mode": "0o770"}]
    apply_coverage_attention(statuses, gaps)
    assert statuses["Application File Coverage"][0] == "ATTN"
    assert statuses["ELF Security Review"][0] == "ATTN"
    assert statuses["Network Surface Review"][0] == "ATTN"
    assert "No active connection observed" in statuses["Network Surface Review"][1]
    assert "Static application-file coverage is limited" in statuses["ELF Security Review"][1]


def test_readme_has_authorized_use_and_protected_root_guidance():
    text = Path("README.md").read_text(encoding="utf-8")
    assert "## Authorized Use" in text
    assert "explicit permission to test" in text
    assert "cannot be recursively read/traversed" in text


def test_post_analysis_surfaces_inaccessible_root_as_attention(tmp_path: Path):
    import ubuntuclientassess as uca
    from modules.common import write_json

    working = tmp_path / "working"
    working.mkdir()
    base = {
        "schema_version": 6,
        "packages": [], "snap_packages": [], "flatpak_packages": [], "flatpak_remotes": [],
        "processes": [], "services": [], "running_services": [], "timers": [],
        "listening_sockets": [], "network_connections": [], "unix_sockets": [],
        "mounts": [], "users": [], "groups": [], "user_crontab": [], "root_crontab": [],
        "capabilities": [], "suid_sgid": [], "filesystem": {}, "filesystem_collection_gaps": [],
    }
    post = dict(base)
    post["filesystem"] = {
        "/opt/ExampleAgent": {"type": "directory", "mode": "drwxrwx---", "mode_octal": "0o770", "uid": 0, "gid": 1001, "owner": "root", "group": "example-agent", "size": 4096, "mtime_ns": 1, "ctime_ns": 1, "sha256": None}
    }
    post["filesystem_collection_gaps"] = [
        {"path": "/opt/ExampleAgent", "operation": "walk", "errno": 13, "error": "Permission denied"}
    ]
    write_json(working / "snapshot_pre.json", base)
    write_json(working / "snapshot_post.json", post)
    metadata = {"application_roots": [], "application_scope": {}, "analysis_roots": []}
    status = {}
    assert uca.post_analysis(tmp_path, None, [], status, {"type": "script"}, metadata) is True
    assert status["Application File Coverage"][0] == "ATTN"
    assert status["ELF Security Review"][0] == "ATTN"
    assert metadata["application_root"] == "/opt/ExampleAgent"
    assert metadata["application_file_coverage"]["limited"] is True
    assert "Application File Coverage Limitation" in (tmp_path / "reports" / "binary_security_review.txt").read_text(encoding="utf-8")
    assert "Static Application File Coverage" in (tmp_path / "reports" / "tester_review.txt").read_text(encoding="utf-8")
    assert "Application File Coverage: LIMITED" in (tmp_path / "reports" / "assessment_coverage.txt").read_text(encoding="utf-8")


def test_snapshot_walk_records_permission_errors(monkeypatch, tmp_path: Path):
    import modules.snapshot as snapshot

    root = tmp_path / "root"
    root.mkdir()
    denied = root / "ProtectedApp"

    def fake_walk(path, followlinks=False, onerror=None):
        if onerror:
            onerror(PermissionError(13, "Permission denied", str(denied)))
        return iter(())

    monkeypatch.setattr(snapshot.os, "walk", fake_walk)
    gaps = []
    list(snapshot._walk_snapshot_paths(root, [], gaps))
    assert gaps
    assert gaps[0]["path"] == str(denied)
    assert gaps[0]["operation"] == "walk"
