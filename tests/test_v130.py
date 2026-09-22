from __future__ import annotations

import json
from pathlib import Path
import socket


def test_repeated_weak_python_indicators_do_not_reach_high_confidence(tmp_path):
    from modules.application_profile import profile_application
    app = tmp_path / "app"; app.mkdir()
    for i in range(10):
        (app / f"module{i}.py").write_text("print('x')\n", encoding="utf-8")
    data = profile_application(tmp_path / "assessment", extra_roots=[app])
    python = next(item for item in data["technologies"] if item["technology"] == "Python")
    assert python["score"] >= 8
    assert python["confidence"] == "MEDIUM"
    assert data["primary_technology"] == "Python"


def test_primary_framework_favors_strong_marker_over_many_weak_sources(tmp_path):
    from modules.application_profile import profile_application
    app = tmp_path / "mixed"; app.mkdir()
    (app / "app.asar").write_bytes(b"asar")
    for i in range(15):
        (app / f"helper{i}.py").write_text("pass\n", encoding="utf-8")
    data = profile_application(tmp_path / "assessment", extra_roots=[app])
    assert data["primary_technology"] == "Electron / Chromium"


def test_qt_detection_primary_classification_and_machine_profile(tmp_path):
    from modules.application_profile import profile_application
    app = tmp_path / "vendor"; app.mkdir()
    qt = app / "libQt6Core.so.6"; qt.write_bytes(b"\x7fELF" + b"\x00" * 64)
    data = profile_application(tmp_path / "assessment", extra_roots=[app])
    qt_data = next(item for item in data["technologies"] if item["technology"] == "Qt")
    assert data["primary_technology"] == "Qt"
    assert "Qt 6.x" in qt_data["version_hints"]
    assert "Native ELF" not in data["supporting_technologies"]
    machine = json.loads((tmp_path / "assessment" / "working" / "application_profile.json").read_text())
    assert machine["primary_technology"] == "Qt"
    report = (tmp_path / "assessment" / "reports" / "application_profile.txt").read_text()
    assert "Detection score:" in report
    assert "Evidence score:" not in report
    assert "Primary technology:" in report


def test_electron_beats_supporting_native_elf_as_primary(tmp_path):
    from modules.application_profile import profile_application
    app = tmp_path / "electron"; app.mkdir()
    (app / "app.asar").write_bytes(b"asar")
    for i in range(6):
        (app / f"lib{i}.so").write_bytes(b"\x7fELF" + b"\x00" * 16)
    data = profile_application(tmp_path / "assessment", extra_roots=[app])
    assert data["primary_technology"] == "Electron / Chromium"
    assert "Native ELF" in data["supporting_technologies"]


def test_unix_socket_permission_analysis_flags_privileged_world_writable(tmp_path):
    from modules.ipc import analyze_socket_line
    sock_path = tmp_path / "control.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(sock_path)); sock_path.chmod(0o666)
        line = f'u_str LISTEN 0 4096 {sock_path} 12345 * 0 users:(("vendor-root",pid=123,fd=3))'
        result = analyze_socket_line(line, {"vendor-root": {"root"}})
        assert result["path"] == str(sock_path)
        assert result["filesystem"]["world_write"] is True
        assert result["privileged_process"] is True
        assert result["review_level"] == "HIGH"
    finally:
        sock.close()


def test_policykit_parser_marks_permissive_action_for_review(tmp_path):
    from modules.ipc import _policykit_details
    policy = tmp_path / "vendor.policy"
    text = '<policyconfig><action id="com.vendor.admin"><defaults><allow_any>yes</allow_any><allow_inactive>auth_admin</allow_inactive><allow_active>auth_admin_keep</allow_active></defaults></action></policyconfig>'
    policy.write_text(text, encoding="utf-8")
    details = _policykit_details(policy, text)
    assert details[0]["action"] == "com.vendor.admin"
    assert details[0]["permissive_review"] is True


def test_runtime_sample_analysis_correlates_children_network_and_ipc():
    from modules.runtime_observation import analyze_samples
    samples = [{
        "processes": [
            {"pid": 100, "ppid": 1, "user": "root", "group": "root", "comm": "vendor", "args": "/opt/vendor/bin/vendor"},
            {"pid": 101, "ppid": 100, "user": "root", "group": "root", "comm": "sh", "args": "sh -c fixed-helper"},
            {"pid": 900, "ppid": 1, "user": "interactive-user", "group": "interactive-user", "comm": "browser", "args": "browser"},
        ],
        "listeners": ['tcp LISTEN 0 128 0.0.0.0:18080 0.0.0.0:* users:(("vendor",pid=100,fd=4))'],
        "connections": ['tcp ESTAB 0 0 10.0.0.2:40000 10.0.0.3:443 users:(("vendor",pid=100,fd=5))'],
        "unix_sockets": ['u_str LISTEN 0 128 /run/vendor.sock 123 * 0 users:(("vendor",pid=100,fd=6))'],
    }]
    data = analyze_samples(samples, ["/opt/vendor"])
    assert {p["pid"] for p in data["application_processes"]} == {100, 101}
    assert [p["pid"] for p in data["child_processes"]] == [101]
    assert [p["pid"] for p in data["shell_children"]] == [101]
    assert len(data["externally_bound_listeners"]) == 1
    assert len(data["connections"]) == 1
    assert len(data["unix_sockets"]) == 1
    assert data["privileged_process_count"] == 2


def test_runtime_observation_single_sample_writes_working_json(monkeypatch, tmp_path):
    import modules.runtime_observation as ro
    monkeypatch.setattr(ro, "_sample", lambda: {"captured_at": "now", "processes": [], "listeners": [], "connections": [], "unix_sockets": []})
    data = ro.collect_runtime_observation(tmp_path, application_hints=["vendor"], duration_seconds=0)
    assert data["sample_count"] == 1
    assert (tmp_path / "working" / "runtime_observation.json").is_file()


def test_runtime_review_renders_observed_data_and_technology_focus(tmp_path):
    from modules.runtime import write_runtime_guidance
    profile = {"primary_technology": "Qt", "supporting_technologies": ["Native ELF"], "technologies": [{"technology": "Qt", "confidence": "HIGH", "kind": "framework", "runtime_focus": ["Observe Qt runtime."], "guidance": []}]}
    observation = {"duration_seconds": 5, "sample_count": 4, "application_processes": [{"pid": 12, "ppid": 1, "user": "interactive-user", "comm": "vendor", "args": "/opt/vendor/vendor"}], "child_processes": [], "privileged_process_count": 0, "listeners": [], "externally_bound_listeners": [], "connections": [], "unix_sockets": [], "socket_analysis": [], "shell_children": [], "file_activity": {"created": [], "modified": [], "deleted": [], "suppressed": 0}}
    write_runtime_guidance(tmp_path, "/opt/vendor/vendor", profile, observation)
    text = (tmp_path / "reports" / "runtime_review.txt").read_text()
    assert "Guided Runtime Observation" in text
    assert "Primary technology:       Qt" in text
    assert "Observe Qt runtime." in text
    assert "PID 12" in text


def test_runtime_ipc_update_is_idempotent(tmp_path):
    from modules.common import write_text, report_path
    from modules.ipc import update_ipc_with_runtime
    write_text(report_path(tmp_path, "ipc_review.txt"), "IPC Review\n==========\n")
    runtime = {"duration_seconds": 2, "socket_analysis": []}
    update_ipc_with_runtime(tmp_path, runtime, {})
    update_ipc_with_runtime(tmp_path, runtime, {})
    text = (tmp_path / "reports" / "ipc_review.txt").read_text()
    assert text.count("Guided Runtime IPC Observation") == 1


def test_runtime_review_items_merge_without_renumbering_existing_state(tmp_path):
    from modules.tester_review import generate_tester_review, merge_additional_review_items, update_review_item
    profile = {"primary_technology": "Qt", "technologies": [{"technology": "Qt", "confidence": "HIGH", "guidance": ["Review Qt."], "runtime_focus": [], "ipc_focus": []}]}
    state = generate_tester_review(tmp_path, profile_data=profile)
    original = state["items"][0]
    update_review_item(tmp_path, original["identity"], status="VALIDATED")
    runtime = {"externally_bound_listeners": ['tcp LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* users:(("vendor",pid=1,fd=3))'], "application_processes": [{"pid": 1, "user": "root"}]}
    merged = merge_additional_review_items(tmp_path, profile_data=profile, runtime_data=runtime)
    tech = next(item for item in merged["items"] if item["identity"] == original["identity"])
    assert tech["id"] == original["id"]
    assert tech["status"] == "VALIDATED"
    assert any(item["category"] == "RUNTIME" for item in merged["items"])


def test_main_menu_keeps_existing_numbers_and_adds_runtime(monkeypatch, tmp_path):
    import ubuntuclientassess as uca
    for choice, expected in (("3", "appendix"), ("4", "verify"), ("5", "runtime")):
        monkeypatch.setattr(uca.Prompt, "ask", lambda *args, _choice=choice, **kwargs: _choice)
        monkeypatch.setattr(uca, "ask_path", lambda *args, **kwargs: tmp_path)
        action, path = uca._interactive_main_menu()
        assert action == expected
        assert path == tmp_path


def test_cli_exposes_runtime_observation_flags():
    import subprocess, sys
    script = Path(__file__).resolve().parents[1] / "ubuntuclientassess.py"
    out = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True, check=True).stdout
    assert "--runtime-observe" in out
    assert "--runtime-observe-seconds" in out


def test_coverage_catalog_contains_runtime_and_ipc_areas(tmp_path):
    from modules.assessment_coverage import FULL_CATALOG_IDS, generate_assessment_coverage
    assert "TC-IPC-002" in FULL_CATALOG_IDS
    assert "TC-RUN-002" in FULL_CATALOG_IDS
    profile = {"primary_technology": "Qt", "supporting_technologies": ["Native ELF"], "technologies": [{"technology": "Qt"}, {"technology": "Native ELF"}]}
    generate_assessment_coverage(tmp_path, "full", profile)
    text = (tmp_path / "reports" / "assessment_coverage.txt").read_text()
    assert "Runtime IPC Authorization" in text
    assert "Guided Runtime Correlation" in text
    assert "Technology / Framework-Specific Testing" in text


def test_manifest_records_optional_machine_profile_and_runtime_observation(tmp_path):
    from modules.artifacts import finalize_artifact_manifest, verify_artifact_manifest
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout, report_path, write_json, write_text
    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "assessment_metadata.json", {"version": "1.3.0", "mode": "full"})
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "tester_review_state.json", {"schema_version": 1, "framework_version": "1.3.0", "items": []})
    write_json(tmp_path / "working" / "application_profile.json", {"schema_version": 1})
    write_json(tmp_path / "working" / "runtime_observation.json", {"schema_version": 1})
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"artifact_manifest.txt"}:
        write_text(report_path(tmp_path, name), "ok")
    manifest = finalize_artifact_manifest(tmp_path, "full")
    supporting = {entry["path"] for entry in manifest["supporting_files"]}
    assert "working/application_profile.json" in supporting
    assert "working/runtime_observation.json" in supporting
    assert verify_artifact_manifest(tmp_path) == []


def test_runtime_process_matching_ignores_incidental_shell_path_mentions():
    from modules.runtime_observation import analyze_samples
    samples = [{
        "processes": [
            {"pid": 10, "ppid": 1, "user": "interactive-user", "group": "interactive-user", "comm": "bash", "args": "bash -lc echo /opt/vendor/app && sleep 2"},
            {"pid": 20, "ppid": 1, "user": "interactive-user", "group": "interactive-user", "comm": "python3", "args": "python3 /opt/vendor/app/client.py"},
            {"pid": 21, "ppid": 20, "user": "interactive-user", "group": "interactive-user", "comm": "helper", "args": "/opt/vendor/app/helper"},
        ],
        "listeners": [], "connections": [], "unix_sockets": [],
    }]
    data = analyze_samples(samples, ["/opt/vendor/app/client.py", "/opt/vendor/app"])
    assert {item["pid"] for item in data["application_processes"]} == {20, 21}
    assert {item["pid"] for item in data["child_processes"]} == {21}
