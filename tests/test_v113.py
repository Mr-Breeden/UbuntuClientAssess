from __future__ import annotations

from pathlib import Path


def test_redaction_handles_quoted_config_and_authorization_headers():
    from modules.common import redact_sensitive_text

    samples = [
        '"token": "JSONSECRET"',
        "'password': 'YAMLSECRET'",
        'Authorization: Bearer BEARERSECRET123',
        'Authorization: Basic BASICSECRET123',
    ]
    cleaned = "\n".join(redact_sensitive_text(item) for item in samples)
    for secret in ("JSONSECRET", "YAMLSECRET", "BEARERSECRET123", "BASICSECRET123"):
        assert secret not in cleaned
    assert cleaned.count("[REDACTED]") >= 4


def test_custom_workflow_redacts_literal_sensitive_helper_argument(tmp_path):
    import ubuntuclientassess as uca

    installer = tmp_path / "client.deb"
    installer.write_bytes(b"x")
    argv, display = uca._build_custom_command(
        "sudo /opt/Vendor/bin/use_authorization_code.sh LITERAL-AUTH-CODE",
        installer,
    )
    assert argv[-1] == "LITERAL-AUTH-CODE"
    assert "LITERAL-AUTH-CODE" not in display
    assert "[REDACTED]" in display


def test_custom_workflow_redacts_sensitive_url_query(tmp_path):
    import ubuntuclientassess as uca

    installer = tmp_path / "client.deb"
    installer.write_bytes(b"x")
    _argv, display = uca._build_custom_command(
        "curl https://setup.example.test/enroll?token=URLSECRET&mode=test",
        installer,
    )
    assert "URLSECRET" not in display
    assert "token=[REDACTED]" in display


def test_standard_sticky_tmp_parent_is_not_reported():
    import modules.permissions as permissions

    concerns = permissions._parent_write_concerns(Path("/tmp/uca-v113-marker"), {})
    assert not any("/tmp" in item for item in concerns)


def test_nonstandard_world_writable_sticky_parent_remains_reviewable(tmp_path):
    import modules.permissions as permissions

    ipc = tmp_path / "commands"
    ipc.mkdir()
    ipc.chmod(0o1777)
    concerns = permissions._parent_write_concerns(ipc / "request", {})
    assert any("World-writable parent directory" in item and str(ipc) in item for item in concerns)


def test_symlink_classification_evaluates_world_writable_target(tmp_path):
    import modules.permissions as permissions

    target = tmp_path / "target"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o666)
    link = tmp_path / "launcher"
    link.symlink_to(target)
    result = permissions._classify(
        str(link),
        {
            "type": "symlink",
            "mode_octal": "0o777",
            "mode": "lrwxrwxrwx",
            "owner": "root",
            "group": "root",
        },
        {},
    )
    assert result is not None
    assert result["resolved_path"] == str(target)
    assert "Resolved symlink target is world-writable" in result["concern_list"]


def test_finalize_failure_never_leaves_completed_state(tmp_path, monkeypatch):
    import ubuntuclientassess as uca
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout, read_json, report_path, write_json, write_text

    ensure_assessment_layout(tmp_path)
    metadata_path = tmp_path / "assessment_metadata.json"
    metadata = {"version": "1.1.3", "assessment_name": "Failure Test", "mode": "full"}
    write_json(metadata_path, metadata)
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "tester_review_state.json", {"schema_version": 1, "framework_version": "1.2.0", "items": []})
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"assessment_report.html", "artifact_manifest.txt", "module_status.txt"}:
        write_text(report_path(tmp_path, name), "ok")

    monkeypatch.setattr(uca, "generate_consolidated_report", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert uca.finalize_assessment(tmp_path, "full", metadata_path, metadata, {}) is False
    state = read_json(metadata_path)["run_state"]
    assert state["status"] == "failed"
    assert state["stage"] == "artifact-finalization"


def test_upgrade_network_correlation_uses_existing_post_process(tmp_path):
    from modules.network import review_network

    connection = 'tcp ESTAB 0 0 10.0.0.10:44444 198.51.100.20:443 users:(("vendor-client",pid=<PID>,fd=<FD>))'
    diff = {
        "files_added": [],
        "files_changed": ["/opt/Vendor/bin/vendor-client"],
        "post_filesystem": {"/opt/Vendor/bin/vendor-client": {"mode": "-rwxr-xr-x"}},
        "processes_added": [],
        "post_processes": ["root root vendor-client /opt/Vendor/bin/vendor-client --daemon"],
        "network_connections_added": [connection],
        "listening_sockets_added": [],
        "listening_sockets_removed": [],
    }
    data = review_network(diff, tmp_path, [Path("/opt/Vendor")])
    assert connection in data["new_connections"]


def test_dpkg_status_transition_is_package_modified_not_added_removed(tmp_path):
    from modules.common import write_json
    from modules.install_changes import compare_snapshots

    pre = tmp_path / "pre.json"
    post = tmp_path / "post.json"
    write_json(pre, {"packages": ["rc \tdemo-package\t1.0"], "filesystem": {}})
    write_json(post, {"packages": ["ii \tdemo-package\t1.0"], "filesystem": {}})
    diff = compare_snapshots(pre, post, tmp_path)
    assert diff["packages_added"] == []
    assert diff["packages_removed"] == []
    assert len(diff["packages_modified"]) == 1
    assert diff["packages_modified"][0]["identity"] == "demo-package"
    report = (tmp_path / "reports" / "install_changes.txt").read_text(encoding="utf-8")
    assert "Packages Modified" in report
