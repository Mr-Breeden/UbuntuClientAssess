from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_update_review_redacts_sensitive_url_query(tmp_path):
    from modules.update_review import review_updates

    cfg = tmp_path / "updater.conf"
    cfg.write_text(
        "update_url=https://updates.example.test/client?token=SUPERSECRET&channel=prod\n",
        encoding="utf-8",
    )
    data = review_updates({"files_added": [str(cfg)], "files_changed": []}, tmp_path, {})
    report = (tmp_path / "reports" / "update_review.txt").read_text(encoding="utf-8")
    assert "SUPERSECRET" not in report
    assert "[REDACTED]" in report
    assert "SUPERSECRET" not in json.dumps(data)


def test_storage_does_not_suppress_generic_application_lib_config(tmp_path):
    from modules.storage import review_storage

    cfg = tmp_path / "opt" / "Vendor" / "lib" / "config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text('client_secret="DO_NOT_PERSIST"\n', encoding="utf-8")
    data = review_storage({"files_added": [str(cfg)], "files_changed": []}, tmp_path)
    report = (tmp_path / "reports" / "local_storage_review.txt").read_text(encoding="utf-8")
    assert any(hit["path"] == str(cfg) for hit in data["secret_hits"])
    assert "DO_NOT_PERSIST" not in report


def test_network_does_not_suppress_generic_application_lib_config(tmp_path):
    from modules.network import review_network

    cfg = tmp_path / "opt" / "Vendor" / "lib" / "client.conf"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("server=https://api.vendor.test/v1\n", encoding="utf-8")
    data = review_network({"files_added": [str(cfg)], "files_changed": [], "listening_sockets_added": [], "listening_sockets_removed": []}, tmp_path)
    assert any(item["endpoint"] == "https://api.vendor.test/v1" for item in data["endpoints"])


def test_deb_installation_verification_requires_selected_version_match():
    import ubuntuclientassess as uca

    assert uca.deb_installation_complete({
        "installed": True,
        "installer_version": "6.1.0",
        "installed_version": "6.1.0",
    }) is True
    assert uca.deb_installation_complete({
        "installed": True,
        "installer_version": "6.1.0",
        "installed_version": "6.0.0",
    }) is False
    assert "expected 6.1.0, observed 6.0.0" in uca.deb_installation_verification_detail({
        "installed": True,
        "installer_version": "6.1.0",
        "installed_version": "6.0.0",
    })


def test_sensitive_command_line_redaction():
    from modules.common import redact_sensitive_text

    raw = "client --token TOPSECRET --password=hunter2 https://x.test/a?access_token=ABC&mode=1"
    cleaned = redact_sensitive_text(raw)
    assert "TOPSECRET" not in cleaned
    assert "hunter2" not in cleaned
    assert "ABC" not in cleaned
    assert cleaned.count("[REDACTED]") >= 3


def test_acl_aware_user_can_write_honors_named_user_and_mask(tmp_path, monkeypatch):
    import modules.common as common

    target = tmp_path / "owned-by-root"
    target.write_text("x", encoding="utf-8")
    test_uid = target.stat().st_uid + 1
    monkeypatch.setattr(common.pwd, "getpwnam", lambda _user: SimpleNamespace(pw_uid=test_uid, pw_gid=1000))
    monkeypatch.setattr(common.os, "getgrouplist", lambda _user, _gid: [1000])
    monkeypatch.setattr(common, "command_exists", lambda name: "/usr/bin/getfacl" if name == "getfacl" else None)
    monkeypatch.setattr(common.os, "listxattr", lambda path, follow_symlinks=True: ["system.posix_acl_access"])

    def writable(_cmd, timeout=10):
        return {"returncode": 0, "stdout": f"user::rw-\nuser:{test_uid}:rw-\ngroup::r--\nmask::rw-\nother::r--\n", "stderr": "", "cmd": _cmd}

    monkeypatch.setattr(common, "run_cmd", writable)
    assert common.user_can_write(target, "tester") is True

    def masked(_cmd, timeout=10):
        return {"returncode": 0, "stdout": f"user::rw-\nuser:{test_uid}:rw-\ngroup::r--\nmask::r--\nother::r--\n", "stderr": "", "cmd": _cmd}

    monkeypatch.setattr(common, "run_cmd", masked)
    assert common.user_can_write(target, "tester") is False


def test_empty_rpath_component_is_preserved_and_flagged(monkeypatch, tmp_path):
    import modules.elf_analysis as elf

    binary = tmp_path / "demo"
    binary.write_bytes(b"x")
    monkeypatch.setattr(elf, "run_cmd", lambda cmd, timeout=30: {
        "returncode": 0,
        "stdout": " 0x000000000000000f (RPATH) Library rpath: [/trusted::/also-trusted]\n",
        "stderr": "",
        "cmd": cmd,
    })
    dynamic = elf._extract_dynamic(binary)
    assert dynamic["rpath"] == ["/trusted", "", "/also-trusted"]
    concern, finding = elf._search_path_concern(binary, "")
    assert "current working directory" in concern.lower()
    assert finding is True


def test_manifest_verifier_rejects_path_escape(tmp_path):
    from modules.artifacts import finalize_artifact_manifest, verify_artifact_manifest
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout, read_json, write_json

    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "assessment_metadata.json", {"version": "1.1.3", "mode": "full"})
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 5})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 5})
    write_json(tmp_path / "working" / "tester_review_state.json", {"schema_version": 1, "framework_version": "1.2.0", "items": []})
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"artifact_manifest.txt"}:
        (tmp_path / "reports" / name).write_text("ok\n", encoding="utf-8")
    finalize_artifact_manifest(tmp_path, "full")
    data = read_json(tmp_path / "assessment_manifest.json")
    data["reports"][0]["path"] = "../../etc/passwd"
    write_json(tmp_path / "assessment_manifest.json", data)
    issues = verify_artifact_manifest(tmp_path)
    assert any("Unsafe recorded path" in issue for issue in issues)


def test_changed_existing_service_receives_deep_review(tmp_path, monkeypatch):
    import modules.services as services

    unit_path = "/etc/systemd/system/demo.service"

    def fake_run(cmd, timeout=20, **_kwargs):
        if cmd[:2] == ["systemctl", "cat"]:
            return {"returncode": 0, "stdout": "[Service]\nUser=root\nExecStart=/bin/true\n", "stderr": "", "cmd": cmd}
        if cmd[:2] == ["systemctl", "show"]:
            out = "\n".join([
                "User=root", "Group=root", "DynamicUser=no",
                "ExecStart={ path=/bin/true ; argv[]=/bin/true ; }",
                "EnvironmentFiles=", "WorkingDirectory=", f"FragmentPath={unit_path}", "DropInPaths=",
                "NoNewPrivileges=no", "ProtectSystem=no", "ProtectHome=no", "PrivateTmp=no", "CapabilityBoundingSet=",
            ])
            return {"returncode": 0, "stdout": out, "stderr": "", "cmd": cmd}
        return {"returncode": 1, "stdout": "", "stderr": "", "cmd": cmd}

    monkeypatch.setattr(services, "run_cmd", fake_run)
    data = services.review_services({
        "services_added": [], "services_modified": [], "timers_added": [],
        "files_added": [], "files_changed": [unit_path],
        "post_service_units": {"demo.service": {"state": "enabled", "preset": "enabled"}},
    }, tmp_path)
    assert len(data["services"]) == 1
    assert data["services"][0]["unit"] == "demo.service"
    assert data["services"][0]["change_type"] == "modified"
    assert data["services"][0]["privileged"] is True


def test_root_crontab_is_compared_and_reported(tmp_path):
    from modules.common import write_json
    from modules.install_changes import compare_snapshots

    base = {"filesystem": {}, "root_crontab": [], "user_crontab": []}
    pre = tmp_path / "pre.json"
    post = tmp_path / "post.json"
    write_json(pre, base)
    changed = dict(base)
    changed["root_crontab"] = ["@reboot /opt/vendor/agent"]
    write_json(post, changed)
    diff = compare_snapshots(pre, post, tmp_path)
    assert diff["root_crontab_added"] == ["@reboot /opt/vendor/agent"]
    report = (tmp_path / "reports" / "install_changes.txt").read_text(encoding="utf-8")
    assert "Root Cron Entries Added" in report


def test_maintainer_script_paths_expand_snapshot_coverage(tmp_path):
    from modules.installer_analysis import discover_installer_paths

    if subprocess.run(["which", "dpkg-deb"], capture_output=True).returncode != 0:
        pytest.skip("dpkg-deb unavailable")
    pkg = tmp_path / "pkg"
    (pkg / "DEBIAN").mkdir(parents=True)
    (pkg / "DEBIAN" / "control").write_text(
        "Package: uca-test\nVersion: 1.0\nArchitecture: all\nMaintainer: Test <test@example.test>\nDescription: test\n",
        encoding="utf-8",
    )
    (pkg / "DEBIAN" / "postinst").write_text("#!/bin/sh\nmkdir -p /var/lib/uca-test/runtime\n", encoding="utf-8")
    (pkg / "DEBIAN" / "postinst").chmod(0o755)
    deb = tmp_path / "uca-test.deb"
    subprocess.run(["dpkg-deb", "--build", str(pkg), str(deb)], check=True, capture_output=True)
    paths = {str(p) for p in discover_installer_paths(deb)}
    assert "/var/lib/uca-test/runtime" in paths
    assert "/var/lib/uca-test" in paths


def test_missing_required_tools_abort_before_analysis(tmp_path, monkeypatch):
    import ubuntuclientassess as uca

    installer = tmp_path / "sample.zip"
    installer.write_bytes(b"not-an-archive")
    monkeypatch.setattr(uca, "banner", lambda: None)
    monkeypatch.setattr(uca, "detect_tools", lambda _out: ({}, False))
    monkeypatch.setattr(sys, "argv", [
        "ubuntuclientassess.py", "--non-interactive", "--installer-analysis-only",
        "-i", str(installer), "-o", str(tmp_path / "assessment"), "-n", "Test",
    ])
    assert uca.main() == 3
    assert not (tmp_path / "assessment" / "working" / "snapshot_pre.json").exists()


def test_installer_analysis_redacts_secret_assignments_in_scripts(tmp_path):
    from modules.installer_analysis import analyze_installer

    script = tmp_path / "install.sh"
    script.write_text("#!/bin/sh\npassword=INSTALLERSECRET\ncurl https://setup.example.test/?token=URLSECRET\n", encoding="utf-8")
    script.chmod(0o755)
    analyze_installer(script, tmp_path)
    report = (tmp_path / "reports" / "installer_analysis.txt").read_text(encoding="utf-8")
    assert "INSTALLERSECRET" not in report
    assert "URLSECRET" not in report
    assert "[REDACTED]" in report
