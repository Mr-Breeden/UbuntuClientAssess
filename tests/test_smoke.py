from pathlib import Path
import hashlib
import struct
import zipfile
import pytest

from modules.common import METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, VERSION, human_size, write_json
from modules.install_changes import compare_snapshots
from modules.installer_analysis import discover_installer_paths
from modules.snapshot import _collect_filesystem, merge_tracked_paths
from modules.storage import review_storage
from modules.update_review import review_updates


def test_human_size():
    assert human_size(1024) == "1.00 KB"


def test_version_111_contract():
    assert VERSION == "2.0.6"
    assert METHODOLOGY_VERSION == "2.4"
    assert TEST_CASE_CATALOG_VERSION == "1.1"


def test_deb_install_confirmation_defaults_yes(monkeypatch):
    import ubuntuclientassess as uca

    observed = {}

    def fake_ask(prompt, *, default):
        observed.update({"prompt": prompt, "default": default})
        return default

    monkeypatch.setattr(uca.Confirm, "ask", fake_ask)

    assert uca.confirm_deb_installation() is True
    assert observed == {"prompt": "Install this .deb now?", "default": True}


def test_snapshot_path_collapse():
    paths = merge_tracked_paths([Path("/opt/vendor"), Path("/opt/vendor/bin/app"), Path("/usr/bin/vendor-app")])
    assert Path("/opt") in paths
    assert Path("/opt/vendor/bin/app") not in paths
    assert Path("/usr/bin/vendor-app") in paths


def test_snapshot_diff(tmp_path: Path):
    pre = {
        "packages": ["a\t1"],
        "processes": [],
        "services": [], "running_services": [], "timers": [], "user_crontab": [],
        "listening_sockets": ["tcp LISTEN 0 10 127.0.0.1:1234 0.0.0.0:* users:((\"a\",pid=<PID>,fd=3))"],
        "unix_sockets": [], "capabilities": [], "suid_sgid": [],
        "filesystem": {"/opt/a": {"type": "file", "mode_octal": "0o644", "uid": 0, "gid": 0, "owner": "root", "group": "root", "size": 1, "mtime_ns": 1, "sha256": "a"}},
    }
    post = {
        "packages": ["a\t1", "b\t1"],
        "processes": ["root root b /opt/b"],
        "services": ["b.service enabled"], "running_services": ["b.service loaded active running B"], "timers": [], "user_crontab": ["@reboot /opt/b"],
        "listening_sockets": ["tcp LISTEN 0 10 0.0.0.0:4321 0.0.0.0:* users:((\"b\",pid=<PID>,fd=3))"],
        "unix_sockets": [], "capabilities": [], "suid_sgid": [],
        "filesystem": {
            "/opt/a": {"type": "file", "mode_octal": "0o644", "uid": 0, "gid": 0, "owner": "root", "group": "root", "size": 2, "mtime_ns": 2, "sha256": "b"},
            "/opt/b": {"type": "file", "mode_octal": "0o755", "uid": 0, "gid": 0, "owner": "root", "group": "root", "size": 3, "mtime_ns": 2, "sha256": "c"},
        },
    }
    write_json(tmp_path / "snapshot_pre.json", pre)
    write_json(tmp_path / "snapshot_post.json", post)
    diff = compare_snapshots(tmp_path / "snapshot_pre.json", tmp_path / "snapshot_post.json", tmp_path)
    assert "b\t1" in diff["packages_added"]
    assert "/opt/b" in diff["files_added"]
    assert "/opt/a" in diff["files_changed"]
    assert "@reboot /opt/b" in diff["user_crontab_added"]
    assert (tmp_path / "reports" / "install_changes.txt").exists()


def test_storage_redacts_values(tmp_path: Path):
    secret = tmp_path / "app.conf"
    secret.write_text("client_secret = super-secret-value\n", encoding="utf-8")
    diff = {"files_added": [str(secret)], "files_changed": []}
    data = review_storage(diff, tmp_path)
    report = (tmp_path / "reports" / "local_storage_review.txt").read_text()
    assert data["secret_hits"]
    assert "super-secret-value" not in report
    assert "[REDACTED]" in report


def test_update_http_candidate(tmp_path: Path):
    updater = tmp_path / "updater.conf"
    updater.write_text("update_url=http://updates.example.test/client\n", encoding="utf-8")
    diff = {"files_added": [str(updater)], "files_changed": []}
    data = review_updates(diff, tmp_path)
    assert data["insecure_update_url_candidates"]


def test_discover_installer_paths_non_deb(tmp_path: Path):
    p = tmp_path / "installer.sh"
    p.write_text("#!/bin/sh\n")
    assert discover_installer_paths(p) == []


def test_deb_discovery_avoids_broad_roots(tmp_path: Path):
    # This test uses a tiny package when dpkg-deb is available on the test host.
    import shutil
    import subprocess
    if not shutil.which("dpkg-deb"):
        return
    pkg = tmp_path / "pkg"
    (pkg / "DEBIAN").mkdir(parents=True)
    (pkg / "usr/lib/vendor-demo").mkdir(parents=True)
    (pkg / "usr/bin").mkdir(parents=True)
    (pkg / "etc/systemd/system").mkdir(parents=True)
    (pkg / "DEBIAN/control").write_text(
        "Package: vendor-demo\nVersion: 1\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: test\n",
        encoding="utf-8",
    )
    (pkg / "usr/lib/vendor-demo/app.conf").write_text("x=1\n")
    (pkg / "usr/bin/vendor-demo").write_text("#!/bin/sh\n")
    (pkg / "etc/systemd/system/vendor-demo.service").write_text("[Service]\nExecStart=/usr/bin/vendor-demo\n")
    deb = tmp_path / "vendor-demo.deb"
    subprocess.run(["dpkg-deb", "--build", str(pkg), str(deb)], check=True, capture_output=True)
    paths = discover_installer_paths(deb)
    assert Path("/usr") not in paths
    assert Path("/etc") not in paths
    assert Path("/usr/lib") not in paths
    assert Path("/usr/lib/vendor-demo") in paths
    assert Path("/usr/bin/vendor-demo") in paths


def test_cli_workflow_modes():
    import subprocess
    import sys

    script = Path(__file__).resolve().parents[1] / "ubuntuclientassess.py"
    help_text = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "--installer-analysis-only" in help_text
    assert "--allow-installed-deb" in help_text
    assert "--exclude-path" in help_text
    assert "--include-path" in help_text
    assert "--data-root" in help_text
    assert "--network-observation-seconds" in help_text
    assert "--retain-payload" in help_text
    assert "--verbose" in help_text
    assert "--verify-assessment" in help_text
    assert "--version" in help_text
    assert "--phase" not in help_text
    assert "pre-installation snapshot only" not in help_text.lower()
    assert "post-installation snapshot + analysis" not in help_text.lower()

    version_text = subprocess.run(
        [sys.executable, str(script), "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "2.0.6" in version_text
    assert "methodology 2.4" in version_text
    assert "coverage catalog 1.1" in version_text


def test_deb_package_state_treats_residual_config_as_present(tmp_path, monkeypatch):
    import ubuntuclientassess as uca

    installer = tmp_path / "demo.deb"
    installer.write_bytes(b"placeholder")

    def fake_run(cmd, timeout=45, env=None):
        if cmd[:3] == ["dpkg-deb", "-f", str(installer)] and cmd[-1] == "Package":
            return {"returncode": 0, "stdout": "demo\n", "stderr": ""}
        if cmd[:3] == ["dpkg-deb", "-f", str(installer)] and cmd[-1] == "Version":
            return {"returncode": 0, "stdout": "1.2.3\n", "stderr": ""}
        if cmd[0] == "dpkg-query":
            return {"returncode": 0, "stdout": "deinstall ok config-files\t1.2.3", "stderr": ""}
        raise AssertionError(cmd)

    monkeypatch.setattr(uca, "run_cmd", fake_run)
    state = uca.deb_package_state(installer)

    assert state and state["dpkg_present"] is True
    assert state["installed"] is False
    assert state["dpkg_status"] == "deinstall ok config-files"


def test_deb_installation_completion_requires_installed_state():
    import ubuntuclientassess as uca

    assert uca.deb_installation_complete(None) is False
    assert uca.deb_installation_complete({"installed": False}) is False
    assert uca.deb_installation_complete({"installed": True}) is True


def test_assessment_coverage_is_read_only_and_replaces_test_cases(tmp_path):
    from modules.assessment_coverage import generate_assessment_coverage

    generate_assessment_coverage(tmp_path)
    text = (tmp_path / "reports" / "assessment_coverage.txt").read_text(encoding="utf-8")

    assert "read-only coverage map" in text
    assert "not an editable completion checklist" in text
    assert "[ ] COMPLETED" not in text
    assert "[ ] NOT APPLICABLE" not in text
    assert not (tmp_path / "reports" / "test_cases.txt").exists()


def test_assessment_coverage_has_no_duplicate_validation_or_screenshot_sections(tmp_path):
    from modules.assessment_coverage import generate_assessment_coverage
    generate_assessment_coverage(tmp_path)
    text = (tmp_path / "reports" / "assessment_coverage.txt").read_text(encoding="utf-8")
    assert "Detailed Validation Procedure" not in text
    assert "Screenshot\n----------" not in text
    assert "<SCREENSHOT>" not in text


def test_installer_only_assessment_coverage_references_only_generated_artifacts(tmp_path):
    from modules.assessment_coverage import generate_assessment_coverage

    generate_assessment_coverage(tmp_path, "installer-analysis-only")
    text = (tmp_path / "reports" / "assessment_coverage.txt").read_text(encoding="utf-8")

    assert "Execution Mode: Installer Analysis Only" in text
    assert "installer_analysis.txt" in text
    assert "runtime_review.txt" in text
    assert "install_changes.txt" not in text
    assert "permissions_review.txt" not in text
    assert "service_review.txt" not in text


def test_frozen_coverage_catalog_identifiers_and_versions(tmp_path):
    import re
    from modules.assessment_coverage import FULL_CATALOG_IDS, INSTALLER_ONLY_CATALOG_IDS, FRAMEWORK_CASE_ID, generate_assessment_coverage

    profile = {"technologies": [{"technology": "Native ELF"}]}
    generate_assessment_coverage(tmp_path / "full", "full", profile)
    generate_assessment_coverage(tmp_path / "static", "installer-analysis-only", profile)
    full_text = (tmp_path / "full" / "reports" / "assessment_coverage.txt").read_text(encoding="utf-8")
    static_text = (tmp_path / "static" / "reports" / "assessment_coverage.txt").read_text(encoding="utf-8")
    full_ids = re.findall(r"^\[(TC-[A-Z]+-\d{3})\]", full_text, re.M)
    static_ids = re.findall(r"^\[(TC-[A-Z]+-\d{3})\]", static_text, re.M)
    assert full_ids == [*FULL_CATALOG_IDS, FRAMEWORK_CASE_ID]
    assert static_ids == [*INSTALLER_ONLY_CATALOG_IDS, FRAMEWORK_CASE_ID]
    assert len(full_ids) == len(set(full_ids)) and len(static_ids) == len(set(static_ids))
    for text in (full_text, static_text):
        assert "Methodology Version: 2.4" in text
        assert "Coverage Catalog Version: 1.1" in text


def test_timer_diff_ignores_volatile_schedule_fields(tmp_path):
    pre = {
        "packages": [], "processes": [], "services": [], "running_services": [],
        "timers": ["Wed 2026-08-26 14:30:06 EDT 58min Wed 2026-08-26 13:31:08 EDT 2s ago anacron.timer anacron.service"],
        "listening_sockets": [], "unix_sockets": [], "user_crontab": [], "capabilities": [], "suid_sgid": [], "filesystem": {},
    }
    post = {
        **pre,
        "timers": ["Wed 2026-08-26 15:30:06 EDT 58min Wed 2026-08-26 14:31:08 EDT 2s ago anacron.timer anacron.service"],
    }
    write_json(tmp_path / "pre.json", pre)
    write_json(tmp_path / "post.json", post)
    diff = compare_snapshots(tmp_path / "pre.json", tmp_path / "post.json", tmp_path)
    assert diff["timers_added"] == []
    assert diff["timers_removed"] == []


def test_storage_suppresses_bundled_source_keyword_noise(tmp_path):
    noisy = tmp_path / "backend" / "lib" / "cffi" / "_cffi_errors.h"
    noisy.parent.mkdir(parents=True)
    noisy.write_text('const char *msg = "invalid password format";\n', encoding="utf-8")
    real = tmp_path / "config" / "client.conf"
    real.parent.mkdir(parents=True)
    real.write_text('client_secret = redacted-test-value\n', encoding="utf-8")
    data = review_storage({"files_added": [str(noisy), str(real)], "files_changed": []}, tmp_path)
    assert len(data["secret_hits"]) == 1
    assert data["secret_hits"][0]["path"] == str(real)
    report = (tmp_path / "reports" / "local_storage_review.txt").read_text()
    assert str(noisy) not in report
    assert "redacted-test-value" not in report


def test_findings_do_not_promote_generic_permission_observations(tmp_path):
    from modules.findings import generate_findings
    findings = generate_findings(
        tmp_path,
        {"permission_candidates": [{"path": "/tmp/example", "concerns": "World-writable object"}]},
        {"exposed_listener_candidates": ["0.0.0.0:1234"]},
        {"services": [{"unit": "demo.service", "privileged": True, "user": []}], "risk_candidates": []},
        {"rpath_candidates": [], "finding_candidates": []},
        {},
        {},
    )
    assert findings == []
    text = (tmp_path / "reports" / "findings.txt").read_text()
    assert "No correlated automatic finding candidates" in text


def test_findings_deduplicate_same_update_identity_across_lines(tmp_path):
    from modules.findings import generate_findings

    update_candidates = [
        {"url": "http://updates.vendor.test/client", "path": "/opt/vendor/updater.conf", "line": 4, "confidence": "HIGH"},
        {"url": "http://updates.vendor.test/client", "path": "/opt/vendor/updater.conf", "line": 19, "confidence": "HIGH"},
    ]
    findings = generate_findings(tmp_path, {}, {}, {}, {}, {}, {"insecure_update_url_candidates": update_candidates})
    assert len(findings) == 1
    assert "Duplicate candidates suppressed: 1" in (tmp_path / "reports" / "findings.txt").read_text(encoding="utf-8")
    assert "Duplicate candidates suppressed: 1" in (tmp_path / "reports" / "findings_summary.txt").read_text(encoding="utf-8")


def test_sudoers_setenv_dynamic_helper_is_high_attention_candidate(tmp_path, monkeypatch):
    from modules import persistence

    helper = "/opt/DemoClient/bin/idp-helper"
    policy = "/etc/sudoers.d/democlient"
    sudo_output = """Matching Defaults entries for tester on host:
    env_reset

User tester may run the following commands on host:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/DemoClient/bin/idp-helper direct-login *
"""

    def fake_run(cmd, timeout=45, env=None):
        assert cmd[:3] == ["sudo", "-n", "-l"]
        assert env and env["LC_ALL"] == "C"
        return {"cmd": cmd, "returncode": 0, "stdout": sudo_output, "stderr": ""}

    monkeypatch.setattr(persistence, "run_cmd", fake_run)
    diff = {
        "files_added": [policy, helper],
        "files_changed": [],
        "post_filesystem": {
            policy: {"type": "file", "owner": "root", "group": "root", "mode_octal": "0o440"},
            helper: {"type": "file", "owner": "root", "group": "root", "mode_octal": "0o755"},
        },
    }
    elf_data = {
        "elf_files": [{
            "path": helper,
            "interpreter": "/lib64/ld-linux-x86-64.so.2",
            "dynamic": {"needed": ["libc.so.6"]},
        }],
    }

    data = persistence.review_persistence(diff, tmp_path, elf_data)

    assert data["sudo_policy_status"] == "captured"
    assert len(data["sudo_policy_candidates"]) == 1
    candidate = data["sudo_policy_candidates"][0]
    assert candidate["command_path"] == helper
    assert candidate["finding_candidate"] is True
    assert candidate["severity"] == "High"
    assert candidate["setenv"] is True
    assert candidate["nopasswd"] is True
    assert candidate["wildcards"] is True
    # The tester's unrelated baseline ALL rule must not be attributed to the application.
    assert all(item["command"] != "ALL" for item in data["sudo_policy_candidates"])
    report = (tmp_path / "reports" / "persistence_review.txt").read_text(encoding="utf-8")
    assert "[HIGH ATTENTION / FINDING CANDIDATE]" in report
    assert "[REVIEW REQUIRED]" in report


def test_sudo_policy_parser_preserves_tag_state_and_no_setenv_override():
    from modules.persistence import _parse_sudo_policy

    records = _parse_sudo_policy(
        "(root) NOPASSWD: SETENV: /opt/Demo/a, PASSWD: NOSETENV: /opt/Demo/b, ALL"
    )

    assert records[0]["nopasswd"] is True and records[0]["setenv"] is True
    assert records[1]["nopasswd"] is False and records[1]["setenv"] is False
    # NOSETENV remains sticky for the following ALL command specification.
    assert records[2]["all_commands"] is True and records[2]["setenv"] is False


def test_unavailable_sudo_policy_listing_remains_manual_review_required(tmp_path, monkeypatch):
    from modules import persistence

    policy = "/etc/sudoers.d/democlient"

    def fake_run(cmd, timeout=45, env=None):
        return {"cmd": cmd, "returncode": 1, "stdout": "", "stderr": "a password is required"}

    monkeypatch.setattr(persistence, "run_cmd", fake_run)
    data = persistence.review_persistence(
        {
            "files_added": [policy],
            "files_changed": [],
            "post_filesystem": {
                policy: {"type": "file", "owner": "root", "group": "root", "mode_octal": "0o440"},
            },
        },
        tmp_path,
    )

    assert data["sudo_policy_status"] == "unavailable"
    assert data["sudo_policy_candidates"] == []
    assert len(data["review_required"]) == 1
    report = (tmp_path / "reports" / "persistence_review.txt").read_text(encoding="utf-8")
    assert "[ATTENTION]" in report
    assert "must be inspected manually before assessment closeout" in report


def test_findings_promote_correlated_sudo_rule_and_list_manual_review(tmp_path):
    from modules.findings import generate_findings

    persistence_data = {
        "sudo_policy_candidates": [{
            "runas": "root",
            "command": "/opt/DemoClient/bin/idp-helper direct-login *",
            "severity": "High",
            "finding_candidate": True,
            "concerns": [
                "SETENV permits caller-controlled environment variables",
                "the permitted executable is dynamically linked, increasing loader-environment risk",
            ],
        }],
        "review_required": [{
            "identity": "sudoers-review:/etc/sudoers.d/democlient",
            "title": "Changed sudoers Policy Requires Manual Review",
            "evidence": "/etc/sudoers.d/democlient was added.",
            "action": "Inspect and validate the policy with visudo.",
        }],
    }

    findings = generate_findings(tmp_path, {}, {}, {}, {}, {}, {}, persistence_data)

    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert findings[0]["title"] == "Potentially Unsafe sudoers Rule Introduced by Application"
    report = (tmp_path / "reports" / "findings.txt").read_text(encoding="utf-8")
    summary = (tmp_path / "reports" / "findings_summary.txt").read_text(encoding="utf-8")
    assert "Manual Review Required" in report
    assert "/etc/sudoers.d/democlient was added" in report
    assert "High:   1" in summary
    assert "Manual review required: 1" in summary


def test_main_sudoers_file_is_tracked_and_high_interest():
    from modules.path_interest import classify_high_interest
    from modules.snapshot import default_tracked_paths

    assert Path("/etc/sudoers") in default_tracked_paths()
    assert classify_high_interest("/etc/sudoers", "file", "-r--r-----") == (True, "SYSTEM CONFIG")


def test_assessment_layout_separates_reports_and_working(tmp_path):
    from modules.common import ensure_assessment_layout
    ensure_assessment_layout(tmp_path)
    assert (tmp_path / "reports").is_dir()
    assert (tmp_path / "working").is_dir()
    assert (tmp_path / "working" / "README.txt").exists()


def test_finalized_artifact_manifest_verifies_and_detects_tampering(tmp_path):
    from modules.artifacts import finalize_artifact_manifest, verify_artifact_manifest
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout

    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "assessment_metadata.json", {"version": "1.2.0", "mode": "full"})
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 5})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 5})
    write_json(tmp_path / "working" / "tester_review_state.json", {"schema_version": 1, "framework_version": "1.2.0", "items": []})
    write_json(tmp_path / "working" / "security_model.json", {"schema_version": 1, "objects": [], "observations": [], "relationships": [], "correlations": []})
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"artifact_manifest.txt"}:
        (tmp_path / "reports" / name).write_text(f"complete {name}\n", encoding="utf-8")

    data = finalize_artifact_manifest(tmp_path, "full")
    assert data["inventory_status"] == "COMPLETE"
    assert data["framework_version"] == "2.0.6"
    assert len(data["expected_reports"]) == 21
    assert verify_artifact_manifest(tmp_path) == []

    import subprocess
    import sys
    script = Path(__file__).resolve().parents[1] / "ubuntuclientassess.py"
    verified = subprocess.run(
        [sys.executable, str(script), "--verify-assessment", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "verification passed" in verified.stdout.lower()

    (tmp_path / "reports" / "network_surface_review.txt").write_text("tampered\n", encoding="utf-8")
    issues = verify_artifact_manifest(tmp_path)
    assert any("network_surface_review.txt" in issue and "mismatch" in issue.lower() for issue in issues)
    rejected = subprocess.run(
        [sys.executable, str(script), "--verify-assessment", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 9


def test_installer_only_manifest_rejects_stale_snapshots(tmp_path):
    from modules.artifacts import finalize_artifact_manifest
    from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout

    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "assessment_metadata.json", {"version": "1.2.0", "mode": "installer-analysis-only"})
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 5})
    for name in EXPECTED_REPORTS_BY_MODE["installer-analysis-only"] - {"artifact_manifest.txt"}:
        (tmp_path / "reports" / name).write_text(f"complete {name}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="stale pre/post snapshots"):
        finalize_artifact_manifest(tmp_path, "installer-analysis-only")


def test_binary_checksec_parser_strips_ansi_and_parses_fields():
    from modules.elf_analysis import _parse_checksec
    sample = (
        "RELRO STACK CANARY NX PIE RPATH RUNPATH Symbols FORTIFY Fortified Fortifiable FILE\n"
        "\x1b[33mPartial RELRO\x1b[m   \x1b[32mCanary found\x1b[m   \x1b[32mNX enabled\x1b[m   "
        "\x1b[31mNo PIE\x1b[m   No RPATH  No RUNPATH  No Symbols  Yes 10 32 /opt/demo\n"
    )
    data = _parse_checksec(sample, Path('/opt/demo'))
    assert data['relro'] == 'Partial'
    assert data['canary'] == 'Enabled'
    assert data['nx'] == 'Enabled'
    assert data['pie'] == 'Disabled'
    assert data['fortify'] == 'Enabled'
    assert data['fortified'] == 10


def test_install_changes_summarizes_large_added_tree(tmp_path):
    pre = {"packages": [], "processes": [], "services": [], "running_services": [], "timers": [], "listening_sockets": [], "unix_sockets": [], "user_crontab": [], "capabilities": [], "suid_sgid": [], "filesystem": {}}
    post_fs = {}
    for i in range(500):
        post_fs[f"/opt/Demo/backend/lib/file{i}.dat"] = {"type": "file", "mode": "-rw-r--r--", "mode_octal": "0o644", "uid": 0, "gid": 0, "owner": "root", "group": "root", "size": 10, "mtime_ns": 1, "sha256": str(i)}
    post = {**pre, "filesystem": post_fs}
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    text = (tmp_path / 'reports' / 'install_changes.txt').read_text()
    assert 'Total filesystem objects added: 500' in text
    assert 'routine/bundled added object(s) are not listed individually' in text
    assert len(text.splitlines()) < 250


def test_install_changes_keeps_ten_thousand_file_package_report_bounded(tmp_path):
    pre = {"packages": [], "processes": [], "services": [], "running_services": [], "timers": [], "listening_sockets": [], "unix_sockets": [], "user_crontab": [], "capabilities": [], "suid_sgid": [], "filesystem": {}}
    post_fs = {
        f"/opt/LargeClient/backend/lib/file{i}.dat": {
            "type": "file", "mode": "-rw-r--r--", "mode_octal": "0o644",
            "uid": 0, "gid": 0, "owner": "root", "group": "root",
            "size": 1024, "mtime_ns": 1, "sha256": f"{i:064x}",
        }
        for i in range(10000)
    }
    write_json(tmp_path / "pre-large.json", pre)
    write_json(tmp_path / "post-large.json", {**pre, "filesystem": post_fs})
    compare_snapshots(tmp_path / "pre-large.json", tmp_path / "post-large.json", tmp_path)
    report = (tmp_path / "reports" / "install_changes.txt").read_text(encoding="utf-8")
    assert "Total filesystem objects added: 10000" in report
    assert "10000 routine/bundled added object(s) are not listed individually." in report
    assert len(report) < 20000


def test_install_changes_does_not_expand_bundled_library_scripts(tmp_path):
    from modules.install_changes import _is_high_interest
    meta = {"type": "file", "mode": "-rw-r--r--"}
    assert _is_high_interest('/opt/Demo/lib/vendor/update.py', meta) == (False, '')
    assert _is_high_interest('/opt/Demo/_internal/certifi/cacert.pem', meta) == (False, '')
    assert _is_high_interest('/opt/Demo/bin/update-client.sh', {**meta, "mode": "-rwxr-xr-x"}) == (True, 'SCRIPT')


def test_installer_analysis_uses_shared_high_interest_filter():
    from modules.installer_analysis import _content_interest
    assert _content_interest('/opt/staging/Demo/lib/update.pyc', '-rw-r--r--') == (False, '')
    assert _content_interest('/opt/staging/Demo/lib/certifi/cacert.pem', '-rw-r--r--') == (False, '')
    assert _content_interest('/opt/staging/Demo/gssapi/tests/test_raw.py', '-rw-r--r--') == (False, '')
    assert _content_interest('/opt/staging/Demo/share/tk8.6/demos/browse', '-rwxr-xr-x') == (False, '')
    assert _content_interest('/opt/staging/Demo/lib/runtime.so', 'lrwxrwxrwx') == (False, '')
    assert _content_interest('/opt/staging/Demo/bin/update-client.sh', '-rwxr-xr-x') == (True, 'SCRIPT')


def test_service_review_does_not_repeat_raw_new_timers_section(tmp_path):
    from modules.services import review_services
    review_services({"services_added": [], "timers_added": []}, tmp_path)
    text = (tmp_path / 'reports' / 'service_review.txt').read_text()
    assert 'New Timers' not in text
    assert 'Application Timers' in text


def test_update_review_suppresses_third_party_documentation_noise(tmp_path):
    noisy = tmp_path / 'backend' / 'lib' / 'dukpy' / 'jsmodules' / 'babel-6.26.0.min.js'
    noisy.parent.mkdir(parents=True)
    noisy.write_text('http://babeljs.io/docs/usage/options/ update verify signature', encoding='utf-8')
    updater = tmp_path / 'bin' / 'update-client.conf'
    updater.parent.mkdir(parents=True)
    updater.write_text('update_url=http://updates.example.invalid/client\nchecksum=sha256\n', encoding='utf-8')
    data = review_updates({"files_added": [str(noisy), str(updater)], "files_changed": []}, tmp_path)
    report = (tmp_path / 'reports' / 'update_review.txt').read_text()
    assert 'babeljs.io' not in report
    assert 'updates.example.invalid' in report
    assert data['insecure_update_url_candidates']


def test_symlink_mode_bits_are_not_treated_as_writable_permission_issue(tmp_path, monkeypatch):
    import modules.permissions as permissions
    from modules.permissions import review_permissions
    monkeypatch.setattr(permissions, "_parent_write_concerns", lambda path, cache=None: [])
    target = tmp_path / 'demo.service'
    target.write_text('[Service]\nExecStart=/bin/true\n', encoding='utf-8')
    target.chmod(0o644)
    link = tmp_path / 'multi-user.target.wants.demo.service'
    link.symlink_to(target)
    diff = {
        'files_added': [str(link)], 'files_changed': [],
        'post_filesystem': {
            str(link): {'type': 'symlink', 'mode': 'lrwxrwxrwx', 'mode_octal': '0o777', 'owner': 'root', 'group': 'root', 'uid': 0, 'gid': 0, 'target': str(target)},
        },
        'capabilities_added': [], 'suid_sgid_added': [],
    }
    data = review_permissions(diff, tmp_path)
    assert data['permission_candidates'] == []



def test_socket_normalization_ignores_pid_fd_inode_changes():
    from modules.snapshot import _normalize_socket_lines
    pre = ['tcp LISTEN 0 10 127.0.0.1:1234 0.0.0.0:* users:(("demo",pid=100,fd=3)) ino:111 sk:aaa']
    post = ['tcp LISTEN 0 10 127.0.0.1:1234 0.0.0.0:* users:(("demo",pid=200,fd=9)) ino:222 sk:bbb']
    assert _normalize_socket_lines(pre) == _normalize_socket_lines(post)


def test_unix_socket_normalization_ignores_queue_and_bare_inode_changes():
    from modules.snapshot import _normalize_socket_lines
    pre = [
        'u_dgr UNCONN 11 0 @3629176864237038870 16854 * 0',
        'u_str LISTEN 0 4096 /run/cups/cups.sock 31770 * 0',
    ]
    post = [
        'u_dgr UNCONN 0 0 @3629176864237038870 16854 * 0',
        'u_str LISTEN 0 4096 /run/cups/cups.sock 55995 * 0',
    ]
    assert _normalize_socket_lines(pre) == _normalize_socket_lines(post)


def test_snapshot_comparison_renormalizes_legacy_unix_socket_rows(tmp_path):
    pre = {"unix_sockets": ['u_str LISTEN 0 4096 /run/cups/cups.sock 31770 * 0'], "filesystem": {}}
    post = {"unix_sockets": ['u_str LISTEN 0 4096 /run/cups/cups.sock 55995 * 0'], "filesystem": {}}
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    diff = compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    assert diff['unix_sockets_added'] == []
    assert diff['unix_sockets_removed'] == []


def test_service_state_change_is_modified_not_added_removed(tmp_path):
    pre = {"services": ["demo.service disabled enabled"], "service_units": {"demo.service": {"state": "disabled", "preset": "enabled"}}, "filesystem": {}}
    post = {"services": ["demo.service enabled enabled"], "service_units": {"demo.service": {"state": "enabled", "preset": "enabled"}}, "filesystem": {}}
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    diff = compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    assert diff['services_added'] == []
    assert diff['services_removed'] == []
    assert len(diff['services_modified']) == 1
    assert diff['services_modified'][0]['unit'] == 'demo.service'
    assert diff['post_service_units']['demo.service']['state'] == 'enabled'


def test_user_group_mount_changes_are_compared(tmp_path):
    pre = {
        "users": ["root:x:0:0:root:/root:/bin/bash"],
        "groups": ["vendor:x:999:alice"],
        "mounts": ["/ /dev/sda1 ext4 rw"],
        "filesystem": {},
    }
    post = {
        "users": ["root:x:0:0:root:/root:/bin/bash", "vendor:x:999:999::/nonexistent:/usr/sbin/nologin"],
        "groups": ["vendor:x:999:alice,bob"],
        "mounts": ["/ /dev/sda1 ext4 rw", "/opt/vendor tmpfs tmpfs rw"],
        "filesystem": {},
    }
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    diff = compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    assert any(x.startswith('vendor:') for x in diff['users_added'])
    assert diff['groups_modified']
    assert any(x.startswith('/opt/vendor ') for x in diff['mounts_added'])


def test_volatile_root_runtime_mount_is_suppressed(tmp_path):
    pre = {"mounts": ["/ /dev/sda1 ext4 rw"], "filesystem": {}}
    post = {"mounts": ["/ /dev/sda1 ext4 rw", "/run/user/0 tmpfs tmpfs rw,mode=700"], "filesystem": {}}
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    diff = compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    assert diff['mounts_added'] == []


def test_gvfs_session_metadata_is_suppressed_from_filesystem_diff(tmp_path):
    path = '/home/tester/.local/share/gvfs-metadata/root-session.log'
    pre = {"filesystem": {path: {"type": "file", "size": 1, "mtime_ns": 1, "sha256": "a"}}}
    post = {"filesystem": {path: {"type": "file", "size": 2, "mtime_ns": 2, "sha256": "b"}}}
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    diff = compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    assert diff['files_changed'] == []
    assert 'gvfs-metadata' not in (tmp_path / 'reports' / 'install_changes.txt').read_text()


def test_gnome_shell_application_state_is_suppressed(tmp_path):
    parent = '/home/tester/.local/share/gnome-shell'
    state = parent + '/application_state'
    pre = {"filesystem": {
        parent: {"type": "directory", "mtime_ns": 1},
        state: {"type": "file", "size": 1, "mtime_ns": 1, "sha256": "a"},
    }}
    post = {"filesystem": {
        parent: {"type": "directory", "mtime_ns": 2},
        state: {"type": "file", "size": 2, "mtime_ns": 2, "sha256": "b"},
    }}
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    diff = compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    assert diff['files_changed'] == []
    assert 'gnome-shell' not in (tmp_path / 'reports' / 'install_changes.txt').read_text()


def test_packagekit_running_service_churn_is_suppressed(tmp_path):
    pre = {"running_services": [], "filesystem": {}}
    post = {"running_services": ["packagekit.service loaded active running PackageKit Daemon"], "filesystem": {}}
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    diff = compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    assert diff['running_services_added'] == []
    assert 'packagekit.service' not in (tmp_path / 'reports' / 'install_changes.txt').read_text()


def test_network_specific_non_loopback_bind_is_review_candidate(tmp_path):
    from modules.network import review_network
    data = review_network({"listening_sockets_added": ["tcp LISTEN 0 128 192.268.1.25:8443 0.0.0.0:*"], "listening_sockets_removed": []}, tmp_path)
    assert data['exposed_listener_candidates']
    loopback = review_network({"listening_sockets_added": ["tcp LISTEN 0 128 127.0.0.1:8443 0.0.0.0:*"], "listening_sockets_removed": []}, tmp_path)
    assert loopback['exposed_listener_candidates'] == []


def test_dbus_activation_name_is_parsed(tmp_path):
    from modules.ipc import review_ipc
    p = tmp_path / 'usr' / 'share' / 'dbus-1' / 'system-services' / 'com.vendor.Demo.service'
    p.parent.mkdir(parents=True)
    p.write_text('[D-BUS Service]\nName=com.vendor.Demo\nExec=/opt/vendor/demo\nUser=root\n', encoding='utf-8')
    data = review_ipc({"files_added": [str(p)], "files_changed": [], "unix_sockets_added": [], "post_filesystem": {}}, tmp_path)
    assert 'com.vendor.Demo' in data['dbus_names']


def test_security_scan_paths_include_package_usr_lib_path(tmp_path):
    from modules.snapshot import _security_scan_paths
    vendor = tmp_path / 'usr' / 'lib' / 'vendor'
    vendor.mkdir(parents=True)
    paths = _security_scan_paths([vendor])
    assert vendor in paths


def test_elf_search_path_uses_interactive_user_write_helper(tmp_path, monkeypatch):
    import modules.elf_analysis as elf
    d = tmp_path / 'lib'
    d.mkdir()
    called = {"value": False}
    def fake_can_write(path):
        called['value'] = True
        return False
    monkeypatch.setattr(elf, 'user_can_write', fake_can_write)
    elf._search_path_concern(tmp_path / 'bin', str(d))
    assert called['value']


def test_elf_search_path_flags_tester_owned_directory(tmp_path):
    from modules.elf_analysis import _search_path_concern

    d = tmp_path / "lib"
    d.mkdir()
    concern, finding_candidate = _search_path_concern(tmp_path / "bin", str(d))

    assert finding_candidate is True
    assert concern and "tester has write access" in concern


def test_snapshot_excludes_configured_paths(tmp_path):
    tracked = tmp_path / "tracked"
    excluded = tracked / "runner-state"
    included = tracked / "application"
    excluded.mkdir(parents=True)
    included.mkdir()
    (excluded / "Cookies").write_text("noise", encoding="utf-8")
    (included / "client.conf").write_text("expected", encoding="utf-8")

    filesystem = _collect_filesystem([tracked], [excluded])

    assert str(included / "client.conf") in filesystem
    assert str(excluded) not in filesystem
    assert str(excluded / "Cookies") not in filesystem


def test_snapshot_reuses_hash_for_unchanged_inode(tmp_path, monkeypatch):
    import modules.snapshot as snapshot

    target = tmp_path / "large-client.bin"
    target.write_bytes(b"release-hardening" * 1024)
    calls = []

    def fake_hash(path, max_bytes=None):
        calls.append(path)
        return "a" * 64

    snapshot._HASH_CACHE.clear()
    monkeypatch.setattr(snapshot, "sha256_file", fake_hash)
    first = snapshot._collect_filesystem([target])
    second = snapshot._collect_filesystem([target])
    assert first[str(target)]["sha256"] == second[str(target)]["sha256"] == "a" * 64
    assert calls == [target]


def test_large_package_timeout_scales_with_bounded_ceiling():
    from modules.installer_analysis import MAX_PACKAGE_COMMAND_TIMEOUT, _package_command_timeout

    assert _package_command_timeout(0, base=120) == 120
    assert _package_command_timeout(2 * 1024 * 1024 * 1024, base=120) > 120
    assert _package_command_timeout(100 * 1024 * 1024 * 1024, base=120) == MAX_PACKAGE_COMMAND_TIMEOUT


def test_runtime_review_has_no_screenshot_placeholder(tmp_path):
    from modules.runtime import write_runtime_guidance
    write_runtime_guidance(tmp_path)
    text = (tmp_path / 'reports' / 'runtime_review.txt').read_text()
    assert '<SCREENSHOT>' not in text
    assert '\nEvidence\n' not in text


def test_clean_generated_artifacts_removes_stale_reports_and_full_snapshots(tmp_path):
    from modules.common import clean_generated_artifacts, ensure_assessment_layout
    ensure_assessment_layout(tmp_path)
    (tmp_path / 'reports' / 'findings.txt').write_text('STALE')
    (tmp_path / 'working' / 'snapshot_pre.json').write_text('{}')
    (tmp_path / 'working' / 'snapshot_post.json').write_text('{}')
    (tmp_path / 'working' / 'deb_control').mkdir()
    (tmp_path / 'working' / 'deb_control' / 'postinst').write_text('old')
    (tmp_path / 'reports' / '.findings.txt.abcd.tmp').write_text('partial')
    (tmp_path / '.assessment_metadata.json.abcd.tmp').write_text('partial')
    (tmp_path / 'assessment_manifest.json').write_text('{}')
    (tmp_path / 'working' / 'INTERRUPTED_RUN.txt').write_text('old interruption')
    clean_generated_artifacts(tmp_path, full_run=True)
    assert not (tmp_path / 'reports' / 'findings.txt').exists()
    assert not (tmp_path / 'working' / 'snapshot_pre.json').exists()
    assert not (tmp_path / 'working' / 'snapshot_post.json').exists()
    assert not (tmp_path / 'working' / 'deb_control').exists()
    assert not (tmp_path / 'reports' / '.findings.txt.abcd.tmp').exists()
    assert not (tmp_path / '.assessment_metadata.json.abcd.tmp').exists()
    assert not (tmp_path / 'working' / 'INTERRUPTED_RUN.txt').exists()
    assert not (tmp_path / 'assessment_manifest.json').exists()


def test_installer_only_cleanup_removes_stale_full_snapshots(tmp_path):
    from modules.common import clean_generated_artifacts, ensure_assessment_layout

    ensure_assessment_layout(tmp_path)
    (tmp_path / "working" / "snapshot_pre.json").write_text("{}", encoding="utf-8")
    (tmp_path / "working" / "snapshot_post.json").write_text("{}", encoding="utf-8")
    clean_generated_artifacts(tmp_path, full_run=False)
    assert not (tmp_path / "working" / "snapshot_pre.json").exists()
    assert not (tmp_path / "working" / "snapshot_post.json").exists()


def test_atomic_write_preserves_previous_file_when_replace_fails(tmp_path, monkeypatch):
    import modules.common as common

    target = tmp_path / "report.txt"
    target.write_text("complete-old\n", encoding="utf-8")

    def fail_replace(source, destination):
        raise OSError("simulated interruption before atomic replace")

    monkeypatch.setattr(common.os, "replace", fail_replace)
    with pytest.raises(OSError):
        common.write_text(target, "partial-new")
    assert target.read_text(encoding="utf-8") == "complete-old\n"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_interrupted_run_records_recovery_state(tmp_path):
    import ubuntuclientassess as uca

    metadata_path = tmp_path / "assessment_metadata.json"
    metadata = {"installation": {"status": "in-progress", "confirmed": False}}
    uca._set_run_state(metadata_path, metadata, "package-installation")
    uca._mark_active_run_interrupted()
    recorded = uca.read_json(metadata_path)
    assert recorded["run_state"]["status"] == "interrupted"
    assert recorded["run_state"]["stage"] == "package-installation"
    assert recorded["installation"]["status"] == "interrupted"
    marker = tmp_path / "working" / "INTERRUPTED_RUN.txt"
    assert marker.is_file()
    assert "restore a clean VM baseline" in marker.read_text(encoding="utf-8")
    uca._ACTIVE_RUN = None


def test_installer_analysis_clears_previous_deb_control_and_payload(tmp_path):
    import shutil
    import subprocess
    from modules.installer_analysis import analyze_installer
    if not shutil.which('dpkg-deb'):
        return

    def build(name: str, with_postinst: bool, payload_name: str):
        pkg = tmp_path / name
        (pkg / 'DEBIAN').mkdir(parents=True)
        (pkg / 'DEBIAN' / 'control').write_text(
            f'Package: {name}\nVersion: 1\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: test\n'
        )
        if with_postinst:
            (pkg / 'DEBIAN' / 'postinst').write_text('#!/bin/sh\necho OLD-MARKER\n')
            (pkg / 'DEBIAN' / 'postinst').chmod(0o755)
        (pkg / 'opt' / name).mkdir(parents=True)
        (pkg / 'opt' / name / payload_name).write_text('x')
        deb = tmp_path / f'{name}.deb'
        subprocess.run(['dpkg-deb', '--build', str(pkg), str(deb)], check=True, capture_output=True)
        return deb

    a = build('uca-a', True, 'old.txt')
    b = build('uca-b', False, 'new.txt')
    analyze_installer(a, tmp_path, retain_payload=True)
    analyze_installer(b, tmp_path, retain_payload=True)
    report = (tmp_path / 'reports' / 'installer_analysis.txt').read_text()
    assert 'OLD-MARKER' not in report
    assert not (tmp_path / 'working' / 'deb_payload' / 'opt' / 'uca-a' / 'old.txt').exists()
    assert (tmp_path / 'working' / 'deb_payload' / 'opt' / 'uca-b' / 'new.txt').exists()
    analyze_installer(b, tmp_path)
    assert not (tmp_path / 'working' / 'deb_payload').exists()
    assert 'Not retained for this full assessment' in (tmp_path / 'reports' / 'installer_analysis.txt').read_text()


def test_service_review_uses_effective_systemctl_show_values(tmp_path, monkeypatch):
    import modules.services as services
    def fake_run(cmd, timeout=45, env=None):
        if cmd[:3] == ['systemctl', 'cat', 'demo.service']:
            return {"returncode": 0, "stdout": '[Service]\nUser=root\nExecStart=/opt/vendor/old\n# drop-in\nUser=vendor\nExecStart=\nExecStart=/opt/vendor/new\n', "stderr": ''}
        if cmd[:3] == ['systemctl', 'show', 'demo.service']:
            return {"returncode": 0, "stdout": 'User=vendor\nGroup=vendor\nDynamicUser=no\nExecStart={ path=/opt/vendor/new ; argv[]=/opt/vendor/new ; }\nEnvironmentFiles=\nWorkingDirectory=/opt/vendor\nFragmentPath=/etc/systemd/system/demo.service\nDropInPaths=/etc/systemd/system/demo.service.d/override.conf\nNoNewPrivileges=no\nProtectSystem=no\nProtectHome=no\nPrivateTmp=no\nCapabilityBoundingSet=\n', "stderr": ''}
        return {"returncode": 1, "stdout": '', "stderr": ''}
    monkeypatch.setattr(services, 'run_cmd', fake_run)
    monkeypatch.setattr(services, '_write_concerns', lambda p: [])
    monkeypatch.setattr(services, '_resolve_exec_chain', lambda p: [p])
    data = services.review_services({
        "services_added": ['demo.service'],
        "post_service_units": {"demo.service": {"state": "enabled", "preset": "enabled"}},
        "timers_added": [],
        "services_modified": [],
    }, tmp_path)
    rec = data['services'][0]
    assert rec['user'] == 'vendor'
    assert rec['privileged'] is False
    assert rec['exec_paths'] == ['/opt/vendor/new']
    assert '/opt/vendor/old' not in rec['exec_paths']
    report = (tmp_path / 'reports' / 'service_review.txt').read_text()
    assert 'State:     enabled' in report
    assert 'Preset:    enabled' in report
    assert 'State:     demo.service' not in report


def test_install_changes_suppresses_ambient_process_churn(tmp_path):
    pre = {"packages": [], "processes": [], "services": [], "running_services": [], "timers": [], "listening_sockets": [], "unix_sockets": [], "user_crontab": [], "capabilities": [], "suid_sgid": [], "filesystem": {}}
    post = {
        **pre,
        "processes": [
            "root root demo /opt/Demo/bin/demo",
            "root root kworker/0:0 [kworker/0:0-events]",
        ],
        "filesystem": {
            "/opt/Demo/bin/demo": {"type": "file", "mode": "-rwxr-xr-x", "mode_octal": "0o755", "uid": 0, "gid": 0, "owner": "root", "group": "root", "size": 1, "mtime_ns": 1, "sha256": "x"},
        },
    }
    write_json(tmp_path / 'pre.json', pre)
    write_json(tmp_path / 'post.json', post)
    diff = compare_snapshots(tmp_path / 'pre.json', tmp_path / 'post.json', tmp_path)
    assert len(diff['processes_added']) == 2
    report = (tmp_path / 'reports' / 'install_changes.txt').read_text()
    assert '/opt/Demo/bin/demo' in report
    assert 'kworker/0:0-events' not in report
    assert 'Ambient host processes suppressed from this section: 1' in report


def test_permissions_do_not_treat_public_cert_or_generic_cfg_as_secret(tmp_path):
    from modules.permissions import _is_sensitive_read_candidate
    public_cert = tmp_path / 'cacert.pem'
    public_cert.write_text('-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n')
    generic_cfg = tmp_path / '_c_ast.cfg'
    generic_cfg.write_text('not sensitive')
    private_key = tmp_path / 'client.pem'
    private_key.write_text('-----BEGIN PRIVATE KEY-----\nredacted\n')
    library_symbol = tmp_path / 'modifyPassword.pyc'
    library_symbol.write_bytes(b'compiled code')
    assert _is_sensitive_read_candidate(public_cert) is False
    assert _is_sensitive_read_candidate(generic_cfg) is False
    assert _is_sensitive_read_candidate(private_key) is True
    assert _is_sensitive_read_candidate(library_symbol) is False


def test_storage_permission_note_respects_private_ancestor(tmp_path):
    from modules.storage import _permission_note
    private_dir = tmp_path / 'private'
    private_dir.mkdir(mode=0o700)
    artifact = private_dir / 'state.json'
    artifact.write_text('{}')
    artifact.chmod(0o644)
    assert _permission_note(artifact) is None


def test_elf_review_notes_suppress_routine_shared_library_observations():
    from modules.elf_analysis import _review_notes
    routine_dso = {
        "shared_object": True,
        "checksec": {"canary": "Disabled", "nx": "Enabled", "relro": "Partial", "pie": "DSO"},
        "dynamic": {"rpath": [], "runpath": ["$ORIGIN"]},
        "search_path_concerns": [],
    }
    assert _review_notes(routine_dso) == []
    routine_dso["checksec"]["nx"] = "Disabled"
    assert _review_notes(routine_dso) == ["NX disabled"]


def test_custom_workflow_rejects_shell_control_operators():
    import ubuntuclientassess as uca
    assert uca._contains_shell_control('sudo apt update && sudo apt install ./x.deb')
    assert not uca._contains_shell_control('sudo apt install -y {INSTALLER}')


def test_noninteractive_installer_analysis_requires_installer(tmp_path):
    import subprocess, sys
    script = Path(__file__).resolve().parents[1] / 'ubuntuclientassess.py'
    result = subprocess.run([sys.executable, str(script), '--non-interactive', '--installer-analysis-only', '-o', str(tmp_path), '-n', 'NoInstaller'], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'requires an installer/package file' in (result.stdout + result.stderr)


def test_noninteractive_full_requires_auto_install(tmp_path):
    import subprocess, sys
    installer = tmp_path / 'dummy.deb'
    installer.write_text('not a real deb')
    script = Path(__file__).resolve().parents[1] / 'ubuntuclientassess.py'
    result = subprocess.run([sys.executable, str(script), '--non-interactive', '-i', str(installer), '-o', str(tmp_path / 'out'), '-n', 'Demo'], capture_output=True, text=True)
    assert result.returncode != 0
    assert '--auto-install-deb' in (result.stdout + result.stderr)


def test_snapshot_diff_compares_connections_and_container_packages(tmp_path):
    pre = {"filesystem": {}, "network_connections": [], "snap_packages": [], "flatpak_packages": [], "flatpak_remotes": []}
    post = {
        "filesystem": {},
        "network_connections": ['tcp ESTAB 0 0 127.0.0.1:50000 203.0.113.8:443 users:(("demo",pid=99,fd=7))'],
        "snap_packages": ["demo 1.0 1 latest/stable vendor strict"],
        "flatpak_packages": ["org.example.Demo\tapp/org.example.Demo/x86_64/stable\t1.0\tstable\tflathub\tuser"],
        "flatpak_remotes": ["flathub\thttps://dl.flathub.org/repo/\t-\t-\t-\tuser"],
    }
    write_json(tmp_path / "pre.json", pre)
    write_json(tmp_path / "post.json", post)
    diff = compare_snapshots(tmp_path / "pre.json", tmp_path / "post.json", tmp_path)
    assert diff["network_connections_added"]
    assert diff["snap_packages_added"]
    assert diff["flatpak_packages_added"]
    assert diff["flatpak_remotes_added"]


def test_network_discovers_tls_proxy_and_redacts_url_secrets(tmp_path):
    from modules.network import review_network

    config = tmp_path / "client.conf"
    config.write_text(
        "api=https://user:password@api.example.test/v1?token=very-secret&mode=prod\n"
        "https_proxy=http://proxy.example.test:8080\n",
        encoding="utf-8",
    )
    connection = 'tcp ESTAB 0 0 127.0.0.1:50000 203.0.113.8:443 users:(("client",pid=<PID>,fd=<FD>))'
    data = review_network({
        "files_added": [str(config), "/opt/demo/client"], "files_changed": [],
        "processes_added": ["tester tester client /opt/demo/client"],
        "network_connections_added": [connection],
        "listening_sockets_added": [], "listening_sockets_removed": [],
    }, tmp_path)
    report = (tmp_path / "reports" / "network_surface_review.txt").read_text()
    assert data["tls_endpoints"]
    assert data["proxy_indicators"]
    assert data["new_connections"] == [connection]
    assert "very-secret" not in report
    assert "user:password" not in report
    assert "[REDACTED]" in report


def test_network_suppresses_bundled_dependency_and_reference_noise(tmp_path):
    from modules.network import review_network

    bundled = tmp_path / "app" / "lib" / "dukpy"
    bundled.mkdir(parents=True)
    (bundled / "runtime.js").write_text(
        "docs=https://www.w3.org/TR/example\n"
        "https_proxy=http://proxy.dependency.test:8080\n"
        "ssl_verify=false\n",
        encoding="utf-8",
    )
    tests = tmp_path / "app" / "gssapi" / "tests"
    tests.mkdir(parents=True)
    (tests / "test_raw.py").write_text(
        "issue='https://github.com/vendor/project/issues/123'\n",
        encoding="utf-8",
    )
    internal = tmp_path / "app" / "modules" / "Plugin" / "_internal"
    internal.mkdir(parents=True)
    native_dependency = internal / "_cffi_backend.cpython-312-x86_64-linux-gnu.so"
    native_dependency.write_bytes(b"https://cffi.readthedocs.io/en/latest/using.html\n")
    config = tmp_path / "app" / "client.conf"
    config.write_text("update=https://updates.vendor.test/client\n", encoding="utf-8")

    data = review_network({
        "files_added": [str(bundled / "runtime.js"), str(tests / "test_raw.py"), str(native_dependency), str(config)],
        "files_changed": [], "listening_sockets_added": [], "listening_sockets_removed": [],
    }, tmp_path)
    report = (tmp_path / "reports" / "network_surface_review.txt").read_text()
    assert [item["endpoint"] for item in data["endpoints"]] == ["https://updates.vendor.test/client"]
    assert not data["proxy_indicators"]
    assert "w3.org" not in report
    assert "github.com/vendor/project/issues" not in report
    assert "proxy.dependency.test" not in report
    assert "cffi.readthedocs.io" not in report


def test_storage_profiles_chromium_config_and_logs(tmp_path):
    profile = tmp_path / "Default"
    profile.mkdir()
    cookies = profile / "Cookies"
    cookies.write_bytes(b"SQLite format 3\x00" + b"\x00" * 128)
    config = tmp_path / "settings.conf"
    config.write_text("rejectUnauthorized=false\n", encoding="utf-8")
    log = tmp_path / "logs" / "client.log"
    log.parent.mkdir()
    log.write_text("normal log line\n", encoding="utf-8")
    data = review_storage({"files_added": [str(cookies), str(config), str(log)], "files_changed": []}, tmp_path)
    assert data["chromium_storage"]
    assert data["configuration_risks"]
    assert data["temporary_log_artifacts"]


def test_update_review_validates_checksum_manifest(tmp_path):
    payload = tmp_path / "client.bin"
    payload.write_bytes(b"roadmap-validation")
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{hashlib.sha256(payload.read_bytes()).hexdigest()}  client.bin\n", encoding="utf-8")
    data = review_updates({"files_added": [str(manifest), str(payload)], "files_changed": []}, tmp_path)
    assert data["checksum_validations"]
    assert data["checksum_validations"][0]["status"] == "PASS"


def test_checksum_manifest_rejects_parent_traversal(tmp_path):
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{'0' * 64}  ../outside.bin\n", encoding="utf-8")
    data = review_updates({"files_added": [str(manifest)], "files_changed": []}, tmp_path)
    assert data["checksum_validations"][0]["unsafe"] == ["../outside.bin"]
    assert data["checksum_validations"][0]["status"] == "FAIL"


def test_archive_review_flags_traversal_and_fingerprints_framework(tmp_path):
    from modules.application_profile import profile_application
    from modules.installer_analysis import analyze_installer

    archive = tmp_path / "client.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape", "unsafe")
        handle.writestr("client/resources/app.asar", "placeholder")
        handle.writestr("client/lib/runtime.jar", "placeholder")
    installer_data = analyze_installer(archive, tmp_path)
    assert installer_data["archive"]["unsafe_members"]
    profile = profile_application(tmp_path, installer_data=installer_data)
    technologies = {item["technology"] for item in profile["technologies"]}
    assert "Electron / Chromium" in technologies
    assert "Java / JVM" in technologies


def test_script_installer_static_analysis_without_execution(tmp_path):
    from modules.installer_analysis import analyze_installer

    script = tmp_path / "vendor.run"
    script.write_text(
        "#!/bin/bash\n"
        "update_url=https://updates.example.test/client\n"
        "install_path=/opt/vendor/client\n"
        "echo __ARCHIVE_BELOW__ >/dev/null\n",
        encoding="utf-8",
    )
    data = analyze_installer(script, tmp_path)
    assert data["script_analysis"]["syntax"] == "valid"
    assert data["script_analysis"]["urls"] == ["https://updates.example.test/client"]
    assert "/opt/vendor/client" in data["script_analysis"]["install_paths"]
    assert data["script_analysis"]["embedded_archive"]


def test_application_profile_detects_native_python_and_dotnet(tmp_path):
    from modules.application_profile import profile_application

    root = tmp_path / "app"
    root.mkdir()
    (root / "client").write_bytes(b"\x7fELF" + b"\x00" * 32)
    (root / "base_library.zip").write_bytes(b"PK\x03\x04")
    (root / "client.runtimeconfig.json").write_text("{}", encoding="utf-8")
    data = profile_application(tmp_path, extra_roots=[root])
    technologies = {item["technology"] for item in data["technologies"]}
    assert {"Native ELF", "Python", ".NET / Mono"}.issubset(technologies)


def test_application_profile_rejects_native_pe_stubs_and_prefers_installed_evidence(tmp_path):
    from modules.application_profile import profile_application

    installed = tmp_path / "installed" / "setuptools"
    installed.mkdir(parents=True)
    launchers = []
    for index in range(20):
        launcher = installed / f"cli-{index}.exe"
        launcher.write_bytes(b"MZ" + b"\x00" * 510)
        launchers.append(str(launcher))
    extracted = tmp_path / "working" / "deb_payload"
    extracted.mkdir(parents=True)
    (extracted / "uninstalled.runtimeconfig.json").write_text("{}", encoding="utf-8")

    data = profile_application(
        tmp_path,
        diff={"files_added": launchers, "files_changed": []},
        installer_data={"extracted_root": str(extracted), "member_paths": ["uninstalled.runtimeconfig.json"]},
    )
    technologies = {item["technology"] for item in data["technologies"]}
    assert ".NET / Mono" not in technologies
    assert data["archive_members_considered"] == 0
    assert data["files_considered"] == len(launchers)


def test_application_profile_identifies_managed_pe_cli_header(tmp_path):
    from modules.application_profile import profile_application

    assembly = bytearray(512)
    assembly[:2] = b"MZ"
    struct.pack_into("<I", assembly, 0x3C, 0x80)
    assembly[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", assembly, 0x94, 224)
    optional = 0x98
    struct.pack_into("<H", assembly, optional, 0x10B)
    struct.pack_into("<I", assembly, optional + 92, 16)
    struct.pack_into("<II", assembly, optional + 96 + (14 * 8), 0x2000, 72)
    target = tmp_path / "client.dll"
    target.write_bytes(assembly)

    data = profile_application(tmp_path, extra_roots=[target])
    dotnet = next(item for item in data["technologies"] if item["technology"] == ".NET / Mono")
    assert dotnet["confidence"] == "MEDIUM"
    assert dotnet["evidence"][0]["indicator"] == "Managed PE with CLI header"


def test_snap_squashfs_is_extracted_without_execution(tmp_path):
    import shutil
    import subprocess
    from modules.installer_analysis import analyze_installer

    if not shutil.which("mksquashfs") or not shutil.which("unsquashfs"):
        return
    source = tmp_path / "snap-root"
    (source / "meta").mkdir(parents=True)
    (source / "meta" / "snap.yaml").write_text("name: roadmap-demo\nversion: '1'\nconfinement: strict\n", encoding="utf-8")
    snap = tmp_path / "roadmap-demo.snap"
    subprocess.run(["mksquashfs", str(source), str(snap), "-noappend", "-quiet", "-processors", "1"], check=True, capture_output=True)
    data = analyze_installer(snap, tmp_path / "assessment")
    assert data["type"] == "snap"
    assert data["extraction"]["status"] == "extracted", data["extraction"]
    assert (Path(data["extracted_root"]) / "meta" / "snap.yaml").is_file()


def test_post_analysis_generates_roadmap_report_set(tmp_path):
    import ubuntuclientassess as uca

    working = tmp_path / "working"
    working.mkdir()
    snapshot = {
        "schema_version": 5,
        "packages": [], "snap_packages": [], "flatpak_packages": [], "flatpak_remotes": [],
        "processes": [], "services": [], "running_services": [], "timers": [],
        "listening_sockets": [], "network_connections": [], "unix_sockets": [],
        "mounts": [], "users": [], "groups": [], "user_crontab": [],
        "capabilities": [], "suid_sgid": [], "filesystem": {},
    }
    write_json(working / "snapshot_pre.json", snapshot)
    write_json(working / "snapshot_post.json", snapshot)
    status = {}
    assert uca.post_analysis(tmp_path, None, None, status, {"type": "archive"}) is True
    for report in (
        "install_changes.txt", "application_profile.txt", "network_surface_review.txt",
        "local_storage_review.txt", "update_review.txt", "runtime_review.txt",
        "findings.txt", "findings_summary.txt", "assessment_coverage.txt",
    ):
        assert (tmp_path / "reports" / report).is_file(), report
    assert status["Network Surface Review"][0] == "ATTN"
    assert all(state == "PASS" for name, (state, _detail) in status.items() if name != "Network Surface Review")


def test_post_analysis_marks_unresolved_privileged_policy_as_attention(tmp_path, monkeypatch):
    import ubuntuclientassess as uca

    working = tmp_path / "working"
    working.mkdir()
    snapshot = {
        "schema_version": 5,
        "packages": [], "snap_packages": [], "flatpak_packages": [], "flatpak_remotes": [],
        "processes": [], "services": [], "running_services": [], "timers": [],
        "listening_sockets": [], "network_connections": [], "unix_sockets": [],
        "mounts": [], "users": [], "groups": [], "user_crontab": [],
        "capabilities": [], "suid_sgid": [], "filesystem": {},
    }
    write_json(working / "snapshot_pre.json", snapshot)
    write_json(working / "snapshot_post.json", snapshot)

    def fake_persistence(diff, output_dir, elf_data):
        (output_dir / "reports").mkdir(parents=True, exist_ok=True)
        (output_dir / "reports" / "persistence_review.txt").write_text("review required\n", encoding="utf-8")
        return {
            "sudo_policy_candidates": [],
            "review_required": [{
                "identity": "sudoers-review:/etc/sudoers.d/demo",
                "title": "Changed sudoers Policy Requires Manual Review",
                "evidence": "/etc/sudoers.d/demo was added.",
                "action": "Inspect it.",
            }],
        }

    monkeypatch.setattr(uca, "review_persistence", fake_persistence)
    status = {}

    assert uca.post_analysis(tmp_path, None, None, status, {"type": "archive"}) is True
    assert status["Persistence Review"][0] == "ATTN"
    assert "1 privileged policy change(s) require manual review" in status["Persistence Review"][1]
    assert "Manual review required: 1" in (
        tmp_path / "reports" / "findings_summary.txt"
    ).read_text(encoding="utf-8")


def test_permissions_skip_getfacl_without_extended_acl(tmp_path, monkeypatch):
    import modules.permissions as permissions

    target = tmp_path / "plain.conf"
    target.write_text("x=1\n", encoding="utf-8")
    monkeypatch.setattr(permissions.os, "listxattr", lambda path, follow_symlinks=True: [])
    monkeypatch.setattr(permissions, "run_cmd", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("getfacl should not run")))
    assert permissions._acl_write_entries(target) == []


def test_elf_magic_detection_does_not_spawn_file(tmp_path, monkeypatch):
    import modules.elf_analysis as elf_analysis

    target = tmp_path / "client"
    target.write_bytes(b"\x7fELF" + b"\0" * 32)
    monkeypatch.setattr(elf_analysis, "run_cmd", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("file should not run")))
    assert elf_analysis._is_elf(target) is True


def test_bundled_sdk_and_lockfile_noise_is_suppressed(tmp_path):
    from modules.network import _discover_endpoints
    from modules.storage import review_storage
    from modules.update_review import review_updates

    sdk = tmp_path / "lib" / "botocore" / "data" / "service-2.json"
    sdk.parent.mkdir(parents=True)
    sdk.write_text('{"update_url": "https://docs.example.test/update", "token": "string"}', encoding="utf-8")
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"resolved": "https://registry.npmjs.org/demo/-/demo.tgz"}', encoding="utf-8")
    diff = {"files_added": [str(sdk), str(lock)], "files_changed": []}

    endpoints, _, _ = _discover_endpoints([sdk, lock])
    assert endpoints == []
    assert review_storage(diff, tmp_path)["secret_hits"] == []
    assert review_updates(diff, tmp_path)["urls"] == []


def test_vendor_shared_library_endpoints_remain_discoverable(tmp_path, monkeypatch):
    import modules.network as network

    library = tmp_path / "vendor" / "lib" / "client-network.so.1"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"\x7fELF" + b"\0" * 32)
    monkeypatch.setattr(network, "command_exists", lambda name: name == "strings")
    monkeypatch.setattr(
        network,
        "run_cmd",
        lambda *args, **kwargs: {"returncode": 0, "stdout": "https://api.vendor.example.test/v1\n"},
    )

    endpoints, _, _ = network._discover_endpoints([library])
    assert [item["endpoint"] for item in endpoints] == ["https://api.vendor.example.test/v1"]


def test_known_library_project_urls_are_reference_noise(tmp_path):
    from modules.network import _discover_endpoints, _reference_url

    assert _reference_url("http://www.qt.io/licensing/") is True
    assert _reference_url("http://cairographics.org") is True
    notice = tmp_path / "notice.txt"
    notice.write_text("Created by cairo (http://cairographics.org)\n", encoding="utf-8")
    assert _discover_endpoints([notice])[0] == []


def test_executable_marked_resource_is_not_high_interest():
    from modules.path_interest import classify_high_interest

    assert classify_high_interest("/opt/vendor/icons/logo.png", "file", "-rwxr-xr-x") == (False, "")


def test_home_top_level_discovery_respects_exclusions(tmp_path, monkeypatch):
    import ubuntuclientassess as uca

    (tmp_path / ".vendor").mkdir()
    (tmp_path / ".runner").mkdir()
    monkeypatch.setattr(uca, "get_interactive_home", lambda: tmp_path)
    assert uca._home_top_level_entries([tmp_path / ".runner"]) == {(tmp_path / ".vendor").resolve()}


def test_update_icons_are_not_update_endpoints(tmp_path):
    icon = tmp_path / 'software-update-available.svg'
    icon.write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
    config = tmp_path / 'updater.conf'
    config.write_text('update_url=http://updates.example.test/client')
    data = review_updates({'files_added': [str(icon), str(config)], 'files_changed': []}, tmp_path)
    assert str(icon) not in data['updater_paths']
    assert [x['url'] for x in data['insecure_update_url_candidates']] == ['http://updates.example.test/client']


def test_update_findings_group_endpoint_and_preserve_locations(tmp_path):
    from modules.findings import generate_findings
    candidates = [
        {'url': 'http://updates.example.test/client', 'path': '/opt/client/a.conf', 'line': 1, 'confidence': 'HIGH'},
        {'url': 'http://updates.example.test/client', 'path': '/opt/client/b.conf', 'line': 2, 'confidence': 'HIGH'},
        {'url': 'http://updates.example.test/other', 'path': '/opt/client/c.conf', 'line': 3, 'confidence': 'HIGH'},
    ]
    findings = generate_findings(tmp_path, {}, {}, {}, {}, update_data={'insecure_update_url_candidates': candidates})
    assert len(findings) == 2
    assert '/opt/client/a.conf:1' in findings[0]['evidence']
    assert '/opt/client/b.conf:2' in findings[0]['evidence']


def test_snapshot_prunes_excluded_directory_before_traversal(tmp_path, monkeypatch):
    from modules import snapshot
    root = tmp_path / 'root'
    excluded = root / 'excluded'
    excluded.mkdir(parents=True)
    (excluded / 'secret').write_text('excluded')
    included = root / 'included'
    included.write_text('included')
    (root / 'link').symlink_to(excluded, target_is_directory=True)
    original = snapshot.os.scandir
    visited = []
    def scan(path):
        visited.append(Path(path))
        assert Path(path) != excluded
        return original(path)
    monkeypatch.setattr(snapshot.os, 'scandir', scan)
    result = snapshot._collect_filesystem([root], [excluded])
    assert str(included) in result
    assert str(excluded) not in result
    assert result[str(root / 'link')]['type'] == 'symlink'
    assert str(root / 'link' / 'secret') not in result
    assert visited == [root]


def test_snapshot_owner_lookup_cached_within_capture(tmp_path, monkeypatch):
    from modules import snapshot
    (tmp_path / 'a').write_text('a')
    (tmp_path / 'b').write_text('b')
    original = snapshot._safe_owner
    calls = []
    def owner(st):
        calls.append((st.st_uid, st.st_gid))
        return original(st)
    monkeypatch.setattr(snapshot, '_safe_owner', owner)
    result = snapshot._collect_filesystem([tmp_path])
    assert len(result) == 3
    assert len(calls) == 1


def test_security_scan_prunes_literal_excluded_paths(tmp_path, monkeypatch):
    from modules import snapshot
    excluded = tmp_path / 'excluded[1]'
    excluded.mkdir()
    hidden = excluded / 'helper'
    hidden.write_text('hidden')
    hidden.chmod(0o4755)
    visible = tmp_path / 'helper'
    visible.write_text('visible')
    visible.chmod(0o4755)
    monkeypatch.setattr(snapshot, '_security_scan_paths', lambda _: [tmp_path])
    assert snapshot._collect_suid_sgid([tmp_path], [excluded]) == [str(visible)]


def test_capability_scan_uses_exclusion_pruning(tmp_path, monkeypatch):
    from modules import snapshot
    excluded = tmp_path / 'excluded'
    calls = []
    monkeypatch.setattr(snapshot, '_security_scan_paths', lambda _: [tmp_path, excluded])
    monkeypatch.setattr(snapshot, 'command_exists', lambda _: True)
    def run(cmd, **kwargs):
        calls.append(cmd)
        return {'returncode': 0, 'stdout': ''}
    monkeypatch.setattr(snapshot, 'run_cmd', run)
    snapshot._collect_capabilities([tmp_path], [excluded])
    assert len(calls) == 1
    assert '-prune' in calls[0]
    assert str(excluded) in calls[0]
    assert calls[0][-4:] == ['-exec', 'getcap', '{}', '+']
