from __future__ import annotations

import stat
from pathlib import Path


def test_v143_version_contract():
    from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION

    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")


def test_debsig_verify_exit_code_mapping():
    from modules.update_review import _debsig_status

    assert _debsig_status(0)[0] == "VALID"
    assert _debsig_status(10)[0] == "NO SIGNATURE"
    assert _debsig_status(11)[0] == "NO POLICY"
    assert _debsig_status(12)[0] == "NO MATCHING POLICY"
    assert _debsig_status(13)[0] == "VERIFICATION FAILED"
    assert _debsig_status(14)[0] == "ERROR"
    assert _debsig_status(99)[0] == "ERROR"


def test_deb_signature_check_uses_debsig_verify_and_optional_debsigs(monkeypatch, tmp_path):
    import modules.update_review as update

    installer = tmp_path / "vendor.deb"
    installer.write_bytes(b"not-a-real-deb")
    commands = []

    def fake_exists(name: str):
        return f"/usr/bin/{name}" if name in {"debsig-verify", "debsigs"} else None

    def fake_run(cmd, timeout=30, **kwargs):
        commands.append(list(cmd))
        if cmd[0] == "debsigs":
            return {"returncode": 0, "stdout": "origin signature", "stderr": ""}
        if cmd[0] == "debsig-verify":
            return {"returncode": 11, "stdout": "", "stderr": "No policy directory"}
        raise AssertionError(cmd)

    monkeypatch.setattr(update, "command_exists", fake_exists)
    monkeypatch.setattr(update, "run_cmd", fake_run)
    records = update._signature_checks([], {"type": "deb", "path": str(installer)})

    assert commands == [["debsigs", "--list", str(installer)], ["debsig-verify", str(installer)]]
    assert len(records) == 1
    assert records[0]["tool"] == "debsig-verify"
    assert records[0]["status"] == "NO POLICY"
    assert "origin signature" in records[0]["detail"]
    assert "No policy directory" in records[0]["detail"]


def test_deb_signature_check_reports_missing_verifier_without_dpkg_sig(monkeypatch, tmp_path):
    import modules.update_review as update

    installer = tmp_path / "vendor.deb"
    installer.write_bytes(b"not-a-real-deb")
    monkeypatch.setattr(update, "command_exists", lambda name: None)

    records = update._signature_checks([], {"type": "deb", "path": str(installer)})
    assert len(records) == 1
    assert records[0]["tool"] == "debsig-verify"
    assert records[0]["status"] == "NOT CHECKED"
    assert "dpkg-sig" not in records[0]["detail"]


def test_equivalent_elf_candidates_collapse_to_one_finding(tmp_path):
    from modules.findings import generate_findings

    elf_data = {
        "finding_candidates": [
            {
                "binary": "/opt/vendor/bin/helper-a",
                "kind": "RPATH",
                "path": "/opt/vendor/lib",
                "concern": "search path is writable by the test account",
                "finding_candidate": True,
            },
            {
                "binary": "/opt/vendor/bin/helper-b",
                "kind": "RPATH",
                "path": "/opt/vendor/lib",
                "concern": "search path is writable by the test account",
                "finding_candidate": True,
            },
        ]
    }
    findings = generate_findings(tmp_path, {}, {}, {}, elf_data)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "Writable ELF Library Search Path"
    assert finding["validation_targets"] == ["/opt/vendor/bin/helper-a", "/opt/vendor/bin/helper-b"]
    assert "2 application binaries" in finding["condition"]
    assert "/opt/vendor/bin/helper-a" in finding["evidence"]
    assert "/opt/vendor/bin/helper-b" in finding["evidence"]


def test_distinct_elf_root_causes_remain_separate_findings(tmp_path):
    from modules.findings import generate_findings

    elf_data = {
        "finding_candidates": [
            {"binary": "/opt/vendor/bin/a", "kind": "RPATH", "path": "/opt/vendor/lib-a", "concern": "writable", "finding_candidate": True},
            {"binary": "/opt/vendor/bin/b", "kind": "RPATH", "path": "/opt/vendor/lib-b", "concern": "writable", "finding_candidate": True},
        ]
    }
    findings = generate_findings(tmp_path, {}, {}, {}, elf_data)
    assert len(findings) == 2


def test_sgid_directory_only_is_not_permission_review_candidate(tmp_path):
    from modules.permissions import _classify

    directory = tmp_path / "shared"
    directory.mkdir()
    directory.chmod(0o2755)
    st = directory.stat()
    meta = {
        "type": "directory",
        "mode_octal": oct(stat.S_IMODE(st.st_mode)),
        "mode": stat.filemode(st.st_mode),
        "owner": "root",
        "group": "root",
    }
    assert _classify(str(directory), meta, {}) is None


def test_sgid_directory_is_retained_when_access_concern_exists(tmp_path):
    from modules.permissions import _classify

    directory = tmp_path / "shared"
    directory.mkdir()
    directory.chmod(0o2777)
    st = directory.stat()
    meta = {
        "type": "directory",
        "mode_octal": oct(stat.S_IMODE(st.st_mode)),
        "mode": stat.filemode(st.st_mode),
        "owner": "root",
        "group": "root",
    }
    item = _classify(str(directory), meta, {})
    assert item is not None
    assert "World-writable object" in item["concerns"]
    assert "SGID bit set" in item["concerns"]
