from __future__ import annotations

from pathlib import Path

from modules.common import ensure_assessment_layout, report_path, write_json, write_text


def test_v142_version_contract():
    from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")


def test_detailed_validation_omits_evidence_to_capture():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item = {
        "category": "ELF",
        "title": "ELF Library Search Path Requires Validation",
        "condition": "/opt/vendor/app: RPATH=/opt/vendor/lib; writable",
        "validation_targets": ["/opt/vendor/app"],
        "search_path": "/opt/vendor/lib",
        "search_kind": "RPATH",
    }
    text = "\n".join(render_playbook_lines(playbook_for(item)))
    assert "Evidence to Capture" not in text
    assert "Prerequisites" not in text
    assert "Cleanup" not in text
    assert "Expected Secure Behavior" in text
    assert "Potentially Vulnerable Behavior" in text
    assert "Do Not Report / Stop If" in text


def test_service_config_reference_is_classified_separately_from_execstart(tmp_path):
    import modules.services as svc

    app = tmp_path / "vendor"
    app.mkdir()
    config = app / "config.json"
    config.write_text('{"setting": true}\n', encoding="utf-8")
    wrapper = app / "updater.py"
    wrapper.write_text(f"#!/usr/bin/python3\nCONFIG = '{config}'\nprint(CONFIG)\n", encoding="utf-8")
    wrapper.chmod(0o755)

    assert svc._classify_referenced_path(config) == "ConfigurationDependency"
    chain = svc._resolve_exec_chain(str(wrapper))
    assert str(wrapper) in chain
    assert str(config) not in chain


def test_runtime_confirmation_merges_static_listener_socket_and_fifo(tmp_path):
    from modules.tester_review import generate_tester_review, merge_additional_review_items

    listener = 'tcp LISTEN 0 8 0.0.0.0:18080 0.0.0.0:* users:(("python3",pid=42,fd=5))'
    sock_line = 'u_str LISTEN 0 4 /run/vendor/control.sock 123 * 0'
    initial = generate_tester_review(
        tmp_path,
        network_data={"exposed_listener_candidates": [listener]},
        ipc_data={"unix_sockets": [sock_line], "fifo_candidates": ["/run/vendor/commands.fifo"]},
    )
    assert len(initial["items"]) == 3

    runtime = {
        "externally_bound_listeners": [listener],
        "socket_analysis": [{"review_level": "HIGH", "path": "/run/vendor/control.sock", "line": sock_line}],
        "fifo_paths": ["/run/vendor/commands.fifo"],
    }
    merged = merge_additional_review_items(tmp_path, runtime_data=runtime)
    assert len(merged["items"]) == 3
    assert all(item.get("runtime_confirmed") for item in merged["items"])


def test_runtime_new_object_still_creates_review_item(tmp_path):
    from modules.tester_review import generate_tester_review, merge_additional_review_items
    generate_tester_review(tmp_path, network_data={"exposed_listener_candidates": []})
    runtime = {"externally_bound_listeners": ["tcp LISTEN 0 8 0.0.0.0:9999 0.0.0.0:*"]}
    state = merge_additional_review_items(tmp_path, runtime_data=runtime)
    assert len(state["items"]) == 1
    assert state["items"][0]["title"] == "Runtime Application Listener Requires Validation"
    assert state["items"][0]["runtime_confirmed"] is True


def test_fast_network_sampling_does_not_inflate_full_sample_count(monkeypatch, tmp_path):
    import modules.runtime_observation as ro
    monkeypatch.setattr(ro, "_sample", lambda **kwargs: {"captured_at": "now", "processes": [], "listeners": [], "connections": [], "unix_sockets": []})
    monkeypatch.setattr(ro, "_connection_lines", lambda **kwargs: ["tcp TIME-WAIT 0 0 127.0.0.1:18080 127.0.0.1:45000"])
    data = ro.collect_runtime_observation(tmp_path / "assessment", duration_seconds=0)
    assert data["sample_count"] == 1
    assert "fast_network_sample_count" in data


def test_runtime_file_modification_reaches_final_progress(monkeypatch, tmp_path):
    import modules.runtime_observation as ro

    root = tmp_path / "data"
    root.mkdir()
    target = root / "state.json"
    target.write_text("before", encoding="utf-8")
    progress = []

    def sample(**kwargs):
        target.write_text("after-change", encoding="utf-8")
        return {"captured_at": "now", "processes": [], "listeners": [], "connections": [], "unix_sockets": []}

    monkeypatch.setattr(ro, "_sample", sample)
    data = ro.collect_runtime_observation(tmp_path / "assessment", filesystem_roots=[root], duration_seconds=0, progress_callback=lambda d: progress.append(d))
    assert str(target) in data["file_activity"]["modified"]
    assert progress and str(target) in progress[-1]["file_activity"]["modified"]


def test_crypto_private_key_salt_and_ca_correlation_redacts_values(monkeypatch, tmp_path):
    import modules.storage as storage
    from modules.findings import generate_findings
    from modules.tester_review import generate_tester_review

    app = tmp_path / "vendor"
    app.mkdir()
    config = app / "security.conf"
    secret_value = "VERY-PRIVATE-KEY-MATERIAL-123456"
    salt_value = "SALT-VALUE-ABCDEF"
    config.write_text(f'ca_private_key = "{secret_value}"\nkdf_salt = "{salt_value}"\n', encoding="utf-8")
    config.chmod(0o644)
    cert = app / "local-ca.crt"
    cert.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n", encoding="utf-8")

    monkeypatch.setattr(storage, "_certificate_record", lambda p: ({
        "path": str(p), "is_ca": True, "self_signed": True, "subject": "CN=Local CA", "issuer": "CN=Local CA", "permission": "world-readable"
    } if p == cert else None))
    monkeypatch.setattr(storage, "_permission_note", lambda p: "world-readable" if p == config else None)

    data = storage.review_storage({"files_added": [str(config), str(cert)]}, tmp_path / "assessment", [app])
    assert data["crypto_material"]
    crypto = next(x for x in data["crypto_material"] if x["path"] == str(config))
    assert crypto["private_key"] is True and crypto["salt"] is True
    assert str(cert) in crypto["related_ca_certificates"]

    review = generate_tester_review(tmp_path / "assessment", storage_data=data)
    assert any(x["category"] == "CRYPTO" for x in review["items"])
    findings = generate_findings(tmp_path / "assessment", {}, {}, {}, {}, storage_data=data)
    assert any(x["title"] == "Potential Exposure of Local CA Private Signing Material" for x in findings)

    report = report_path(tmp_path / "assessment", "local_storage_review.txt").read_text(encoding="utf-8")
    finding_text = report_path(tmp_path / "assessment", "findings.txt").read_text(encoding="utf-8")
    assert secret_value not in report and salt_value not in report
    assert secret_value not in finding_text and salt_value not in finding_text
    assert "values: [REDACTED]" in report


def test_salt_alone_is_not_review_item_or_finding(tmp_path):
    from modules.storage import review_storage
    from modules.tester_review import build_review_items
    from modules.findings import generate_findings

    app = tmp_path / "vendor"
    app.mkdir()
    config = app / "security.conf"
    config.write_text('kdf_salt = "public-non-secret-input"\n', encoding="utf-8")
    data = review_storage({"files_added": [str(config)]}, tmp_path / "assessment", [app])
    assert data["crypto_material"] and data["crypto_material"][0]["salt"] is True
    assert not any(x["category"] == "CRYPTO" for x in build_review_items(storage_data=data))
    assert not any(x["category"] == "CRYPTO" for x in generate_findings(tmp_path / "assessment", {}, {}, {}, {}, storage_data=data))


def _finalized_repair_fixture(tmp_path):
    from modules.artifacts import finalize_artifact_manifest
    from modules.common import EXPECTED_REPORTS_BY_MODE, VERSION, ensure_assessment_layout
    from modules.consolidated_report import refresh_consolidated_report
    from modules.findings import generate_findings
    from modules.tester_review import generate_tester_review

    ensure_assessment_layout(tmp_path)
    write_json(tmp_path / "assessment_metadata.json", {
        "version": VERSION, "assessment_name": "Repair Test", "installer": "/tmp/vendor.deb", "mode": "full",
        "run_state": {"status": "completed"}, "installation": {"status": "completed"},
    })
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 6})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 6})
    service = {"risk_candidates": [{"privileged": True, "unit": "vendor.service", "path_type": "ConfigurationDependency", "path": "/opt/vendor/config", "concerns": "world-writable"}]}
    generate_tester_review(tmp_path, service_data=service)
    generate_findings(tmp_path, {}, {}, service, {})
    for name in EXPECTED_REPORTS_BY_MODE["full"] - {"artifact_manifest.txt", "findings.txt", "findings_summary.txt", "tester_review.txt", "evidence_guide.txt", "assessment_report.html"}:
        write_text(report_path(tmp_path, name), "ok")
    write_text(report_path(tmp_path, "module_status.txt"), "[PASS   ] Findings Generation\n[PASS   ] Tester Review Queue")
    refresh_consolidated_report(tmp_path)
    finalize_artifact_manifest(tmp_path, "full")


def test_generated_report_repair_restores_derived_report_without_mutating_review_state(tmp_path):
    import hashlib
    import ubuntuclientassess as uca
    from modules.artifacts import verify_artifact_manifest

    _finalized_repair_fixture(tmp_path)
    state = tmp_path / "working" / "tester_review_state.json"
    before_state = hashlib.sha256(state.read_bytes()).hexdigest()
    findings = report_path(tmp_path, "findings.txt")
    findings.write_text(findings.read_text(encoding="utf-8").replace("[PENDING]", "[VALIDATED]", 1), encoding="utf-8")
    assert verify_artifact_manifest(tmp_path)
    status = uca._generated_report_repair_status(tmp_path)
    assert status["repairable"] is True and "findings.txt" in status["modified"]
    assert uca._repair_generated_reports(tmp_path) == 0
    assert verify_artifact_manifest(tmp_path) == []
    assert hashlib.sha256(state.read_bytes()).hexdigest() == before_state
    assert "[PENDING]" in findings.read_text(encoding="utf-8")


def test_generated_report_repair_refuses_authoritative_state_tamper(tmp_path):
    import ubuntuclientassess as uca
    _finalized_repair_fixture(tmp_path)
    findings = report_path(tmp_path, "findings.txt")
    findings.write_text(findings.read_text(encoding="utf-8") + "\nmanual edit\n", encoding="utf-8")
    state = tmp_path / "working" / "tester_review_state.json"
    state.write_text(state.read_text(encoding="utf-8") + " ", encoding="utf-8")
    status = uca._generated_report_repair_status(tmp_path)
    assert status["repairable"] is False
    assert any("authoritative/supporting state" in x for x in status["unsafe"])


def test_changed_certificate_outside_application_root_is_retained_for_crypto_correlation(monkeypatch, tmp_path):
    import modules.storage as storage
    app = tmp_path / "app"
    app.mkdir()
    config = app / "security.conf"
    config.write_text('private_key = "encoded-key-material"\n', encoding="utf-8")
    # Model a shared trust-store path outside the application root while keeping
    # the test filesystem self-contained; the .crt suffix invokes the same
    # changed-crypto exception used for real system trust stores.
    trust = tmp_path / "shared-trust"
    trust.mkdir()
    cert = trust / "vendor-ca.crt"
    cert.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setattr(storage, "_certificate_record", lambda p: ({
        "path": str(p), "is_ca": True, "self_signed": True, "subject": "CN=Vendor CA", "issuer": "CN=Vendor CA", "permission": "world-readable"
    } if p == cert else None))
    data = storage.review_storage({"files_added": [str(config), str(cert)]}, tmp_path / "assessment", [app])
    assert any(x["path"] == str(cert) and x["is_ca"] for x in data["certificate_records"])
    crypto = next(x for x in data["crypto_material"] if x["path"] == str(config))
    assert str(cert) in crypto["related_ca_certificates"]


def test_snapshot_tracks_common_certificate_roots():
    from modules.snapshot import default_tracked_paths
    roots = set(default_tracked_paths())
    assert Path("/etc/ssl") in roots
    assert Path("/etc/pki") in roots
    assert Path("/etc/ca-certificates") in roots
    assert Path("/usr/local") in roots  # covers /usr/local/share/ca-certificates


def test_service_finding_uses_dependency_role_wording(tmp_path):
    from modules.findings import generate_findings
    from modules.tester_review import generate_tester_review
    service = {"risk_candidates": [{"privileged": True, "unit": "vendor.service", "path_type": "ConfigurationDependency", "path": "/opt/vendor/updater.conf", "concerns": "world-writable"}]}
    generate_tester_review(tmp_path, service_data=service)
    generate_findings(tmp_path, {}, {}, service, {})
    text = report_path(tmp_path, "findings.txt").read_text(encoding="utf-8")
    assert "configuration/data dependency: /opt/vendor/updater.conf" in text
    assert "ExecStart=/opt/vendor/updater.conf" not in text
    assert "IMPORTANT - GENERATED ASSESSMENT ARTIFACT" in text
    assert "Manual edits intentionally invalidate assessment integrity" in text
