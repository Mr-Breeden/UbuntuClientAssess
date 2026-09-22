from __future__ import annotations

from pathlib import Path

from modules.common import ensure_assessment_layout, report_path, write_json, write_text


def test_v141_version_contract():
    from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")


def test_review_status_contract_and_summary(tmp_path):
    from modules.tester_review import generate_tester_review, update_review_item, VALID_STATUSES
    assert VALID_STATUSES == {"PENDING", "VALIDATED", "NOT APPLICABLE", "INFORMATIONAL"}
    state = generate_tester_review(tmp_path, network_data={"exposed_listener_candidates": ["tcp LISTEN 0 8 0.0.0.0:9000 0.0.0.0:*"]})
    ident = state["items"][0]["identity"]
    update_review_item(tmp_path, ident, status="INFORMATIONAL", notes="Expected local service exposure for this product role.")
    text = report_path(tmp_path, "tester_review.txt").read_text(encoding="utf-8")
    assert "Informational:            1" in text
    assert "Status:      INFORMATIONAL" in text


def test_validation_playbook_omits_prerequisites_and_cleanup(tmp_path):
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item = {"category": "SVC", "title": "Privileged Service Path Requires Validation", "condition": "demo.service references EnvironmentFile /opt/demo/config: writable.", "evidence": []}
    text = "\n".join(render_playbook_lines(playbook_for(item)))
    assert "Prerequisites" not in text
    assert "Cleanup" not in text
    assert "restore" not in text.lower()
    assert "Goal" in text and "Expected Secure Behavior" in text and "Do Not Report / Stop If" in text


def test_findings_banner_and_structured_elf_validation(tmp_path):
    from modules.findings import generate_findings
    from modules.tester_review import generate_tester_review
    elf = {"finding_candidates": [{"binary": "/opt/vendor/bin/client", "kind": "RPATH", "path": "/opt/vendor/lib", "concern": "Library search directory is world-writable", "finding_candidate": True}]}
    generate_tester_review(tmp_path, elf_data=elf)
    generate_findings(tmp_path, {}, {}, {}, elf)
    text = report_path(tmp_path, "findings.txt").read_text(encoding="utf-8")
    assert "[FINDING CANDIDATE UAF-001]" in text
    assert "WRITABLE ELF LIBRARY SEARCH PATH" in text
    assert "VALIDATION PROCEDURE" in text
    assert "Prerequisites" not in text and "Cleanup" not in text
    assert "ls -ld /opt/vendor/lib" in text
    assert "namei -l /opt/vendor/lib" in text
    assert "'/opt/vendor/lib - Library search directory" not in text


def test_review_disposition_refreshes_findings_and_html(tmp_path):
    import ubuntuclientassess as uca
    from modules.findings import generate_findings
    from modules.tester_review import generate_tester_review, update_review_item
    from modules.consolidated_report import generate_consolidated_report, refresh_consolidated_report

    ensure_assessment_layout(tmp_path)
    metadata = {"version": "1.5.3", "assessment_name": "Dashboard Test", "installer": "/tmp/demo.deb", "mode": "full"}
    write_json(tmp_path / "assessment_metadata.json", metadata)
    write_text(report_path(tmp_path, "module_status.txt"), "[PASS   ] Findings Generation\n[PASS   ] Tester Review Queue")

    service = {"risk_candidates": [{"privileged": True, "unit": "demo.service", "path_type": "EnvironmentFile", "path": "/opt/demo/config", "concerns": "world-writable"}]}
    state = generate_tester_review(tmp_path, service_data=service)
    generate_findings(tmp_path, {}, {}, service, {})
    generate_consolidated_report(tmp_path, "Dashboard Test", "/tmp/demo.deb", "full", "1.5.4", {"Findings Generation": ("PASS", ""), "Tester Review Queue": ("PASS", "")})

    html = report_path(tmp_path, "assessment_report.html").read_text(encoding="utf-8")
    assert "1 total" in html or "1 total" in html.lower()
    assert "TRQ-001" in html
    assert "Writable Path Referenced by Privileged systemd Service" in html
    assert "PENDING" in html

    identity = state["items"][0]["identity"]
    update_review_item(tmp_path, identity, status="NOT APPLICABLE", notes="Service does not consume the writable field in a privileged operation.")
    from modules.findings import refresh_findings_dispositions
    refresh_findings_dispositions(tmp_path)
    refresh_consolidated_report(tmp_path)
    findings = report_path(tmp_path, "findings.txt").read_text(encoding="utf-8")
    html = report_path(tmp_path, "assessment_report.html").read_text(encoding="utf-8")
    assert "[NOT APPLICABLE]" in findings
    assert "NOT APPLICABLE" in html
    assert "Service does not consume" in html


def test_sudo_finding_has_dedicated_review_relationship(tmp_path):
    from modules.findings import generate_findings
    from modules.tester_review import generate_tester_review
    persistence = {
        "sudo_policy_candidates": [{"runas": "root", "command": "/opt/vendor/helper *", "severity": "High", "finding_candidate": True, "concerns": ["wildcard arguments"]}],
        "review_required": [],
    }
    state = generate_tester_review(tmp_path, persistence_data=persistence)
    finding = generate_findings(tmp_path, {}, {}, {}, {}, persistence_data=persistence)[0]
    identities = {item["identity"] for item in state["items"]}
    assert finding["review_identity"] in identities
    assert any(item["title"] == "Potentially Unsafe sudoers Rule Requires Validation" for item in state["items"])
