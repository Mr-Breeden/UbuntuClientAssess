from html.parser import HTMLParser
from pathlib import Path

from modules.consolidated_report import generate_consolidated_report
from modules.common import EXPECTED_REPORTS_BY_MODE, ensure_assessment_layout, report_path, write_json, write_text


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(attributes["id"])
        if tag == "a" and attributes.get("href"):
            self.hrefs.append(attributes["href"])


def test_storage_candidate_routes_to_tester_review_without_secret_values(tmp_path):
    from modules.findings import generate_findings
    from modules.storage import review_storage
    from modules.tester_review import generate_tester_review

    ensure_assessment_layout(tmp_path)
    config = tmp_path / "app.conf"
    config.write_text('client_secret = test-secret-never-publish\n')
    storage = review_storage({"files_added": [str(config)], "files_changed": []}, tmp_path)
    findings = generate_findings(tmp_path, {}, {}, {}, {}, storage)
    assert findings == []
    state = generate_tester_review(tmp_path, storage_data=storage)
    assert len(state["items"]) == 1
    assert state["items"][0]["title"] == "Potential Credential or Token Storage"
    review = report_path(tmp_path, "tester_review.txt").read_text()
    assert str(config) in review
    assert "test-secret-never-publish" not in review


def test_consolidated_html_escapes_content_sorts_findings_and_links_reports(tmp_path):
    ensure_assessment_layout(tmp_path)
    write_text(
        report_path(tmp_path, "findings.txt"),
        """Findings
========

[1] Medium <item>
---------------
Severity:       Medium
Evidence:       A < B
Recommendation: Validate <carefully>

[2] High item
-------------
Severity:       High
Evidence:       Trusted path is writable
Recommendation: Restrict the path

Manual Review Required
----------------------
[R1] Policy <review>
Evidence: sudoers changed
Action: inspect <scope>
""",
    )
    write_text(report_path(tmp_path, "assessment_coverage.txt"), "Assessment coverage")
    generate_consolidated_report(
        tmp_path,
        "Client <script>alert(1)</script>",
        Path("/sensitive/source/client.deb"),
        "full",
        "1.2.0",
        {"Findings Generation": ("PASS", "Review <output>")},
    )

    report = report_path(tmp_path, "assessment_report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in report
    assert "Client &lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "Review &lt;output&gt;" in report
    assert "/sensitive/source" not in report
    assert report.index("High item") < report.index("Medium &lt;item&gt;")
    assert 'href="findings.txt"' in report
    assert 'href="assessment_coverage.txt"' in report
    assert "Policy &lt;review&gt;" in report


def test_consolidated_html_links_resolve_to_files_or_page_anchors(tmp_path):
    ensure_assessment_layout(tmp_path)
    write_text(report_path(tmp_path, "module_status.txt"), "status")
    generate_consolidated_report(
        tmp_path,
        "Test",
        None,
        "installer-analysis-only",
        "1.2.0",
        {"Tool Detection": ("PASS", "")},
    )
    parser = LinkParser()
    parser.feed(report_path(tmp_path, "assessment_report.html").read_text(encoding="utf-8"))
    reports = tmp_path / "reports"
    for href in parser.hrefs:
        if href.startswith("#"):
            assert href[1:] in parser.ids
        else:
            assert (reports / href).is_file(), href


def test_consolidated_html_does_not_copy_report_contents(tmp_path):
    ensure_assessment_layout(tmp_path)
    secret = "secret-value-that-must-not-enter-html"
    write_text(report_path(tmp_path, "local_storage_review.txt"), secret)
    generate_consolidated_report(
        tmp_path,
        "Test",
        None,
        "full",
        "1.2.0",
        {"Local Storage Review": ("PASS", "Sensitive values redacted")},
    )
    report = report_path(tmp_path, "assessment_report.html").read_text(encoding="utf-8")
    assert secret not in report
    assert 'href="local_storage_review.txt"' in report


def test_assessment_finalization_generates_and_verifies_html_report(tmp_path):
    import ubuntuclientassess as uca
    from modules.artifacts import verify_artifact_manifest

    ensure_assessment_layout(tmp_path)
    metadata_path = tmp_path / "assessment_metadata.json"
    metadata = {
        "version": "1.2.0",
        "assessment_name": "Integration Test",
        "installer": None,
        "mode": "full",
    }
    write_json(metadata_path, metadata)
    write_json(tmp_path / "working" / "snapshot_pre.json", {"schema_version": 5})
    write_json(tmp_path / "working" / "snapshot_post.json", {"schema_version": 5})
    write_json(tmp_path / "working" / "tester_review_state.json", {"schema_version": 1, "framework_version": "1.2.0", "items": []})
    write_json(tmp_path / "working" / "security_model.json", {"schema_version": 1, "objects": [], "observations": [], "relationships": [], "correlations": []})
    generated_by_finalization = {"assessment_report.html", "artifact_manifest.txt", "module_status.txt"}
    for name in EXPECTED_REPORTS_BY_MODE["full"] - generated_by_finalization:
        write_text(report_path(tmp_path, name), f"complete {name}")

    assert uca.finalize_assessment(tmp_path, "full", metadata_path, metadata, {}) is True
    report = report_path(tmp_path, "assessment_report.html")
    assert report.is_file()
    assert "UbuntuClientAssess v2.0.6" in report.read_text(encoding="utf-8")
    assert verify_artifact_manifest(tmp_path) == []
