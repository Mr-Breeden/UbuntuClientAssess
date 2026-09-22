from pathlib import Path

from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, ensure_assessment_layout
from modules.security_model import MODEL_SCHEMA_VERSION, build_security_model
from modules.findings import generate_findings
from modules.tester_review import generate_tester_review


def _setup(tmp_path: Path) -> None:
    ensure_assessment_layout(tmp_path)


def test_v190_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def test_current_model_owns_sudo_and_local_ca_findings(tmp_path: Path):
    _setup(tmp_path)
    command = "/opt/example/bin/helper *"
    key_path = "/opt/example/security/ca.key"
    cert_path = "/opt/example/security/ca.crt"
    persistence_data = {
        "sudo_policy_candidates": [{
            "finding_candidate": True,
            "command": command,
            "runas": "root",
            "concerns": ["wildcards broaden caller-controlled arguments or paths"],
            "severity": "High",
        }]
    }
    storage_data = {
        "crypto_material": [{
            "path": key_path,
            "private_key": True,
            "salt": False,
            "permission": "world-readable",
            "related_ca_certificates": [cert_path],
        }]
    }
    model = build_security_model(tmp_path, storage_data=storage_data, persistence_data=persistence_data)
    sudo_corr = next(x for x in model["correlations"] if x["kind"] == "unsafe_sudo_policy")
    crypto_corr = next(x for x in model["correlations"] if x["kind"] == "exposed_local_ca_private_key")
    assert sudo_corr["drives_finding"] is True
    assert crypto_corr["drives_finding"] is True
    assert crypto_corr["drives_review"] is True
    assert crypto_corr["rule_id"] == "CORR-CRYPTO-LOCAL-CA"

    review = generate_tester_review(tmp_path, storage_data=storage_data, persistence_data=persistence_data)
    sudo_review = next(x for x in review["items"] if x.get("category") == "PERS" and "Unsafe sudoers" in x.get("title", ""))
    crypto_review = next(x for x in review["items"] if x.get("category") == "CRYPTO")
    assert sudo_review["generation_source"] == "correlation_engine"
    assert crypto_review["generation_source"] == "correlation_engine"

    findings = generate_findings(tmp_path, {}, {}, {}, {}, storage_data=storage_data, persistence_data=persistence_data)
    by_category = {x["category"]: x for x in findings}
    assert by_category["PERS"]["generation_source"] == "correlation_engine"
    assert by_category["CRYPTO"]["generation_source"] == "correlation_engine"
    assert by_category["PERS"]["correlation_rule"] == "CORR-SUDO-RULE"
    assert by_category["CRYPTO"]["correlation_rule"] == "CORR-CRYPTO-LOCAL-CA"


def test_schema10_current_findings_do_not_call_compatibility_generator(monkeypatch, tmp_path: Path):
    import modules.findings as findings_module
    _setup(tmp_path)
    persistence_data = {
        "sudo_policy_candidates": [{
            "finding_candidate": True,
            "command": "/opt/example/bin/helper *",
            "runas": "root",
            "concerns": ["wildcards broaden caller-controlled arguments or paths"],
            "severity": "High",
        }]
    }
    build_security_model(tmp_path, persistence_data=persistence_data)

    def fail_compat(*args, **kwargs):
        raise AssertionError("compatibility finding generator must not run for schema-10 current assessments")

    monkeypatch.setattr(findings_module, "_generate_findings_compatibility", fail_compat)
    findings = findings_module.generate_findings(tmp_path, {}, {}, {}, {}, persistence_data=persistence_data)
    assert findings and findings[0]["generation_source"] == "correlation_engine"


def test_guided_review_source_uses_category_scoped_post_save_totals_and_context_label():
    source = Path("ubuntuclientassess.py").read_text(encoding="utf-8")
    assert 'category_items = [x for x in fresh_items if review_category(x) == selected_category]' in source
    assert 'next_label = "Save & Next Pending" if current_category == "__ALL__" else "Save & Next Pending in Category"' in source
    assert 'cat_items = fresh_items if current_category == "__ALL__"' not in source


def test_distributable_tree_has_no_known_engagement_identifiers():
    root = Path(__file__).resolve().parents[1]
    forbidden = ["Dru" + "va", "Va" + "sion", "in" + "Sync"]
    text_suffixes = {".py", ".md", ".txt", ".sh", ".ini", ".toml", ".cfg", ".json", ".yaml", ".yml"}
    offenders = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in text_suffixes:
            continue
        if any(part in {"__pycache__", ".pytest_cache", ".git"} for part in path.parts):
            continue
        data = path.read_text(encoding="utf-8", errors="ignore").casefold()
        for token in forbidden:
            if token.casefold() in data:
                offenders.append(f"{path.relative_to(root)}:{token}")
    assert offenders == []
