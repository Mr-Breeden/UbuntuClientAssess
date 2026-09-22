import json
import re
from pathlib import Path

from modules.application_service import (
    SERVICE_CONTRACT_VERSION,
    SERVICE_OPERATIONS,
    UbuntuClientAssessService,
)
from modules.common import METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, VERSION, write_json
from modules.security_model import MODEL_SCHEMA_VERSION


def test_v193_release_contract_is_final_pre_gui_milestone():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10
    assert SERVICE_CONTRACT_VERSION == "1.0"


def test_service_capabilities_are_json_safe_and_complete():
    service = UbuntuClientAssessService()
    result = service.capabilities()
    payload = result.as_dict()
    json.dumps(payload)
    assert result.ok is True
    assert result.code == "capabilities-ready"
    assert result.data["presentation_neutral"] is True
    assert result.data["service_contract_version"] == "1.0"
    assert result.data["security_model_schema"] == 10
    names = {item["name"] for item in result.data["operations"]}
    assert {
        "assessment_overview", "state_revision", "verify_assessment", "review_snapshot",
        "assessment_status", "save_review_item", "finalize_runtime_observation",
        "create_client_appendix", "repair_generated_reports", "recover_interrupted_operation",
    } <= names
    assert names == {item["name"] for item in SERVICE_OPERATIONS}
    assert result.data["runtime_collection"]["commit_operation"] == "finalize_runtime_observation"


def test_assessment_overview_is_presentation_neutral_and_json_safe(tmp_path: Path):
    write_json(tmp_path / "assessment_metadata.json", {
        "assessment_name": "Example Assessment",
        "mode": "full",
        "framework_version": VERSION,
        "methodology_version": METHODOLOGY_VERSION,
        "run_state": {"status": "completed", "stage": "complete"},
        "installation": {"status": "completed"},
    })
    write_json(tmp_path / "working" / "tester_review_state.json", {
        "schema_version": 1,
        "framework_version": VERSION,
        "items": [
            {"id": "TRQ-001", "status": "VALIDATED"},
            {"id": "TRQ-002", "status": "PENDING"},
            {"id": "TRQ-003", "status": "INFORMATIONAL"},
        ]
    })
    result = UbuntuClientAssessService().assessment_overview(tmp_path)
    assert result.ok is True
    assert result.code == "overview-ready"
    assert result.data["review"]["total"] == 3
    assert result.data["review"]["pending"] == 1
    assert result.data["review"]["completed"] == 2
    json.dumps(result.as_dict())


def test_application_service_remains_free_of_terminal_presentation_dependencies():
    source = Path("modules/application_service.py").read_text(encoding="utf-8")
    for forbidden in ("rich.", "prompt_toolkit", "Console(", "Prompt.", "Confirm."):
        assert forbidden not in source


def test_revamped_docs_have_current_roles_and_no_release_history_in_readme_methodology():
    readme = Path("README.md").read_text(encoding="utf-8")
    methodology = Path("METHODOLOGY.md").read_text(encoding="utf-8")
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    assert "Current release: **2.0.6**" in readme
    assert "Methodology 2.4" in methodology
    assert "## [2.0.6]" in changelog and "## [1.0.0]" in changelog
    assert not re.search(r"^## v1\.\d+\.\d+", readme, flags=re.MULTILINE)
    assert not re.search(r"^## Methodology \d+\.\d+ —", methodology, flags=re.MULTILINE)


def test_changelog_starts_supported_history_at_v100():
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    releases = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", changelog, flags=re.MULTILINE)
    assert releases
    assert releases[-1] == "1.0.0"
    assert all(int(version.split(".")[0]) >= 1 for version in releases)


def test_documentation_hygiene_forbidden_names_and_retired_artifacts():
    docs = [Path("README.md"), Path("METHODOLOGY.md"), Path("CHANGELOG.md"), Path("TESTER_GUIDE.md")]
    joined = "\n".join(path.read_text(encoding="utf-8") for path in docs)
    lowered = joined.lower()
    for forbidden in (("Dru" + "va").lower(), ("Va" + "sion").lower(), ("in" + "Sync").lower()):
        assert forbidden not in lowered
    for retired in ("test_cases.txt", "assessment_metadata.csv", "findings.csv"):
        assert retired not in joined


def _bash_array_items(source: str, name: str) -> list[str]:
    match = re.search(rf"{name}=\(\s*(.*?)\s*\)", source, flags=re.DOTALL)
    assert match, f"{name} not found"
    return re.findall(r"[A-Za-z0-9.+_-]+", match.group(1))


def test_readme_dependency_matrix_matches_installer_package_inventory():
    installer = Path("install_dependencies.sh").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")
    core = _bash_array_items(installer, "CORE_PACKAGES")
    optional = _bash_array_items(installer, "EXTRA_PACKAGES")
    assert len(core) == 21
    assert len(optional) == 34
    for package in core + optional:
        assert f"`{package}`" in readme, f"README dependency matrix missing {package}"
    assert "READY WITH REDUCED COVERAGE" in readme
    assert "requirements.txt` contains only Python packages" in readme
