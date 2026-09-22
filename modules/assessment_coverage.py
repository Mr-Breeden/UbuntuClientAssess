from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, read_json, report_path, write_text, working_dir


@dataclass(frozen=True)
class CoverageArea:
    id: str
    title: str
    categories: tuple[str, ...]
    reports: tuple[str, ...]
    automated: str
    manual_focus: str
    runtime_relevant: bool = False


FULL_COVERAGE_AREAS: tuple[CoverageArea, ...] = (
    CoverageArea("TC-INST-001", "Installation / Host Changes", (), ("install_changes.txt", "installer_analysis.txt"), "YES", "Confirm material installation changes are expected and in scope."),
    CoverageArea("TC-PERM-001", "Filesystem Permission Boundaries", ("PERM",), ("permissions_review.txt",), "YES", "Validate effective access only where it crosses a meaningful application trust boundary."),
    CoverageArea("TC-PRIV-001", "Privileged Helpers / Local Privilege Boundaries", ("SUID", "CAP", "POLKIT"), ("permissions_review.txt", "service_review.txt", "ipc_review.txt"), "YES", "Exercise privileged operations as a low-privileged user and confirm authorization and protected execution chains."),
    CoverageArea("TC-SVC-001", "systemd Service Security", ("SVC",), ("service_review.txt",), "YES", "Validate privilege, consumed paths, service hardening, and any attacker influence over the execution chain."),
    CoverageArea("TC-PERS-001", "Persistence / Privilege Policy", ("PERS",), ("persistence_review.txt",), "YES", "Confirm introduced persistence and privilege-policy mechanisms are necessary, scoped, and protected."),
    CoverageArea("TC-BIN-001", "ELF Binary / Library Resolution", ("ELF",), ("binary_security_review.txt",), "YES", "Validate exploitable library resolution only where writable search locations intersect a meaningful execution boundary."),
    CoverageArea("TC-NET-001", "Network Exposure", ("RUNTIME",), ("network_surface_review.txt", "runtime_review.txt"), "PARTIAL", "Exercise network-facing features and validate intended bind scope, authentication, authorization, and reachability.", True),
    CoverageArea("TC-COMM-001", "Client / Server Communication", ("COMM",), ("network_surface_review.txt", "runtime_review.txt"), "PARTIAL", "Exercise communication workflows and validate transport, peer trust, proxy behavior, sensitive-data handling, and failure behavior.", True),
    CoverageArea("TC-IPC-001", "Local IPC Security", ("IPC", "DBUS", "POLKIT"), ("ipc_review.txt",), "YES", "Validate caller authorization and trust boundaries for sockets, FIFOs, D-Bus, and PolicyKit-controlled operations.", True),
    CoverageArea("TC-IPC-002", "Runtime IPC Authorization", ("IPC", "DBUS", "POLKIT"), ("ipc_review.txt", "runtime_review.txt"), "PARTIAL", "Observe legitimate runtime IPC first, then validate harmless unauthorized requests where appropriate.", True),
    CoverageArea("TC-STOR-001", "Local Sensitive Data Storage", ("STOR",), ("local_storage_review.txt",), "YES", "Inspect highlighted storage without copying secrets into reports; validate necessity and local access controls."),
    CoverageArea("TC-UPD-001", "Update Mechanism", ("UPD",), ("update_review.txt", "installer_analysis.txt"), "YES", "Validate update transport, authenticity, downgrade resistance, and privilege used during installation."),
    CoverageArea("TC-RUN-001", "Runtime Behavior", ("RUNTIME",), ("runtime_review.txt",), "PARTIAL", "Exercise representative workflows and review process, file, network, IPC, and privileged behavior.", True),
    CoverageArea("TC-RUN-002", "Guided Runtime Correlation", ("RUNTIME", "IPC", "COMM"), ("runtime_review.txt", "ipc_review.txt", "tester_review.txt"), "PARTIAL", "Run Guided Runtime Observation for relevant workflows and resolve newly confirmed or discovered review items.", True),
    CoverageArea("TC-FWK-001", "Technology / Framework-Specific Testing", ("TECH",), ("application_profile.txt", "runtime_review.txt"), "PARTIAL", "Use detected technology context to perform framework-specific manual testing that generic static checks cannot prove."),
)

INSTALLER_ONLY_COVERAGE_AREAS: tuple[CoverageArea, ...] = (
    CoverageArea("TC-PKG-001", "Installer Package Static Review", (), ("installer_analysis.txt", "application_profile.txt"), "YES", "Review metadata, package structure, scripts, extraction safety, and high-interest payload files."),
    CoverageArea("TC-RUN-001", "Runtime Test Planning", (), ("runtime_review.txt",), "NO", "Prepare application-specific runtime commands and paths for a later Full Assessment."),
)

# Compatibility aliases retained for code/tests that use the historical catalog constants.
FULL_CATALOG_IDS = tuple(area.id for area in FULL_COVERAGE_AREAS if area.id != "TC-FWK-001")
INSTALLER_ONLY_CATALOG_IDS = tuple(area.id for area in INSTALLER_ONLY_COVERAGE_AREAS)
FRAMEWORK_CASE_ID = "TC-FWK-001"


def _review_items(output_dir: Path) -> list[dict[str, Any]]:
    path = working_dir(output_dir) / "tester_review_state.json"
    if not path.is_file():
        return []
    try:
        return list(read_json(path).get("items", []) or [])
    except Exception:
        return []


def _runtime_present(output_dir: Path) -> bool:
    path = working_dir(output_dir) / "runtime_observation.json"
    if not path.is_file():
        return False
    try:
        data = read_json(path)
    except Exception:
        return False
    return bool(
        data.get("application_processes")
        or data.get("connections")
        or data.get("listeners")
        or data.get("unix_sockets")
        or data.get("fifo_paths")
        or any((data.get("file_activity") or {}).get(k) for k in ("created", "modified", "deleted"))
    )


def _areas_for_mode(mode: str, profile_data: dict[str, Any] | None = None) -> tuple[CoverageArea, ...]:
    profile_data = profile_data or {}
    if mode == "installer-analysis-only":
        areas = list(INSTALLER_ONLY_COVERAGE_AREAS)
        if profile_data.get("technologies"):
            areas.append(next(area for area in FULL_COVERAGE_AREAS if area.id == FRAMEWORK_CASE_ID))
        return tuple(areas)
    if mode != "full":
        raise ValueError(f"Unsupported assessment-coverage mode: {mode}")
    # TC-FWK-001 is intentionally retained for Full Assessments even when no
    # specific framework is positively identified. Generic/native applications
    # still require technology-specific manual reasoning.
    return FULL_COVERAGE_AREAS


def build_assessment_coverage(output_dir: Path, mode: str = "full", profile_data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    profile_data = profile_data or {}
    reviews = _review_items(output_dir)
    runtime_present = _runtime_present(output_dir)
    records: list[dict[str, Any]] = []
    for area in _areas_for_mode(mode, profile_data):
        related = [x for x in reviews if str(x.get("category") or "").upper() in set(area.categories)] if area.categories else []
        pending = [x for x in related if str(x.get("status") or "PENDING") == "PENDING"]
        completed = [x for x in related if str(x.get("status") or "PENDING") != "PENDING"]
        if related:
            review_state = "PENDING" if pending else "RESOLVED"
        else:
            review_state = "NO SPECIFIC REVIEW ITEM"
        if area.runtime_relevant:
            runtime_state = "OBSERVED" if runtime_present else "NOT YET OBSERVED"
        else:
            runtime_state = "NOT REQUIRED BY THIS COVERAGE ROW"
        records.append({
            "id": area.id,
            "title": area.title,
            "automated": area.automated,
            "related_review_ids": [str(x.get("id") or "") for x in related if x.get("id")],
            "related_review_count": len(related),
            "pending_review_count": len(pending),
            "completed_review_count": len(completed),
            "review_state": review_state,
            "runtime_state": runtime_state,
            "manual_focus": area.manual_focus,
            "reports": list(area.reports),
        })
    return records


def generate_assessment_coverage(output_dir: Path, mode: str = "full", profile_data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    profile_data = profile_data or {}
    records = build_assessment_coverage(output_dir, mode, profile_data)
    mode_label = "Installer Analysis Only" if mode == "installer-analysis-only" else "Full Assessment"
    total_related = sum(int(r["related_review_count"]) for r in records)
    pending_related = sum(int(r["pending_review_count"]) for r in records)
    runtime_observed = any(r["runtime_state"] == "OBSERVED" for r in records)
    coverage_limitations = list(profile_data.get("coverage_limitations", []) or [])
    lines = [
        "UbuntuClientAssess Assessment Coverage",
        "=" * 38,
        "",
        f"Execution Mode: {mode_label}",
        f"Methodology Version: {METHODOLOGY_VERSION}",
        f"Coverage Catalog Version: {TEST_CASE_CATALOG_VERSION}",
        f"Coverage Areas: {len(records)}",
        f"Related review references: {total_related}",
        f"Pending related review references: {pending_related}",
        f"Guided Runtime Observation: {'OBSERVED' if runtime_observed else 'NOT OBSERVED'}",
        f"Application File Coverage: {'LIMITED' if coverage_limitations else 'COMPLETE FOR IDENTIFIED ROOTS'}",
        "",
        "Purpose",
        "-------",
        "This generated report is a read-only coverage map. It does not replace Guided Review and it is not an editable completion checklist.",
        "Use Guided Review for condition-specific validation. Use this report to make sure a security area is not treated as tested merely because UbuntuClientAssess generated no review item for it.",
        "Manual edits intentionally invalidate assessment integrity.",
        "",
    ]
    if coverage_limitations:
        lines += [
            "Static Application File Coverage Limitation",
            "-------------------------------------------",
            "One or more identified application roots could not be recursively inspected. Automated zero-result sections in affected static-analysis areas are incomplete, not proof of absence.",
        ]
        for gap in coverage_limitations:
            lines.append(f"- {gap.get('path')} | owner={gap.get('owner')} group={gap.get('group')} mode={gap.get('mode')}")
        lines.append("")
    lines += [
        "Coverage Summary",
        "----------------",
        f"{'ID':<12} {'Area':<52} {'Auto':<8} {'TRQs':>4} {'Pending':>7} {'Runtime':<8}",
        f"{'-'*12} {'-'*52} {'-'*8} {'-'*4} {'-'*7} {'-'*8}",
    ]
    for record in records:
        runtime_short = "YES" if record["runtime_state"] == "OBSERVED" else ("NO" if record["runtime_state"] == "NOT YET OBSERVED" else "N/A")
        lines.append(
            f"{record['id']:<12} {record['title'][:52]:<52} {record['automated']:<8} {record['related_review_count']:>4} {record['pending_review_count']:>7} {runtime_short:<8}"
        )
    lines += [""]
    for record in records:
        heading = f"[{record['id']}] {record['title']}"
        related = ", ".join(record["related_review_ids"]) or "None generated"
        reports = ", ".join(record["reports"]) or "No dedicated tester report generated"
        lines += [
            heading,
            "=" * len(heading),
            "",
            f"Automated coverage: {record['automated']}",
            f"Review state: {record['review_state']}",
            f"Related review items: {related}",
            f"Runtime evidence: {record['runtime_state']}",
            f"Supporting reports: {reports}",
            "",
            "Manual tester focus",
            "-------------------",
            record["manual_focus"],
            "",
        ]
        if not record["related_review_ids"]:
            lines += [
                "Coverage note",
                "-------------",
                "No specific review candidate was generated for this area. This does not mean the area was manually tested or is automatically secure.",
                "",
            ]
    write_text(report_path(output_dir, "assessment_coverage.txt"), "\n".join(lines))
    return records


def refresh_assessment_coverage(output_dir: Path) -> list[dict[str, Any]]:
    metadata_path = output_dir / "assessment_metadata.json"
    metadata = read_json(metadata_path) if metadata_path.is_file() else {}
    profile_path = working_dir(output_dir) / "application_profile.json"
    profile_data = read_json(profile_path) if profile_path.is_file() else {}
    mode = str(metadata.get("mode") or "full")
    return generate_assessment_coverage(output_dir, mode, profile_data)


# Transitional API alias for extensions that imported the old function name.
# v1.6.2 retains the v1.6.1 assessment_coverage.txt replacement for test_cases.txt.
def generate_test_cases(output_dir: Path, mode: str = "full", profile_data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return generate_assessment_coverage(output_dir, mode, profile_data)
