from __future__ import annotations

"""Reusable application-service layer for UbuntuClientAssess.

The service layer owns stateful assessment operations that must behave the same
regardless of presentation surface. The terminal CLI and localhost web UI consume these same methods without reimplementing review,
integrity, runtime-finalization, state-concurrency, or client-export rules.

This module intentionally contains no prompt or terminal-rendering code.
"""

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from modules.artifacts import (
    assessment_verification_summary,
    finalize_artifact_manifest,
    verify_artifact_manifest,
)
from modules.assessment_coverage import refresh_assessment_coverage
from modules.assessment_workflow import AssessmentWorkflow, WorkflowError
from modules.client_appendix import create_client_appendix
from modules.common import METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, VERSION, read_json, sha256_file, write_json
from modules.consolidated_report import refresh_consolidated_report
from modules.findings import refresh_findings_dispositions
from modules.ipc import update_ipc_with_runtime
from modules.runtime import write_runtime_guidance
from modules.security_model import MODEL_SCHEMA_VERSION, merge_runtime_security_model, synchronize_security_model
from modules.state_guard import (
    AssessmentBusyError,
    StaleStateError,
    StateTransaction,
    assessment_lock,
    assessment_revision,
    pending_transaction,
    recover_interrupted_transaction,
    require_revision,
)
from modules.tester_review import (
    category_progress,
    load_review_state,
    merge_additional_review_items,
    refresh_review_reports,
    review_category,
    review_group,
    shared_validation_for,
    update_review_item,
)
from modules.validation_guidance import playbook_for, render_playbook_lines



SERVICE_CONTRACT_VERSION = "1.0"

SERVICE_OPERATIONS = (
    {"name": "capabilities", "kind": "read", "state_change": False},
    {"name": "assessment_overview", "kind": "read", "state_change": False},
    {"name": "start_assessment", "kind": "write", "state_change": True},
    {"name": "continue_assessment", "kind": "write", "state_change": True},
    {"name": "state_revision", "kind": "read", "state_change": False},
    {"name": "verify_assessment", "kind": "read", "state_change": False},
    {"name": "review_snapshot", "kind": "read", "state_change": False},
    {"name": "assessment_status", "kind": "read", "state_change": False},
    {"name": "save_review_item", "kind": "write", "state_change": True},
    {"name": "finalize_runtime_observation", "kind": "write", "state_change": True},
    {"name": "create_client_appendix", "kind": "write", "state_change": True},
    {"name": "repair_generated_reports", "kind": "write", "state_change": True},
    {"name": "recover_interrupted_operation", "kind": "write", "state_change": True},
)

REPAIRABLE_GENERATED_REPORTS = {
    "findings.txt",
    "findings_summary.txt",
    "tester_review.txt",
    "evidence_guide.txt",
    "assessment_coverage.txt",
    "assessment_report.html",
    "artifact_manifest.txt",
}

# Bounded transaction sets keep rollback fast and avoid copying raw installer
# payloads/snapshots that these operations never modify.
REVIEW_TRANSACTION_FILES = (
    "working/tester_review_state.json",
    "reports/tester_review.txt",
    "reports/evidence_guide.txt",
    "reports/findings.txt",
    "reports/findings_summary.txt",
    "reports/assessment_coverage.txt",
    "reports/assessment_report.html",
    "reports/artifact_manifest.txt",
    "assessment_manifest.json",
)

RUNTIME_TRANSACTION_FILES = REVIEW_TRANSACTION_FILES + (
    "assessment_metadata.json",
    "working/runtime_observation.json",
    "working/security_model.json",
    "reports/runtime_review.txt",
    "reports/ipc_review.txt",
)

REPAIR_TRANSACTION_FILES = (
    "reports/tester_review.txt",
    "reports/evidence_guide.txt",
    "reports/findings.txt",
    "reports/findings_summary.txt",
    "reports/assessment_coverage.txt",
    "reports/assessment_report.html",
    "reports/artifact_manifest.txt",
    "assessment_manifest.json",
)


def _json_safe(value: Any) -> Any:
    """Recursively normalize service data to JSON-native values.

    Presentation layers must never need to know that backend modules use
    pathlib, sets/tuples, or datetime objects internally.
    """
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return value


@dataclass(slots=True)
class ServiceResult:
    """Presentation-neutral result returned by stateful service operations."""

    ok: bool
    code: str
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
            "data": _json_safe(self.data),
            "errors": _json_safe(list(self.errors)),
        }


class UbuntuClientAssessService:
    """Non-interactive assessment operations shared by current/future UIs."""

    def __init__(self) -> None:
        self.workflow = AssessmentWorkflow()

    def start_assessment(
        self,
        *,
        assessment_name: str,
        output_root: Path,
        installer: Path,
        mode: str = "full",
        application_root: Path | None = None,
        application_path: str | None = None,
        network_observation_seconds: float = 5.0,
        allow_installed_deb: bool = False,
        progress_callback=None,
    ) -> ServiceResult:
        try:
            data = self.workflow.start(
                assessment_name=assessment_name,
                output_root=output_root,
                installer=installer,
                mode=mode,
                application_root=application_root,
                application_path=application_path,
                network_observation_seconds=network_observation_seconds,
                allow_installed_deb=allow_installed_deb,
                progress_callback=progress_callback,
            )
            waiting = data.get("status") == "waiting-for-installation"
            return ServiceResult(True, "assessment-waiting-installation" if waiting else "assessment-completed", "Assessment prepared; complete installation/setup outside the browser, then continue" if waiting else "Assessment completed", data=data)
        except WorkflowError as exc:
            return ServiceResult(False, "assessment-start-failed", "Assessment could not be started", errors=[str(exc)])
        except Exception as exc:
            return ServiceResult(False, "assessment-start-failed", "Assessment could not be started", errors=[str(exc)])

    def continue_assessment(self, assessment_dir: Path, *, include_discovered_home: bool = True, progress_callback=None) -> ServiceResult:
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "GUI assessment continuation", exclusive=True):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                data = self.workflow.continue_full(assessment_dir, include_discovered_home=include_discovered_home, progress_callback=progress_callback)
            return ServiceResult(True, "assessment-completed", "Assessment completed", data=data)
        except AssessmentBusyError as exc:
            return self._busy(exc)
        except WorkflowError as exc:
            return ServiceResult(False, "assessment-continue-failed", "Assessment could not continue", errors=[str(exc)])
        except Exception as exc:
            return ServiceResult(False, "assessment-continue-failed", "Assessment could not continue", errors=[str(exc)])

    def capabilities(self) -> ServiceResult:
        """Describe the stable presentation-neutral service contract.

        This is intentionally data-only so a future localhost GUI can discover
        supported backend actions without importing terminal presentation code.
        """
        return ServiceResult(
            True,
            "capabilities-ready",
            "Application-service capabilities loaded",
            data={
                "service_contract_version": SERVICE_CONTRACT_VERSION,
                "framework_version": VERSION,
                "methodology_version": METHODOLOGY_VERSION,
                "coverage_catalog_version": TEST_CASE_CATALOG_VERSION,
                "security_model_schema": MODEL_SCHEMA_VERSION,
                "presentation_neutral": True,
                "operations": [dict(item) for item in SERVICE_OPERATIONS],
                "runtime_collection": {
                    "collector": "presentation-orchestrated",
                    "commit_operation": "finalize_runtime_observation",
                    "note": "The UI owns start/stop interaction; committed runtime evidence is finalized by the shared service.",
                },
            },
        )

    def assessment_overview(self, assessment_dir: Path) -> ServiceResult:
        """Return a compact JSON-safe assessment summary for non-CLI front ends."""
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "assessment overview", exclusive=False):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                metadata_path = assessment_dir / "assessment_metadata.json"
                if not metadata_path.is_file():
                    return ServiceResult(False, "overview-unavailable", "Assessment metadata is missing")
                metadata = read_json(metadata_path)
                review_counts = {"available": False, "total": 0, "pending": 0, "completed": 0, "statuses": {}}
                review_path = assessment_dir / "working" / "tester_review_state.json"
                if review_path.is_file():
                    state = load_review_state(assessment_dir)
                    items = list(state.get("items", []) or [])
                    statuses: dict[str, int] = {}
                    for item in items:
                        status = str(item.get("status") or "PENDING")
                        statuses[status] = statuses.get(status, 0) + 1
                    pending_count = statuses.get("PENDING", 0)
                    review_counts = {
                        "available": True,
                        "total": len(items),
                        "pending": pending_count,
                        "completed": len(items) - pending_count,
                        "statuses": statuses,
                    }
                manifest_path = assessment_dir / "assessment_manifest.json"
                inventory_revision = None
                if manifest_path.is_file():
                    try:
                        inventory_revision = read_json(manifest_path).get("inventory_revision")
                    except Exception:
                        inventory_revision = None
                data = {
                    "assessment": str(assessment_dir),
                    "assessment_name": metadata.get("assessment_name") or assessment_dir.name,
                    "mode": metadata.get("mode"),
                    "framework_version": metadata.get("framework_version") or VERSION,
                    "methodology_version": metadata.get("methodology_version") or METHODOLOGY_VERSION,
                    "run_state": metadata.get("run_state") or {},
                    "installation": metadata.get("installation") or {},
                    "application_file_coverage": metadata.get("application_file_coverage") or {"limited": False, "gaps": []},
                    "privileged_static_review": metadata.get("privileged_static_review") or {},
                    "review": review_counts,
                    "revision": assessment_revision(assessment_dir),
                    "inventory_revision": inventory_revision,
                }
                return ServiceResult(True, "overview-ready", "Assessment overview loaded", data=data)
        except AssessmentBusyError as exc:
            return self._busy(exc)
        except Exception as exc:
            return ServiceResult(False, "overview-failed", "Assessment overview could not be loaded", errors=[str(exc)])

    @staticmethod
    def _resolve(path: Path) -> Path:
        return Path(path).expanduser().resolve()

    @staticmethod
    def _busy(exc: Exception) -> ServiceResult:
        return ServiceResult(False, "assessment-busy", "Assessment is busy", errors=[str(exc)])

    @staticmethod
    def _pending_transaction_result(assessment_dir: Path) -> ServiceResult | None:
        pending = pending_transaction(assessment_dir)
        if not pending:
            return None
        operation = str(pending.get("operation") or "unknown")
        started = str(pending.get("started_at") or "unknown")
        return ServiceResult(
            False,
            "interrupted-transaction",
            "An interrupted assessment write requires recovery",
            data={"transaction": pending, "action": "recover-interrupted"},
            errors=[f"Interrupted operation: {operation} (started {started})"],
        )

    def state_revision(self, assessment_dir: Path) -> ServiceResult:
        """Return the optimistic-concurrency token for the current assessment state."""
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "state revision", exclusive=False):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                revision = assessment_revision(assessment_dir)
        except AssessmentBusyError as exc:
            return self._busy(exc)
        return ServiceResult(True, "revision-ready", "Assessment revision loaded", data={"revision": revision})

    def verify_assessment(self, assessment_dir: Path) -> ServiceResult:
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "integrity verification", exclusive=False):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                result = assessment_verification_summary(assessment_dir)
                result["revision"] = assessment_revision(assessment_dir)
        except AssessmentBusyError as exc:
            return self._busy(exc)
        issues = [str(x) for x in result.get("issues", [])]
        return ServiceResult(
            ok=bool(result.get("passed")),
            code="verification-passed" if result.get("passed") else "verification-failed",
            message="Assessment verification passed" if result.get("passed") else "Assessment verification failed",
            data=result,
            errors=issues,
        )

    def recover_interrupted_operation(self, assessment_dir: Path) -> ServiceResult:
        """Rollback a hard-interrupted multi-file write to its pre-operation state."""
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "interrupted transaction recovery", exclusive=True):
                pending = pending_transaction(assessment_dir)
                if not pending:
                    return ServiceResult(True, "no-recovery-needed", "No interrupted assessment write was found", data={"revision": assessment_revision(assessment_dir)})
                recovered = recover_interrupted_transaction(assessment_dir)
                issues = verify_artifact_manifest(assessment_dir)
                if issues:
                    return ServiceResult(
                        False,
                        "recovery-integrity-failed",
                        "Interrupted write was rolled back but assessment integrity still requires attention",
                        data={"recovered": recovered, "revision": assessment_revision(assessment_dir)},
                        errors=list(issues),
                    )
                return ServiceResult(
                    True,
                    "recovery-complete",
                    "Interrupted assessment write rolled back to the last consistent state",
                    data={"recovered": recovered, "revision": assessment_revision(assessment_dir)},
                )
        except AssessmentBusyError as exc:
            return self._busy(exc)
        except Exception as exc:
            return ServiceResult(False, "recovery-failed", "Interrupted assessment write could not be recovered", errors=[str(exc)])

    def create_client_appendix(self, assessment_dir: Path) -> ServiceResult:
        assessment_dir = self._resolve(assessment_dir)
        try:
            # Export holds an exclusive lock so a review/runtime writer cannot
            # change source files halfway through the copy/hash operation.
            with assessment_lock(assessment_dir, "ClientAppendix export", exclusive=True):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                result = create_client_appendix(assessment_dir)
                result["source_revision"] = assessment_revision(assessment_dir)
        except AssessmentBusyError as exc:
            return self._busy(exc)
        except Exception as exc:
            repair = self.generated_report_repair_status(assessment_dir)
            return ServiceResult(
                ok=False,
                code="client-appendix-failed",
                message="Client appendix export failed",
                data={"repair": repair},
                errors=[str(exc)],
            )
        return ServiceResult(True, "client-appendix-created", "Client appendix created", data=result)

    def _review_snapshot_unlocked(self, assessment_dir: Path) -> ServiceResult:
        issues = verify_artifact_manifest(assessment_dir)
        if issues:
            return ServiceResult(False, "integrity-failed", "Assessment verification failed", errors=list(issues))
        try:
            metadata = read_json(assessment_dir / "assessment_metadata.json")
        except Exception as exc:
            return ServiceResult(False, "metadata-unreadable", "Assessment metadata could not be loaded", errors=[str(exc)])
        if str(metadata.get("mode") or "") != "full":
            return ServiceResult(False, "review-unavailable", "Guided review is available only for completed Full Assessments")
        try:
            state = load_review_state(assessment_dir)
        except Exception as exc:
            return ServiceResult(False, "review-state-unreadable", "Tester review queue could not be loaded", errors=[str(exc)])

        items = list(state.get("items", []))
        # Provide the same complete validation procedure used by the CLI/text
        # reports so browser clients never have to reconstruct tester guidance.
        enriched_items: list[dict[str, Any]] = []
        for source_item in items:
            item = dict(source_item)
            playbook = playbook_for(item)
            item["validation_procedure"] = "\n".join(render_playbook_lines(playbook)).strip()
            item["expected_secure_behavior"] = str(playbook.get("secure_result") or "")
            item["potentially_vulnerable_behavior"] = str(playbook.get("vulnerable_result") or "")
            item["do_not_report"] = "\n".join(f"- {x}" for x in (playbook.get("stop_conditions") or []))
            enriched_items.append(item)
        items = enriched_items
        groups: dict[str, dict[str, Any]] = {}
        for item in items:
            category = review_category(item)
            key, label = review_group(item)
            key = str(item.get("review_group") or key)
            label = str(item.get("review_group_label") or label)
            composite = f"{category}::{key}"
            group = groups.setdefault(composite, {
                "category": category,
                "key": key,
                "label": label,
                "item_ids": [],
                "shared_validation": list(item.get("shared_validation") or shared_validation_for(item)),
            })
            group["item_ids"].append(str(item.get("id") or ""))

        pending = sum(1 for item in items if item.get("status") == "PENDING")
        revision = assessment_revision(assessment_dir)
        return ServiceResult(True, "review-ready", "Tester review state loaded", data={
            "assessment": metadata.get("assessment_name") or assessment_dir.name,
            "state": state,
            "items": items,
            "categories": category_progress(items),
            "groups": list(groups.values()),
            "progress": {"total": len(items), "completed": len(items) - pending, "pending": pending},
            "revision": revision,
        })

    def review_snapshot(self, assessment_dir: Path) -> ServiceResult:
        """Return review state plus presentation-neutral category/group metadata."""
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "Guided Review read", exclusive=False):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                return self._review_snapshot_unlocked(assessment_dir)
        except AssessmentBusyError as exc:
            return self._busy(exc)

    def save_review_item(
        self,
        assessment_dir: Path,
        identity: str,
        *,
        status: str,
        notes: str = "",
        expected_revision: str | None = None,
    ) -> ServiceResult:
        """Persist one disposition with locking, stale-write detection and rollback."""
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "Guided Review save", exclusive=True):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                try:
                    base_revision = require_revision(assessment_dir, expected_revision)
                except StaleStateError as exc:
                    return ServiceResult(False, "stale-state", "Assessment state changed before the review item could be saved", data={"current_revision": assessment_revision(assessment_dir)}, errors=[str(exc)])
                before = self._review_snapshot_unlocked(assessment_dir)
                if not before.ok:
                    return before
                try:
                    with StateTransaction(assessment_dir, "Guided Review save", REVIEW_TRANSACTION_FILES, base_revision=base_revision) as tx:
                        state = update_review_item(assessment_dir, identity, status=status, notes=notes)
                        self._refresh_review_outputs(assessment_dir)
                        tx.commit()
                except Exception as exc:
                    return ServiceResult(False, "review-save-failed", "Unable to save review state; prior consistent state was restored", errors=[str(exc)])
                revision = assessment_revision(assessment_dir)
        except AssessmentBusyError as exc:
            return self._busy(exc)

        items = list(state.get("items", []))
        pending_count = sum(1 for item in items if item.get("status") == "PENDING")
        updated = next((x for x in items if str(x.get("identity")) == str(identity)), None)
        selected_category = review_category(updated) if updated else None
        category_items = [x for x in items if selected_category and review_category(x) == selected_category]
        category_pending = sum(1 for x in category_items if x.get("status") == "PENDING")
        return ServiceResult(True, "review-saved", "Review item saved and assessment manifest refreshed", data={
            "state": state,
            "updated_item": updated,
            "revision": revision,
            "progress": {"total": len(items), "completed": len(items) - pending_count, "pending": pending_count},
            "category_progress": {
                "category": selected_category,
                "total": len(category_items),
                "completed": len(category_items) - category_pending,
                "pending": category_pending,
            },
        })

    def finalize_runtime_observation(
        self,
        assessment_dir: Path,
        observation: dict[str, Any],
        profile_data: dict[str, Any],
        *,
        application_path: str | None = None,
        metadata_updates: dict[str, Any] | None = None,
        expected_revision: str | None = None,
    ) -> ServiceResult:
        """Apply runtime evidence as one recoverable, stale-protected transaction."""
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "runtime finalization", exclusive=True):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                try:
                    base_revision = require_revision(assessment_dir, expected_revision)
                except StaleStateError as exc:
                    return ServiceResult(False, "stale-state", "Assessment state changed while runtime observation was being collected", data={"current_revision": assessment_revision(assessment_dir)}, errors=[str(exc)])
                try:
                    with StateTransaction(assessment_dir, "runtime finalization", RUNTIME_TRANSACTION_FILES, base_revision=base_revision) as tx:
                        metadata_path = assessment_dir / "assessment_metadata.json"
                        metadata = read_json(metadata_path)
                        if str(metadata.get("mode") or "") != "full":
                            raise RuntimeError("Runtime observation is available only for Full Assessments")
                        if metadata_updates:
                            allowed = {"application_path", "application_root", "application_scope", "application_roots", "analysis_roots", "data_roots", "expected_runtime_roots"}
                            for key in allowed:
                                if key in metadata_updates:
                                    metadata[key] = metadata_updates[key]
                            write_json(metadata_path, metadata)
                        write_json(assessment_dir / "working" / "runtime_observation.json", observation)
                        write_runtime_guidance(assessment_dir, application_path or metadata.get("application_path"), profile_data, observation)
                        update_ipc_with_runtime(assessment_dir, observation, profile_data)
                        merge_runtime_security_model(assessment_dir, observation, profile_data)
                        state = merge_additional_review_items(assessment_dir, profile_data=profile_data, runtime_data=observation)
                        refresh_findings_dispositions(assessment_dir)
                        synchronize_security_model(assessment_dir)
                        refresh_assessment_coverage(assessment_dir)
                        refresh_consolidated_report(assessment_dir)
                        finalize_artifact_manifest(assessment_dir, "full")
                        issues = verify_artifact_manifest(assessment_dir)
                        if issues:
                            raise RuntimeError("; ".join(issues))
                        tx.commit()
                except Exception as exc:
                    return ServiceResult(False, "runtime-finalization-failed", "Runtime observation could not be finalized; prior consistent state was restored", errors=[str(exc)])
                revision = assessment_revision(assessment_dir)
        except AssessmentBusyError as exc:
            return self._busy(exc)

        items = list(state.get("items", []))
        pending_count = sum(1 for item in items if item.get("status") == "PENDING")
        return ServiceResult(True, "runtime-finalized", "Runtime observation saved and assessment manifest refreshed", data={
            "state": state,
            "revision": revision,
            "pending_review_items": pending_count,
            "sample_count": observation.get("sample_count", 0),
            "application_process_count": len(observation.get("application_processes", [])),
            "connection_count": len(observation.get("connections", [])),
            "unix_socket_count": len(observation.get("unix_sockets", [])),
            "fifo_count": len(observation.get("fifo_paths", [])),
            "client_appendix_stale": (assessment_dir / "ClientAppendix").exists(),
        })

    def generated_report_repair_status(self, assessment_dir: Path) -> dict[str, Any]:
        assessment_dir = self._resolve(assessment_dir)
        manifest_path = assessment_dir / "assessment_manifest.json"
        if not manifest_path.is_file():
            return {"repairable": False, "modified": [], "unsafe": ["assessment_manifest.json is missing"]}
        try:
            manifest = read_json(manifest_path)
        except Exception as exc:
            return {"repairable": False, "modified": [], "unsafe": [f"assessment_manifest.json unreadable: {exc}"]}
        if manifest.get("framework_version") != VERSION or manifest.get("methodology_version") != METHODOLOGY_VERSION:
            return {"repairable": False, "modified": [], "unsafe": ["assessment was finalized by a different framework/methodology version"]}

        reports = assessment_dir / "reports"
        expected = set(str(x) for x in manifest.get("expected_reports", []) if x)
        actual = {path.name for path in reports.iterdir() if path.is_file()} if reports.is_dir() else set()
        missing = expected - actual
        unexpected = actual - expected
        unsafe: list[str] = []
        modified: set[str] = set()
        if unexpected:
            unsafe.append(f"unexpected tester reports: {sorted(unexpected)}")
        for name in missing:
            if name in REPAIRABLE_GENERATED_REPORTS:
                modified.add(name)
            else:
                unsafe.append(f"missing non-repairable tester report: {name}")

        for entry in manifest.get("reports", []) or []:
            rel = str(entry.get("path") or "")
            name = Path(rel).name
            path = assessment_dir / rel
            bad = (not path.is_file()) or path.stat().st_size != entry.get("size") or sha256_file(path) != entry.get("sha256")
            if bad:
                if name in REPAIRABLE_GENERATED_REPORTS:
                    modified.add(name)
                else:
                    unsafe.append(f"integrity mismatch in non-repairable report: {rel}")

        for entry in manifest.get("supporting_files", []) or []:
            rel = str(entry.get("path") or "")
            path = assessment_dir / rel
            bad = (not path.is_file()) or path.stat().st_size != entry.get("size") or sha256_file(path) != entry.get("sha256")
            if bad:
                unsafe.append(f"integrity mismatch in authoritative/supporting state: {rel}")

        for entry in manifest.get("extraction_directories", []) or []:
            directory = assessment_dir / str(entry.get("path") or "")
            if not directory.is_dir():
                unsafe.append(f"missing extraction/raw evidence directory: {entry.get('path')}")

        for issue in verify_artifact_manifest(assessment_dir):
            if issue.startswith((
                "Extraction inventory mismatch", "Unsafe recorded path", "Unsafe extraction path",
                "Unsupported manifest schema", "Framework version mismatch", "Methodology version mismatch",
            )) and issue not in unsafe:
                unsafe.append(issue)
        return {"repairable": bool(modified) and not unsafe, "modified": sorted(modified), "unsafe": unsafe}

    def repair_generated_reports(self, assessment_dir: Path) -> ServiceResult:
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "generated-report repair", exclusive=True):
                pending = self._pending_transaction_result(assessment_dir)
                if pending:
                    return pending
                status = self.generated_report_repair_status(assessment_dir)
                if not status.get("repairable"):
                    errors = list(status.get("unsafe", [])) or ["No repairable generated-report mismatch was identified."]
                    return ServiceResult(False, "repair-unsafe", "Generated-report repair is not safe for this assessment", data=status, errors=errors)
                base_revision = assessment_revision(assessment_dir)
                try:
                    with StateTransaction(assessment_dir, "generated-report repair", REPAIR_TRANSACTION_FILES, base_revision=base_revision) as tx:
                        metadata = read_json(assessment_dir / "assessment_metadata.json")
                        mode = str(metadata.get("mode") or "")
                        if mode == "full":
                            if not (assessment_dir / "working" / "tester_review_state.json").is_file():
                                raise RuntimeError("authoritative tester review state is missing")
                            refresh_review_reports(assessment_dir)
                            if not (assessment_dir / "working" / "finding_candidates.json").is_file():
                                raise RuntimeError("structured finding candidate state is missing")
                            refresh_findings_dispositions(assessment_dir)
                        refresh_assessment_coverage(assessment_dir)
                        refresh_consolidated_report(assessment_dir)
                        finalize_artifact_manifest(assessment_dir, mode)
                        issues = verify_artifact_manifest(assessment_dir)
                        if issues:
                            raise RuntimeError("; ".join(issues))
                        tx.commit()
                except Exception as exc:
                    return ServiceResult(False, "repair-failed", "Generated-report repair failed; prior consistent state was restored", data=status, errors=[str(exc)])
                return ServiceResult(True, "repair-complete", "Generated tester reports regenerated from trusted internal state", data={**status, "revision": assessment_revision(assessment_dir)})
        except AssessmentBusyError as exc:
            return self._busy(exc)

    def assessment_status(self, assessment_dir: Path) -> ServiceResult:
        assessment_dir = self._resolve(assessment_dir)
        try:
            with assessment_lock(assessment_dir, "assessment status", exclusive=False):
                pending = pending_transaction(assessment_dir)
                if pending:
                    data = {
                        "assessment": str(assessment_dir),
                        "status": "INTERRUPTED WRITE / RECOVERABLE",
                        "action": "recover-transaction",
                        "detail": "A state-changing operation was interrupted. Roll back its transaction before continuing.",
                        "transaction": pending,
                    }
                    metadata_path = assessment_dir / "assessment_metadata.json"
                    if metadata_path.is_file():
                        try:
                            data["metadata"] = read_json(metadata_path)
                        except Exception:
                            pass
                    return ServiceResult(False, "status-interrupted-write", "Interrupted assessment write is recoverable", data=data)

                metadata_path = assessment_dir / "assessment_metadata.json"
                if not metadata_path.is_file():
                    data = {"assessment": str(assessment_dir), "status": "UNKNOWN", "action": "restart", "detail": "assessment_metadata.json is missing"}
                    return ServiceResult(False, "status-unknown", "Assessment status is unknown", data=data)
                try:
                    metadata = read_json(metadata_path)
                except Exception as exc:
                    data = {"assessment": str(assessment_dir), "status": "UNKNOWN", "action": "restart", "detail": f"metadata unreadable: {exc}"}
                    return ServiceResult(False, "status-unknown", "Assessment status is unknown", data=data, errors=[str(exc)])

                run_state = metadata.get("run_state") if isinstance(metadata.get("run_state"), dict) else {}
                work = assessment_dir / "working"
                pre = (work / "snapshot_pre.json").is_file()
                post = (work / "snapshot_post.json").is_file()
                installation = metadata.get("installation") if isinstance(metadata.get("installation"), dict) else {}
                install_status = str(installation.get("status") or "unknown")
                base = {
                    "assessment": str(assessment_dir), "metadata": metadata, "pre": pre, "post": post,
                    "installation_status": install_status, "revision": assessment_revision(assessment_dir),
                }
                completed = str(run_state.get("status") or "") == "completed"
                if str(run_state.get("stage") or "") == "waiting-for-installation" and pre and not post:
                    base.update({
                        "status": "WAITING FOR INSTALLATION",
                        "action": "continue-installation",
                        "detail": "Install/configure the application outside the browser, complete first-run setup, then continue the assessment.",
                        "install_command": str((metadata.get("gui_workflow") or {}).get("install_command") or ""),
                    })
                    return ServiceResult(True, "status-waiting-installation", "Assessment is waiting for installation/setup", data=base)
                if completed:
                    issues = verify_artifact_manifest(assessment_dir)
                    if not issues:
                        base.update({"status": "COMPLETED", "action": "none", "detail": ""})
                        return ServiceResult(True, "status-completed", "Assessment completed", data=base)
                    repair = self.generated_report_repair_status(assessment_dir)
                    action = "repair-generated" if repair.get("repairable") else "verify"
                    base.update({"status": "COMPLETED / INTEGRITY ISSUE", "action": action, "detail": "; ".join(issues), "repair": repair})
                    return ServiceResult(False, "status-integrity-issue", "Completed assessment has an integrity issue", data=base, errors=list(issues))
                if pre and post:
                    base.update({"status": "RECOVERABLE", "action": "post-analysis", "detail": "Trustworthy pre/post snapshots exist; post-analysis/finalization can be rerun."})
                    return ServiceResult(True, "status-recoverable", "Assessment can resume from post-analysis", data=base)
                changed_state = install_status in {"in-progress", "interrupted", "completed", "verification-failed", "not-confirmed"} or str(run_state.get("stage") or "").startswith(("installation", "package-verification", "application-exercise", "post-installation"))
                if pre and not post and changed_state:
                    base.update({"status": "VM RESET REQUIRED", "action": "reset", "detail": "Installation may have changed machine state without a trustworthy post-install snapshot."})
                    return ServiceResult(False, "status-reset-required", "VM reset required", data=base)
                if pre and not post:
                    base.update({"status": "RESTART RECOMMENDED", "action": "restart", "detail": "Only the pre-install snapshot is trustworthy; restart from the clean VM baseline."})
                    return ServiceResult(False, "status-restart-recommended", "Assessment restart recommended", data=base)
                base.update({"status": "INCOMPLETE", "action": "restart", "detail": "Required recovery checkpoints are incomplete."})
                return ServiceResult(False, "status-incomplete", "Assessment is incomplete", data=base)
        except AssessmentBusyError as exc:
            return self._busy(exc)

    @staticmethod
    def _refresh_review_outputs(assessment_dir: Path) -> None:
        metadata = read_json(assessment_dir / "assessment_metadata.json")
        mode = str(metadata.get("mode") or "")
        if mode != "full":
            raise RuntimeError("Guided review is available only for completed Full Assessments")
        refresh_findings_dispositions(assessment_dir)
        refresh_assessment_coverage(assessment_dir)
        refresh_consolidated_report(assessment_dir)
        finalize_artifact_manifest(assessment_dir, mode)
        issues = verify_artifact_manifest(assessment_dir)
        if issues:
            raise RuntimeError("Assessment verification failed after review update: " + "; ".join(issues))
