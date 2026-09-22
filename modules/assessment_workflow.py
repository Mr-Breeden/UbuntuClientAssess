from __future__ import annotations

"""Presentation-neutral staged assessment orchestration for the localhost GUI.

The terminal CLI remains authoritative for fully interactive/custom workflows.  This
module exposes the safe subset needed by the browser: prepare a Full Assessment to
the pre-install checkpoint, continue after the tester performs installation/setup,
and run Installer Analysis Only without terminal prompts.
"""

import hashlib
import re
import shlex
from pathlib import Path
from typing import Any, Callable

from modules.app_scope import discover_runtime_roots, infer_debian_application_scope
from modules.application_profile import profile_application
from modules.artifacts import finalize_artifact_manifest, verify_artifact_manifest
from modules.assessment_coverage import generate_assessment_coverage
from modules.common import (
    METHODOLOGY_VERSION,
    TEST_CASE_CATALOG_VERSION,
    VERSION,
    clean_generated_artifacts,
    ensure_assessment_layout,
    get_interactive_home,
    now_iso,
    read_json,
    report_path,
    run_cmd,
    working_dir,
    write_json,
    write_text,
)
from modules.consolidated_report import generate_consolidated_report
from modules.coverage_limits import apply_coverage_attention, append_coverage_notes, detect_application_file_coverage_gaps, enrich_analysis_roots, load_post_snapshot
from modules.elf_analysis import analyze_elf
from modules.findings import generate_findings
from modules.install_changes import compare_snapshots
from modules.installer_analysis import analyze_installer, discover_installer_paths
from modules.ipc import review_ipc
from modules.network import review_network
from modules.permissions import review_permissions
from modules.persistence import review_persistence
from modules.runtime import write_runtime_guidance
from modules.security_model import build_security_model, synchronize_security_model
from modules.services import review_services
from modules.snapshot import collect_snapshot, merge_tracked_paths
from modules.storage import review_storage
from modules.tester_review import generate_tester_review
from modules.tool_detection import detect_tools
from modules.update_review import review_updates


class WorkflowError(RuntimeError):
    pass


def _emit_progress(callback, *, phase: str, module: str = "", status: str = "running", completed: int | None = None, total: int | None = None, message: str = "") -> None:
    if not callback:
        return
    payload: dict[str, Any] = {"phase": phase, "module": module, "status": status}
    if completed is not None:
        payload["completed"] = completed
    if total is not None:
        payload["total"] = total
        payload["percent"] = int((completed or 0) * 100 / total) if total else 0
    if message:
        payload["message"] = message
    try:
        callback(payload)
    except Exception:
        pass


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "_", str(name or "")).strip()
    return cleaned or "UbuntuClientAssess"


def _set_run_state(metadata_path: Path, metadata: dict[str, Any], stage: str, status: str = "running", detail: str = "") -> None:
    previous = metadata.get("run_state") if isinstance(metadata.get("run_state"), dict) else {}
    state: dict[str, Any] = {
        "status": status,
        "stage": stage,
        "started_at": previous.get("started_at") or now_iso(),
        "updated_at": now_iso(),
    }
    if detail:
        state["detail"] = detail
    metadata["run_state"] = state
    write_json(metadata_path, metadata)


def _record(statuses: dict[str, tuple[str, str]], name: str, state: str, detail: str = "") -> None:
    statuses[name] = (state, detail)


def _write_module_status(output_dir: Path, statuses: dict[str, tuple[str, str]]) -> None:
    lines = [
        "UbuntuClientAssess Module Status",
        "=" * 32,
        "",
        "PASS means the module completed without an internal error. WARN means a recoverable module error reduced coverage. ATTN identifies a manual validation/coverage limitation. FAIL means the assessment cannot be trusted/finalized.",
        "",
    ]
    for name, (state, detail) in statuses.items():
        suffix = f" - {detail}" if detail else ""
        lines.append(f"[{state:<7}] {name}{suffix}")
    write_text(report_path(output_dir, "module_status.txt"), "\n".join(lines))


def _step(statuses: dict[str, tuple[str, str]], name: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        result = fn(*args, **kwargs)
        _record(statuses, name, "PASS")
        return result
    except Exception as exc:
        _record(statuses, name, "WARN", str(exc))
        return None


def _home_entries(excluded: list[Path]) -> set[Path]:
    home = get_interactive_home()
    try:
        return {
            p.absolute() for p in home.iterdir()
            if not any(p.absolute() == x or x in p.absolute().parents for x in excluded)
        }
    except OSError:
        return set()


def _deb_package_state(installer: Path) -> dict[str, Any] | None:
    package_r = run_cmd(["dpkg-deb", "-f", str(installer), "Package"])
    version_r = run_cmd(["dpkg-deb", "-f", str(installer), "Version"])
    package = package_r["stdout"].strip()
    installer_version = version_r["stdout"].strip()
    if not package:
        return None
    installed_r = run_cmd(["dpkg-query", "-W", "-f=${Status}\t${Version}", package])
    present = installed_r["returncode"] == 0
    status_text, _, recorded_version = installed_r["stdout"].partition("\t")
    installed = present and status_text == "install ok installed"
    return {
        "package": package,
        "installer_version": installer_version or None,
        "dpkg_present": present,
        "dpkg_status": status_text.strip() if present else None,
        "installed": installed,
        "installed_version": recorded_version.strip() if present and recorded_version else None,
    }


def _deb_installation_complete(state: dict[str, Any] | None) -> bool:
    if not state or not state.get("installed"):
        return False
    expected = str(state.get("installer_version") or "").strip()
    observed = str(state.get("installed_version") or "").strip()
    return (expected == observed) if (expected or observed) else True


def _build_context(installer: Path, output_dir: Path, application_root: Path | None = None, application_path: str | None = None) -> dict[str, Any]:
    installer_paths = discover_installer_paths(installer)
    scope = infer_debian_application_scope(installer, installer_paths)
    inferred_roots = [Path(v) for v in scope.get("application_roots", []) or []]
    runtime_roots = discover_runtime_roots(scope, existing_only=False)
    if application_root is None and scope.get("application_root"):
        application_root = Path(str(scope["application_root"]))
    app_path = application_path or scope.get("application_path")
    requested = inferred_roots + runtime_roots + ([application_root] if application_root else [])
    tracked = merge_tracked_paths(installer_paths + requested)
    digest = hashlib.sha256("\n".join(str(p) for p in installer_paths).encode("utf-8")).hexdigest() if installer_paths else None
    return {
        "installer_paths": installer_paths,
        "scope": scope,
        "inferred_roots": inferred_roots,
        "expected_runtime_roots": runtime_roots,
        "application_root": application_root,
        "application_path": app_path,
        "tracked_paths": tracked,
        "installer_path_digest": digest,
    }


def _finalize(output_dir: Path, metadata: dict[str, Any], statuses: dict[str, tuple[str, str]], mode: str) -> None:
    metadata_path = output_dir / "assessment_metadata.json"
    _record(statuses, "Artifact Inventory", "PASS")
    _write_module_status(output_dir, statuses)
    generate_consolidated_report(output_dir, str(metadata.get("assessment_name") or output_dir.name), metadata.get("installer"), mode, VERSION, statuses)
    finalize_artifact_manifest(output_dir, mode)
    issues = verify_artifact_manifest(output_dir)
    if issues:
        raise WorkflowError("Artifact finalization failed: " + "; ".join(issues))
    _set_run_state(metadata_path, metadata, "complete", "completed")
    finalize_artifact_manifest(output_dir, mode)
    issues = verify_artifact_manifest(output_dir)
    if issues:
        raise WorkflowError("Final integrity verification failed: " + "; ".join(issues))


def _post_analysis(output_dir: Path, metadata: dict[str, Any], statuses: dict[str, tuple[str, str]], installer_data: dict[str, Any], progress_callback=None) -> None:
    roots = [Path(v) for v in metadata.get("analysis_roots", []) or []]
    pre = working_dir(output_dir) / "snapshot_pre.json"
    post = working_dir(output_dir) / "snapshot_post.json"
    if not pre.is_file() or not post.is_file():
        raise WorkflowError("Required pre/post snapshots were not found")
    _emit_progress(progress_callback, phase="analysis", module="Installation Differential", completed=6, total=21)
    diff = _step(statuses, "Installation Differential", compare_snapshots, pre, post, output_dir)
    if diff is None:
        raise WorkflowError("Snapshot comparison failed")

    roots = enrich_analysis_roots(roots, diff)
    post_scope = infer_debian_application_scope(None, roots)
    learned_roots = [str(p) for p in roots]
    metadata["analysis_roots"] = learned_roots
    metadata["application_roots"] = sorted(set([str(v) for v in metadata.get("application_roots", []) or []] + [str(v) for v in post_scope.get("application_roots", []) or []]))
    if not metadata.get("application_root") and post_scope.get("application_root"):
        metadata["application_root"] = post_scope.get("application_root")
    prior_scope = metadata.get("application_scope") if isinstance(metadata.get("application_scope"), dict) else {}
    merged_scope = dict(prior_scope)
    for key in ("application_root", "application_path", "application_slug", "package"):
        if not merged_scope.get(key) and post_scope.get(key):
            merged_scope[key] = post_scope.get(key)
    merged_scope["application_roots"] = metadata["application_roots"]
    metadata["application_scope"] = merged_scope
    coverage_gaps = detect_application_file_coverage_gaps(load_post_snapshot(output_dir), roots)
    metadata["application_file_coverage"] = {"limited": bool(coverage_gaps), "gaps": coverage_gaps}
    write_json(output_dir / "assessment_metadata.json", metadata)
    statuses["Application File Coverage"] = ("ATTN" if coverage_gaps else "PASS", "Static application-file coverage is limited" if coverage_gaps else "Identified application roots were recursively accessible")

    _emit_progress(progress_callback, phase="analysis", module="Application / Framework Profile", completed=7, total=21)
    profile = _step(statuses, "Application / Framework Profile", profile_application, output_dir, diff, installer_data, roots) or {}
    profile["coverage_limitations"] = coverage_gaps
    try:
        write_json(working_dir(output_dir) / "application_profile.json", profile)
    except Exception:
        pass
    _emit_progress(progress_callback, phase="analysis", module="Permissions Review", completed=8, total=21)
    permissions = _step(statuses, "Permissions Review", review_permissions, diff, output_dir) or {}
    _emit_progress(progress_callback, phase="analysis", module="ELF Security Review", completed=9, total=21)
    elf = _step(statuses, "ELF Security Review", analyze_elf, diff, output_dir) or {}
    _emit_progress(progress_callback, phase="analysis", module="systemd Service Review", completed=10, total=21)
    services = _step(statuses, "systemd Service Review", review_services, diff, output_dir) or {}
    _emit_progress(progress_callback, phase="analysis", module="Persistence Review", completed=11, total=21)
    persistence = _step(statuses, "Persistence Review", review_persistence, diff, output_dir, elf) or {}
    if persistence.get("review_required"):
        _record(statuses, "Persistence Review", "ATTN", f"{len(persistence['review_required'])} privileged policy change(s) require manual review")
    _emit_progress(progress_callback, phase="analysis", module="Network Surface Review", completed=12, total=21)
    network = _step(statuses, "Network Surface Review", review_network, diff, output_dir, roots) or {}
    if not network.get("new_connections"):
        _record(statuses, "Network Surface Review", "ATTN", "No active application connection observed during the configured sampling window")
    _emit_progress(progress_callback, phase="analysis", module="IPC Review", completed=13, total=21)
    ipc = _step(statuses, "IPC Review", review_ipc, diff, output_dir, roots) or {}
    _emit_progress(progress_callback, phase="analysis", module="Local Storage Review", completed=14, total=21)
    storage = _step(statuses, "Local Storage Review", review_storage, diff, output_dir, roots) or {}
    _emit_progress(progress_callback, phase="analysis", module="Update Mechanism Review", completed=15, total=21)
    updates = _step(statuses, "Update Mechanism Review", review_updates, diff, output_dir, installer_data) or {}
    if any(x.get("status") not in {"VALID"} for x in updates.get("signature_validations", [])):
        _record(statuses, "Update Mechanism Review", "ATTN", "Installer signature was not independently verified")
    _emit_progress(progress_callback, phase="analysis", module="Runtime Guidance", completed=16, total=21)
    _step(statuses, "Runtime Guidance", write_runtime_guidance, output_dir, metadata.get("application_path"), profile)
    _emit_progress(progress_callback, phase="correlating", module="Security Correlation Model", completed=17, total=21)
    _step(statuses, "Security Correlation Model", build_security_model, output_dir, permissions, network, services, elf, ipc, storage, updates, persistence, profile)
    _emit_progress(progress_callback, phase="correlating", module="Tester Review Queue", completed=18, total=21)
    _step(statuses, "Tester Review Queue", generate_tester_review, output_dir, permissions, network, services, elf, ipc, storage, updates, persistence, profile)
    _emit_progress(progress_callback, phase="correlating", module="Findings Generation", completed=19, total=21)
    _step(statuses, "Findings Generation", generate_findings, output_dir, permissions, network, services, elf, storage, updates, persistence)
    synchronize_security_model(output_dir)
    _emit_progress(progress_callback, phase="finalizing", module="Assessment Coverage", completed=20, total=21)
    _step(statuses, "Assessment Coverage", generate_assessment_coverage, output_dir, "full", profile)
    append_coverage_notes(output_dir, coverage_gaps)
    apply_coverage_attention(statuses, coverage_gaps)


class AssessmentWorkflow:
    """Staged non-interactive assessment workflow used by the web interface."""

    def start(
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
    ) -> dict[str, Any]:
        _emit_progress(progress_callback, phase="preparing", module="Initialize Assessment", completed=0, total=21)
        name = _safe_name(assessment_name)
        output_root = Path(output_root).expanduser().resolve()
        installer = Path(installer).expanduser().resolve()
        if mode not in {"full", "installer-analysis-only"}:
            raise WorkflowError("Unsupported assessment mode")
        if not installer.is_file():
            raise WorkflowError("Installer/package file was not found")
        output_root.mkdir(parents=True, exist_ok=True)
        output_dir = (output_root / name).resolve()
        if output_root not in output_dir.parents:
            raise WorkflowError("Assessment output path is outside the selected root")
        if (output_dir / "assessment_metadata.json").exists():
            raise WorkflowError("An assessment with this name already exists in the selected root")

        package_state = _deb_package_state(installer) if installer.name.lower().endswith(".deb") else None
        if mode == "full" and package_state and package_state.get("dpkg_present") and not allow_installed_deb:
            raise WorkflowError("Clean baseline required: the selected Debian package is already known to dpkg")

        clean_generated_artifacts(output_dir, full_run=(mode == "full"))
        ensure_assessment_layout(output_dir)
        excluded = [output_dir]
        ctx = _build_context(installer, output_dir, application_root, application_path)
        metadata: dict[str, Any] = {
            "framework": "UbuntuClientAssess",
            "version": VERSION,
            "methodology_version": METHODOLOGY_VERSION,
            "test_case_catalog_version": TEST_CASE_CATALOG_VERSION,
            "assessment_name": name,
            "assessment_started_at": now_iso(),
            "last_run_at": now_iso(),
            "mode": mode,
            "installer": str(installer),
            "application_path": ctx["application_path"],
            "application_root": str(ctx["application_root"]) if ctx["application_root"] else None,
            "application_scope": ctx["scope"],
            "application_roots": [str(p) for p in ctx["inferred_roots"]],
            "expected_runtime_roots": [str(p) for p in ctx["expected_runtime_roots"]],
            "installer_declared_path_count": len(ctx["installer_paths"]),
            "installer_declared_paths_sha256": ctx["installer_path_digest"],
            "tracked_paths": [str(p) for p in ctx["tracked_paths"]],
            "include_paths": [],
            "data_roots": [],
            "excluded_paths": [str(p) for p in excluded],
            "deb_package_state_at_start": package_state,
            "installation": {
                "method": "not-applicable" if mode == "installer-analysis-only" else "external-manual",
                "confirmed": mode == "installer-analysis-only",
                "status": "not-applicable" if mode == "installer-analysis-only" else "not-started",
            },
            "gui_workflow": {"network_observation_seconds": float(network_observation_seconds)},
        }
        metadata_path = output_dir / "assessment_metadata.json"
        _set_run_state(metadata_path, metadata, "initialized")
        statuses: dict[str, tuple[str, str]] = {}

        _emit_progress(progress_callback, phase="preparing", module="Tool Detection", completed=1, total=21)
        detection = _step(statuses, "Tool Detection", detect_tools, output_dir)
        ready = bool(detection and isinstance(detection, tuple) and len(detection) > 1 and detection[1])
        if not ready:
            _record(statuses, "Tool Detection", "FAIL", "One or more required tools are missing")
            _write_module_status(output_dir, statuses)
            _set_run_state(metadata_path, metadata, "tool-detection", "failed", "Required tools are missing")
            raise WorkflowError("One or more required tools are missing")

        _emit_progress(progress_callback, phase="preparing", module="Installer Analysis", completed=2, total=21)
        installer_data = _step(statuses, "Installer Analysis", analyze_installer, installer, output_dir, mode == "installer-analysis-only") or {}
        if mode == "installer-analysis-only":
            _set_run_state(metadata_path, metadata, "installer-analysis")
            _emit_progress(progress_callback, phase="analysis", module="Application / Framework Profile", completed=3, total=5)
            profile = _step(statuses, "Application / Framework Profile", profile_application, output_dir, {}, installer_data, ctx["inferred_roots"]) or {}
            _emit_progress(progress_callback, phase="analysis", module="Runtime Guidance", completed=4, total=5)
            _step(statuses, "Runtime Guidance", write_runtime_guidance, output_dir, metadata.get("application_path"), profile)
            _emit_progress(progress_callback, phase="finalizing", module="Assessment Coverage", completed=5, total=5)
            _step(statuses, "Assessment Coverage", generate_assessment_coverage, output_dir, mode, profile)
            _write_module_status(output_dir, statuses)
            _finalize(output_dir, metadata, statuses, mode)
            _emit_progress(progress_callback, phase="completed", module="Assessment Complete", status="completed", completed=5, total=5)
            return {"assessment": str(output_dir), "status": "completed", "mode": mode}

        before_home = sorted(str(p) for p in _home_entries(excluded))
        write_json(working_dir(output_dir) / "gui_pre_home_entries.json", {"paths": before_home})
        _set_run_state(metadata_path, metadata, "pre-installation-snapshot")
        _emit_progress(progress_callback, phase="pre-install-snapshot", module="Pre-Installation Snapshot", completed=3, total=21)
        pre = _step(statuses, "Pre-Installation Snapshot", collect_snapshot, working_dir(output_dir) / "snapshot_pre.json", "pre-install", ctx["tracked_paths"], excluded, progress_callback=lambda d: _emit_progress(progress_callback, phase="pre-install-snapshot", module=str(d.get("stage") or "Pre-Installation Snapshot"), status=str(d.get("status") or "running"), completed=3, total=21))
        if pre is None:
            _record(statuses, "Pre-Installation Snapshot", "FAIL", "Baseline capture failed")
            _write_module_status(output_dir, statuses)
            _set_run_state(metadata_path, metadata, "pre-installation-snapshot", "failed", "Baseline capture failed")
            raise WorkflowError("Pre-installation snapshot failed")

        quoted_installer = shlex.quote(str(installer))
        suffix = installer.suffix.lower()
        if suffix == ".deb":
            install_command = f"sudo apt install -y {quoted_installer}"
        elif suffix == ".sh":
            install_command = f"sudo bash {quoted_installer}"
        elif suffix in {".run", ".appimage"}:
            install_command = f"chmod +x {quoted_installer} && sudo {quoted_installer}"
        else:
            install_command = f"Follow the vendor-approved installation procedure for: {quoted_installer}"
        metadata["installation"].update({"status": "awaiting-external-installation", "confirmed": False})
        metadata["gui_workflow"].update({"install_command": install_command, "prepared_at": now_iso()})
        _set_run_state(metadata_path, metadata, "waiting-for-installation", "waiting", "Perform installation/application setup outside the browser, then continue")
        _write_module_status(output_dir, statuses)
        _emit_progress(progress_callback, phase="waiting-for-installation", module="External Installation / Setup", status="waiting", completed=4, total=21, message="Complete the vendor-approved installation/setup outside the browser, then continue")
        return {
            "assessment": str(output_dir),
            "status": "waiting-for-installation",
            "mode": mode,
            "install_command": install_command,
            "application_root": metadata.get("application_root"),
            "application_path": metadata.get("application_path"),
        }

    def continue_full(self, assessment_dir: Path, *, include_discovered_home: bool = True, progress_callback=None) -> dict[str, Any]:
        _emit_progress(progress_callback, phase="installation-verification", module="Installation / Setup Confirmation", completed=4, total=21)
        output_dir = Path(assessment_dir).expanduser().resolve()
        metadata_path = output_dir / "assessment_metadata.json"
        if not metadata_path.is_file():
            raise WorkflowError("Assessment metadata is missing")
        metadata = read_json(metadata_path)
        if metadata.get("mode") != "full":
            raise WorkflowError("Only Full Assessments use the installation continuation step")
        stage = str((metadata.get("run_state") or {}).get("stage") or "")
        if stage != "waiting-for-installation":
            raise WorkflowError(f"Assessment is not waiting for installation (current stage: {stage or 'unknown'})")
        installer = Path(str(metadata.get("installer") or "")).expanduser().resolve()
        if not installer.is_file():
            raise WorkflowError("Recorded installer/package file is no longer available")
        is_deb = installer.name.lower().endswith(".deb")
        package_after = _deb_package_state(installer) if is_deb else None
        metadata["deb_package_state_after_installation"] = package_after
        if is_deb and not _deb_installation_complete(package_after):
            raise WorkflowError("Debian package installation could not be verified; install the selected package before continuing")

        statuses: dict[str, tuple[str, str]] = {}
        existing_status = report_path(output_dir, "module_status.txt")
        # Re-establish core stage statuses for the final module-status report.
        _record(statuses, "Tool Detection", "PASS")
        _record(statuses, "Installer Analysis", "PASS")
        _record(statuses, "Pre-Installation Snapshot", "PASS")
        if is_deb:
            _record(statuses, "Debian Package Verification", "PASS")
        else:
            _record(statuses, "Manual Installation Confirmation", "PASS", "Tester confirmed vendor-managed installation/setup before post-install capture")
        _record(statuses, "Application Setup / Exercise", "PASS")

        metadata["installation"].update({"status": "completed", "confirmed": True})
        metadata["application_exercise"] = {"status": "confirmed", "method": "gui-continuation", "confirmed_at": now_iso()}
        _set_run_state(metadata_path, metadata, "installation-complete")

        excluded = [Path(v) for v in metadata.get("excluded_paths", []) or []]
        tracked = [Path(v) for v in metadata.get("tracked_paths", []) or []]
        data_roots = [Path(v) for v in metadata.get("data_roots", []) or []]
        before_data = read_json(working_dir(output_dir) / "gui_pre_home_entries.json") if (working_dir(output_dir) / "gui_pre_home_entries.json").is_file() else {"paths": []}
        before = {Path(v) for v in before_data.get("paths", []) or []}
        now = _home_entries(excluded)
        new_home = sorted((now - before), key=str)
        accepted: list[Path] = new_home if include_discovered_home else []
        ignored: list[Path] = [] if include_discovered_home else new_home
        if accepted:
            data_roots = sorted(set(data_roots + accepted), key=str)
            tracked = merge_tracked_paths(tracked + accepted)
        metadata["data_roots"] = [str(p) for p in data_roots]
        metadata["discovered_home_paths"] = [str(p) for p in accepted]
        metadata["ignored_discovered_home_paths"] = [str(p) for p in ignored]
        metadata["tracked_paths"] = [str(p) for p in tracked]

        seconds = float((metadata.get("gui_workflow") or {}).get("network_observation_seconds") or 5.0)
        _set_run_state(metadata_path, metadata, "post-installation-snapshot")
        _emit_progress(progress_callback, phase="post-install-snapshot", module="Post-Installation Snapshot", completed=5, total=21)
        post = _step(statuses, "Post-Installation Snapshot", collect_snapshot, working_dir(output_dir) / "snapshot_post.json", "post-install", tracked, excluded, seconds, progress_callback=lambda d: _emit_progress(progress_callback, phase="post-install-snapshot", module=str(d.get("stage") or "Post-Installation Snapshot"), status=str(d.get("status") or "running"), completed=5, total=21))
        if post is None:
            _record(statuses, "Post-Installation Snapshot", "FAIL", "Post-install state capture failed")
            _write_module_status(output_dir, statuses)
            _set_run_state(metadata_path, metadata, "post-installation-snapshot", "failed", "Post-install state capture failed")
            raise WorkflowError("Post-installation snapshot failed")

        scope = metadata.get("application_scope") if isinstance(metadata.get("application_scope"), dict) else {}
        inferred = [Path(v) for v in metadata.get("application_roots", []) or []]
        runtime_roots = discover_runtime_roots(scope, existing_only=True)
        for p in runtime_roots:
            if p not in data_roots and str(p).startswith(str(get_interactive_home())):
                data_roots.append(p)
        app_root = Path(str(metadata["application_root"])) if metadata.get("application_root") else None
        analysis_roots = sorted(set(data_roots + inferred + runtime_roots + ([app_root] if app_root else [])), key=str)
        metadata["application_runtime_roots"] = [str(p) for p in runtime_roots]
        metadata["analysis_roots"] = [str(p) for p in analysis_roots]
        write_json(metadata_path, metadata)

        _set_run_state(metadata_path, metadata, "post-analysis")
        installer_data: dict[str, Any] = {}
        # Installer analysis report already exists; re-running the analysis keeps
        # the structured inputs deterministic for post-analysis.
        installer_data = _step(statuses, "Installer Analysis", analyze_installer, installer, output_dir, False) or {}
        _post_analysis(output_dir, metadata, statuses, installer_data, progress_callback=progress_callback)
        _write_module_status(output_dir, statuses)
        failed = [name for name, (state, _) in statuses.items() if state == "FAIL"]
        if failed:
            _set_run_state(metadata_path, metadata, "post-analysis", "failed", "Incomplete modules: " + ", ".join(failed))
            raise WorkflowError("Assessment modules failed: " + ", ".join(failed))
        _emit_progress(progress_callback, phase="finalizing", module="Artifact Inventory & Integrity", completed=21, total=21)
        _finalize(output_dir, metadata, statuses, "full")
        _emit_progress(progress_callback, phase="completed", module="Assessment Complete", status="completed", completed=21, total=21)
        return {
            "assessment": str(output_dir),
            "status": "completed",
            "mode": "full",
            "new_home_paths_included": [str(p) for p in accepted],
        }
