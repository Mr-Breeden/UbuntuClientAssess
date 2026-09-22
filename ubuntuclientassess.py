#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from prompt_toolkit import prompt as toolkit_prompt
    from prompt_toolkit.completion import PathCompleter
except ImportError as exc:
    print(f"[!] Missing Python dependency: {getattr(exc, 'name', 'unknown')}")
    print("    Install with: python3 -m pip install -r requirements.txt")
    raise SystemExit(2)

from modules.common import (
    METHODOLOGY_VERSION,
    TEST_CASE_CATALOG_VERSION,
    VERSION,
    clean_generated_artifacts,
    ensure_assessment_layout,
    get_interactive_home,
    now_iso,
    read_json,
    redact_sensitive_text,
    report_path,
    run_cmd,
    working_dir,
    write_json,
    write_text,
)
from modules.artifacts import finalize_artifact_manifest, verify_artifact_manifest, assessment_verification_summary
from modules.tool_detection import detect_tools
from modules.snapshot import collect_snapshot, configure_progress, merge_tracked_paths
from modules.installer_analysis import analyze_installer, discover_installer_paths
from modules.install_changes import compare_snapshots
from modules.permissions import review_permissions
from modules.elf_analysis import analyze_elf
from modules.services import review_services
from modules.persistence import review_persistence
from modules.network import review_network
from modules.ipc import review_ipc, update_ipc_with_runtime
from modules.storage import review_storage
from modules.update_review import review_updates
from modules.application_profile import profile_application, load_machine_profile
from modules.runtime import write_runtime_guidance
from modules.runtime_observation import collect_runtime_observation, MAX_OBSERVATION_SECONDS
from modules.findings import generate_findings, refresh_findings_dispositions
from modules.assessment_coverage import generate_assessment_coverage, refresh_assessment_coverage
from modules.consolidated_report import generate_consolidated_report, refresh_consolidated_report
from modules.coverage_limits import apply_coverage_attention, append_coverage_notes, detect_application_file_coverage_gaps, enrich_analysis_roots, load_post_snapshot
from modules.privileged_review import collect_protected_application_roots, restore_assessment_ownership
from modules.state_guard import assessment_lock
from modules.client_appendix import create_client_appendix
from modules.tester_review import generate_tester_review, load_review_state, merge_additional_review_items, refresh_review_reports, update_review_item, category_progress, review_category, review_group, shared_validation_for
from modules.app_scope import infer_debian_application_scope, discover_runtime_roots
from modules.validation_guidance import playbook_for, render_playbook_lines
from modules.security_model import build_security_model, merge_runtime_security_model, synchronize_security_model
from modules.application_service import UbuntuClientAssessService
from modules.web_gui import DEFAULT_GUI_PORT, run_gui, validate_gui_port

console = Console()
service = UbuntuClientAssessService()
_ACTIVE_RUN: tuple[Path, dict] | None = None
_MODULE_TIMINGS: dict[str, float] = {}


def _set_run_state(
    metadata_path: Path,
    metadata: dict,
    stage: str,
    status: str = "running",
    detail: str = "",
) -> None:
    global _ACTIVE_RUN
    previous = metadata.get("run_state") if isinstance(metadata.get("run_state"), dict) else {}
    state = {
        "status": status,
        "stage": stage,
        "started_at": previous.get("started_at") or now_iso(),
        "updated_at": now_iso(),
    }
    if detail:
        state["detail"] = detail
    metadata["run_state"] = state
    write_json(metadata_path, metadata)
    _ACTIVE_RUN = (metadata_path, metadata)


def _mark_active_run_interrupted() -> None:
    if _ACTIVE_RUN is None:
        return
    metadata_path, metadata = _ACTIVE_RUN
    installation = metadata.get("installation")
    if isinstance(installation, dict) and installation.get("status") == "in-progress":
        installation["status"] = "interrupted"
        installation["confirmed"] = False
    stage = str((metadata.get("run_state") or {}).get("stage") or "unknown")
    try:
        _set_run_state(metadata_path, metadata, stage, "interrupted", "Execution interrupted by the tester or host")
    except OSError:
        pass
    marker = metadata_path.parent / "working" / "INTERRUPTED_RUN.txt"
    try:
        write_text(
            marker,
            "\n".join([
                "UbuntuClientAssess Interrupted Run",
                "===================================",
                "",
                f"Last recorded stage: {stage}",
                "The final report set is incomplete and must not be treated as current.",
                "Before rerunning a Full Assessment, verify the package state and restore a clean VM baseline if installation may have started.",
                "If both schema-compatible pre/post snapshots already exist, preserve them for troubleshooting before starting another run.",
            ]),
        )
    except OSError:
        pass


def sanitize_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip()
    return cleaned or "UbuntuClientAssess"


def banner() -> None:
    console.print(
        Panel.fit(
            f"[bold]UbuntuClientAssess v{VERSION}[/bold]\nUbuntu Thick Client Assessment Framework",
            border_style="cyan",
        )
    )


def _expand_path(value: str) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(value.strip()))
    return Path(expanded).resolve()


def _is_excluded_path(path: Path, excluded_paths: list[Path]) -> bool:
    return any(path == excluded or excluded in path.parents for excluded in excluded_paths)


def _home_top_level_entries(excluded_paths: list[Path]) -> set[Path]:
    """Return current direct home children for low-noise application-data discovery."""
    home = get_interactive_home()
    try:
        return {
            path.absolute()
            for path in home.iterdir()
            if not _is_excluded_path(path.absolute(), excluded_paths)
        }
    except OSError:
        return set()


def ask_path(
    label: str,
    default: str | None = None,
    *,
    only_directories: bool = False,
    allow_blank: bool = False,
    must_exist: bool = False,
    must_be_file: bool = False,
) -> Path | None:
    completer = PathCompleter(expanduser=True, only_directories=only_directories)

    while True:
        suffix = f" [{default}]" if default else ""
        blank_hint = " (leave blank if unavailable)" if allow_blank else ""
        value = toolkit_prompt(
            f"{label}{blank_hint}{suffix}: ",
            completer=completer,
            complete_while_typing=False,
        ).strip()

        if not value:
            if default:
                value = default
            elif allow_blank:
                return None
            else:
                console.print("[yellow][!] A path is required. Press Tab to browse available paths.[/yellow]")
                continue

        path = _expand_path(value)

        if must_exist and not path.exists():
            console.print(f"[yellow][!] Path does not exist:[/yellow] {path}")
            console.print("    Re-enter the path or use Tab completion to select it.")
            continue

        if must_be_file and path.exists() and not path.is_file():
            console.print(f"[yellow][!] Expected a file but received:[/yellow] {path}")
            continue

        if only_directories and path.exists() and not path.is_dir():
            console.print(f"[yellow][!] Expected a directory but received:[/yellow] {path}")
            continue

        return path


def confirm_deb_installation() -> bool:
    return Confirm.ask("Install this .deb now?", default=True)


def install_deb(installer: Path) -> int:
    console.print(f"\n[cyan][+] Installing Debian package:[/cyan] {installer}")
    proc = subprocess.run(["sudo", "apt", "install", "-y", str(installer)])
    return proc.returncode


def deb_package_state(installer: Path) -> dict[str, str | bool | None] | None:
    if not installer.name.lower().endswith(".deb"):
        return None
    package_result = run_cmd(["dpkg-deb", "-f", str(installer), "Package"])
    version_result = run_cmd(["dpkg-deb", "-f", str(installer), "Version"])
    package = package_result["stdout"].strip()
    installer_version = version_result["stdout"].strip()
    if package_result["returncode"] != 0 or not package:
        return None
    installed_result = run_cmd(["dpkg-query", "-W", "-f=${Status}\t${Version}", package])
    dpkg_present = installed_result["returncode"] == 0
    status_text, _, recorded_version = installed_result["stdout"].partition("\t")
    installed = dpkg_present and status_text == "install ok installed"
    return {
        "package": package,
        "installer_version": installer_version or None,
        "dpkg_present": dpkg_present,
        "dpkg_status": status_text.strip() if dpkg_present else None,
        "installed": installed,
        "installed_version": recorded_version.strip() if dpkg_present and recorded_version else None,
    }


def deb_installation_complete(state: dict[str, str | bool | None] | None) -> bool:
    if not state or not state.get("installed"):
        return False
    expected = str(state.get("installer_version") or "").strip()
    observed = str(state.get("installed_version") or "").strip()
    if expected or observed:
        return bool(expected and observed and expected == observed)
    return True


def deb_installation_verification_detail(state: dict[str, str | bool | None] | None) -> str:
    if not state or not state.get("installed"):
        return "Package is not installed after the installation workflow"
    expected = str(state.get("installer_version") or "unknown")
    observed = str(state.get("installed_version") or "unknown")
    if expected != observed:
        return f"Installed package version does not match selected installer (expected {expected}, observed {observed})"
    return "Package/version verification failed"


def _contains_shell_control(template: str) -> bool:
    # Custom workflow commands are intentionally executed without a shell.
    # Requiring separate steps avoids hidden behavior in &&, pipes, redirects,
    # command substitution, or semicolon-separated command strings.
    return bool(re.search(r"(?:&&|\|\||[;|<>]|`|\$\()", template))


SENSITIVE_WORKFLOW_COMMAND_RE = re.compile(
    r"(?i)(?:password|passwd|secret|credential|token|auth(?:orization)?[_-]?code|api[_-]?key|apikey)"
)


def _redact_workflow_display_tokens(tokens: list[str]) -> str:
    """Render workflow argv without persisting obvious secret-bearing positional values."""
    shown = list(tokens)
    sensitive_command_index = None
    for index, token in enumerate(shown):
        try:
            name = Path(token).name
        except Exception:
            name = token
        if SENSITIVE_WORKFLOW_COMMAND_RE.search(name):
            sensitive_command_index = index
            break
    if sensitive_command_index is not None:
        # Scripts/helpers whose own name declares a credential/token operation
        # commonly accept the value as an unlabeled positional argument. Mask
        # positional values after the helper name in addition to key-based redaction.
        for index in range(sensitive_command_index + 1, len(shown)):
            if not shown[index].startswith("-"):
                shown[index] = "[REDACTED]"
    return redact_sensitive_text(shlex.join(shown))


def _display_template(template: str, installer: Path) -> str:
    rendered = template.replace("{INSTALLER}", str(installer)).replace("{SECRET}", "[REDACTED]")
    try:
        return _redact_workflow_display_tokens(shlex.split(rendered))
    except ValueError:
        return redact_sensitive_text(rendered)


def _build_custom_command(template: str, installer: Path) -> tuple[list[str], str]:
    try:
        tokens = shlex.split(template)
    except ValueError as exc:
        raise ValueError(f"Unable to parse command: {exc}") from exc
    if not tokens:
        raise ValueError("Command is empty")

    secret_value: str | None = None
    if any("{SECRET}" in token for token in tokens):
        secret_value = getpass.getpass("Value for {SECRET} (not stored): ")

    argv: list[str] = []
    display_tokens: list[str] = []
    for token in tokens:
        actual = token.replace("{INSTALLER}", str(installer))
        shown = token.replace("{INSTALLER}", str(installer))
        if "{SECRET}" in actual:
            actual = actual.replace("{SECRET}", secret_value or "")
            shown = shown.replace("{SECRET}", "[REDACTED]")
        argv.append(actual)
        display_tokens.append(shown)
    return argv, _redact_workflow_display_tokens(display_tokens)

def collect_custom_workflow(installer: Path) -> list[str]:
    console.print("\n[bold]Custom Installation Workflow[/bold]")
    console.print("Enter vendor/client installation or configuration commands one at a time.")
    console.print("Use [bold]{INSTALLER}[/bold] for the selected package and [bold]{SECRET}[/bold] for a sensitive value that must not be stored.")
    console.print("Enter a blank line when finished. Shell chaining/operators (&&, |, ;, redirects) are not accepted; enter each command as its own step.\n")
    commands: list[str] = []
    index = 1
    while True:
        value = Prompt.ask(f"Command {index}", default="").strip()
        if not value:
            break
        if _contains_shell_control(value):
            console.print("[yellow][!] Enter each command as a separate step; shell chaining, pipes, and redirection are intentionally disabled.[/yellow]")
            continue
        try:
            shlex.split(value)
        except ValueError as exc:
            console.print(f"[yellow][!] Invalid command quoting: {exc}[/yellow]")
            continue
        commands.append(value)
        index += 1
    return commands


def execute_custom_workflow(installer: Path, commands: list[str]) -> tuple[bool, list[dict[str, object]]]:
    if not commands:
        return False, []
    console.print("\n[bold]Installation Workflow[/bold]")
    for idx, template in enumerate(commands, 1):
        console.print(f"[{idx}] {_display_template(template, installer)}")
    if not Confirm.ask("Execute this workflow?", default=True):
        return False, []

    results: list[dict[str, object]] = []
    all_success = True
    for idx, template in enumerate(commands, 1):
        try:
            argv, display = _build_custom_command(template, installer)
        except ValueError as exc:
            console.print(f"[red][!] Step {idx}: {exc}[/red]")
            results.append({"step": idx, "command": _display_template(template, installer), "returncode": 2})
            all_success = False
            break
        console.print(f"\n[cyan][{idx}/{len(commands)}][/cyan] {display}")
        try:
            proc = subprocess.run(argv)
            rc = proc.returncode
        except FileNotFoundError:
            rc = 127
        results.append({"step": idx, "command": display, "returncode": rc})
        if rc == 0:
            console.print("[green]    Result: SUCCESS[/green]")
            continue
        all_success = False
        console.print(f"[red]    Result: FAILED (exit code {rc})[/red]")
        if not Confirm.ask("Continue with remaining workflow commands?", default=False):
            break
    return all_success, results


def record_status(status: dict[str, tuple[str, str]], name: str, state: str, detail: str = "") -> None:
    status[name] = (state, detail)


def write_module_status(output_dir: Path, status: dict[str, tuple[str, str]]) -> None:
    lines = [
        "UbuntuClientAssess Module Status", "=" * 32, "",
        "PASS means the module completed without an internal error. WARN means a recoverable module error reduced coverage. ATTN identifies a manual validation/coverage limitation. FAIL means the assessment cannot be trusted/finalized.", "",
    ]
    for name, (state, detail) in status.items():
        suffix = f" - {detail}" if detail else ""
        timing = f" ({_MODULE_TIMINGS[name]:.2f}s)" if name in _MODULE_TIMINGS else ""
        lines.append(f"[{state:<7}] {name}{timing}{suffix}")
    write_text(report_path(output_dir, "module_status.txt"), "\n".join(lines))


def run_module(status: dict[str, tuple[str, str]], name: str, fn: Callable, *args, **kwargs):
    started = time.monotonic()
    try:
        if console.is_terminal:
            with console.status(f"[cyan]{name}...[/cyan]"):
                result = fn(*args, **kwargs)
        else:
            result = fn(*args, **kwargs)
        elapsed = time.monotonic() - started
        _MODULE_TIMINGS[name] = round(elapsed, 3)
        record_status(status, name, "PASS")
        console.print(f"[green]✓[/green] {name} [dim]({elapsed:.1f}s)[/dim]")
        return result
    except Exception as exc:
        _MODULE_TIMINGS[name] = round(time.monotonic() - started, 3)
        record_status(status, name, "WARN", str(exc))
        console.print(f"[yellow][!] {name}: {exc}[/yellow]")
        return None


def _print_timing_summary() -> None:
    if not _MODULE_TIMINGS:
        return
    total = sum(_MODULE_TIMINGS.values())
    console.print("\n[bold]Assessment Processing Timing[/bold]")
    console.print(f"Framework processing time (module sum): {total:.1f}s")
    slow = sorted(_MODULE_TIMINGS.items(), key=lambda item: item[1], reverse=True)[:5]
    for name, seconds in slow:
        console.print(f"  {name:<34} {seconds:>7.2f}s")
    console.print("[dim]Tester interaction, installation, sign-in, and manual wait time are not represented by the module sum.[/dim]")


def finalize_assessment(
    output_dir: Path,
    mode: str,
    metadata_path: Path,
    metadata: dict,
    status: dict[str, tuple[str, str]],
) -> bool:
    """Freeze the final report set and only mark the run complete after verification succeeds."""
    record_status(status, "Artifact Inventory", "PASS")
    write_module_status(output_dir, status)
    _set_run_state(metadata_path, metadata, "artifact-finalization", "running")
    try:
        generate_consolidated_report(
            output_dir,
            str(metadata.get("assessment_name") or output_dir.name),
            metadata.get("installer"),
            mode,
            VERSION,
            status,
        )
        finalize_artifact_manifest(output_dir, mode)
        issues = verify_artifact_manifest(output_dir)
        if issues:
            raise RuntimeError("; ".join(issues))

        # Artifact generation and its first integrity verification have succeeded.
        # Persist the final run state, then refresh the manifest so its metadata
        # hash reflects the completed state and verify once more.
        _set_run_state(metadata_path, metadata, "complete", "completed")
        finalize_artifact_manifest(output_dir, mode)
        issues = verify_artifact_manifest(output_dir)
        if issues:
            raise RuntimeError("; ".join(issues))
        return True
    except Exception as exc:
        record_status(status, "Artifact Inventory", "FAIL", str(exc))
        write_module_status(output_dir, status)
        _set_run_state(metadata_path, metadata, "artifact-finalization", "failed", str(exc))
        console.print(f"[red][!] Artifact finalization failed:[/red] {exc}")
        return False


def post_analysis(
    output_dir: Path,
    application_path: str | None,
    analysis_roots: list[Path] | None,
    status: dict[str, tuple[str, str]],
    installer_data: dict | None = None,
    metadata: dict | None = None,
) -> bool:
    analysis_roots = analysis_roots or []
    pre = working_dir(output_dir) / "snapshot_pre.json"
    post = working_dir(output_dir) / "snapshot_post.json"
    if not pre.exists() or not post.exists():
        record_status(status, "Installation Differential", "FAIL", "Required pre/post snapshot not found")
        console.print("[red][!] Required pre/post snapshots were not found; differential analysis cannot continue.[/red]")
        return False

    diff = run_module(status, "Installation Differential", compare_snapshots, pre, post, output_dir)
    if diff is None:
        record_status(status, "Installation Differential", "FAIL", "Snapshot comparison failed")
        return False

    analysis_roots = enrich_analysis_roots(analysis_roots, diff)
    post_scope = infer_debian_application_scope(None, analysis_roots)
    coverage_gaps = detect_application_file_coverage_gaps(load_post_snapshot(output_dir), analysis_roots)
    if metadata is not None:
        metadata["analysis_roots"] = [str(p) for p in analysis_roots]
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
        metadata["application_file_coverage"] = {"limited": bool(coverage_gaps), "gaps": coverage_gaps}
    record_status(status, "Application File Coverage", "ATTN" if coverage_gaps else "PASS", "Static application-file coverage is limited" if coverage_gaps else "Identified application roots were recursively accessible")

    profile_data = run_module(
        status,
        "Application / Framework Profile",
        profile_application,
        output_dir,
        diff,
        installer_data or {},
        analysis_roots,
    ) or {}
    profile_data["coverage_limitations"] = coverage_gaps
    try:
        write_json(working_dir(output_dir) / "application_profile.json", profile_data)
    except Exception:
        pass

    permission_data = run_module(status, "Permissions Review", review_permissions, diff, output_dir) or {}
    elf_data = run_module(status, "ELF Security Review", analyze_elf, diff, output_dir) or {}
    service_data = run_module(status, "systemd Service Review", review_services, diff, output_dir) or {}
    persistence_data = run_module(status, "Persistence Review", review_persistence, diff, output_dir, elf_data) or {}
    if persistence_data.get("review_required"):
        record_status(status, "Persistence Review", "ATTN", f"{len(persistence_data['review_required'])} privileged policy change(s) require manual review")
    network_data = run_module(status, "Network Surface Review", review_network, diff, output_dir, analysis_roots) or {}
    if not network_data.get("new_connections"):
        record_status(status, "Network Surface Review", "ATTN", "No active application connection observed during the configured sampling window")
    ipc_data = run_module(status, "IPC Review", review_ipc, diff, output_dir, analysis_roots) or {}
    storage_data = run_module(status, "Local Storage Review", review_storage, diff, output_dir, analysis_roots) or {}
    update_data = run_module(status, "Update Mechanism Review", review_updates, diff, output_dir, installer_data or {}) or {}
    if any(item.get("status") not in {"VALID"} for item in update_data.get("signature_validations", [])):
        record_status(status, "Update Mechanism Review", "ATTN", "Installer signature was not independently verified")
    run_module(status, "Runtime Guidance", write_runtime_guidance, output_dir, application_path, profile_data)
    run_module(status, "Security Correlation Model", build_security_model, output_dir, permission_data, network_data, service_data, elf_data, ipc_data, storage_data, update_data, persistence_data, profile_data)
    run_module(status, "Tester Review Queue", generate_tester_review, output_dir, permission_data, network_data, service_data, elf_data, ipc_data, storage_data, update_data, persistence_data, profile_data)
    run_module(status, "Findings Generation", generate_findings, output_dir, permission_data, network_data, service_data, elf_data, storage_data, update_data, persistence_data)
    synchronize_security_model(output_dir)
    run_module(status, "Assessment Coverage", generate_assessment_coverage, output_dir, "full", profile_data)
    append_coverage_notes(output_dir, coverage_gaps)
    apply_coverage_attention(status, coverage_gaps)
    return True



def _refresh_review_manifest(assessment_dir: Path) -> None:
    metadata = read_json(assessment_dir / "assessment_metadata.json")
    mode = str(metadata.get("mode") or "")
    if mode != "full":
        raise RuntimeError("Guided review is available only for completed Full Assessments")
    # Review disposition is a first-class assessment state in v1.4.1. Refresh
    # every tester-facing view that depends on it before re-freezing integrity.
    refresh_findings_dispositions(assessment_dir)
    refresh_assessment_coverage(assessment_dir)
    refresh_consolidated_report(assessment_dir)
    finalize_artifact_manifest(assessment_dir, mode)
    issues = verify_artifact_manifest(assessment_dir)
    if issues:
        raise RuntimeError("Assessment verification failed after review update: " + "; ".join(issues))


def run_tester_review(assessment_dir: Path) -> int:
    assessment_dir = assessment_dir.expanduser().resolve()
    review_result = service.review_snapshot(assessment_dir)
    if not review_result.ok:
        console.print(f"[red][!] {review_result.message}:[/red] {assessment_dir}")
        for issue in review_result.errors:
            console.print(f"  - {issue}")
        return 9 if review_result.code == "integrity-failed" else 2
    state = review_result.data["state"]
    review_revision = str(review_result.data.get("revision") or "")
    metadata = read_json(assessment_dir / "assessment_metadata.json")

    current_category: str | None = None
    direct_id: str | None = None
    previous_id: str | None = None

    while True:
        items = list(state.get("items", []))
        if not items:
            console.print("[green]No prioritized review candidates were generated.[/green]")
            return 0
        pending = [item for item in items if item.get("status") == "PENDING"]
        completed = len(items) - len(pending)

        selected = None
        if direct_id:
            selected = next((item for item in items if str(item.get("id")) == direct_id), None)
            direct_id = None

        if selected is None and current_category is None:
            rows = category_progress(items)
            console.print("\n[bold]UbuntuClientAssess Guided Review[/bold]")
            console.print(f"Assessment: [cyan]{metadata.get('assessment_name') or assessment_dir.name}[/cyan]")
            console.print(f"Progress: {completed} / {len(items)} completed | {len(pending)} pending")
            console.print("\n[bold]Review Categories[/bold]")
            for idx, row in enumerate(rows, 1):
                console.print(f"  {idx}) {row['category']:<28} {row['completed']} / {row['total']} complete | {row['pending']} pending")
            console.print("  A) All Review Items")
            console.print("  Q) Quit")
            choice = Prompt.ask("Select category", default="Q").strip()
            if choice.casefold() == "q":
                return 0
            if choice.casefold() == "a":
                current_category = "__ALL__"
                continue
            if choice.isdigit() and 1 <= int(choice) <= len(rows):
                current_category = str(rows[int(choice)-1]["category"])
                continue
            console.print("[yellow][!] Unknown category selection.[/yellow]")
            continue

        if selected is None:
            display = items if current_category == "__ALL__" else [x for x in items if review_category(x) == current_category]
            label = "All Review Items" if current_category == "__ALL__" else str(current_category)
            category_completed = sum(1 for x in display if x.get("status") != "PENDING")
            console.print(f"\n[bold]{label}[/bold]")
            console.print(f"Progress: {category_completed} / {len(display)} complete | {len(display)-category_completed} pending")

            groups: list[str] = []
            for item in display:
                key = str(item.get("review_group") or review_group(item)[0])
                if key not in groups:
                    groups.append(key)
            for key in groups:
                grouped = [x for x in display if str(x.get("review_group") or review_group(x)[0]) == key]
                group_label = str(grouped[0].get("review_group_label") or review_group(grouped[0])[1])
                console.print(f"\n[bold cyan]{group_label}[/bold cyan]")
                for item in grouped:
                    color = "red" if item.get("priority") == "HIGH" else "yellow" if item.get("priority") == "MEDIUM" else "dim"
                    console.print(f"  {item.get('id')}  [{color}]{item.get('priority')}[/{color}]  [{item.get('status')}] {item.get('title')}")
            console.print("\n[dim]Enter a TRQ number/ID, B to return to categories, or Q to quit.[/dim]")
            choice = Prompt.ask("Select review item", default="B").strip()
            folded = choice.casefold()
            if folded == "q":
                return 0
            if folded == "b":
                current_category = None
                continue
            normalized = choice.upper()
            if normalized.isdigit():
                normalized = f"TRQ-{int(normalized):03d}"
            selected = next((item for item in display if str(item.get("id", "")).upper() == normalized), None)
            if selected is None:
                console.print("[yellow][!] Unknown review ID for this category.[/yellow]")
                continue

        previous_id = str(selected.get("id"))
        selected_category = review_category(selected)
        group_key = str(selected.get("review_group") or review_group(selected)[0])
        group_label = str(selected.get("review_group_label") or review_group(selected)[1])
        group_items = [x for x in items if review_category(x) == selected_category and str(x.get("review_group") or review_group(x)[0]) == group_key]
        related_ids = [str(x.get("id")) for x in group_items]
        completed_related = [str(x.get("id")) for x in group_items if x.get("status") != "PENDING" and str(x.get("id")) != previous_id]

        console.print(f"\n[bold]{selected.get('id')} — {selected.get('title')}[/bold]")
        console.print(f"Category: {selected_category} | Group: {group_label}")
        console.print(f"Priority: {selected.get('priority')} | Status: {selected.get('status')}")
        if len(group_items) > 1:
            console.print(f"Related review items: {', '.join(related_ids)}")
            console.print("\n[bold]Shared Validation Context[/bold]")
            for entry in (selected.get("shared_validation") or shared_validation_for(selected)):
                console.print(f"  - {entry}")
            if completed_related:
                console.print(f"[dim]Prior group items completed: {', '.join(completed_related)}. Reuse prior evidence when the underlying context is unchanged.[/dim]")

        console.print(f"\n[bold]Condition[/bold]\n{selected.get('condition')}")
        if selected.get("runtime_confirmed"):
            console.print("\n[bold green]Runtime Confirmation[/bold green]\nYES")
            for observation in (selected.get("runtime_observations") or [])[:10]:
                console.print(f"  - {observation}")
        console.print(f"\n[bold]Why it matters[/bold]\n{selected.get('why_it_matters')}")
        console.print("\n[bold]Detailed Validation Procedure[/bold]")
        for line in render_playbook_lines(playbook_for(selected)):
            console.print(line)
        console.print("[dim]Do not paste passwords, tokens, or other sensitive values into tester notes.[/dim]")
        notes = Prompt.ask("Tester notes", default=str(selected.get("notes") or ""))
        current = str(selected.get("status") or "PENDING")
        default_disp = {"PENDING": "1", "VALIDATED": "2", "NOT APPLICABLE": "3", "INFORMATIONAL": "4"}.get(current, "1")
        console.print("Disposition: 1) PENDING  2) VALIDATED  3) NOT APPLICABLE  4) INFORMATIONAL  5) Cancel")
        disp = Prompt.ask("Selection", choices=["1", "2", "3", "4", "5"], default=default_disp)
        if disp == "5":
            continue
        status_value = {"1": "PENDING", "2": "VALIDATED", "3": "NOT APPLICABLE", "4": "INFORMATIONAL"}[disp]
        save_result = service.save_review_item(
            assessment_dir, str(selected["identity"]), status=status_value, notes=notes,
            expected_revision=review_revision or None,
        )
        if not save_result.ok:
            console.print(f"[red][!] {save_result.message}[/red]")
            for issue in save_result.errors:
                console.print(f"  - {issue}")
            return 8
        state = save_result.data["state"]
        review_revision = str(save_result.data.get("revision") or review_revision)
        console.print(f"[green]✓ {selected.get('id')} saved as {status_value} and assessment manifest refreshed.[/green]")
        # Keep the compact CLI counters derived from the service-returned state.
        # The service is authoritative for the write/regeneration transaction;
        # these local calculations are presentation only.
        fresh_items = list(state.get("items", []))
        remaining = sum(1 for item in fresh_items if item.get("status") == "PENDING")
        done = len(fresh_items) - remaining
        category_items = [x for x in fresh_items if review_category(x) == selected_category]
        category_done = sum(1 for x in category_items if x.get("status") != "PENDING")
        completed = done
        console.print(f"[dim]Review progress: {completed} / {len(fresh_items)} completed | {remaining} pending[/dim]")
        console.print(f"[dim]{selected_category}: {category_done} / {len(category_items)} completed | {len(category_items)-category_done} pending[/dim]")

        next_label = "Save & Next Pending" if current_category == "__ALL__" else "Save & Next Pending in Category"
        console.print(f"1) {next_label}  2) Previous Item  3) Return to Category  4) Quit")
        after = Prompt.ask("Next action", choices=["1", "2", "3", "4"], default="1")
        if after == "4":
            return 0
        if after == "2":
            display = list(state.get("items", [])) if current_category == "__ALL__" else [x for x in state.get("items", []) if review_category(x) == selected_category]
            ids = [str(x.get("id")) for x in display]
            try:
                idx = ids.index(previous_id)
                direct_id = ids[max(0, idx - 1)]
            except ValueError:
                direct_id = None
            continue
        if after == "3":
            continue

        fresh = list(state.get("items", []))
        scope = fresh if current_category == "__ALL__" else [x for x in fresh if review_category(x) == selected_category]
        ids = [str(x.get("id")) for x in scope]
        try:
            idx = ids.index(previous_id)
        except ValueError:
            idx = -1
        next_pending = next((x for x in scope[idx + 1:] + scope[:idx + 1] if x.get("status") == "PENDING"), None)
        if next_pending:
            direct_id = str(next_pending.get("id"))
        else:
            console.print(f"[green]✓ No pending items remain in {selected_category}.[/green]")
            current_category = None



def _runtime_application_context(assessment_dir: Path, metadata: dict) -> tuple[list[str], list[Path]]:
    hints: list[str] = []
    roots: list[Path] = []
    for key in ("application_path", "application_root"):
        value = str(metadata.get(key) or "").strip()
        if value:
            hints.append(value)

    for key in ("application_roots", "analysis_roots", "application_runtime_roots", "data_roots"):
        for value in metadata.get(key, []) or []:
            path = Path(str(value)).expanduser().resolve(strict=False)
            if path.exists() and path not in roots:
                roots.append(path)

    # Expected application-specific runtime/user-data roots are useful even
    # when they do not exist at observation start: the before/after collector
    # can then record their creation during the exercised workflow.
    for value in metadata.get("expected_runtime_roots", []) or []:
        path = Path(str(value)).expanduser().resolve(strict=False)
        if path not in roots:
            roots.append(path)

    application_root = str(metadata.get("application_root") or "").strip()
    if application_root:
        root = Path(application_root).expanduser().resolve(strict=False)
        if root.exists() and root not in roots:
            roots.append(root)

    application_path = str(metadata.get("application_path") or "").strip()
    if application_path:
        app = Path(application_path).expanduser().resolve(strict=False)
        if app.parent.exists() and str(app.parent) not in {"/usr/bin", "/usr/sbin", "/bin", "/sbin"} and app.parent not in roots:
            roots.append(app.parent)

    scope = metadata.get("application_scope") if isinstance(metadata.get("application_scope"), dict) else {}
    for path in discover_runtime_roots(scope, existing_only=True):
        if path not in roots:
            roots.append(path)

    return sorted(set(hints)), sorted(set(roots), key=str)


def run_runtime_observation(assessment_dir: Path, duration_seconds: float = 0.0, *, non_interactive: bool = False) -> int:
    assessment_dir = assessment_dir.expanduser().resolve()
    verification = service.verify_assessment(assessment_dir)
    if not verification.ok:
        console.print(f"[red][!] {verification.message}:[/red] {assessment_dir}")
        for issue in verification.errors:
            console.print(f"  - {issue}")
        return 9
    runtime_base_revision = str(verification.data.get("revision") or "")
    try:
        metadata = read_json(assessment_dir / "assessment_metadata.json")
    except Exception as exc:
        console.print(f"[red][!] Assessment metadata could not be read:[/red] {exc}")
        return 2
    if str(metadata.get("mode") or "") != "full":
        console.print("[red][!] Guided runtime observation is available only for completed Full Assessments.[/red]")
        return 2
    if duration_seconds < 0 or duration_seconds > MAX_OBSERVATION_SECONDS:
        console.print(f"[red][!] --runtime-observe-seconds must be between 0 and {int(MAX_OBSERVATION_SECONDS)}.[/red]")
        return 2
    if non_interactive and duration_seconds <= 0:
        console.print("[red][!] Non-interactive runtime observation requires --runtime-observe-seconds greater than 0.[/red]")
        return 2

    profile_data = load_machine_profile(assessment_dir)
    hints, roots = _runtime_application_context(assessment_dir, metadata)

    # v1.4 can enrich older completed assessments by re-inferring the package scope.
    if not hints and metadata.get("installer"):
        installer = Path(str(metadata.get("installer"))).expanduser().resolve(strict=False)
        declared = discover_installer_paths(installer) if installer.is_file() else []
        inferred = infer_debian_application_scope(installer if installer.is_file() else None, declared)
        if inferred.get("application_root"):
            metadata["application_root"] = inferred["application_root"]
        if inferred.get("application_path"):
            metadata["application_path"] = inferred["application_path"]
        metadata["application_scope"] = inferred
        metadata["application_roots"] = inferred.get("application_roots", [])
        hints, roots = _runtime_application_context(assessment_dir, metadata)

    if not hints and not non_interactive:
        console.print("[yellow][!] UbuntuClientAssess could not automatically identify the installed application root.[/yellow]")
        console.print("Enter the installed application's executable or installation directory.")
        console.print("[dim]Examples: /opt/vendor/client, /opt/vendor, /usr/bin/vendor-client[/dim]")
        console.print("[dim]Do not enter the UbuntuClientAssess assessment directory.[/dim]")
        while True:
            selected = ask_path("Installed application executable/root", allow_blank=True, must_exist=True)
            if selected is None:
                break
            selected = selected.resolve(strict=False)
            if selected == assessment_dir or assessment_dir in selected.parents:
                console.print("[yellow][!] That path is the UbuntuClientAssess assessment directory, not the installed application.[/yellow]")
                continue
            hints.append(str(selected))
            if selected.is_dir():
                roots.append(selected)
                metadata["application_root"] = str(selected)
            else:
                metadata["application_path"] = str(selected)
                if str(selected.parent) not in {"/usr/bin", "/usr/sbin", "/bin", "/sbin"}:
                    roots.append(selected.parent)
            break

    # Runtime context is kept in memory during collection and committed by the
    # application service together with runtime evidence. This avoids changing
    # authoritative state before stale-write/locking checks run.

    console.print("\n[bold]Guided Runtime Observation[/bold]")
    console.print(f"Assessment: [cyan]{metadata.get('assessment_name') or assessment_dir.name}[/cyan]")
    console.print(f"Primary technology: [cyan]{profile_data.get('primary_technology') or 'not confidently identified'}[/cyan]")
    console.print(f"Correlation hints: {', '.join(hints) if hints else 'none; activity will be collected but may remain unattributed'}")
    if roots:
        console.print(f"Filesystem roots monitored: {', '.join(str(path) for path in roots)}")
    else:
        console.print("Filesystem roots monitored: none (process/network/IPC observation only)")
    console.print("[dim]UbuntuClientAssess will not launch the application or invoke D-Bus/IPC methods automatically.[/dim]")
    console.print("\n[bold]Recommended Application Exercise[/bold]")
    for label in ("Launch/close the application", "Authentication or session workflow", "Network-dependent features", "Privileged/helper actions", "File/configuration changes", "Update functionality if in scope"):
        console.print(f"[ ] {label}")

    elevated_visibility = False
    if shutil.which("sudo"):
        if non_interactive:
            elevated_visibility = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        elif Confirm.ask("Use sudo for read-only process/socket ownership correlation?", default=True):
            elevated_visibility = subprocess.run(["sudo", "-v"]).returncode == 0
            if not elevated_visibility:
                console.print("[yellow][!] Continuing without elevated endpoint ownership visibility.[/yellow]")

    observed_flags: set[str] = set()
    def _progress(data: dict) -> None:
        checks = [
            ("process", bool(data.get("application_processes")), "Application process identified"),
            ("privileged", int(data.get("privileged_process_count", 0)) > 0, "Privileged application/service process identified"),
            ("connection", bool(data.get("connections")), "Active/recent network connection observed"),
            ("listener", bool(data.get("listeners")), "Listening network socket observed"),
            ("unix", bool(data.get("unix_sockets")), "Unix-domain socket observed"),
            ("fifo", bool(data.get("fifo_paths")), "Application FIFO detected"),
            ("file", any((data.get("file_activity") or {}).get(key) for key in ("created", "modified", "deleted")), "Application file activity observed"),
        ]
        for key, present, label in checks:
            if present and key not in observed_flags:
                observed_flags.add(key)
                console.print(f"[green][✓][/green] {label}")

    wait_for_stop = None
    if duration_seconds > 0:
        console.print(f"[green][+] Capturing for {duration_seconds:g} seconds. Exercise the application now.[/green]")
    else:
        console.print("[green][+] Start/exercise the application now. Press Enter when the workflow is complete.[/green]")
        def _wait() -> None:
            Prompt.ask("Press Enter to stop observation", default="")
        wait_for_stop = _wait

    try:
        observation = collect_runtime_observation(
            assessment_dir, application_hints=hints, filesystem_roots=roots,
            duration_seconds=duration_seconds if duration_seconds > 0 else None, wait_for_stop=wait_for_stop,
            elevated_visibility=elevated_visibility, progress_callback=_progress, persist=False,
        )
    except Exception as exc:
        console.print(f"[red][!] Runtime observation collection failed:[/red] {exc}")
        return 8

    runtime_context = {
        key: metadata.get(key) for key in (
            "application_path", "application_root", "application_scope", "application_roots",
            "analysis_roots", "data_roots", "expected_runtime_roots",
        ) if key in metadata
    }
    runtime_result = service.finalize_runtime_observation(
        assessment_dir, observation, profile_data, application_path=metadata.get("application_path"),
        metadata_updates=runtime_context, expected_revision=runtime_base_revision or None,
    )
    if not runtime_result.ok:
        console.print(f"[red][!] {runtime_result.message}:[/red] {'; '.join(runtime_result.errors)}")
        return 8

    summary = runtime_result.data
    console.print("\n[green][+] Runtime observation saved and assessment manifest refreshed.[/green]")
    console.print(f"Samples: {summary['sample_count']} | App processes: {summary['application_process_count']} | Connections: {summary['connection_count']} | Unix sockets: {summary['unix_socket_count']} | FIFOs: {summary['fifo_count']}")
    console.print(f"Pending tester review items: {summary['pending_review_items']}")
    console.print("[dim]Updated: runtime_review.txt, ipc_review.txt, tester_review.txt, evidence_guide.txt, findings.txt, assessment_coverage.txt, assessment_report.html[/dim]")
    if summary.get("client_appendix_stale"):
        console.print("[yellow][!] ClientAppendix already exists and may now be stale. Recreate it after completing the updated review queue.[/yellow]")
    return 0


REPAIRABLE_GENERATED_REPORTS = {
    "findings.txt", "findings_summary.txt", "tester_review.txt", "evidence_guide.txt",
    "assessment_coverage.txt", "assessment_report.html", "artifact_manifest.txt",
}


def _generated_report_repair_status(assessment_dir: Path) -> dict:
    return service.generated_report_repair_status(assessment_dir)

def _repair_generated_reports(assessment_dir: Path) -> int:
    result = service.repair_generated_reports(assessment_dir)
    if not result.ok:
        console.print(f"[red][!] {result.message}[/red]")
        for issue in result.errors:
            console.print(f"  - {issue}")
        return 12
    console.print("[green][+] Generated tester reports regenerated from trusted internal state.[/green]")
    for name in sorted(result.data.get("modified", [])):
        console.print(f"  - {name}")
    console.print("[green][+] Assessment manifest refreshed and integrity verification passed.[/green]")
    return 0

def _assessment_recovery_info(assessment_dir: Path) -> dict:
    return service.assessment_status(assessment_dir).data

def _print_assessment_status(assessment_dir: Path) -> int:
    info = _assessment_recovery_info(assessment_dir)
    metadata = info.get("metadata") or {}
    console.print("\n[bold]Assessment Status / Recovery[/bold]")
    console.print(f"Assessment: {metadata.get('assessment_name') or Path(info['assessment']).name}")
    console.print(f"Status: [cyan]{info.get('status')}[/cyan]")
    console.print(f"Last stage: {(metadata.get('run_state') or {}).get('stage', 'unknown')}")
    console.print(f"Pre-install snapshot:  {'✓' if info.get('pre') else '✗'}")
    console.print(f"Post-install snapshot: {'✓' if info.get('post') else '✗'}")
    console.print(f"Installation state:    {info.get('installation_status', 'unknown')}")
    if info.get('detail'):
        console.print(f"Guidance: {info['detail']}")
    action = info.get('action')
    if action == 'post-analysis':
        console.print("[green]Safe recovery point: rerun post-analysis/finalization with --resume-assessment.[/green]")
    elif action == 'repair-generated':
        modified = ", ".join((info.get("repair") or {}).get("modified", []))
        console.print(f"[yellow]Generated tester report(s) were modified outside UbuntuClientAssess: {modified or 'derived report'}.[/yellow]")
        console.print("[green]Safe recovery is available: regenerate derived reports from trusted internal review/candidate state.[/green]")
    elif action == 'recover-transaction':
        tx = info.get("transaction") or {}
        console.print(f"[yellow]Interrupted write detected: {tx.get('operation', 'unknown operation')}.[/yellow]")
        console.print(f"[green]Safe rollback is available with --recover-interrupted-operation {assessment_dir}.[/green]")
    elif action == 'reset':
        console.print("[yellow]Revert the disposable Ubuntu VM to its clean snapshot and restart the assessment. Do not blindly resume.[/yellow]")
    elif action == 'restart':
        console.print("[yellow]Restart the assessment from a known-good VM baseline.[/yellow]")
    return 0


def _resume_assessment(assessment_dir: Path) -> int:
    assessment_dir = assessment_dir.expanduser().resolve()
    info = _assessment_recovery_info(assessment_dir)
    if info.get('status') == 'COMPLETED':
        console.print("[green][+] Assessment is already completed.[/green]")
        return _run_assessment_verification(assessment_dir)
    if info.get('action') != 'post-analysis':
        _print_assessment_status(assessment_dir)
        return 11
    metadata = info.get('metadata') or {}
    if str(metadata.get('mode') or '') != 'full':
        console.print("[red][!] Resume currently supports Full Assessment post-analysis recovery only.[/red]")
        return 2
    metadata_path = assessment_dir / 'assessment_metadata.json'
    _set_run_state(metadata_path, metadata, 'recovery-post-analysis', 'running', 'v1.4 safe post-analysis recovery')
    status: dict[str, tuple[str, str]] = {}
    # Revalidate tool availability and regenerate installer analysis if the installer remains available.
    _, ready = run_module(status, 'Tool Detection', detect_tools, assessment_dir) or ({}, False)
    if not ready:
        record_status(status, 'Tool Detection', 'FAIL', 'Required tools missing during recovery')
        write_module_status(assessment_dir, status)
        return 3
    installer_data: dict = {}
    installer_text = str(metadata.get('installer') or '')
    installer = Path(installer_text).expanduser().resolve(strict=False) if installer_text else None
    if installer and installer.is_file():
        installer_data = run_module(status, 'Installer Analysis', analyze_installer, installer, assessment_dir, False) or {}
    else:
        record_status(status, 'Installer Analysis', 'SKIPPED', 'Recorded installer is unavailable; retaining prior package context')
    record_status(status, 'Pre-Installation Snapshot', 'PASS', 'Existing recovery checkpoint')
    record_status(status, 'Installation / Configuration', 'PASS', 'Existing recovery checkpoint')
    record_status(status, 'Post-Installation Snapshot', 'PASS', 'Existing recovery checkpoint')
    roots = [Path(str(x)).expanduser().resolve(strict=False) for x in (metadata.get('analysis_roots') or metadata.get('application_roots') or metadata.get('data_roots') or [])]
    if metadata.get('application_root'):
        roots.append(Path(str(metadata['application_root'])).expanduser().resolve(strict=False))
    roots = sorted(set(roots), key=str)
    ok = post_analysis(assessment_dir, metadata.get('application_path'), roots, status, installer_data)
    metadata['module_timings_seconds'] = dict(_MODULE_TIMINGS)
    write_module_status(assessment_dir, status)
    if not ok or any(state == 'FAIL' for state, _ in status.values()):
        _set_run_state(metadata_path, metadata, 'recovery-post-analysis', 'failed', 'Recovery post-analysis failed')
        return 7
    if not finalize_assessment(assessment_dir, 'full', metadata_path, metadata, status):
        return 8
    console.print("[green][+] Assessment recovery completed and integrity manifest refreshed.[/green]")
    _print_timing_summary()
    return 0



def _run_privileged_static_review(assessment_dir: Path) -> int:
    assessment_dir = assessment_dir.expanduser().resolve()
    if os.geteuid() != 0:
        console.print("[red][!] Privileged static review must be launched through sudo/root authentication.[/red]")
        return 13
    if not (assessment_dir / "assessment_metadata.json").is_file():
        console.print("[red][!] Assessment metadata is missing.[/red]")
        return 2
    original = assessment_dir.stat()
    prior_review_items: list[dict] = []
    try:
        with assessment_lock(assessment_dir, "privileged static review", exclusive=True):
            review_path = working_dir(assessment_dir) / "tester_review_state.json"
            if review_path.is_file():
                prior_review_items = list((load_review_state(assessment_dir).get("items") or []))
            collection = collect_protected_application_roots(assessment_dir)
            console.print(f"[green][+] Privileged collection completed:[/green] {collection['objects_collected']} object(s) from {len(collection['roots'])} protected root(s)")
            metadata_path = assessment_dir / "assessment_metadata.json"
            metadata = read_json(metadata_path)
            status: dict[str, tuple[str, str]] = {}
            _, ready = run_module(status, "Tool Detection", detect_tools, assessment_dir) or ({}, False)
            if not ready:
                record_status(status, "Tool Detection", "FAIL", "One or more required tools are missing")
                write_module_status(assessment_dir, status)
                return 3
            installer_data: dict = {}
            installer_text = str(metadata.get("installer") or "")
            installer = Path(installer_text).expanduser().resolve(strict=False) if installer_text else None
            if installer and installer.is_file():
                installer_data = run_module(status, "Installer Analysis", analyze_installer, installer, assessment_dir, False) or {}
            else:
                record_status(status, "Installer Analysis", "SKIPPED", "Recorded installer is unavailable; retaining installed-application evidence")
            record_status(status, "Pre-Installation Snapshot", "PASS", "Existing assessment checkpoint")
            record_status(status, "Installation / Configuration", "PASS", "Existing assessment checkpoint")
            record_status(status, "Post-Installation Snapshot", "PASS", "Augmented by targeted privileged static collection")
            roots = [Path(str(x)).expanduser().resolve(strict=False) for x in (metadata.get("analysis_roots") or metadata.get("application_roots") or [])]
            if metadata.get("application_root"):
                roots.append(Path(str(metadata["application_root"])).expanduser().resolve(strict=False))
            roots = sorted(set(roots), key=str)
            if not post_analysis(assessment_dir, metadata.get("application_path"), roots, status, installer_data, metadata):
                write_module_status(assessment_dir, status)
                return 7
            # Preserve dispositions/notes for review identities that remain present
            # after privileged evidence expands the analysis. Newly discovered items
            # remain PENDING and must still be reviewed by the tester.
            if prior_review_items:
                current = load_review_state(assessment_dir)
                current_ids = {str(x.get("identity") or "") for x in (current.get("items") or [])}
                for item in prior_review_items:
                    identity = str(item.get("identity") or "")
                    if not identity or identity not in current_ids:
                        continue
                    update_review_item(
                        assessment_dir, identity,
                        status=str(item.get("status") or "PENDING"),
                        notes=str(item.get("notes") or item.get("tester_notes") or ""),
                    )
                refresh_findings_dispositions(assessment_dir)
                refresh_assessment_coverage(assessment_dir)
                refresh_consolidated_report(assessment_dir)
            metadata["privileged_static_review"] = {
                "completed_at": now_iso(),
                "roots": collection["roots"],
                "objects_collected": collection["objects_collected"],
                "remaining_collection_gaps": collection["remaining_collection_gaps"],
            }
            write_module_status(assessment_dir, status)
            if not finalize_assessment(assessment_dir, "full", metadata_path, metadata, status):
                return 8
            console.print("[green][+] Privileged static review completed and affected analyses were regenerated.[/green]")
            return 0
    finally:
        uid = int(os.environ.get("SUDO_UID", original.st_uid))
        gid = int(os.environ.get("SUDO_GID", original.st_gid))
        restore_assessment_ownership(assessment_dir, uid, gid)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"UbuntuClientAssess v{VERSION}")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION} (methodology {METHODOLOGY_VERSION}, coverage catalog {TEST_CASE_CATALOG_VERSION})")
    parser.add_argument("--gui", action="store_true", help=f"Start the localhost web interface (default port: {DEFAULT_GUI_PORT})")
    parser.add_argument("--port", type=int, default=DEFAULT_GUI_PORT, metavar="PORT", help=f"Web interface port used with --gui (default: {DEFAULT_GUI_PORT})")
    parser.add_argument("--gui-root", metavar="PATH", help="Initial assessment root shown by the web interface (default: ./Assessments)")
    parser.add_argument("--no-browser", action="store_true", help="With --gui, do not automatically open the local web interface in a browser")
    parser.add_argument("--verify-assessment", metavar="PATH", help="Verify a finalized assessment report set and recorded integrity hashes without changing it")
    parser.add_argument("--create-client-appendix", metavar="PATH", help="Verify a completed assessment and refresh ClientAppendix/ with approved client-facing technical artifacts")
    parser.add_argument("--review", metavar="PATH", help="Open the guided tester review queue for a completed Full Assessment")
    parser.add_argument("--runtime-observe", metavar="PATH", help="Run a tester-controlled post-assessment runtime observation and correlate processes, network activity, local IPC, and scoped file changes")
    parser.add_argument("--assessment-status", metavar="PATH", help="Show phase/recovery status for an existing assessment without changing it")
    parser.add_argument("--resume-assessment", metavar="PATH", help="Safely resume post-analysis/finalization only when trustworthy pre/post snapshots exist")
    parser.add_argument("--repair-generated-reports", metavar="PATH", help="Regenerate integrity-protected derived reports from trusted internal assessment state")
    parser.add_argument("--recover-interrupted-operation", metavar="PATH", help="Roll back an interrupted state transaction to the last consistent assessment state")
    parser.add_argument("--privileged-static-review", metavar="PATH", help=argparse.SUPPRESS)
    parser.add_argument("--runtime-observe-seconds", type=float, default=0.0, metavar="SECONDS", help=f"Use a timed runtime observation instead of pressing Enter to stop (maximum {int(MAX_OBSERVATION_SECONDS)} seconds)")
    parser.add_argument("-i", "--installer", help="Path to .deb, AppImage, .snap, .flatpak/ref/repo, .run, .sh, or archive")
    parser.add_argument("-o", "--output", help="Assessment output directory")
    parser.add_argument("-n", "--assessment-name", help="Assessment name")
    parser.add_argument("--application-path", help="Installed application executable path for runtime guidance")
    parser.add_argument("--application-root", help="Optional installed application directory to include in snapshots and report review; it may be absent before installation")
    parser.add_argument(
        "--include-path", action="append", default=[],
        help="Include an additional file or directory in pre/post snapshots. May be repeated and may not exist before installation.",
    )
    parser.add_argument(
        "--data-root", action="append", default=[],
        help="Include an expected application data directory in snapshots and storage/network review. May be repeated.",
    )
    parser.add_argument(
        "--installer-analysis-only",
        action="store_true",
        help="Analyze the supplied installer/package without performing the full pre/install/post assessment workflow.",
    )
    parser.add_argument("--auto-install-deb", action="store_true", help="In a non-interactive full assessment, install a .deb using sudo apt install -y")
    parser.add_argument(
        "--allow-installed-deb",
        action="store_true",
        help="Allow a full assessment to start when the Debian package is already installed. Use only for intentional upgrade or reinstall testing.",
    )
    parser.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        help="Exclude a path and its descendants from filesystem snapshots. May be supplied more than once for known assessment-runner noise.",
    )
    parser.add_argument(
        "--network-observation-seconds", type=float, default=5.0, metavar="SECONDS",
        help="Union socket observations for this many seconds during the post snapshot (default: 5; maximum: 60).",
    )
    parser.add_argument("--retain-payload", action="store_true", help="Retain a fully extracted installer payload for manual review; full assessments omit it by default.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show snapshot roots and stage starts.")
    parser.add_argument("--debug", action="store_true", help="Show per-item snapshot diagnostics in addition to verbose progress.")
    parser.add_argument("--non-interactive", action="store_true", help="Do not prompt for missing actions")
    return parser.parse_args()


def _run_client_appendix_export(assessment_dir: Path) -> int:
    result = service.create_client_appendix(assessment_dir)
    if not result.ok:
        console.print(f"[red][!] {result.message}:[/red] {'; '.join(result.errors)}")
        repair = result.data.get("repair") or {}
        if repair.get("repairable"):
            console.print("[yellow]The integrity issue is limited to generated tester report(s). Use Assessment Status / Recovery or --repair-generated-reports to regenerate them from trusted internal state.[/yellow]")
        return 10
    data = result.data
    console.print(f"[green][+] Client appendix created:[/green] {data['path']}")
    console.print(f"[green][+] Copied technical artifacts:[/green] {len(data['copied'])}")
    console.print("[green][+] Generated:[/green] assessment_report.html, README.txt, SHA256SUMS.txt")
    console.print("[dim]Internal findings, tester workflow/coverage artifacts, module/tool status, manifests, snapshots, and working data were excluded.[/dim]")
    return 0

def _run_assessment_verification(assessment_dir: Path) -> int:
    service_result = service.verify_assessment(assessment_dir)
    result = service_result.data
    console.print("\n[bold]Assessment Integrity Verification[/bold]")
    console.print("=================================")
    console.print(f"Assessment: {assessment_dir.name}")
    console.print(f"Framework:  UbuntuClientAssess {result.get('framework_version') or VERSION}")
    console.print(f"Methodology: {result.get('methodology_version') or METHODOLOGY_VERSION}")
    console.print(f"Coverage catalog: {result.get('coverage_catalog_version') or TEST_CASE_CATALOG_VERSION}\n")
    for check in result.get("checks", []):
        status = str(check.get("status") or "FAIL")
        style = "green" if status == "PASS" else "red"
        console.print(f"[{style}]{status:4}[/{style}]  {check.get('name')} - {check.get('detail')}")
    console.print(f"\nArtifacts recorded: {result.get('report_count',0)} reports | {result.get('supporting_count',0)} supporting files | {result.get('extraction_count',0)} extraction inventories")
    if not service_result.ok:
        console.print("[red]Overall status: FAIL[/red]")
        for issue in service_result.errors:
            console.print(f"  - {issue}")
        return 9
    console.print("[green]Overall status: PASS — assessment verification passed[/green]")
    return 0

def _interactive_main_menu() -> tuple[str, Path | None]:
    console.print("\n[bold]Main Menu[/bold]")
    console.print("---------")
    console.print("1) Start New Assessment")
    console.print("2) Review Completed Assessment")
    console.print("3) Create Client Appendix")
    console.print("4) Verify Assessment Integrity")
    console.print("5) Guided Runtime Observation")
    console.print("6) Exit")
    console.print("7) Assessment Status / Recovery")
    choice = Prompt.ask("Selection", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")
    if choice == "1":
        return "assessment", None
    if choice == "6":
        return "exit", None

    labels = {
        "2": "Completed assessment directory to review",
        "3": "Completed assessment directory for ClientAppendix export",
        "4": "Assessment directory to verify integrity",
        "5": "Completed assessment directory for Guided Runtime Observation",
        "7": "Assessment directory for Status / Recovery",
    }
    console.print("[dim]Tip: path prompts support Tab completion, ~, relative paths, and environment variables.[/dim]")
    assessment_dir = ask_path(labels[choice], only_directories=True, must_exist=True)
    assert assessment_dir is not None
    return {"2": "review", "3": "appendix", "4": "verify", "5": "runtime", "7": "status"}[choice], assessment_dir


def main() -> int:
    _MODULE_TIMINGS.clear()
    args = parse_args()
    configure_progress(verbose=args.verbose or args.debug, debug=args.debug)
    if args.privileged_static_review:
        return _run_privileged_static_review(_expand_path(args.privileged_static_review))
    if args.network_observation_seconds < 0 or args.network_observation_seconds > 60:
        console.print("[red][!] --network-observation-seconds must be between 0 and 60.[/red]")
        return 2
    if args.gui:
        try:
            gui_port = validate_gui_port(args.port)
        except ValueError as exc:
            console.print(f"[red][!] {exc}[/red]")
            return 2
        gui_root = _expand_path(args.gui_root) if args.gui_root else (Path.cwd() / "Assessments").resolve()
        return run_gui(port=gui_port, assessment_root=gui_root, open_browser=not args.no_browser)

    banner()

    if len(sys.argv) == 1:
        action, assessment_dir = _interactive_main_menu()
        if action == "exit":
            console.print("[dim]Exiting UbuntuClientAssess.[/dim]")
            return 0
        if action == "review":
            assert assessment_dir is not None
            return run_tester_review(assessment_dir)
        if action == "appendix":
            assert assessment_dir is not None
            return _run_client_appendix_export(assessment_dir)
        if action == "verify":
            assert assessment_dir is not None
            return _run_assessment_verification(assessment_dir)
        if action == "runtime":
            assert assessment_dir is not None
            return run_runtime_observation(assessment_dir)
        if action == "status":
            assert assessment_dir is not None
            _print_assessment_status(assessment_dir)
            info = _assessment_recovery_info(assessment_dir)
            if info.get("action") == "post-analysis" and Confirm.ask("Resume from the safe post-analysis recovery point now?", default=True):
                return _resume_assessment(assessment_dir)
            if info.get("action") == "repair-generated" and Confirm.ask("Regenerate modified generated reports from trusted internal state now?", default=True):
                return _repair_generated_reports(assessment_dir)
            return 0

    admin_actions = [bool(args.verify_assessment), bool(args.create_client_appendix), bool(args.review), bool(args.runtime_observe), bool(args.assessment_status), bool(args.resume_assessment), bool(args.repair_generated_reports), bool(args.recover_interrupted_operation)]
    if sum(admin_actions) > 1:
        console.print("[red][!] Assessment administration actions are mutually exclusive.[/red]")
        return 2

    if args.assessment_status:
        return _print_assessment_status(_expand_path(args.assessment_status))

    if args.resume_assessment:
        return _resume_assessment(_expand_path(args.resume_assessment))

    if args.repair_generated_reports:
        return _repair_generated_reports(_expand_path(args.repair_generated_reports))
    if args.recover_interrupted_operation:
        result = service.recover_interrupted_operation(_expand_path(args.recover_interrupted_operation))
        if result.ok:
            console.print(f"[green][+] {result.message}.[/green]")
            return 0
        console.print(f"[red][!] {result.message}:[/red] {'; '.join(result.errors)}")
        return 12

    if args.review:
        if args.non_interactive:
            console.print("[red][!] --review is interactive and cannot be combined with --non-interactive.[/red]")
            return 2
        return run_tester_review(_expand_path(args.review))

    if args.runtime_observe:
        return run_runtime_observation(_expand_path(args.runtime_observe), args.runtime_observe_seconds, non_interactive=args.non_interactive)

    if args.create_client_appendix:
        return _run_client_appendix_export(_expand_path(args.create_client_appendix))

    if args.verify_assessment:
        return _run_assessment_verification(_expand_path(args.verify_assessment))

    if args.assessment_name:
        assessment_name = sanitize_name(args.assessment_name)
    elif args.non_interactive:
        assessment_name = "UbuntuClientAssess"
    else:
        assessment_name = sanitize_name(Prompt.ask("Assessment name", default="Ubuntu Client Assessment"))

    if args.output:
        output_dir = Path(os.path.expanduser(args.output)).resolve()
    elif args.non_interactive:
        output_dir = Path.cwd() / assessment_name
    else:
        console.print("[dim]Tip: path prompts support Tab completion, ~, relative paths, and environment variables.[/dim]")
        base = ask_path("Assessment output directory", str(Path.cwd() / "Assessments"), only_directories=True)
        assert base is not None
        output_dir = base / assessment_name
    metadata_path = output_dir / "assessment_metadata.json"
    existing_metadata: dict = {}
    if metadata_path.exists():
        try:
            existing_metadata = read_json(metadata_path)
        except Exception:
            existing_metadata = {}
    prior_run_state = existing_metadata.get("run_state") if isinstance(existing_metadata.get("run_state"), dict) else {}
    if prior_run_state.get("status") in {"running", "interrupted"}:
        prior_stage = prior_run_state.get("stage") or "unknown"
        console.print(f"[yellow][!] Previous assessment attempt was incomplete at stage:[/yellow] {prior_stage}")
        console.print("    Verify package state and restore a clean baseline if installation may have started before rerunning Full Assessment.")

    installer: Path | None = _expand_path(args.installer) if args.installer else None
    if installer is None:
        prior_installer = existing_metadata.get("installer")
        if prior_installer and Path(prior_installer).is_file():
            installer = Path(prior_installer)
            console.print(f"[dim]Using installer recorded for this assessment: {installer}[/dim]")
    if installer is not None and not installer.is_file():
        console.print(f"[red][!] Installer/package file not found:[/red] {installer}")
        return 2
    if installer is None and not args.non_interactive:
        installer = ask_path("Installer/package path", allow_blank=True, must_exist=True, must_be_file=True)

    application_root: Path | None = None
    if args.application_root:
        application_root = _expand_path(args.application_root)
    elif existing_metadata.get("application_root"):
        prior_root = _expand_path(str(existing_metadata["application_root"]))
        application_root = prior_root
        console.print(f"[dim]Using application root recorded for this assessment: {application_root}[/dim]")
    if application_root is not None and not application_root.exists():
        console.print(f"[dim]Application root will be monitored if it is created: {application_root}[/dim]")

    include_paths = [_expand_path(value) for value in args.include_path]
    data_roots = [_expand_path(value) for value in args.data_root]
    for value in existing_metadata.get("data_roots", []):
        prior = _expand_path(str(value))
        if prior not in data_roots:
            data_roots.append(prior)

    mode = "installer-analysis-only" if args.installer_analysis_only else "full"
    if not args.non_interactive and not args.installer_analysis_only:
        console.print("\n[bold]Execution mode[/bold]")
        console.print("  1. Full assessment (pre snapshot -> install/configure -> post snapshot -> analysis)")
        console.print("  2. Installer analysis only")
        choice = Prompt.ask("Selection", choices=["1", "2"], default="1")
        mode = {"1": "full", "2": "installer-analysis-only"}[choice]

    # Fail early when an execution mode cannot perform meaningful work.
    if mode == "installer-analysis-only" and installer is None:
        console.print("[red][!] Installer Analysis Only requires an installer/package file.[/red]")
        return 2
    if args.non_interactive and mode == "full":
        if installer is None or not installer.name.lower().endswith(".deb") or not args.auto_install_deb:
            console.print("[red][!] Non-interactive Full Assessment requires a .deb installer and --auto-install-deb.[/red]")
            return 2

    package_state = deb_package_state(installer) if installer else None
    if mode == "full" and package_state and package_state.get("dpkg_present") and not args.allow_installed_deb:
        package = package_state.get("package") or installer.name
        version = package_state.get("installed_version") or "unknown version"
        dpkg_status = package_state.get("dpkg_status") or "known to dpkg"
        console.print(f"[red][!] Clean baseline required:[/red] {package} {version} has Debian package state: {dpkg_status}.")
        console.print("    Revert to a clean VM snapshot or fully purge the package before starting Full Assessment.")
        console.print("    Use --allow-installed-deb only for an intentional upgrade or reinstall assessment.")
        return 2

    clean_generated_artifacts(output_dir, full_run=(mode == "full"))
    ensure_assessment_layout(output_dir)

    excluded_paths = [_expand_path(value) for value in args.exclude_path]
    excluded_paths.append(output_dir)
    excluded_paths = sorted(set(excluded_paths), key=str)

    installer_paths = discover_installer_paths(installer)
    inferred_scope = infer_debian_application_scope(installer, installer_paths)
    inferred_roots = [Path(value) for value in inferred_scope.get("application_roots", []) or []]
    expected_runtime_roots = discover_runtime_roots(inferred_scope, existing_only=False)
    if application_root is None and inferred_scope.get("application_root"):
        application_root = Path(str(inferred_scope["application_root"]))
        console.print(f"[dim]Automatically inferred application root: {application_root}[/dim]")
    recorded_application_path = args.application_path or existing_metadata.get("application_path") or inferred_scope.get("application_path")
    if not (args.application_path or existing_metadata.get("application_path")) and recorded_application_path:
        console.print(f"[dim]Automatically inferred application launcher: {recorded_application_path}[/dim]")
    requested_paths = include_paths + data_roots + inferred_roots + expected_runtime_roots + ([application_root] if application_root else [])
    tracked_paths = merge_tracked_paths(installer_paths + requested_paths)
    installer_path_digest = hashlib.sha256(
        "\n".join(str(path) for path in installer_paths).encode("utf-8")
    ).hexdigest() if installer_paths else None

    metadata = dict(existing_metadata)
    metadata.pop("phase", None)
    metadata.pop("run_state", None)
    metadata.pop("installation_workflow", None)
    metadata.pop("installation", None)
    metadata.pop("installer_declared_paths", None)
    installation = {
        "method": "not-applicable" if mode == "installer-analysis-only" else "pending",
        "confirmed": mode == "installer-analysis-only",
        "status": "not-applicable" if mode == "installer-analysis-only" else "not-started",
    }
    metadata.update({
        "framework": "UbuntuClientAssess",
        "version": VERSION,
        "methodology_version": METHODOLOGY_VERSION,
        "test_case_catalog_version": TEST_CASE_CATALOG_VERSION,
        "assessment_name": assessment_name,
        "assessment_started_at": existing_metadata.get("assessment_started_at") or now_iso(),
        "last_run_at": now_iso(),
        "mode": mode,
        "installer": str(installer) if installer else None,
        "application_path": recorded_application_path,
        "application_root": str(application_root) if application_root else None,
        "application_scope": inferred_scope,
        "application_roots": [str(path) for path in inferred_roots],
        "expected_runtime_roots": [str(path) for path in expected_runtime_roots],
        "installer_declared_path_count": len(installer_paths),
        "installer_declared_paths_sha256": installer_path_digest,
        "tracked_paths": [str(path) for path in tracked_paths],
        "include_paths": [str(path) for path in include_paths],
        "data_roots": [str(path) for path in data_roots],
        "excluded_paths": [str(p) for p in excluded_paths],
        "deb_package_state_at_start": package_state,
        "installation": installation,
    })
    _set_run_state(metadata_path, metadata, "initialized")

    status: dict[str, tuple[str, str]] = {}
    console.print(f"\n[cyan]Assessment output:[/cyan] {output_dir}")
    if installer_paths:
        console.print(f"[dim]Debian package manifest: {len(installer_paths):,} paths collapsed to {len(tracked_paths)} snapshot roots.[/dim]")

    _, ready = run_module(status, "Tool Detection", detect_tools, output_dir) or ({}, False)
    if not ready:
        record_status(status, "Tool Detection", "FAIL", "One or more required tools are missing; assessment was not started")
        _set_run_state(metadata_path, metadata, "tool-detection", "failed", "Required tools are missing")
        write_module_status(output_dir, status)
        console.print("[red][!] One or more required tools are missing. Assessment aborted before installer execution or snapshot capture.[/red]")
        return 3

    installer_data: dict = {}
    if installer:
        retain_payload = args.retain_payload or mode == "installer-analysis-only"
        installer_data = run_module(status, "Installer Analysis", analyze_installer, installer, output_dir, retain_payload) or {}
    else:
        record_status(status, "Installer Analysis", "SKIPPED", "No installer supplied; manual installation workflow")
        write_text(
            report_path(output_dir, "installer_analysis.txt"),
            "Installer Analysis\n==================\n\nNo installer/package file was supplied to UbuntuClientAssess.\nThe Full Assessment is proceeding with a tester-managed manual installation/configuration workflow, so static package analysis is not available for this run.\n",
        )

    if mode == "installer-analysis-only":
        _set_run_state(metadata_path, metadata, "installer-analysis")
        profile_data = run_module(status, "Application / Framework Profile", profile_application, output_dir, {}, installer_data, inferred_roots) or {}
        run_module(status, "Runtime Guidance", write_runtime_guidance, output_dir, metadata.get("application_path"), profile_data)
        run_module(status, "Assessment Coverage", generate_assessment_coverage, output_dir, mode, profile_data)
        write_module_status(output_dir, status)
        incomplete = [name for name, (state, _) in status.items() if state == "FAIL"]
        if incomplete:
            _set_run_state(metadata_path, metadata, "installer-analysis", "failed", f"Incomplete modules: {', '.join(incomplete)}")
            console.print(f"[red][!] Installer analysis incomplete:[/red] {', '.join(incomplete)}")
            return 6
        metadata["module_timings_seconds"] = dict(_MODULE_TIMINGS)
        write_json(metadata_path, metadata)
        if not finalize_assessment(output_dir, mode, metadata_path, metadata, status):
            return 8
        console.print("\n[green][+] Installer analysis complete.[/green]")
        console.print(f"[green][+] Tester reports:[/green] {output_dir / 'reports'}")
        console.print(f"[dim]Internal working data: {output_dir / 'working'}[/dim]")
        _print_timing_summary()
        return 0

    home_entries_before = _home_top_level_entries(excluded_paths)
    _set_run_state(metadata_path, metadata, "pre-installation-snapshot")
    console.print("\n[cyan][+] Capturing pre-installation snapshot...[/cyan]")
    pre_snapshot = run_module(
        status,
        "Pre-Installation Snapshot",
        collect_snapshot,
        working_dir(output_dir) / "snapshot_pre.json",
        "pre-install",
        tracked_paths,
        excluded_paths,
    )
    if pre_snapshot is None:
        record_status(status, "Pre-Installation Snapshot", "FAIL", "Baseline capture failed; installation was not started")
        _set_run_state(metadata_path, metadata, "pre-installation-snapshot", "failed", "Baseline capture failed; installation was not started")
        write_module_status(output_dir, status)
        console.print("[red][!] Pre-installation snapshot failed. Installation has been aborted to preserve the clean baseline.[/red]")
        return 3

    _set_run_state(metadata_path, metadata, "pre-installation-snapshot-complete")
    installed_by_framework = False
    installation_workflow: list[dict[str, object]] = []
    if installer and installer.name.lower().endswith(".deb"):
        do_install = args.auto_install_deb
        if not args.non_interactive and not do_install:
            do_install = confirm_deb_installation()
        if do_install:
            method = "default"
            if not args.non_interactive:
                console.print("\n[bold]Installation Method[/bold]")
                console.print(f"  1. Default installation\n     sudo apt install -y {installer}")
                console.print("  2. Custom installation workflow\n     Use vendor/client-specific installation and post-install configuration commands.")
                choice = Prompt.ask("Selection", choices=["1", "2"], default="1")
                method = "default" if choice == "1" else "custom"

            if method == "default":
                installation.update({"method": "default-deb", "confirmed": False, "status": "in-progress"})
                _set_run_state(metadata_path, metadata, "package-installation")
                rc = install_deb(installer)
                installation_workflow = [{"step": 1, "command": f"sudo apt install -y {installer}", "returncode": rc}]
                if rc == 0:
                    record_status(status, "Package Installation", "PASS")
                    installed_by_framework = True
                    installation.update({"confirmed": True, "status": "completed"})
                else:
                    record_status(status, "Package Installation", "FAIL", f"apt exited with status {rc}")
                    installation.update({"confirmed": False, "status": "failed", "returncode": rc})
            else:
                installation.update({"method": "custom", "confirmed": False, "status": "in-progress"})
                _set_run_state(metadata_path, metadata, "custom-installation-workflow")
                commands = collect_custom_workflow(installer)
                success, installation_workflow = execute_custom_workflow(installer, commands)
                if installation_workflow:
                    if success:
                        record_status(status, "Custom Installation Workflow", "PASS")
                        installed_by_framework = True
                        installation.update({"confirmed": True, "status": "completed"})
                    else:
                        record_status(status, "Custom Installation Workflow", "FAIL", "One or more workflow commands failed or were stopped")
                        installation.update({"confirmed": False, "status": "failed"})
                else:
                    record_status(status, "Custom Installation Workflow", "SKIPPED", "No workflow executed")
                    installation.update({"confirmed": False, "status": "not-executed"})

    if installation_workflow:
        # Commands are already redacted by execute_custom_workflow before being persisted.
        metadata["installation_workflow"] = installation_workflow
    write_json(metadata_path, metadata)

    if not installed_by_framework:
        if args.non_interactive:
            _set_run_state(metadata_path, metadata, "package-installation", "failed", "Automated installation failed")
            write_module_status(output_dir, status)
            console.print("[red][!] Automated installation failed; post-installation snapshot was not captured.[/red]")
            return 4
        installation.update({"method": "manual", "confirmed": False, "status": "awaiting-confirmation"})
        _set_run_state(metadata_path, metadata, "manual-installation-confirmation")
        console.print("\n[bold]Installation required before post-install capture[/bold]")
        console.print("UbuntuClientAssess has analyzed the supplied installer but has NOT executed it. Install/configure the application now using the vendor-approved procedure in another terminal or desktop session. Complete first-run setup/sign-in, exercise the features you want assessed, wait for background services to start, and keep the application running during capture. Enter credentials only in the application.")
        if not Confirm.ask("Confirm installation/configuration/application exercise is complete", default=False):
            installation.update({"confirmed": False, "status": "not-confirmed"})
            record_status(status, "Manual Installation / Exercise", "FAIL", "Tester did not confirm completion")
            _set_run_state(metadata_path, metadata, "manual-installation-confirmation", "failed", "Tester did not confirm completion")
            write_module_status(output_dir, status)
            console.print("[red][!] Installation/application exercise was not confirmed. Post-installation capture was not started.[/red]")
            return 4
        installation.update({"confirmed": True, "status": "completed"})
        record_status(status, "Manual Installation / Exercise", "PASS")
        _set_run_state(metadata_path, metadata, "installation-complete")

    if installer and installer.name.lower().endswith(".deb"):
        package_state_after = deb_package_state(installer)
        metadata["deb_package_state_after_installation"] = package_state_after
        if not deb_installation_complete(package_state_after):
            detail = deb_installation_verification_detail(package_state_after)
            installation.update({"confirmed": False, "status": "verification-failed"})
            record_status(status, "Debian Package Verification", "FAIL", detail)
            _set_run_state(metadata_path, metadata, "package-verification", "failed", detail)
            write_module_status(output_dir, status)
            console.print(f"[red][!] Debian package installation could not be verified:[/red] {detail}")
            console.print("[red][!] Post-installation capture was not started.[/red]")
            return 4
        record_status(status, "Debian Package Verification", "PASS")
        _set_run_state(metadata_path, metadata, "package-verification-complete")

    if installed_by_framework and not args.non_interactive:
        metadata["application_exercise"] = {"status": "awaiting-confirmation"}
        _set_run_state(metadata_path, metadata, "application-exercise")
        console.print("\n[bold]Post-installation application setup / sign-in[/bold]")
        console.print(f"Open the application in your desktop session, sign in, and complete first-run setup. Exercise the features you want assessed and wait for background services to start. Keep using the application for the first {args.network_observation_seconds:g} seconds after confirming so active connections can be sampled. Enter credentials only in the application.")
        if not Confirm.ask("Ready to capture the configured, signed-in application state?", default=True):
            metadata["application_exercise"] = {"status": "not-confirmed"}
            record_status(status, "Application Setup / Exercise", "FAIL", "Tester did not confirm readiness")
            _set_run_state(metadata_path, metadata, "application-exercise", "failed", "Tester did not confirm readiness")
            write_module_status(output_dir, status)
            console.print("[yellow]Post-installation capture was not started. The pre-installation snapshot is preserved.[/yellow]")
            return 4
        metadata["application_exercise"] = {"status": "confirmed", "confirmed_at": now_iso()}
        record_status(status, "Application Setup / Exercise", "PASS")
    elif args.non_interactive:
        metadata["application_exercise"] = {"status": "not-performed", "reason": "Non-interactive installation-only capture"}
        console.print("[yellow]Non-interactive capture does not include manual sign-in or first-run application exercise.[/yellow]")
    else:
        metadata["application_exercise"] = {"status": "confirmed", "method": "manual-installation-confirmation"}

    new_home_paths = [
        path for path in sorted(_home_top_level_entries(excluded_paths) - home_entries_before, key=str)
        if path not in tracked_paths and not any(root in path.parents for root in tracked_paths)
    ]
    accepted_home_paths: list[Path] = []
    ignored_home_paths: list[Path] = []
    if new_home_paths:
        console.print("\n[cyan]New top-level application-data candidates detected:[/cyan]")
        for path in new_home_paths:
            console.print(f"  {path}")
        include_discovered = args.non_interactive or Confirm.ask(
            "Include these newly created paths in post-capture and application-data review?",
            default=True,
        )
        if include_discovered:
            accepted_home_paths = new_home_paths
            data_roots = sorted(set(data_roots + accepted_home_paths), key=str)
            tracked_paths = merge_tracked_paths(tracked_paths + accepted_home_paths)
        else:
            ignored_home_paths = new_home_paths

    # Only paths explicitly requested by the tester or declared/inferred from
    # the installer/package affect coverage status when absent. Predicted
    # runtime/user-data roots are discovery hints; applications are not
    # required to create every conventional location we can predict.
    coverage_required_paths = include_paths + data_roots + inferred_roots + ([application_root] if application_root else [])
    missing_required = [path for path in coverage_required_paths if not path.exists() and not path.is_symlink()]
    missing_predicted = [path for path in expected_runtime_roots if not path.exists() and not path.is_symlink()]
    if ignored_home_paths or missing_required or args.non_interactive:
        details: list[str] = []
        if ignored_home_paths:
            details.append(f"{len(ignored_home_paths)} newly created home path(s) excluded by tester")
        if missing_required:
            details.append(f"{len(missing_required)} requested or installer-derived path(s) absent after setup")
        if args.non_interactive:
            details.append("manual sign-in/application exercise not performed")
        record_status(status, "Coverage Review", "ATTN", "; ".join(details))
    else:
        detail = f"{len(accepted_home_paths)} newly created home path(s) added automatically" if accepted_home_paths else "No explicit coverage gaps detected"
        if missing_predicted:
            detail += f"; {len(missing_predicted)} predicted runtime/data path(s) were not created (informational)"
        record_status(status, "Coverage Review", "PASS", detail)
    metadata["missing_predicted_runtime_roots"] = [str(path) for path in missing_predicted]
    metadata["data_roots"] = [str(path) for path in data_roots]
    metadata["discovered_home_paths"] = [str(path) for path in accepted_home_paths]
    metadata["ignored_discovered_home_paths"] = [str(path) for path in ignored_home_paths]
    metadata["tracked_paths"] = [str(path) for path in tracked_paths]

    _set_run_state(metadata_path, metadata, "post-installation-snapshot")
    console.print("\n[cyan][+] Capturing post-installation snapshot...[/cyan]")
    post_snapshot = run_module(
        status,
        "Post-Installation Snapshot",
        collect_snapshot,
        working_dir(output_dir) / "snapshot_post.json",
        "post-install",
        tracked_paths,
        excluded_paths,
        args.network_observation_seconds,
    )
    if post_snapshot is None:
        record_status(status, "Post-Installation Snapshot", "FAIL", "Post-install state capture failed")
        _set_run_state(metadata_path, metadata, "post-installation-snapshot", "failed", "Post-install state capture failed")
        write_module_status(output_dir, status)
        console.print("[red][!] Post-installation snapshot failed. Assessment differential is incomplete.[/red]")
        return 5

    _set_run_state(metadata_path, metadata, "post-analysis")
    runtime_roots = discover_runtime_roots(inferred_scope, existing_only=True)
    for path in runtime_roots:
        if path not in data_roots and str(path).startswith(str(get_interactive_home())):
            data_roots.append(path)
    analysis_roots = sorted(set(data_roots + inferred_roots + runtime_roots + ([application_root] if application_root else [])), key=str)
    metadata["application_runtime_roots"] = [str(path) for path in runtime_roots]
    metadata["analysis_roots"] = [str(path) for path in analysis_roots]
    analysis_ok = post_analysis(output_dir, metadata.get("application_path"), analysis_roots, status, installer_data, metadata)
    metadata["module_timings_seconds"] = dict(_MODULE_TIMINGS)
    write_json(metadata_path, metadata)
    write_module_status(output_dir, status)
    if not analysis_ok:
        _set_run_state(metadata_path, metadata, "post-analysis", "failed", "Installation differential or report generation failed")
        console.print("[red][!] UbuntuClientAssess could not complete the installation differential.[/red]")
        return 6

    incomplete = [name for name, (state, _) in status.items() if state == "FAIL"]
    if incomplete:
        _set_run_state(metadata_path, metadata, "post-analysis", "failed", f"Incomplete modules: {', '.join(incomplete)}")
        console.print(f"[red][!] Assessment incomplete; modules require attention:[/red] {', '.join(incomplete)}")
        return 7

    if not finalize_assessment(output_dir, mode, metadata_path, metadata, status):
        return 8
    console.print("\n[green][+] UbuntuClientAssess assessment processing complete.[/green]")
    attention = [name for name, (state, _) in status.items() if state == "ATTN"]
    console.print(f"[green]Modules completed:[/green] {sum(1 for state, _ in status.values() if state == 'PASS')} PASS; {len(attention)} ATTN")
    if attention:
        console.print(f"[yellow]Tester attention:[/yellow] {', '.join(attention)}")
    console.print(f"[green][+] Tester reports:[/green] {output_dir / 'reports'}")
    console.print(f"[dim]Internal working data: {output_dir / 'working'}[/dim]")
    _print_timing_summary()
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        _mark_active_run_interrupted()
        console.print("\n[yellow][!] Assessment interrupted. Recovery state was recorded; generated reports may be incomplete.[/yellow]")
        exit_code = 130
    raise SystemExit(exit_code)
