from __future__ import annotations

import html
import shutil
from pathlib import Path
from urllib.parse import quote

from .artifacts import verify_artifact_manifest
from .common import VERSION, now_iso, read_json, sha256_file, write_text
from .technical_summary import build_technical_summary

FULL_CLIENT_REPORTS = (
    "installer_analysis.txt",
    "application_profile.txt",
    "install_changes.txt",
    "permissions_review.txt",
    "binary_security_review.txt",
    "service_review.txt",
    "persistence_review.txt",
    "network_surface_review.txt",
    "ipc_review.txt",
    "local_storage_review.txt",
    "update_review.txt",
    "runtime_review.txt",
)

INSTALLER_ONLY_CLIENT_REPORTS = (
    "installer_analysis.txt",
    "application_profile.txt",
    "runtime_review.txt",
)

CLIENT_REPORTS_BY_MODE = {
    "full": FULL_CLIENT_REPORTS,
    "installer-analysis-only": INSTALLER_ONLY_CLIENT_REPORTS,
}

INTERNAL_EXCLUSIONS = (
    "findings.txt",
    "findings_summary.txt",
    "assessment_coverage.txt",
    "module_status.txt",
    "tool_detection.txt",
    "tester_review.txt",
    "evidence_guide.txt",
    "artifact_manifest.txt",
    "assessment_manifest.json",
    "working/",
)


def _safe_appendix_path(assessment_dir: Path) -> Path:
    root = assessment_dir.resolve()
    appendix = assessment_dir / "ClientAppendix"
    if appendix.is_symlink():
        raise RuntimeError("ClientAppendix is a symbolic link; refusing to refresh it")
    try:
        appendix.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise RuntimeError("ClientAppendix does not resolve inside the assessment directory") from exc
    return appendix


def _refresh_appendix_directory(appendix: Path) -> None:
    if appendix.is_symlink():
        raise RuntimeError("ClientAppendix is a symbolic link; refusing to remove it")
    if appendix.is_dir():
        shutil.rmtree(appendix)
    elif appendix.exists():
        appendix.unlink()
    appendix.mkdir(parents=True, exist_ok=False)


def _client_index(assessment_name: str, source_version: str, mode: str, filenames: list[str], summary: dict[str, object]) -> str:
    def link(name: str, label: str | None = None) -> str:
        if name not in filenames:
            return ""
        return f'<a class="button" href="{quote(name, safe="._-")}">{html.escape(label or name)}</a>'

    def metric(label: str, value: object) -> str:
        return f'<div class="metric"><span>{html.escape(label)}</span><strong>{html.escape(str(value))}</strong></div>'

    def chips(values: object) -> str:
        vals = [str(x) for x in (values or []) if str(x)] if isinstance(values, list) else []
        return '<div class="chips">'+''.join(f'<code>{html.escape(x)}</code>' for x in vals)+'</div>' if vals else '<span class="muted">None recorded</span>'

    grouped = {
        "Application & Installation": ["application_profile.txt", "installer_analysis.txt", "install_changes.txt"],
        "Privilege & Host Integration": ["permissions_review.txt", "binary_security_review.txt", "service_review.txt", "persistence_review.txt"],
        "Communications & Runtime": ["network_surface_review.txt", "ipc_review.txt", "runtime_review.txt"],
        "Data & Software Supply Chain": ["local_storage_review.txt", "update_review.txt"],
    }
    groups=[]
    for title,names in grouped.items():
        present=[n for n in names if n in filenames]
        if not present:
            continue
        groups.append('<div class="artifact-group"><h3>'+html.escape(title)+'</h3>'+''.join(link(n) for n in present)+'</div>')

    metrics=''.join([
        metric('Services', summary.get('service_count',0)), metric('Network listeners', summary.get('network_listener_count',0)),
        metric('Application endpoints', summary.get('application_endpoint_count',0)), metric('Cleartext endpoint indicators', summary.get('cleartext_endpoint_count',0)),
        metric('Credential-storage indicators', summary.get('credential_storage_count',0)), metric('Update endpoints', summary.get('update_endpoint_count',0)),
        metric('Unix sockets', summary.get('unix_socket_count',0)), metric('D-Bus / PolicyKit', f"{summary.get('dbus_count',0)} / {summary.get('polkit_count',0)}"),
    ])
    runtime_metrics=''.join([
        metric('Processes observed', summary.get('runtime_process_count',0)), metric('Privileged processes', summary.get('privileged_process_count',0)),
        metric('Listeners observed', summary.get('runtime_listener_count',0)), metric('Connections observed', summary.get('runtime_connection_observation_count',0)),
        metric('Runtime Unix sockets', summary.get('runtime_socket_count',0)), metric('Runtime FIFOs', summary.get('runtime_fifo_count',0)),
    ])
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{html.escape(assessment_name)} — Client Technical Appendix</title>
<style>
:root{{--bg:#08111f;--panel:#101c2f;--panel2:#14243a;--text:#e8eef7;--muted:#9fb0c8;--line:#2b405f;--accent:#e95420;--link:#72d0ff;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}main{{width:min(1180px,calc(100% - 32px));margin:36px auto 64px}}h1{{font-size:34px;margin:.2em 0}}h2{{margin-top:34px}}h3{{margin:.2em 0 .8em}}.eyebrow{{color:var(--accent);font-weight:800;text-transform:uppercase;letter-spacing:.08em}}.muted{{color:var(--muted)}}.panel,.metric,.artifact-group{{background:var(--panel);border:1px solid var(--line);border-radius:12px}}.panel{{padding:20px;margin:18px 0}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.metric{{padding:16px}}.metric span{{display:block;color:var(--muted);font-size:13px}}.metric strong{{display:block;font-size:28px;margin-top:4px}}.surface{{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:14px}}.surface .panel{{margin:0}}.button{{display:inline-block;margin:4px 6px 4px 0;padding:7px 10px;border:1px solid var(--line);border-radius:8px;color:var(--link);text-decoration:none}}.button:hover{{background:var(--panel2)}}.chips{{display:flex;gap:6px;flex-wrap:wrap}}code{{background:#07101d;border:1px solid var(--line);border-radius:6px;padding:3px 6px;overflow-wrap:anywhere}}.artifact-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}.artifact-group{{padding:16px}}.notice{{border-left:4px solid var(--accent)}}a{{color:var(--link)}}
@media print{{:root{{--bg:#fff;--panel:#fff;--panel2:#f7f7f7;--text:#111;--muted:#4b5563;--line:#d2d7de;--link:#0645ad}}main{{width:100%;margin:0}}}}
</style></head><body><main>
<div class="eyebrow">UbuntuClientAssess Client Technical Appendix</div><h1>{html.escape(assessment_name)}</h1>
<p class="muted">Source assessment: UbuntuClientAssess v{html.escape(source_version)} · Mode: {html.escape(mode)} · Security model schema {html.escape(str(summary.get('model_schema') or 'unknown'))}</p>
<div class="panel notice"><strong>About this appendix</strong><p>This dashboard summarizes technical observations collected during the application assessment and provides navigation to supporting evidence. It does not independently declare vulnerabilities. Confirmed vulnerabilities, severity ratings, remediation guidance, and formal conclusions belong in the final penetration test report.</p></div>
<h2>Technical Surface at a Glance</h2><div class="metrics">{metrics}</div>
<div class="surface"><div class="panel"><h3>Network & Communications</h3><p>Observed listeners</p>{chips(summary.get('listeners'))}<p>Application endpoint indicators: <strong>{summary.get('application_endpoint_count',0)}</strong> · Cleartext indicators: <strong>{summary.get('cleartext_endpoint_count',0)}</strong></p>{link('network_surface_review.txt','Open Network Surface Review')} {link('runtime_review.txt','Open Runtime Review')}</div>
<div class="panel"><h3>Services & Privilege</h3><p>Services: <strong>{summary.get('service_count',0)}</strong> · Permission observations: <strong>{summary.get('permission_observation_count',0)}</strong> · SUID/SGID helpers: <strong>{summary.get('suid_helper_count',0)}</strong> · File capabilities: <strong>{summary.get('capability_count',0)}</strong></p>{link('service_review.txt','Open Service Review')} {link('permissions_review.txt','Open Permissions Review')}</div>
<div class="panel"><h3>Local Data & IPC</h3><p>Credential-storage indicators: <strong>{summary.get('credential_storage_count',0)}</strong> · Unix sockets: <strong>{summary.get('unix_socket_count',0)}</strong> · FIFOs: <strong>{summary.get('fifo_count',0)}</strong></p><p>D-Bus names: <strong>{summary.get('dbus_count',0)}</strong> · PolicyKit actions: <strong>{summary.get('polkit_count',0)}</strong></p>{link('local_storage_review.txt','Open Local Storage Review')} {link('ipc_review.txt','Open IPC Review')}</div>
<div class="panel"><h3>Software Update Surface</h3><p>Update endpoints: <strong>{summary.get('update_endpoint_count',0)}</strong> · Cleartext update indicators: <strong>{summary.get('cleartext_update_count',0)}</strong></p>{chips(summary.get('update_endpoints'))}{link('update_review.txt','Open Update Review')}</div></div>
<h2>Runtime Observation</h2><div class="metrics">{runtime_metrics}</div><p>{link('runtime_review.txt','Open Runtime Review')}</p>
<h2>Supporting Technical Artifacts</h2><div class="artifact-grid">{''.join(groups)}</div>
<p class="muted">README.txt describes export boundaries. SHA256SUMS.txt contains integrity hashes for the delivered appendix files.</p>
</main></body></html>'''

def _readme(assessment_name: str, source_version: str, mode: str, copied: list[str]) -> str:
    lines = [
        "UbuntuClientAssess Client Appendix",
        "==================================",
        "",
        f"Assessment: {assessment_name}",
        f"Source Framework: UbuntuClientAssess v{source_version}",
        f"Export Utility: UbuntuClientAssess v{VERSION}",
        f"Execution Mode: {mode}",
        f"Created: {now_iso()}",
        "",
        "Purpose",
        "-------",
        "This directory contains technical assessment artifacts selected for client delivery.",
        "Internal framework data, raw snapshots, tester workflow and assessment-coverage artifacts, automated finding candidates,",
        "tool/module QA output, and working files are intentionally excluded.",
        "",
        "Confirmed vulnerabilities and associated evidence should be documented in the final",
        "penetration test report. The files in this appendix are supporting technical artifacts.",
        "",
        "Included Technical Artifacts",
        "----------------------------",
    ]
    lines.extend(f"- {name}" for name in copied)
    lines += [
        "- assessment_report.html (client-safe appendix index generated during export)",
        "",
        "Intentionally Excluded",
        "----------------------",
    ]
    lines.extend(f"- {name}" for name in INTERNAL_EXCLUSIONS)
    lines += [
        "",
        "Integrity",
        "---------",
        "SHA256SUMS.txt contains SHA-256 hashes for the exported appendix files.",
        "The source assessment remains unchanged by this export.",
    ]
    return "\n".join(lines) + "\n"


def _write_checksums(appendix: Path) -> None:
    entries = []
    for path in sorted(appendix.iterdir(), key=lambda item: item.name.casefold()):
        if not path.is_file() or path.name == "SHA256SUMS.txt":
            continue
        digest = sha256_file(path)
        if digest is None:
            raise RuntimeError(f"Unable to hash exported file: {path.name}")
        entries.append(f"{digest}  {path.name}")
    write_text(appendix / "SHA256SUMS.txt", "\n".join(entries) + "\n")


def create_client_appendix(assessment_dir: Path) -> dict[str, object]:
    """Verify a finalized assessment and export only approved client-facing artifacts.

    The source assessment is never mutated except for creating/refreshing ClientAppendix/.
    Existing tester reports and working evidence remain in place.
    """
    assessment_dir = assessment_dir.expanduser().resolve()
    if not assessment_dir.is_dir():
        raise RuntimeError(f"Assessment directory does not exist: {assessment_dir}")

    manifest_path = assessment_dir / "assessment_manifest.json"
    metadata_path = assessment_dir / "assessment_metadata.json"
    if not manifest_path.is_file() or not metadata_path.is_file():
        raise RuntimeError("Assessment is not finalized: assessment manifest or metadata is missing")

    issues = verify_artifact_manifest(assessment_dir, allow_framework_version_mismatch=True, allow_methodology_version_mismatch=True)
    if issues:
        raise RuntimeError("Assessment integrity verification failed: " + "; ".join(issues))

    manifest = read_json(manifest_path)
    metadata = read_json(metadata_path)
    mode = str(manifest.get("mode") or metadata.get("mode") or "")
    approved = CLIENT_REPORTS_BY_MODE.get(mode)
    if approved is None:
        raise RuntimeError(f"Unsupported assessment mode for client appendix export: {mode or 'unknown'}")

    run_state = metadata.get("run_state") if isinstance(metadata.get("run_state"), dict) else {}
    if run_state.get("status") != "completed":
        raise RuntimeError(f"Assessment run_state is not completed: {run_state.get('status') or 'unknown'}")

    review_state_path = assessment_dir / "working" / "tester_review_state.json"
    if review_state_path.is_file():
        review_state = read_json(review_state_path)
        pending = [item for item in review_state.get("items", []) if item.get("status") == "PENDING"]
        if pending:
            raise RuntimeError(
                f"Tester review queue still contains {len(pending)} pending item(s); resolve them with --review before creating ClientAppendix"
            )

    reports = assessment_dir / "reports"
    missing = [name for name in approved if not (reports / name).is_file()]
    if missing:
        raise RuntimeError("Required client-facing reports are missing: " + ", ".join(missing))

    appendix = _safe_appendix_path(assessment_dir)
    _refresh_appendix_directory(appendix)

    copied: list[str] = []
    try:
        for name in approved:
            source = reports / name
            destination = appendix / name
            shutil.copy2(source, destination, follow_symlinks=False)
            if source.is_symlink() or destination.is_symlink():
                raise RuntimeError(f"Client-facing report must not be a symbolic link: {name}")
            if sha256_file(source) != sha256_file(destination):
                raise RuntimeError(f"Exported report hash mismatch: {name}")
            copied.append(name)

        assessment_name = str(metadata.get("assessment_name") or assessment_dir.name)
        source_version = str(manifest.get("framework_version") or metadata.get("version") or "unknown")
        summary = build_technical_summary(assessment_dir)
        write_text(appendix / "assessment_report.html", _client_index(assessment_name, source_version, mode, copied, summary))
        write_text(appendix / "README.txt", _readme(assessment_name, source_version, mode, copied))
        _write_checksums(appendix)
    except Exception:
        # Never leave a partially refreshed appendix that could be mistaken for complete delivery output.
        if appendix.is_dir() and not appendix.is_symlink():
            shutil.rmtree(appendix, ignore_errors=True)
        raise

    return {
        "path": appendix,
        "mode": mode,
        "source_version": str(manifest.get("framework_version") or "unknown"),
        "copied": copied,
        "generated": ["assessment_report.html", "README.txt", "SHA256SUMS.txt"],
        "excluded": list(INTERNAL_EXCLUSIONS),
    }
