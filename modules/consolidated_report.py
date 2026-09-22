from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
from typing import Any
import re
from urllib.parse import quote

from .common import (
    METHODOLOGY_VERSION,
    TEST_CASE_CATALOG_VERSION,
    read_json,
    report_path,
    reports_dir,
    write_text,
    working_dir,
)
from .security_model import MODEL_SCHEMA_VERSION
from .assessment_coverage import build_assessment_coverage
from .technical_summary import build_technical_summary
from .tester_review import category_progress, review_category, review_group, shared_validation_for

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

REPORT_PHASES = {
    "Reporting": ("findings.txt", "findings_summary.txt", "module_status.txt", "tool_detection.txt", "assessment_coverage.txt", "tester_review.txt", "evidence_guide.txt"),
    "Package / Application": ("installer_analysis.txt", "application_profile.txt"),
    "Installation / Privilege": ("install_changes.txt", "permissions_review.txt", "binary_security_review.txt", "service_review.txt", "persistence_review.txt"),
    "Runtime / Surface": ("runtime_review.txt", "network_surface_review.txt", "ipc_review.txt", "local_storage_review.txt", "update_review.txt"),
}

MODULE_REPORTS = {
    "Tool Detection": ("tool_detection.txt",), "Installer Analysis": ("installer_analysis.txt",),
    "Application / Framework Profile": ("application_profile.txt",), "Installation Differential": ("install_changes.txt",),
    "Permissions Review": ("permissions_review.txt",), "ELF Security Review": ("binary_security_review.txt",),
    "systemd Service Review": ("service_review.txt",), "Persistence Review": ("persistence_review.txt",),
    "Network Surface Review": ("network_surface_review.txt",), "IPC Review": ("ipc_review.txt",),
    "Local Storage Review": ("local_storage_review.txt",), "Update Mechanism Review": ("update_review.txt",),
    "Runtime Guidance": ("runtime_review.txt",), "Findings Generation": ("findings.txt", "findings_summary.txt"),
    "Security Correlation Model": (), "Assessment Coverage": ("assessment_coverage.txt",),
    "Tester Review Queue": ("tester_review.txt", "evidence_guide.txt"), "Artifact Inventory": ("artifact_manifest.txt",),
}

FINDING_SOURCES = {
    "Writable Path Referenced by Privileged systemd Service": ("systemd Service Review", ("service_review.txt", "permissions_review.txt")),
    "Writable ELF Library Search Path": ("ELF Security Review", ("binary_security_review.txt", "permissions_review.txt")),
    "Potential Software Update Retrieval over Cleartext HTTP": ("Update Mechanism Review", ("update_review.txt", "network_surface_review.txt")),
    "Potentially Unsafe sudoers Rule Introduced by Application": ("Persistence Review", ("persistence_review.txt", "permissions_review.txt")),
    "Potential Exposure of Local CA Private Signing Material": ("Local Storage Review", ("local_storage_review.txt", "network_surface_review.txt", "permissions_review.txt")),
}


def _text(value: object) -> str:
    return escape(str(value or ""), quote=True)


def _slug(value: object) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return slug or "item"


def _file_link(filename: str, directory: Path, label: str | None = None) -> str:
    if not (directory / filename).is_file():
        return ""
    return f'<a class="evidence-link" href="{quote(filename, safe="._-")}">{_text(label or filename)}</a>'


def _links(filenames: tuple[str, ...] | list[str], directory: Path) -> str:
    links = [_file_link(name, directory) for name in filenames]
    links = [x for x in links if x]
    return '<span class="muted">No linked tester report generated</span>' if not links else '<span class="link-list">' + "".join(links) + "</span>"


def _review_items(directory: Path) -> list[dict[str, Any]]:
    path = directory.parent / "working" / "tester_review_state.json"
    if not path.is_file():
        return []
    try:
        return list(read_json(path).get("items", []) or [])
    except Exception:
        return []


def _security_model(assessment_dir: Path) -> dict[str, Any]:
    path = working_dir(assessment_dir) / "security_model.json"
    if not path.is_file():
        return {}
    try:
        return read_json(path)
    except Exception:
        return {}


def _parse_findings(directory: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Prefer structured candidates; retain compatibility with older text reports."""
    store = directory.parent / "working" / "finding_candidates.json"
    reviews = _review_items(directory)
    review_by_identity = {str(x.get("identity") or ""): x for x in reviews}
    if store.is_file():
        try:
            payload = read_json(store)
            findings: list[dict[str, Any]] = []
            for raw in payload.get("findings", []) or []:
                review_identity = str(raw.get("review_identity") or "")
                review = review_by_identity.get(review_identity, {})
                record = dict(raw)
                record.update({
                    "id": str(raw.get("id") or "UAF"),
                    "title": str(raw.get("title") or "Finding Candidate"),
                    "severity": str(raw.get("severity") or "Unknown"),
                    "evidence": str(raw.get("evidence") or ""),
                    "status": str(review.get("status") or "PENDING"),
                    "review_id": str(review.get("id") or ""),
                    "notes": str(review.get("notes") or ""),
                })
                findings.append(record)
            return findings, list(payload.get("manual_review", []) or [])
        except Exception:
            pass

    path = directory / "findings.txt"
    if not path.is_file():
        return [], []
    content = path.read_text(encoding="utf-8", errors="replace")
    automatic, _, manual = content.partition("Manual Review Required\n")
    findings: list[dict[str, Any]] = []
    banner = re.compile(r"^=+\n\[FINDING CANDIDATE (UAF-\d+)\]\s+([A-Z]+)\s+\[([^\]]+)\]\n(.+)\n=+\n", re.MULTILINE)
    for fid, severity, status, title in banner.findall(automatic):
        findings.append({"id": fid, "title": title.title(), "severity": severity.title(), "evidence": "See findings.txt", "status": status, "review_id": "", "notes": ""})
    if not findings:
        pattern = re.compile(r"^\[(\d+)\] (.+)\n-+\nSeverity:\s+(.+)\nEvidence:\s+(.+)\nRecommendation:\s+(.+)$", re.MULTILINE)
        for finding_id, title, severity, evidence, recommendation in pattern.findall(automatic):
            findings.append({"id": f"UARP-{int(finding_id):03d}", "title": title.strip(), "severity": severity.strip(), "evidence": evidence.strip(), "status": "PENDING", "review_id": "", "notes": ""})
    manual_reviews: list[dict[str, Any]] = []
    review_pattern = re.compile(r"^\[R(\d+)\] (.+)\nEvidence:\s*(.+)\nAction:\s*(.+)$", re.MULTILINE)
    for review_id, title, evidence, action in review_pattern.findall(manual):
        manual_reviews.append({"id": f"REVIEW-{int(review_id):03d}", "title": title.strip(), "evidence": evidence.strip(), "action": action.strip()})
    return findings, manual_reviews


def _model_indexes(model: dict[str, Any]) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    objects = {str(x.get("id") or ""): x for x in model.get("objects", []) or []}
    observations = {str(x.get("id") or ""): x for x in model.get("observations", []) or []}
    correlations = {str(x.get("id") or ""): x for x in model.get("correlations", []) or []}
    return objects, observations, correlations


def _observation_context(ids: list[str], observations: dict[str, dict]) -> str:
    rows = []
    for obs_id in ids[:12]:
        obs = observations.get(str(obs_id), {})
        if not obs:
            rows.append(f'<li><code>{_text(obs_id)}</code></li>')
            continue
        rows.append(
            '<li><div><code>'+_text(obs_id)+'</code><div class="obs-summary">'+_text(obs.get("summary") or obs.get("category") or "Observation")+'</div></div>'
            '<span class="source-tag">'+_text(obs.get("source_module") or "unknown")+'</span></li>'
        )
    if not rows:
        return '<span class="muted">No structured observation references attached.</span>'
    return '<ul class="observation-list">'+"".join(rows)+'</ul>'


def _review_source_label(item: dict[str, Any]) -> str:
    source = str(item.get("generation_source") or "")
    if source == "correlation_engine":
        return "Correlation Engine"
    if source == "workflow_guidance" or str(item.get("category") or "") == "TECH":
        return "Workflow Guidance"
    if source == "compatibility_fallback":
        return "Compatibility Fallback"
    return "Legacy Analysis"


def _correlation_basis(item: dict[str, Any], model: dict[str, Any]) -> str:
    objects, observations, correlations = _model_indexes(model)
    corr_id = str(item.get("correlation_id") or "")
    corr = correlations.get(corr_id, {})
    if not corr and item.get("generation_source") != "correlation_engine":
        if _review_source_label(item) == "Legacy Analysis":
            return '<span class="muted">Generated by legacy analysis; structured correlation ownership has not migrated for this category.</span>'
        return '<span class="muted">This item is workflow guidance or a compatibility fallback rather than a structured security correlation.</span>'
    obj_ids = [str(x) for x in (corr.get("object_ids") or []) if str(x)]
    object_lines = []
    for object_id in obj_ids[:10]:
        obj = objects.get(object_id, {})
        kind = str(obj.get("kind") or "object").replace("_", " ").title()
        identity = str(obj.get("identity") or object_id)
        object_lines.append(f'<li><span class="object-kind">{_text(kind)}</span><code>{_text(identity)}</code></li>')
    object_html = '<ul class="relationship-tree">'+"".join(object_lines)+'</ul>' if object_lines else '<span class="muted">No canonical objects attached.</span>'
    obs_ids = [str(x) for x in (item.get("supporting_observation_ids") or corr.get("observation_ids") or []) if str(x)]
    rule = item.get("correlation_rule") or corr.get("rule_id") or "Structured correlation"
    strength = item.get("correlation_strength") or corr.get("strength") or ""
    rationale = item.get("correlation_rationale") or corr.get("rationale") or ""
    quality = item.get("evidence_quality") or corr.get("evidence_quality") or "N/A"
    source_modules = [str(x) for x in (item.get("source_modules") or corr.get("source_modules") or []) if str(x)]
    relationship_ids = [str(x) for x in (item.get("supporting_relationship_ids") or corr.get("relationship_ids") or []) if str(x)]
    evidence_refs = item.get("evidence_refs") or corr.get("evidence_refs") or []
    relationship_html = '<ul class="observation-list">'+''.join(f'<li><code>{_text(x)}</code></li>' for x in relationship_ids[:12])+'</ul>' if relationship_ids else '<span class="muted">No explicit relationship references attached.</span>'
    bookmark_rows = []
    for ref in evidence_refs[:12]:
        if isinstance(ref, dict):
            bookmark_rows.append('<li><div><code>'+_text(ref.get("bookmark") or "evidence")+'</code><div class="obs-summary">'+_text(ref.get("source_module") or "unknown source")+'</div></div></li>')
        else:
            bookmark_rows.append('<li><code>'+_text(ref)+'</code></li>')
    bookmark_html = '<ul class="observation-list">'+''.join(bookmark_rows)+'</ul>' if bookmark_rows else '<span class="muted">No structured evidence bookmarks attached.</span>'
    return (
        '<div class="correlation-block"><div class="mini-grid">'
        f'<div><span>Rule</span><strong>{_text(rule)}</strong></div>'
        f'<div><span>Strength</span><strong>{_text(strength or "N/A")}</strong></div>'
        f'<div><span>Evidence quality</span><strong>{_text(quality)}</strong></div>'
        f'<div><span>Sources</span><strong>{_text(", ".join(source_modules) or "N/A")}</strong></div>'
        f'<div><span>Correlation</span><strong><code>{_text(corr_id or "N/A")}</code></strong></div>'
        '</div>'
        + (f'<h4>Why this candidate exists</h4><p>{_text(rationale)}</p>' if rationale else '')
        + '<h4>Canonical objects</h4>'+object_html
        + '<h4>Supporting relationships</h4>'+relationship_html
        + '<h4>Supporting observations</h4>'+_observation_context(obs_ids, observations)
        + '<h4>Evidence bookmarks</h4>'+bookmark_html+'</div>'
    )


def _review_workspace(items: list[dict[str, Any]], directory: Path, model: dict[str, Any]) -> str:
    if not items:
        return '<div class="empty-state">No prioritized tester review items were generated.</div>'
    progress_cards = []
    for row in category_progress(items):
        progress_cards.append(
            '<div class="metric compact review-category-card">'
            f'<span>{_text(row["category"])}</span><strong>{row["completed"]} / {row["total"]}</strong>'
            f'<small>{row["pending"]} pending</small></div>'
        )
    category_html = '<div class="metrics review-category-metrics">'+''.join(progress_cards)+'</div>'

    queue = []
    details = []
    for index, item in enumerate(items):
        rid = str(item.get("id") or f"TRQ-{index+1:03d}")
        status = str(item.get("status") or "PENDING")
        priority = str(item.get("priority") or "MEDIUM")
        category = review_category(item)
        raw_category = str(item.get("category") or "OTHER")
        group_key = str(item.get("review_group") or review_group(item)[0])
        group_label = str(item.get("review_group_label") or review_group(item)[1])
        source = _review_source_label(item)
        runtime = bool(item.get("runtime_confirmed"))
        search = " ".join(str(item.get(k) or "") for k in ("id", "title", "condition", "why_it_matters", "category", "review_category", "review_group_label", "notes", "correlation_rule"))
        queue.append(
            f'<a href="#review-{_slug(rid)}" class="queue-item" data-review-target="review-{_slug(rid)}" '
            f'data-status="{_text(status)}" data-priority="{_text(priority)}" data-category="{_text(category)}" '
            f'data-source="{_text(source)}" data-runtime="{"yes" if runtime else "no"}" data-order="{index}" data-search="{_text(search.casefold())}">'
            f'<div class="queue-line"><strong>{_text(rid)}</strong><span class="badge disposition-{_slug(status)}">{_text(status)}</span></div>'
            f'<div class="queue-title">{_text(item.get("title") or "Review item")}</div>'
            f'<div class="queue-meta"><span class="badge priority-{_slug(priority)}">{_text(priority)}</span><span>{_text(category)}</span><span>{_text(group_label)}</span>{"<span>Runtime</span>" if runtime else ""}</div></a>'
        )
        runtime_html = ""
        if runtime:
            observations = "<br>".join(_text(x) for x in (item.get("runtime_observations") or [])[:8]) or "Observed during Guided Runtime Observation"
            runtime_html = f'<dt>Runtime confirmation</dt><dd><span class="runtime-pill">CONFIRMED</span><br>{observations}</dd>'
        notes = f'<dt>Tester notes</dt><dd>{_text(item.get("notes"))}</dd>' if item.get("notes") else ""
        related = list(item.get("related_reports") or []) or ["tester_review.txt", "evidence_guide.txt"]
        group_items = [x for x in items if review_category(x) == category and str(x.get("review_group") or review_group(x)[0]) == group_key]
        related_ids = [str(x.get("id") or "") for x in group_items]
        shared = list(item.get("shared_validation") or shared_validation_for(item))
        shared_html = ''
        if len(group_items) > 1 and shared:
            shared_html = (
                '<div class="detail-section shared-validation"><h4>Shared validation context</h4>'
                '<p class="muted">Establish these common facts once for the group and reuse the evidence when the underlying context has not changed. Distinct objects still require their own impact validation.</p>'
                '<ul class="validation-list">'+''.join(f'<li>{_text(x)}</li>' for x in shared)+'</ul>'
                f'<p><strong>Related review items:</strong> {_text(", ".join(related_ids))}</p></div>'
            )
        detail = (
            f'<article class="review-detail-panel" id="review-{_slug(rid)}" data-review-panel="review-{_slug(rid)}">'
            '<div class="finding-heading"><div><span class="finding-id">'+_text(rid)+'</span> '
            f'<span class="badge priority-{_slug(priority)}">{_text(priority)}</span></div><span class="badge disposition-{_slug(status)}">{_text(status)}</span></div>'
            f'<h3>{_text(item.get("title") or "Review item")}</h3><div class="detail-section"><h4>Assessment context</h4><dl>'
            f'<dt>Security area</dt><dd>{_text(category)}</dd><dt>Related group</dt><dd>{_text(group_label)}</dd><dt>Internal category</dt><dd>{_text(raw_category)}</dd><dt>Generation</dt><dd>{_text(source)}</dd>'
            f'<dt>Condition</dt><dd>{_text(item.get("condition"))}</dd>{runtime_html}'
            f'<dt>Why it matters</dt><dd>{_text(item.get("why_it_matters"))}</dd>{notes}'
            f'<dt>Related reports</dt><dd>{_links(related, directory)}</dd></dl></div>'
            + shared_html +
            '<div class="detail-section"><h4>Correlation basis</h4>'+_correlation_basis(item, model)+'</div>'
        )
        validation = [str(x) for x in (item.get("validation") or []) if str(x)]
        evidence = [str(x) for x in (item.get("evidence") or []) if str(x)]
        if validation or evidence:
            detail += '<div class="detail-section"><h4>Item-specific validation quick reference</h4>'
            if validation:
                detail += '<ol class="validation-list">'+"".join(f'<li>{_text(x)}</li>' for x in validation)+'</ol>'
            if evidence:
                detail += '<div class="command-list">'+"".join(f'<code>{_text(x)}</code>' for x in evidence[:10])+'</div>'
            detail += '</div>'
        detail += '</article>'
        details.append(detail)

    categories = [row["category"] for row in category_progress(items)]
    category_options = ''.join(f'<option value="{_text(x)}">{_text(x)}</option>' for x in categories)
    return (
        category_html +
        '<div class="review-toolbar"><label class="search-box">Search queue<input id="review-search" type="search" placeholder="TRQ, path, service, title…"></label>'
        '<label>Security area<select id="filter-category"><option value="">All</option>'+category_options+'</select></label>'
        '<label>Status<select id="filter-status"><option value="">All</option><option>PENDING</option><option>VALIDATED</option><option>NOT APPLICABLE</option><option>INFORMATIONAL</option></select></label>'
        '<label>Priority<select id="filter-priority"><option value="">All</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>'
        '<label>Source<select id="filter-source"><option value="">All</option><option>Correlation Engine</option><option>Workflow Guidance</option><option>Compatibility Fallback</option></select></label>'
        '<label>Runtime<select id="filter-runtime"><option value="">All</option><option value="yes">Confirmed</option><option value="no">Not confirmed</option></select></label>'
        '<button type="button" id="next-pending">Next pending</button><button type="button" id="clear-filters">Clear</button></div>'
        '<div class="review-workspace"><aside class="queue-list" id="review-queue">'+"".join(queue)+'</aside>'
        '<div class="review-detail" id="review-detail">'+"".join(details)+'</div></div>'
    )



def _finding_cards(findings: list[dict[str, Any]], directory: Path, model: dict[str, Any]) -> str:
    if not findings:
        return '<div class="empty-state">No automatic finding candidates were generated. This does not establish that the assessed software has no vulnerabilities.</div>'
    cards = []
    for finding in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(str(x.get("severity")), 99), str(x.get("title")).casefold())):
        module, filenames = FINDING_SOURCES.get(str(finding.get("title")), ("Supporting Review Reports", ("findings.txt",)))
        relation = finding.get("review_id") or "No dedicated review task linked"
        notes = f'<dt>Tester notes</dt><dd>{_text(finding.get("notes"))}</dd>' if finding.get("notes") else ""
        source = "Correlation Engine" if finding.get("generation_source") == "correlation_engine" else "Legacy Analysis"
        provenance = ""
        if finding.get("generation_source") == "correlation_engine":
            provenance = f'<dt>Generation</dt><dd>{_text(source)} · {_text(finding.get("correlation_rule"))} · {_text(finding.get("correlation_strength"))}</dd>'
        cards.append(
            f'<article class="finding severity-{_slug(finding.get("severity"))} status-card-{_slug(finding.get("status"))}" id="finding-{_slug(finding.get("id"))}">'
            '<div class="finding-heading">'
            f'<span class="finding-id">{_text(finding.get("id"))}</span><span><span class="badge severity-badge">{_text(finding.get("severity"))}</span> '
            f'<span class="badge disposition-{_slug(finding.get("status"))}">{_text(finding.get("status") or "PENDING")}</span></span></div>'
            f'<h3>{_text(finding.get("title"))}</h3><dl><dt>Classification</dt><dd>Automatic finding candidate — tester disposition required</dd>'
            f'<dt>Originating review</dt><dd>{_text(module)}</dd><dt>Related review item</dt><dd>{_text(relation)}</dd>{provenance}'
            f'<dt>Evidence summary</dt><dd>{_text(finding.get("evidence"))}</dd>{notes}'
            f'<dt>Supporting files</dt><dd>{_links(filenames, directory)}</dd></dl>'
            + ('<details class="inline-details"><summary>Structured correlation details</summary>'+_correlation_basis(finding, model)+'</details>' if finding.get("generation_source") == "correlation_engine" else '')
            + '</article>'
        )
    return "\n".join(cards)


def _manual_review_cards(reviews: list[dict[str, Any]]) -> str:
    if not reviews:
        return '<div class="empty-state">No separately tracked manual-review items were generated.</div>'
    return "\n".join('<article class="finding review"><h3>'+_text(x.get("title"))+'</h3><dl><dt>Evidence summary</dt><dd>'+_text(x.get("evidence"))+'</dd><dt>Required action</dt><dd>'+_text(x.get("action"))+'</dd></dl></article>' for x in reviews)


def _status_rows(status: dict[str, tuple[str, str]], directory: Path) -> str:
    return "\n".join(f'<tr id="module-{_slug(module)}"><td>{_text(module)}</td><td><span class="badge status-{_slug(state)}">{_text(state)}</span></td><td>{_text(detail or "Completed without additional detail")}</td><td>{_links(MODULE_REPORTS.get(module, ()), directory)}</td></tr>' for module, (state, detail) in status.items())


def _report_sections(directory: Path) -> str:
    sections = []
    for phase, filenames in REPORT_PHASES.items():
        present = [name for name in filenames if (directory / name).is_file()]
        if not present:
            continue
        body = '<ul class="evidence-list">' + "".join('<li>'+_file_link(name, directory)+f'<span class="file-meta">{(directory/name).stat().st_size:,} bytes</span></li>' for name in present) + '</ul>'
        sections.append(f'<details><summary>{_text(phase)} <span class="count">{len(present)}</span></summary>{body}</details>')
    return "\n".join(sections) or '<div class="empty-state">No tester reports were present.</div>'


def _status_from_report(assessment_dir: Path) -> dict[str, tuple[str, str]]:
    path = report_path(assessment_dir, "module_status.txt")
    if not path.is_file():
        return {}
    result: dict[str, tuple[str, str]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^\[([A-Z]+)\s*\]\s+(.+)$", line)
        if not match:
            continue
        state, remainder = match.groups()
        remainder = re.sub(r"\s+\([0-9.]+s\)", "", remainder)
        module, sep, detail = remainder.partition(" - ")
        result[module.strip()] = (state.strip(), detail.strip() if sep else "")
    return result


def _runtime_summary(model: dict[str, Any], directory: Path) -> tuple[int, str]:
    observations = [x for x in model.get("observations", []) or [] if str(x.get("source_module") or "") == "guided_runtime_observation"]
    counts = Counter(str(x.get("category") or "runtime") for x in observations)
    if not observations:
        return 0, '<div class="empty-state">Guided Runtime Observation has not enriched the structured model yet.</div>'
    labels = {
        "runtime_process": "Processes", "runtime_listener": "Listeners", "runtime_connection": "Connections",
        "runtime_unix_socket": "Unix sockets", "runtime_fifo": "FIFOs", "runtime_file_activity": "File activity",
    }
    cards = "".join(f'<div class="metric compact"><span>{_text(labels.get(key,key.replace("_"," ").title()))}</span><strong>{value}</strong></div>' for key, value in sorted(counts.items()))
    return len(observations), '<div class="metrics runtime-metrics">'+cards+'</div><p>'+_file_link("runtime_review.txt", directory, "Open runtime review")+'</p>'


def _correlation_summary(model: dict[str, Any]) -> str:
    correlations = list(model.get("correlations", []) or [])
    if not correlations:
        return '<div class="empty-state">No structured correlations are currently recorded.</div>'
    source_counts = Counter("Correlation Engine" if x.get("generation_source") == "correlation_engine" else "Legacy Bridge" for x in correlations)
    strength_counts = Counter(str(x.get("strength") or "Unspecified") for x in correlations)
    cross_module = sum(1 for x in correlations if x.get("cross_module"))
    suppressed = sum(1 for x in correlations if x.get("suppressed"))
    return (
        '<div class="metrics correlation-metrics">'
        f'<div class="metric compact"><span>Engine-owned</span><strong>{source_counts.get("Correlation Engine",0)}</strong></div>'
        f'<div class="metric compact"><span>Cross-module</span><strong>{cross_module}</strong></div>'
        f'<div class="metric compact"><span>Suppressed</span><strong>{suppressed}</strong></div>'
        f'<div class="metric compact"><span>Legacy bridge</span><strong>{source_counts.get("Legacy Bridge",0)}</strong></div>'
        f'<div class="metric compact"><span>STRONG</span><strong>{strength_counts.get("STRONG",0)}</strong></div>'
        f'<div class="metric compact"><span>REVIEW</span><strong>{strength_counts.get("REVIEW",0)}</strong></div></div>'
    )


def _technical_surface_dashboard(assessment_dir: Path, directory: Path) -> str:
    summary = build_technical_summary(assessment_dir)
    cards = [
        ("Services", summary.get("service_count", 0), ("service_review.txt", "permissions_review.txt")),
        ("Listeners", summary.get("network_listener_count", 0), ("network_surface_review.txt", "runtime_review.txt")),
        ("Cleartext endpoints", summary.get("cleartext_endpoint_count", 0), ("network_surface_review.txt",)),
        ("Credential indicators", summary.get("credential_storage_count", 0), ("local_storage_review.txt",)),
        ("Unix sockets / FIFOs", f"{summary.get('unix_socket_count',0)} / {summary.get('fifo_count',0)}", ("ipc_review.txt", "runtime_review.txt")),
        ("D-Bus / PolicyKit", f"{summary.get('dbus_count',0)} / {summary.get('polkit_count',0)}", ("ipc_review.txt",)),
        ("Update endpoints", summary.get("update_endpoint_count", 0), ("update_review.txt",)),
        ("Runtime observations", summary.get("runtime_process_count", 0) + summary.get("runtime_listener_count", 0) + summary.get("runtime_connection_observation_count", 0) + summary.get("runtime_socket_count", 0) + summary.get("runtime_fifo_count", 0) + summary.get("runtime_file_activity_count", 0), ("runtime_review.txt",)),
    ]
    blocks=[]
    for label,value,files in cards:
        blocks.append(f'<div class="summary-panel"><div class="label">{_text(label)}</div><div class="big">{_text(value)}</div><div>{_links(files,directory)}</div></div>')
    return '<p class="muted">Normalized technical surface derived from the primary structured assessment model.</p><div class="overview-grid">'+''.join(blocks)+'</div>'

def _coverage_dashboard(assessment_dir: Path, mode: str, profile_data: dict[str, Any]) -> str:
    records = build_assessment_coverage(assessment_dir, mode, profile_data)
    if not records:
        return '<div class="empty-state">No assessment coverage records were generated.</div>'
    rows = []
    for record in records:
        pending = int(record.get("pending_review_count") or 0)
        related = int(record.get("related_review_count") or 0)
        review_state = str(record.get("review_state") or "")
        if pending:
            state = f'{pending} pending'
            state_class = 'attn'
        elif related:
            state = 'Review items resolved'
            state_class = 'good'
        else:
            state = 'No specific candidate'
            state_class = 'neutral'
        runtime = str(record.get("runtime_state") or "")
        trqs = ', '.join(record.get("related_review_ids") or []) or 'None'
        reports = _links(tuple(record.get("reports") or []), reports_dir(assessment_dir))
        rows.append(
            f'<tr><td><strong>{_text(record.get("id"))}</strong><br><span class="muted">{_text(record.get("title"))}</span></td>'
            f'<td>{_text(record.get("automated"))}</td><td><span class="coverage-state {state_class}">{_text(state)}</span><br><span class="muted">{_text(trqs)}</span></td>'
            f'<td>{_text(runtime)}</td><td>{_text(record.get("manual_focus"))}</td><td>{reports}</td></tr>'
        )
    return (
        '<p class="muted">This is a generated coverage map, not a second validation queue. '
        'A row with no specific candidate still requires the tester to consider the manual focus for the assessed application.</p>'
        '<div class="table-wrap"><table class="coverage-table"><thead><tr><th>Coverage area</th><th>Automated</th><th>Review state</th><th>Runtime</th><th>Manual tester focus</th><th>Reports</th></tr></thead><tbody>'
        + ''.join(rows) + '</tbody></table></div>'
    )

def refresh_consolidated_report(assessment_dir: Path) -> Path:
    metadata = read_json(assessment_dir / "assessment_metadata.json")
    return generate_consolidated_report(
        assessment_dir,
        str(metadata.get("assessment_name") or assessment_dir.name),
        metadata.get("installer"),
        str(metadata.get("mode") or "full"),
        str(metadata.get("version") or "unknown"),
        _status_from_report(assessment_dir),
    )


def generate_consolidated_report(assessment_dir: Path, assessment_name: str, installer: str | Path | None, mode: str, version: str, status: dict[str, tuple[str, str]]) -> Path:
    directory = reports_dir(assessment_dir)
    output = report_path(assessment_dir, "assessment_report.html")
    findings, manual_reviews = _parse_findings(directory)
    review_items = _review_items(directory)
    model = _security_model(assessment_dir)
    module_counts = Counter(state.upper() for state, _ in status.values())
    severities = Counter(str(item.get("severity")) for item in findings)
    dispositions = Counter(str(item.get("status") or "PENDING") for item in review_items)
    finding_dispositions = Counter(str(item.get("status") or "PENDING") for item in findings)
    processing_coverage = "COMPLETE_WITH_REVIEW_ITEMS" if module_counts.get("ATTN") else "COMPLETE"
    if module_counts.get("WARN") or module_counts.get("FAIL"):
        processing_coverage = "INCOMPLETE"
    runtime_count, runtime_html = _runtime_summary(model, directory)
    correlation_owned = sum(1 for x in review_items if x.get("generation_source") == "correlation_engine")
    workflow_owned = sum(1 for x in review_items if _review_source_label(x) == "Workflow Guidance")
    compatibility_owned = len(review_items) - correlation_owned - workflow_owned
    attention = sum(module_counts.get(x, 0) for x in ("ATTN", "WARN", "FAIL"))
    status_cards = "".join(f'<div class="metric"><span>{state}</span><strong>{module_counts.get(state, 0)}</strong></div>' for state in ("PASS", "ATTN", "WARN", "FAIL", "SKIPPED"))
    review_cards = "".join(f'<div class="metric"><span>{label}</span><strong>{dispositions.get(key, 0)}</strong></div>' for key, label in (("PENDING","Pending"),("VALIDATED","Validated"),("NOT APPLICABLE","Not applicable"),("INFORMATIONAL","Informational")))
    severity_summary = " · ".join(f'{level}: {severities.get(level, 0)}' for level in ("Critical", "High", "Medium", "Low"))
    installer_name = Path(installer).name if installer else "Not supplied"
    manifest_state = "TRACKED" if (assessment_dir / "assessment_manifest.json").is_file() else "PENDING FINALIZATION"
    profile_path = working_dir(assessment_dir) / "application_profile.json"
    profile_data = read_json(profile_path) if profile_path.is_file() else {}
    coverage_html = _coverage_dashboard(assessment_dir, mode, profile_data)

    document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{_text(assessment_name)} — UbuntuClientAssess Tester Dashboard</title><style>
:root{{color-scheme:light dark;--bg:#09111e;--panel:#101a2c;--panel2:#17243a;--panel3:#1d2d47;--text:#e8eef7;--muted:#9fb0c8;--line:#2a3b56;--accent:#e95420;--accent2:#66c7ff;--pass:#36c98f;--warn:#f3bd4f;--fail:#ff6b78;--skip:#91a0b5;--shadow:0 10px 30px rgba(0,0,0,.18)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}a{{color:var(--accent2);text-decoration:none}}a:hover{{text-decoration:underline}}button,input,select{{font:inherit}}button,select,input{{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px 10px}}button{{cursor:pointer}}button:hover{{border-color:var(--accent2)}}code{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}}
header,main,footer{{width:min(1440px,calc(100% - 32px));margin:auto}}header{{padding:34px 0 22px}}h1{{margin:0 0 8px;font-size:clamp(28px,5vw,42px);line-height:1.1}}h2{{margin:34px 0 12px;font-size:24px}}h3{{margin:8px 0 16px}}h4{{margin:16px 0 8px;color:#c8d8ed}}.eyebrow{{color:var(--accent);font-weight:800;letter-spacing:.08em;text-transform:uppercase}}.meta{{color:var(--muted);display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:12px}}
nav{{position:sticky;top:0;z-index:10;background:color-mix(in srgb,var(--bg) 94%,transparent);backdrop-filter:blur(8px);border-block:1px solid var(--line)}}nav div{{width:min(1440px,calc(100% - 32px));margin:auto;display:flex;flex-wrap:wrap;gap:15px;padding:10px 0}}
.notice,.coverage,.finding,details,.table-wrap,.review-workspace,.summary-panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}}.notice{{padding:14px 17px;border-left:4px solid var(--warn)}}.coverage{{margin-top:20px;padding:18px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}}.coverage-grade{{font-size:18px;font-weight:800}}.metrics{{display:grid;grid-template-columns:repeat(5,minmax(80px,1fr));gap:9px;flex:1}}.review-metrics{{grid-template-columns:repeat(4,minmax(100px,1fr))}}.metric{{background:var(--panel2);padding:9px 12px;border-radius:9px;display:flex;justify-content:space-between;gap:10px}}.metric.compact{{min-width:140px}}.metric span,.muted,.file-meta{{color:var(--muted)}}.metric strong{{font-size:19px}}
.overview-grid{{display:grid;grid-template-columns:repeat(4,minmax(180px,1fr));gap:12px;margin:18px 0}}.summary-panel{{padding:16px}}.summary-panel .big{{font-size:30px;font-weight:800;line-height:1.1;margin:5px 0}}.summary-panel .label{{color:var(--muted)}}.summary-panel.attention{{border-color:#8a6429}}.summary-panel.good{{border-color:#246f55}}
.review-toolbar{{display:flex;flex-wrap:wrap;gap:9px;align-items:end;margin:12px 0}}.review-toolbar label{{display:grid;gap:4px;color:var(--muted);font-size:12px}}.search-box{{flex:1;min-width:240px}}.search-box input{{width:100%}}.review-workspace{{display:grid;grid-template-columns:minmax(300px,390px) 1fr;min-height:600px;overflow:hidden}}.queue-list{{border-right:1px solid var(--line);max-height:72vh;overflow:auto;background:#0d1727}}.queue-item{{display:block;padding:13px 14px;border-bottom:1px solid var(--line);color:var(--text);text-decoration:none}}.queue-item[hidden]{{display:none!important}}.queue-item:hover,.queue-item.active{{background:var(--panel3);text-decoration:none}}.queue-line{{display:flex;justify-content:space-between;gap:8px}}.queue-title{{font-weight:700;margin:6px 0}}.queue-meta{{display:flex;flex-wrap:wrap;gap:6px 10px;color:var(--muted);font-size:12px}}.review-detail{{padding:22px;max-height:72vh;overflow:auto}}.enhanced .review-detail-panel{{display:none}}.enhanced .review-detail-panel.active{{display:block}}.detail-section{{border-top:1px solid var(--line);padding-top:10px;margin-top:14px}}
.findings{{display:grid;gap:13px}}.finding{{padding:19px;scroll-margin-top:65px}}.finding-heading{{display:flex;justify-content:space-between;gap:12px}}.finding-id{{font-weight:800;color:var(--accent2)}}.severity-critical,.severity-high{{border-color:#9f3540}}.severity-medium{{border-color:#a8782d}}.review{{border-left:4px solid var(--warn)}}.badge{{display:inline-block;border-radius:999px;padding:2px 8px;font-size:11px;font-weight:800;letter-spacing:.03em}}.severity-badge{{background:var(--panel2);border:1px solid currentColor}}.disposition-validated{{background:var(--pass);color:#071a12}}.disposition-not-applicable{{background:var(--skip);color:#101722}}.disposition-informational{{background:var(--accent2);color:#06131c}}.disposition-pending{{background:var(--warn);color:#2b1c00}}.priority-high{{border:1px solid var(--fail)}}.priority-medium{{border:1px solid var(--warn)}}.priority-low{{border:1px solid var(--skip)}}.runtime-pill{{display:inline-block;background:#234f70;color:#d8efff;border-radius:999px;padding:2px 8px;font-weight:800;font-size:11px}}.source-tag{{color:var(--muted);font-size:11px}}
.status-pass{{color:#071a12;background:var(--pass)}}.status-attn,.status-warn{{color:#2b1c00;background:var(--warn)}}.status-fail{{color:#2b0509;background:var(--fail)}}.status-skipped{{color:#101722;background:var(--skip)}}dl{{display:grid;grid-template-columns:180px 1fr;gap:8px 16px;margin:0}}dt{{color:var(--muted);font-weight:700}}dd{{margin:0;overflow-wrap:anywhere}}.mini-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}}.mini-grid>div{{background:var(--panel2);border-radius:8px;padding:9px;display:grid;gap:3px}}.mini-grid span{{color:var(--muted);font-size:11px}}.relationship-tree,.observation-list{{list-style:none;padding:0;margin:0;display:grid;gap:6px}}.relationship-tree li,.observation-list li{{background:var(--panel2);border-radius:8px;padding:8px 10px;display:flex;gap:10px;justify-content:space-between;align-items:start}}.object-kind{{min-width:100px;color:var(--muted)}}.obs-summary{{margin-top:3px}}.validation-list{{padding-left:22px}}.command-list{{display:grid;gap:6px}}.command-list code{{background:#08101c;border:1px solid var(--line);border-radius:7px;padding:8px;display:block}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:760px}}th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}thead th{{background:var(--panel2);position:sticky;top:0}}.link-list{{display:flex;flex-wrap:wrap;gap:6px}}.evidence-link{{display:inline-block;background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:2px 7px}}details{{margin:9px 0;padding:4px 13px}}summary{{cursor:pointer;font-weight:750;padding:9px 0}}.inline-details{{box-shadow:none;margin-top:14px;background:var(--panel2)}}.count{{background:var(--panel2);border-radius:999px;padding:1px 7px;color:var(--muted)}}.evidence-list{{list-style:none;padding:0 0 8px;margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:7px}}.evidence-list li{{display:flex;align-items:center;justify-content:space-between;gap:8px;background:var(--panel2);border-radius:8px;padding:8px}}.empty-state{{padding:24px;color:var(--muted);border:1px dashed var(--line);border-radius:12px}}footer{{color:var(--muted);padding:38px 0}}
@media(max-width:980px){{.overview-grid{{grid-template-columns:repeat(2,1fr)}}.review-workspace{{grid-template-columns:1fr}}.queue-list{{max-height:340px;border-right:0;border-bottom:1px solid var(--line)}}.review-detail{{max-height:none}}}}@media(max-width:700px){{.metrics,.review-metrics,.mini-grid,.overview-grid{{grid-template-columns:1fr 1fr}}dl{{grid-template-columns:1fr}}}}@media print{{:root{{color-scheme:light;--bg:#fff;--panel:#fff;--panel2:#f4f6f8;--panel3:#eef2f6;--text:#111;--muted:#4b5563;--line:#d2d7de;--accent:#a83200}}nav,.review-toolbar,.queue-list{{display:none!important}}body{{font-size:11px}}a{{color:inherit}}.review-workspace{{display:block;box-shadow:none;border:0}}.review-detail{{max-height:none;padding:0;overflow:visible}}.enhanced .review-detail-panel{{display:block!important;page-break-inside:avoid}}}}
</style><script>document.documentElement.classList.add('enhanced');</script></head><body>
<header><div class="eyebrow">UbuntuClientAssess v{_text(version)}</div><h1>{_text(assessment_name)}</h1><div class="meta"><span>Installer: {_text(installer_name)}</span><span>Mode: {_text(mode)}</span><span>Methodology: {_text(METHODOLOGY_VERSION)}</span><span>Coverage catalog: {_text(TEST_CASE_CATALOG_VERSION)}</span><span>Security model: schema {_text(model.get("schema_version") or MODEL_SCHEMA_VERSION)}</span><span>Offline tester dashboard</span></div><div class="coverage"><div><div class="muted">Assessment processing</div><div class="coverage-grade">{_text(processing_coverage)}</div></div><div class="metrics">{status_cards}</div></div></header>
<nav><div><a href="#overview">Overview</a><a href="#technical-surface">Technical surface</a><a href="#assessment-coverage">Coverage</a><a href="#tester-review">Review workspace</a><a href="#review-points">Finding candidates</a><a href="#correlation-view">Correlation</a><a href="#runtime-activity">Runtime</a><a href="#module-status">Modules</a><a href="#evidence-index">Artifacts</a>{_file_link("tester_review.txt", directory, "Queue TXT")}{_file_link("findings.txt", directory, "Findings TXT")}</div></nav>
<main><p class="notice"><strong>Read-only dashboard:</strong> use UbuntuClientAssess Guided Review to change dispositions or notes. This HTML is regenerated from authoritative review state; manual edits intentionally do not update assessment state.</p>
<section id="overview"><h2>Assessment Overview</h2><div class="overview-grid"><div class="summary-panel"><div class="label">Pending review</div><div class="big">{dispositions.get('PENDING',0)}</div><div>{len(review_items)} total review items</div></div><div class="summary-panel"><div class="label">Finding candidates</div><div class="big">{len(findings)}</div><div>{_text(severity_summary)}</div></div><div class="summary-panel {'attention' if attention else 'good'}"><div class="label">Modules needing attention</div><div class="big">{attention}</div><div>{module_counts.get('PASS',0)} modules passed</div></div><div class="summary-panel"><div class="label">Runtime / integrity</div><div class="big">{'YES' if runtime_count else 'NO'}</div><div>Runtime enriched · Manifest {_text(manifest_state)}</div></div></div><div class="metrics review-metrics">{review_cards}</div></section>
<section id="technical-surface"><h2>Technical Surface</h2>{_technical_surface_dashboard(assessment_dir,directory)}</section>
<section id="assessment-coverage"><h2>Assessment Coverage</h2>{coverage_html}</section>
<section id="tester-review"><h2>Tester Review Workspace</h2><p class="muted">Filter the queue and select an item to keep the condition, correlation basis, runtime evidence, validation steps, notes, and supporting reports in one view. {correlation_owned} items are correlation-engine generated; {workflow_owned} are workflow guidance; {compatibility_owned} use compatibility fallback.</p>{_review_workspace(review_items,directory,model)}</section>
<section id="review-points"><h2>Automatic Finding Candidates</h2><p class="muted">{len(findings)} total · {_text(severity_summary)} · Pending: {finding_dispositions.get('PENDING',0)} · Validated: {finding_dispositions.get('VALIDATED',0)} · Not applicable: {finding_dispositions.get('NOT APPLICABLE',0)} · Informational: {finding_dispositions.get('INFORMATIONAL',0)}</p><div class="findings">{_finding_cards(findings,directory,model)}</div></section>
<section id="correlation-view"><h2>Correlation Model</h2><p class="muted">Structured correlation is intentionally shown as evidence relationships rather than an automatic final vulnerability decision.</p>{_correlation_summary(model)}</section>
<section id="runtime-activity"><h2>Runtime Activity</h2>{runtime_html}</section>
<section id="manual-items"><h2>Explicit Manual-Review Items</h2><p class="muted">Items that require tester resolution but are not automatically severity-rated.</p><div class="findings">{_manual_review_cards(manual_reviews)}</div></section>
<section id="module-status"><h2>Module Health and Evidence</h2><div class="table-wrap"><table><thead><tr><th>Module</th><th>Status</th><th>Details</th><th>Supporting reports</th></tr></thead><tbody>{_status_rows(status,directory)}</tbody></table></div></section>
<section id="evidence-index"><h2>Assessment Artifacts</h2>{_report_sections(directory)}</section></main><footer>Generated locally by UbuntuClientAssess v{_text(version)}. No external scripts, fonts, styles, or network resources are used.</footer>
<script>
(function(){{
 const q=s=>document.querySelector(s), qa=s=>Array.from(document.querySelectorAll(s));
 const items=()=>qa('.queue-item');
 function select(el){{if(!el||el.hidden)return;items().forEach(x=>x.classList.remove('active'));qa('.review-detail-panel').forEach(x=>x.classList.remove('active'));el.classList.add('active');const p=document.getElementById(el.dataset.reviewTarget);if(p)p.classList.add('active');}}
 function filter(){{const term=(q('#review-search')?.value||'').trim().toLowerCase(), category=q('#filter-category')?.value||'', status=q('#filter-status')?.value||'', priority=q('#filter-priority')?.value||'', source=q('#filter-source')?.value||'', runtime=q('#filter-runtime')?.value||'', queue=q('#review-queue');const matched=[],unmatched=[];items().forEach(el=>{{const ok=(!term||el.dataset.search.includes(term))&&(!category||el.dataset.category===category)&&(!status||el.dataset.status===status)&&(!priority||el.dataset.priority===priority)&&(!source||el.dataset.source===source)&&(!runtime||el.dataset.runtime===runtime);el.hidden=!ok;(ok?matched:unmatched).push(el);}});matched.sort((a,b)=>(+a.dataset.order)-(+b.dataset.order));unmatched.sort((a,b)=>(+a.dataset.order)-(+b.dataset.order));if(queue){{[...matched,...unmatched].forEach(el=>queue.appendChild(el));queue.scrollTop=0;}}const active=q('.queue-item.active');if(!active||active.hidden)select(matched[0]||null);}}
 items().forEach(el=>el.addEventListener('click',e=>{{e.preventDefault();select(el);history.replaceState(null,'','#'+el.dataset.reviewTarget);}}));
 ['#review-search','#filter-category','#filter-status','#filter-priority','#filter-source','#filter-runtime'].forEach(sel=>q(sel)?.addEventListener(sel==='#review-search'?'input':'change',filter));
 q('#clear-filters')?.addEventListener('click',()=>{{q('#review-search').value='';['#filter-category','#filter-status','#filter-priority','#filter-source','#filter-runtime'].forEach(s=>q(s).value='');filter();}});
 q('#next-pending')?.addEventListener('click',()=>{{const visible=items().filter(x=>!x.hidden&&x.dataset.status==='PENDING');if(!visible.length)return;const current=q('.queue-item.active');let i=visible.indexOf(current);select(visible[(i+1)%visible.length]);}});
 const fromHash=location.hash?document.querySelector('[data-review-target="'+location.hash.slice(1)+'"]'):null;select(fromHash||items().find(x=>!x.hidden));filter();
}})();
</script></body></html>'''
    write_text(output, document)
    return output
