from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable

from .app_scope import infer_application_roots_from_evidence
from .common import read_json, report_path, working_dir, write_json

STATIC_COVERAGE_MODULES = (
    "Application / Framework Profile",
    "Permissions Review",
    "ELF Security Review",
    "Network Surface Review",
    "Local Storage Review",
    "Update Mechanism Review",
    "Assessment Coverage",
)

_STATIC_PREFIXES = ("/opt/", "/usr/local/", "/usr/lib/", "/usr/libexec/", "/var/opt/", "/var/lib/")


def enrich_analysis_roots(existing_roots: Iterable[Path], diff: dict[str, Any]) -> list[Path]:
    """Add conservative application roots inferred from post-install evidence.

    New /opt and /usr/local roots are high-confidence installation locations.
    Other system roots are added only when also supported by a newly observed
    process path, avoiding ambient /var or /etc churn from widening scope.
    """
    roots = {Path(p).expanduser().resolve(strict=False) for p in existing_roots}
    evidence_paths = [Path(p) for p in (*diff.get("files_added", []), *diff.get("files_changed", []))]
    filesystem_roots = set(infer_application_roots_from_evidence(evidence_paths, ()))
    process_roots = set(infer_application_roots_from_evidence((), diff.get("processes_added", [])))
    # Process churn can include unrelated host applications. Treat /opt and
    # /usr/local process roots as high-confidence, but require corroborating
    # filesystem change evidence before adding roots under shared system trees
    # such as /usr/lib or /var/lib.
    for root in process_roots:
        text = str(root)
        if text.startswith(("/opt/", "/usr/local/")) or root in filesystem_roots:
            roots.add(root)
    for root in filesystem_roots:
        text = str(root)
        if text.startswith(("/opt/", "/usr/local/")) or root in process_roots:
            roots.add(root)
    return sorted(roots, key=str)


def detect_application_file_coverage_gaps(post_snapshot: dict[str, Any], roots: Iterable[Path]) -> list[dict[str, Any]]:
    """Identify application roots whose contents could not be recursively inspected."""
    fs = post_snapshot.get("filesystem", {}) if isinstance(post_snapshot.get("filesystem"), dict) else {}
    raw_gaps = post_snapshot.get("filesystem_collection_gaps", []) or []
    gaps: list[dict[str, Any]] = []
    for raw_root in roots:
        root = Path(raw_root).expanduser().resolve(strict=False)
        text = str(root)
        if not text.startswith(_STATIC_PREFIXES):
            continue
        root_meta = fs.get(text)
        if not root_meta or root_meta.get("type") != "directory":
            continue
        descendants = [p for p in fs if p != text and (p.startswith(text.rstrip("/") + "/"))]
        matching_errors = []
        for item in raw_gaps:
            p = Path(str(item.get("path") or "")).expanduser()
            try:
                matched = p == root or root in p.parents
            except Exception:
                matched = str(p).startswith(text.rstrip("/") + "/")
            if matched:
                matching_errors.append(item)
        inaccessible_now = False
        try:
            inaccessible_now = root.exists() and not os.access(root, os.R_OK | os.X_OK)
        except OSError:
            inaccessible_now = True
        if matching_errors or (not descendants and inaccessible_now):
            reasons = sorted({str(x.get("error") or x.get("operation") or "permission denied") for x in matching_errors})
            gaps.append({
                "path": text,
                "owner": str(root_meta.get("owner") or "unknown"),
                "group": str(root_meta.get("group") or "unknown"),
                "mode": str(root_meta.get("mode_octal") or root_meta.get("mode") or "unknown"),
                "captured_descendants": len(descendants),
                "reason": "; ".join(reasons) if reasons else "directory is not readable/traversable by the assessment user",
                "affected_coverage": [
                    "framework/technology identification",
                    "ELF/binary security review",
                    "permissions review of installed descendants",
                    "static endpoint/configuration discovery",
                    "local storage/configuration review",
                    "updater/component inspection",
                ],
            })
    return gaps


def load_post_snapshot(output_dir: Path) -> dict[str, Any]:
    path = working_dir(output_dir) / "snapshot_post.json"
    return read_json(path) if path.is_file() else {}


def coverage_detail(gaps: list[dict[str, Any]]) -> str:
    if not gaps:
        return "Identified application roots were recursively accessible to the assessment process"
    paths = ", ".join(str(x.get("path")) for x in gaps[:3])
    more = f" (+{len(gaps)-3} more)" if len(gaps) > 3 else ""
    return f"Static application-file coverage is limited; {len(gaps)} application root(s) could not be recursively inspected: {paths}{more}"


def apply_coverage_attention(statuses: dict[str, tuple[str, str]], gaps: list[dict[str, Any]]) -> None:
    detail = coverage_detail(gaps)
    statuses["Application File Coverage"] = ("ATTN" if gaps else "PASS", detail)
    if not gaps:
        return
    for name in STATIC_COVERAGE_MODULES:
        current_state, current_detail = statuses.get(name, ("PASS", ""))
        combined = detail if not current_detail else f"{current_detail}; {detail}"
        statuses[name] = ("ATTN" if current_state != "FAIL" else current_state, combined)


def append_coverage_notes(output_dir: Path, gaps: list[dict[str, Any]]) -> None:
    """Add explicit coverage context to existing tester-facing reports."""
    if not gaps:
        return
    lines = [
        "",
        "Application File Coverage Limitation",
        "------------------------------------",
        "UbuntuClientAssess identified one or more application installation roots that the assessment user could not recursively inspect.",
        "Zero-result sections in this report must not be interpreted as proof that no relevant application files or conditions exist.",
        "",
        "Affected roots:",
    ]
    for gap in gaps:
        lines.append(f"- {gap['path']} | owner={gap['owner']} group={gap['group']} mode={gap['mode']} | {gap['reason']}")
    lines += [
        "",
        "Affected coverage:",
        "- framework/technology identification",
        "- ELF/binary security review",
        "- permissions review of installed descendants",
        "- static endpoint/configuration discovery",
        "- local storage/configuration review",
        "- updater/component inspection",
        "",
        "Perform additional authorized inspection with sufficient filesystem visibility before treating these static-analysis areas as complete.",
    ]
    note = "\n".join(lines) + "\n"
    for name in (
        "application_profile.txt", "permissions_review.txt", "binary_security_review.txt",
        "network_surface_review.txt", "local_storage_review.txt", "update_review.txt",
    ):
        path = report_path(output_dir, name)
        if path.is_file():
            with path.open("a", encoding="utf-8") as handle:
                handle.write(note)
    write_json(working_dir(output_dir) / "application_file_coverage.json", {"limited": True, "gaps": gaps})
