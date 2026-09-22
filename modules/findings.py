from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any
import re

from .common import read_json, report_path, working_dir, write_json, write_text
from .tester_review import stable_review_identity
from .validation_guidance import playbook_for, render_playbook_lines

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CANDIDATE_STORE = "finding_candidates.json"



CORRELATION_OWNED_KINDS = {
    "privileged_service_writable_path",
    "writable_elf_search_path",
    "cleartext_update_path",
    "unsafe_sudo_policy",
    "exposed_local_ca_private_key",
}


def _correlation_owned_findings(output_dir: Path) -> list[dict[str, Any]]:
    """Render the v1.5.2 authoritative finding slice from security_model.json."""
    model_path = working_dir(output_dir) / "security_model.json"
    if not model_path.is_file():
        return []
    model = read_json(model_path)
    objects = {str(item.get("id")): item for item in model.get("objects", []) or []}
    observations = {str(item.get("id")): item for item in model.get("observations", []) or []}
    findings: list[dict[str, Any]] = []

    for corr in model.get("correlations", []) or []:
        kind = str(corr.get("kind") or "")
        if kind not in CORRELATION_OWNED_KINDS or not corr.get("drives_finding"):
            continue
        obs_ids = [str(x) for x in (corr.get("observation_ids") or []) if str(x)]
        obj_ids = [str(x) for x in (corr.get("object_ids") or []) if str(x)]
        provenance = {
            "generation_source": "correlation_engine",
            "correlation_id": str(corr.get("id") or ""),
            "correlation_rule": str(corr.get("rule_id") or ""),
            "correlation_strength": str(corr.get("strength") or ""),
            "supporting_observation_ids": obs_ids,
            "supporting_relationship_ids": [str(x) for x in (corr.get("relationship_ids") or []) if str(x)],
            "source_modules": [str(x) for x in (corr.get("source_modules") or []) if str(x)],
            "cross_module": bool(corr.get("cross_module")),
            "evidence_quality": str(corr.get("evidence_quality") or ""),
            "correlation_rationale": str(corr.get("rationale") or ""),
            "evidence_refs": list(corr.get("evidence_refs") or []),
        }

        if kind == "privileged_service_writable_path":
            service_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "service"), {})
            path_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") in {"file", "directory", "fifo", "unix_socket", "symlink"}), {})
            service_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "service_dependency"), {})
            attrs = service_obs.get("attributes") or {}
            unit = str(service_obj.get("identity") or "unknown.service")
            path = str(path_obj.get("identity") or attrs.get("path") or "unknown path")
            path_type = str(attrs.get("path_type") or "ReferencedPath")
            concerns = str(attrs.get("concerns") or "lower-privileged write concern")
            role_label = _service_path_label(path_type)
            findings.append({
                "identity": str(corr.get("finding_identity") or f"service:{unit}:{path_type}:{path}"),
                "review_identity": str(corr.get("review_identity") or ""),
                "category": "SVC", "severity": "High",
                "title": "Writable Path Referenced by Privileged systemd Service",
                "condition": f"{unit} execution chain consumes {role_label} {path}: {concerns}.",
                "evidence": f"{unit} - {role_label}: {path} ({concerns})",
                "validation_evidence": [f"systemctl cat {unit}", f"namei -l {path}", f"getfacl {path}"],
                "service_unit": unit, "service_path": path, "service_path_type": path_type,
                **provenance,
            })

        elif kind == "writable_elf_search_path":
            binaries = sorted(str(objects[x].get("identity")) for x in obj_ids if x in objects and objects[x].get("kind") == "binary")
            elf_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "elf_search_path"), {})
            attrs = elf_obs.get("attributes") or {}
            search_kind = str(attrs.get("kind") or "RPATH")
            search_path = str(attrs.get("search_path") or "")
            concern = str(attrs.get("concern") or "unsafe search-path condition")
            affected = ", ".join(binaries)
            display_path = search_path or "<empty/current directory>"
            condition = (f"{affected}: {search_kind}={display_path}; {concern}." if len(binaries) == 1
                         else f"{len(binaries)} application binaries share {search_kind}={display_path}; {concern}. Affected binaries: {affected}.")
            evidence = (f"{binaries[0]} - {search_kind}={display_path} - {concern}" if len(binaries) == 1
                        else f"{search_kind}={display_path} - {concern}; affected binaries: {affected}")
            validation_evidence: list[str] = []
            for binary in binaries:
                validation_evidence.extend([f"readelf -d {binary}", f"checksec --file={binary}"])
            findings.append({
                "identity": str(corr.get("finding_identity") or f"elf-group:{search_kind}:{search_path}:{concern}"),
                "review_identity": str(corr.get("review_identity") or ""),
                "category": "ELF", "severity": "Medium",
                "title": "Writable ELF Library Search Path",
                "condition": condition, "evidence": evidence,
                "validation_targets": binaries, "search_path": search_path, "search_kind": search_kind,
                "validation_evidence": validation_evidence, **provenance,
            })

        elif kind == "cleartext_update_path":
            endpoint_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "update_endpoint"), {})
            url = str(endpoint_obj.get("identity") or "")
            locations: list[str] = []
            for obs_id in obs_ids:
                obs = observations.get(obs_id) or {}
                if obs.get("category") != "cleartext_update_endpoint":
                    continue
                attrs = obs.get("attributes") or {}
                location = f"{attrs.get('path')}:{attrs.get('line')}; confidence: {attrs.get('confidence')}"
                if location not in locations:
                    locations.append(location)
            findings.append({
                "identity": str(corr.get("finding_identity") or f"update:{url}"),
                "review_identity": str(corr.get("review_identity") or ""),
                "category": "UPD", "severity": "Medium",
                "title": "Potential Software Update Retrieval over Cleartext HTTP",
                "condition": f"Probable update endpoint: {url}",
                "evidence": f"{url} ({'; '.join(locations)})",
                "validation_evidence": ["Capture the updater process, destination, transport, and signature/checksum validation behavior."],
                **provenance,
            })

        elif kind == "unsafe_sudo_policy":
            sudo_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "sudo_rule"), {})
            sudo_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "sudo_policy"), {})
            obj_attrs = sudo_obj.get("attributes") or {}
            obs_attrs = sudo_obs.get("attributes") or {}
            runas = str(obj_attrs.get("runas") or "root")
            command = str(obj_attrs.get("command") or "unknown")
            concerns = "; ".join(str(x) for x in (obs_attrs.get("concerns") or [])) or "Privileged sudo rule requires validation"
            findings.append({
                "identity": str(corr.get("finding_identity") or f"sudo:{runas}:{command}"),
                "review_identity": str(corr.get("review_identity") or ""),
                "category": "PERS", "severity": "High",
                "title": "Potentially Unsafe sudoers Rule Introduced by Application",
                "condition": f"Run as {runas}: {command} ({concerns})",
                "evidence": f"Run as {runas}: {command} ({concerns})",
                "validation_evidence": ["sudo visudo -c", "sudo -l"],
                **provenance,
            })

        elif kind == "exposed_local_ca_private_key":
            key_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") in {"file", "directory", "symlink"}), {})
            crypto_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "cryptographic_material"), {})
            attrs = crypto_obs.get("attributes") or {}
            path = str(key_obj.get("identity") or "")
            certs = sorted(str(objects[x].get("identity")) for x in obj_ids if x in objects and objects[x].get("kind") == "certificate")
            permission = str(attrs.get("permission") or "")
            cert_text = ", ".join(certs)
            findings.append({
                "identity": str(corr.get("finding_identity") or f"crypto-ca:{path}"),
                "review_identity": str(corr.get("review_identity") or ""),
                "category": "CRYPTO", "severity": "High",
                "title": "Potential Exposure of Local CA Private Signing Material",
                "condition": f"{path} contains private signing material; permission context: {permission}; related CA certificate(s): {cert_text}.",
                "evidence": f"{path} - private signing material detected; values redacted; {permission}; related CA certificate(s): {cert_text}",
                "validation_evidence": [f"stat {path}", f"namei -l {path}", f"getfacl {path}"],
                "crypto_path": path,
                "crypto_certificates": certs,
                **provenance,
            })
    return findings


def _apply_correlation_finding_ownership(output_dir: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    generated = _correlation_owned_findings(output_dir)
    if not generated:
        return findings
    owned = {str(item.get("identity")) for item in generated}
    return [item for item in findings if str(item.get("identity")) not in owned] + generated

def _deduplicate_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Collapse equivalent candidates while preserving structured validation data."""
    unique: dict[tuple[str, ...], dict[str, Any]] = {}
    for finding in findings:
        identity = str(finding.get("identity", "")).strip().casefold()
        if identity:
            key = (identity,)
        else:
            evidence = " ".join(str(finding.get("evidence", "")).split()).casefold()
            evidence = re.sub(r":\d+(?=[;)])", ":<line>", evidence)
            key = (str(finding.get("title", "")).strip().casefold(), evidence)
        current = unique.get(key)
        if current is None or SEVERITY_RANK.get(str(finding.get("severity", "")), 0) > SEVERITY_RANK.get(str(current.get("severity", "")), 0):
            unique[key] = finding
    return list(unique.values()), len(findings) - len(unique)


def _review_state(output_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    path = working_dir(output_dir) / "tester_review_state.json"
    if not path.is_file():
        return {}, {}
    try:
        state = read_json(path)
    except Exception:
        return {}, {}
    by_identity: dict[str, dict[str, Any]] = {}
    id_by_identity: dict[str, str] = {}
    for item in state.get("items", []) or []:
        identity = str(item.get("identity") or "")
        if not identity:
            continue
        by_identity[identity] = item
        if item.get("id"):
            id_by_identity[identity] = str(item["id"])
    return by_identity, id_by_identity


def _candidate_status(finding: dict[str, Any], by_identity: dict[str, dict[str, Any]]) -> str:
    review_identity = str(finding.get("review_identity") or "")
    if review_identity and review_identity in by_identity:
        return str(by_identity[review_identity].get("status") or "PENDING").upper()
    return "PENDING"



def _service_path_label(path_type: str) -> str:
    return {
        "ExecStart": "ExecStart executable",
        "EnvironmentFile": "EnvironmentFile",
        "WorkingDirectory": "working directory",
        "UnitFile": "systemd unit file",
        "DropIn": "systemd drop-in",
        "ConfigurationDependency": "configuration/data dependency",
        "ReferencedPath": "referenced path",
    }.get(str(path_type), str(path_type) or "referenced path")

def _candidate_store_path(output_dir: Path) -> Path:
    return working_dir(output_dir) / CANDIDATE_STORE


def _render_reports(output_dir: Path, payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = list(payload.get("findings", []) or [])
    manual_review = list(payload.get("manual_review", []) or [])
    duplicates_suppressed = int(payload.get("duplicates_suppressed", 0) or 0)
    review_by_identity, review_id_by_identity = _review_state(output_dir)

    lines = [
        "Findings", "=" * 8, "",
        "IMPORTANT - GENERATED ASSESSMENT ARTIFACT",
        "-----------------------------------------",
        "Finding statuses and dispositions in this file are generated from UbuntuClientAssess Guided Review.",
        "Do not manually edit PENDING, VALIDATED, NOT APPLICABLE, or INFORMATIONAL tags in this report.",
        "Manual edits intentionally invalidate assessment integrity; use Assessment Status / Recovery to regenerate derived reports from trusted internal state.",
        "",
        "This file contains automatically correlated finding candidates that require tester disposition before client reporting.",
        "Broader observations remain in the individual review reports. A candidate is not a confirmed vulnerability until the tester marks its related review task VALIDATED.",
        f"Duplicate candidates suppressed: {duplicates_suppressed}",
        "",
    ]

    if findings:
        ordered = sorted(
            findings,
            key=lambda x: (-SEVERITY_RANK.get(str(x.get("severity") or ""), 0), str(x.get("title") or "").casefold(), str(x.get("identity") or "")),
        )
        for idx, finding in enumerate(ordered, 1):
            finding_id = str(finding.get("id") or f"UAF-{idx:03d}")
            finding["id"] = finding_id
            status = _candidate_status(finding, review_by_identity)
            finding["status"] = status
            review_identity = str(finding.get("review_identity") or "")
            related_review_id = review_id_by_identity.get(review_identity)
            title = str(finding.get("title") or "Finding Candidate")
            banner = f"[FINDING CANDIDATE {finding_id}]  {finding.get('severity', 'Unknown').upper()}  [{status}]"
            lines += [
                "=" * 96,
                banner,
                title.upper(),
                "=" * 96,
                "",
                f"Severity:       {finding.get('severity', 'Unknown')}",
                f"Status:         {status}",
            ]
            if related_review_id:
                lines.append(f"Related Review: {related_review_id}")
            if finding.get("generation_source") == "correlation_engine":
                lines += [
                    "Generation:     Correlation Engine",
                    f"Rule:           {finding.get('correlation_rule') or 'structured correlation'}",
                    f"Correlation:    {finding.get('correlation_id') or ''}",
                ]
                supporting = [str(x) for x in (finding.get("supporting_observation_ids") or []) if str(x)]
                if supporting:
                    lines.append("Observations:   " + ", ".join(supporting))
            lines += [
                "",
                "Observed Condition",
                "------------------",
                str(finding.get("evidence") or "No evidence summary supplied."),
                "",
                "VALIDATION PROCEDURE",
                "====================",
                "",
            ]
            synthetic = {
                "category": finding.get("category", ""),
                "title": title,
                "condition": finding.get("condition") or finding.get("evidence", ""),
                "evidence": list(finding.get("validation_evidence", []) or [finding.get("evidence", "")]),
                "validation": [],
                "validation_targets": finding.get("validation_targets", []),
                "search_path": finding.get("search_path"),
                "search_kind": finding.get("search_kind"),
                "service_unit": finding.get("service_unit"),
                "service_path": finding.get("service_path"),
                "service_path_type": finding.get("service_path_type"),
                "crypto_path": finding.get("crypto_path"),
                "crypto_certificates": finding.get("crypto_certificates", []),
            }
            lines += render_playbook_lines(playbook_for(synthetic))
            if review_identity and review_identity in review_by_identity:
                notes = str(review_by_identity[review_identity].get("notes") or "").strip()
                if notes:
                    lines += ["Tester Notes", "------------", notes, ""]
    else:
        lines += ["No correlated automatic finding candidates were generated.", ""]

    lines += ["Manual Review Required", "----------------------"]
    if manual_review:
        lines += [
            "These entries are not counted as severity-rated automatic finding candidates, but they must be resolved before assessment closeout.",
            "",
        ]
        for idx, item in enumerate(manual_review, 1):
            lines += [
                f"[R{idx}] {item.get('title', 'Manual Review Required')}",
                f"Evidence: {item.get('evidence', 'No evidence detail supplied')}",
                f"Action:   {item.get('action', 'Validate the condition manually.')}",
                "",
            ]
    else:
        lines += ["None generated.", ""]
    write_text(report_path(output_dir, "findings.txt"), "\n".join(lines))

    severity_counts = Counter(str(f.get("severity") or "Unknown") for f in findings)
    status_counts = Counter(_candidate_status(f, review_by_identity) for f in findings)
    summary = [
        "Findings Summary", "=" * 16, "",
        f"High:   {severity_counts.get('High', 0)}",
        f"Medium: {severity_counts.get('Medium', 0)}",
        f"Low:    {severity_counts.get('Low', 0)}",
        f"Total:  {len(findings)}",
        "",
        "Candidate Disposition",
        "---------------------",
        f"Pending:        {status_counts.get('PENDING', 0)}",
        f"Validated:      {status_counts.get('VALIDATED', 0)}",
        f"Not applicable: {status_counts.get('NOT APPLICABLE', 0)}",
        f"Informational:  {status_counts.get('INFORMATIONAL', 0)}",
        "",
        f"Manual review required: {len(manual_review)}",
        f"Duplicate candidates suppressed: {duplicates_suppressed}",
        "",
        "Only correlated pentest-relevant candidates are counted. Tester disposition is required before client reporting.",
    ]
    write_text(report_path(output_dir, "findings_summary.txt"), "\n".join(summary))
    return findings


def refresh_findings_dispositions(output_dir: Path) -> list[dict[str, Any]]:
    """Refresh findings.txt/summary from structured candidates and current review state."""
    path = _candidate_store_path(output_dir)
    if not path.is_file():
        return []
    return _render_reports(output_dir, read_json(path))


def _generate_findings_compatibility(
    output_dir: Path,
    permission_data: dict[str, Any],
    network_data: dict[str, Any],
    service_data: dict[str, Any],
    elf_data: dict[str, Any],
    storage_data: dict[str, Any] | None = None,
    update_data: dict[str, Any] | None = None,
    persistence_data: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Generate correlated pentest-relevant finding candidates."""
    storage_data = storage_data or {}
    update_data = update_data or {}
    persistence_data = persistence_data or {}
    findings: list[dict[str, Any]] = []

    for candidate in service_data.get("risk_candidates", []):
        if not candidate.get("privileged") or not candidate.get("concerns"):
            continue
        unit = str(candidate.get("unit") or "unknown.service")
        path_type = str(candidate.get("path_type") or "ReferencedPath")
        path = str(candidate.get("path") or "unknown path")
        concerns = str(candidate.get("concerns") or "")
        raw_review_identity = f"{unit}:{path_type}:{path}"
        role_label = _service_path_label(path_type)
        findings.append({
            "identity": f"service:{raw_review_identity}",
            "review_identity": stable_review_identity("SVC", raw_review_identity),
            "category": "SVC",
            "severity": "High",
            "title": "Writable Path Referenced by Privileged systemd Service",
            "condition": f"{unit} execution chain consumes {role_label} {path}: {concerns}.",
            "evidence": f"{unit} - {role_label}: {path} ({concerns})",
            "validation_evidence": [f"systemctl cat {unit}", f"namei -l {path}", f"getfacl {path}"],
            "service_unit": unit,
            "service_path": path,
            "service_path_type": path_type,
        })

    elf_entries = [item for item in elf_data.get("finding_candidates", []) if item.get("finding_candidate")]
    elf_groups: dict[tuple[str, str, str, bool], list[str]] = {}
    for item in elf_entries:
        key = (
            str(item.get("kind") or "RPATH"),
            str(item.get("path") or ""),
            str(item.get("concern") or "unsafe search-path condition"),
            True,
        )
        elf_groups.setdefault(key, []).append(str(item.get("binary") or ""))

    for (kind, search_path, concern, _), binaries in sorted(elf_groups.items()):
        group_targets = sorted(set(x for x in binaries if x))
        if not group_targets:
            continue
        priority = "HIGH"
        if len(group_targets) == 1:
            raw_review = f"{group_targets[0]}:{kind}:{search_path}"
        else:
            raw_review = f"group:{kind}:{search_path}:{concern}:{priority}"
        review_identity = stable_review_identity("ELF", raw_review)
        affected = ", ".join(group_targets)
        display_path = search_path or "<empty/current directory>"
        condition = (
            f"{affected}: {kind}={display_path}; {concern}."
            if len(group_targets) == 1
            else f"{len(group_targets)} application binaries share {kind}={display_path}; {concern}. Affected binaries: {affected}."
        )
        evidence = (
            f"{group_targets[0]} - {kind}={display_path} - {concern}"
            if len(group_targets) == 1
            else f"{kind}={display_path} - {concern}; affected binaries: {affected}"
        )
        validation_evidence: list[str] = []
        for binary in group_targets:
            validation_evidence.extend([f"readelf -d {binary}", f"checksec --file={binary}"])
        findings.append({
            "identity": f"elf-group:{kind}:{search_path}:{concern}",
            "review_identity": review_identity,
            "category": "ELF",
            "severity": "Medium",
            "title": "Writable ELF Library Search Path",
            "condition": condition,
            "evidence": evidence,
            "validation_targets": group_targets,
            "search_path": search_path,
            "search_kind": kind,
            "validation_evidence": validation_evidence,
        })

    update_evidence: dict[str, list[str]] = {}
    for item in update_data.get("insecure_update_url_candidates", []):
        url = str(item.get("url", ""))
        evidence = f"{item.get('path')}:{item.get('line')}; confidence: {item.get('confidence')}"
        locations = update_evidence.setdefault(url, [])
        if evidence not in locations:
            locations.append(evidence)
    for url, locations in update_evidence.items():
        findings.append({
            "identity": f"update:{url}",
            "review_identity": stable_review_identity("UPD", url),
            "category": "UPD",
            "severity": "Medium",
            "title": "Potential Software Update Retrieval over Cleartext HTTP",
            "condition": f"Probable update endpoint: {url}",
            "evidence": f"{url} ({'; '.join(locations)})",
            "validation_evidence": ["Capture the updater process, destination, transport, and signature/checksum validation behavior."],
        })

    for item in persistence_data.get("sudo_policy_candidates", []):
        if not item.get("finding_candidate"):
            continue
        command = str(item.get("command") or item.get("raw") or "unknown")
        runas = str(item.get("runas") or "root")
        concerns = "; ".join(str(x) for x in (item.get("concerns") or [])) or "Privileged sudo rule requires validation"
        raw_review_identity = f"sudo-candidate:{runas}:{command}"
        findings.append({
            "identity": f"sudo:{runas}:{command}",
            "review_identity": stable_review_identity("PERS", raw_review_identity),
            "category": "PERS",
            "severity": str(item.get("severity") or "High"),
            "title": "Potentially Unsafe sudoers Rule Introduced by Application",
            "condition": f"Run as {runas}: {command} ({concerns})",
            "evidence": f"Run as {runas}: {command} ({concerns})",
            "validation_evidence": ["sudo visudo -c", "sudo -l"],
        })

    for item in storage_data.get("crypto_material", []) or []:
        path = str(item.get("path") or "")
        related_certs = [str(x) for x in (item.get("related_ca_certificates") or []) if str(x)]
        permission = str(item.get("permission") or "")
        if not path or not item.get("private_key") or not related_certs or permission not in {"world-readable", "world-writable"}:
            continue
        indicators = ", ".join(str(x) for x in (item.get("indicators") or [])) or "private key material"
        findings.append({
            "identity": f"crypto-ca:{path}",
            "review_identity": stable_review_identity("CRYPTO", path),
            "category": "CRYPTO",
            "severity": "High",
            "title": "Potential Exposure of Local CA Private Signing Material",
            "condition": f"{path} contains {indicators}; permission context: {permission}; related CA certificate(s): {', '.join(related_certs)}.",
            "evidence": f"{path} - private signing material detected; values redacted; {permission}; related CA certificate(s): {', '.join(related_certs)}",
            "validation_evidence": [f"stat {path}", f"namei -l {path}", f"getfacl {path}"],
            "crypto_path": path,
            "crypto_certificates": related_certs,
        })

    # v1.5.2: selected mature candidates are owned by the structured
    # correlation engine. Unmigrated categories retain legacy generation.
    findings = _apply_correlation_finding_ownership(output_dir, findings)
    findings, duplicates_suppressed = _deduplicate_findings(findings)
    duplicates_suppressed += len(update_data.get("insecure_update_url_candidates", [])) - len(update_evidence)

    # Assign stable display IDs after deterministic ordering.
    ordered = sorted(findings, key=lambda x: (-SEVERITY_RANK.get(str(x.get("severity") or ""), 0), str(x.get("title") or "").casefold(), str(x.get("identity") or "")))
    for idx, finding in enumerate(ordered, 1):
        finding["id"] = f"UAF-{idx:03d}"

    manual_review: list[dict[str, str]] = []
    seen_review: set[str] = set()
    for item in persistence_data.get("review_required", []):
        identity = str(item.get("identity") or item.get("evidence") or "").casefold()
        if not identity or identity in seen_review:
            continue
        seen_review.add(identity)
        manual_review.append(item)

    payload = {
        "schema_version": 1,
        "findings": ordered,
        "manual_review": manual_review,
        "duplicates_suppressed": duplicates_suppressed,
    }
    write_json(_candidate_store_path(output_dir), payload)
    return _render_reports(output_dir, payload)


def generate_findings(
    output_dir: Path,
    permission_data: dict[str, Any],
    network_data: dict[str, Any],
    service_data: dict[str, Any],
    elf_data: dict[str, Any],
    storage_data: dict[str, Any] | None = None,
    update_data: dict[str, Any] | None = None,
    persistence_data: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Render finding candidates from the primary structured model when available.

    v1.9.0 renders every current automatic finding category from structured
    security-model correlations. The module-data generator remains only for
    backward compatibility with older assessment state that lacks schema-10
    structured ownership.
    """
    model_path = working_dir(output_dir) / "security_model.json"
    if model_path.is_file():
        try:
            model = read_json(model_path)
        except Exception:
            model = {}
        if int(model.get("schema_version") or 0) >= 10 and model.get("correlations"):
            # v1.9.0: all current automatic finding categories are rendered directly
            # from structured correlations. The module-data generator remains only
            # for older/missing-model assessments.
            findings = _correlation_owned_findings(output_dir)
            findings, duplicates_suppressed = _deduplicate_findings(findings)
            ordered = sorted(findings, key=lambda x: (-SEVERITY_RANK.get(str(x.get("severity") or ""), 0), str(x.get("title") or "").casefold(), str(x.get("identity") or "")))
            for idx, finding in enumerate(ordered, 1):
                finding["id"] = f"UAF-{idx:03d}"
            manual_review: list[dict[str, str]] = []
            seen_review: set[str] = set()
            for item in (persistence_data or {}).get("review_required", []):
                identity = str(item.get("identity") or item.get("evidence") or "").casefold()
                if identity and identity not in seen_review:
                    seen_review.add(identity)
                    manual_review.append(item)
            payload = {
                "schema_version": 2,
                "generation_source": "structured_security_model",
                "findings": ordered,
                "manual_review": manual_review,
                "duplicates_suppressed": duplicates_suppressed,
            }
            write_json(_candidate_store_path(output_dir), payload)
            return _render_reports(output_dir, payload)
    return _generate_findings_compatibility(
        output_dir, permission_data, network_data, service_data, elf_data,
        storage_data, update_data, persistence_data
    )
