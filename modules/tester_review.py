from __future__ import annotations

import hashlib
import re
import shlex
from collections import Counter
from pathlib import Path
from typing import Any

from .common import VERSION, now_iso, read_json, redact_sensitive_text, report_path, working_dir, write_json, write_text
from .validation_guidance import playbook_for, render_playbook_lines

STATE_SCHEMA_VERSION = 1
PRIORITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# v1.9.0 keeps the review workflow deliberately simple: testers choose a
# security area, then work the related items in their existing stable TRQ order.
# These labels are presentation/workflow metadata; they do not change finding
# severity, correlation ownership, or the underlying security-model schema.
REVIEW_CATEGORY_ORDER = [
    "Privilege & Permissions",
    "Services",
    "Network & Communications",
    "IPC & Authorization",
    "Local Data & Storage",
    "Software Update",
    "Runtime",
    "Technology-Specific",
    "Other",
]

_CATEGORY_BY_CODE = {
    "ELF": "Privilege & Permissions",
    "PERM": "Privilege & Permissions",
    "CAP": "Privilege & Permissions",
    "SUID": "Privilege & Permissions",
    "PERS": "Privilege & Permissions",
    "POLKIT": "Privilege & Permissions",
    "SVC": "Services",
    "NET": "Network & Communications",
    "COMM": "Network & Communications",
    "DBUS": "IPC & Authorization",
    "IPC": "IPC & Authorization",
    "FIFO": "IPC & Authorization",
    "STOR": "Local Data & Storage",
    "STORCFG": "Local Data & Storage",
    "CRYPTO": "Local Data & Storage",
    "UPD": "Software Update",
    "RUNTIME": "Runtime",
    "RUNTIME-IPC": "IPC & Authorization",
    "TECH": "Technology-Specific",
}

def review_category(item: dict[str, Any]) -> str:
    return str(item.get("review_category") or _CATEGORY_BY_CODE.get(str(item.get("category") or "").upper(), "Other"))

def review_group(item: dict[str, Any]) -> tuple[str, str]:
    category = str(item.get("category") or "").upper()
    if category == "SVC" and item.get("service_unit"):
        unit = str(item.get("service_unit"))
        return f"service:{unit}", f"Service: {unit}"
    if category == "ELF":
        path = str(item.get("search_path") or "<empty/current directory>")
        return f"elf-search:{path}", f"Library search path: {path}"
    if category in {"PERM", "CAP", "SUID", "PERS", "POLKIT"}:
        return "privilege-boundaries", "Privilege and permission boundaries"
    if category in {"NET", "COMM"}:
        return "application-communications", "Application communications"
    if category in {"IPC", "FIFO", "DBUS"}:
        return "local-ipc", "Local IPC and authorization"
    if category in {"STOR", "STORCFG", "CRYPTO"}:
        return "local-storage", "Local data and sensitive storage"
    if category == "UPD":
        return "software-update", "Software update mechanism"
    if category == "RUNTIME":
        return "runtime-surface", "Runtime attack surface"
    if category == "TECH":
        return "technology-review", "Technology-specific review"
    title = str(item.get("title") or "Other review")
    return f"other:{title.casefold()}", title

def shared_validation_for(item: dict[str, Any]) -> list[str]:
    category = str(item.get("category") or "").upper()
    if category == "SVC":
        unit = str(item.get("service_unit") or "the affected service")
        return [
            f"Confirm the effective identity and complete systemd configuration for {unit} once, then reuse that service context across this group.",
            "Reuse common unit/parent-path evidence when unchanged; still validate write access, actual consumption, and impact for each distinct path.",
        ]
    if category == "ELF":
        path = str(item.get("search_path") or "the reported search location")
        return [
            f"Confirm effective permissions for {path} once when the same search location is shared by multiple items.",
            "Reuse shared execution-context evidence when unchanged; actual dependency resolution and elevated execution impact remain binary-specific.",
        ]
    if category in {"PERM", "CAP", "SUID", "PERS", "POLKIT"}:
        return [
            "Establish the low-privileged tester identity, group membership, and relevant privilege boundary once and reuse that context while it remains unchanged.",
            "Reuse common parent-directory/ACL evidence where appropriate; validate each distinct object or privileged action separately before reporting.",
        ]
    if category in {"NET", "COMM"}:
        return [
            "Capture the exercised application workflow and representative network evidence once, then map each candidate endpoint to that workflow.",
            "Do not assume every static endpoint is used; confirm runtime use and security impact for each distinct endpoint before reporting.",
        ]
    if category in {"IPC", "FIFO", "DBUS"}:
        return [
            "Establish the owning process/service privilege and low-privileged caller context once for the related IPC mechanism.",
            "Reuse common ownership/protocol evidence, but validate authorization and meaningful actions for each distinct IPC endpoint or method.",
        ]
    if category in {"STOR", "STORCFG", "CRYPTO"}:
        return [
            "Establish the intended local-user/application trust boundary once and reuse the same permission context where unchanged.",
            "Keep secrets redacted; validate whether each distinct value or object is real, accessible, and usable before reporting.",
        ]
    if category == "UPD":
        return [
            "Exercise the real updater once and capture the updater process, transport, and independent signature/authentication behavior.",
            "Reuse the common updater workflow evidence across related endpoints; verify each endpoint actually participates in update delivery.",
        ]
    if category == "RUNTIME":
        return [
            "Reuse the same Guided Runtime Observation capture for related runtime objects when it represents the same exercised workflow.",
            "Validate exposure and authorization separately for each distinct runtime listener, process, or IPC object.",
        ]
    if category == "TECH":
        return ["Apply the framework-specific review guidance once across the application, then record only material security observations in the relevant technical category."]
    return []

def decorate_review_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for item in items:
        category = review_category(item)
        group_key, group_label = review_group(item)
        item["review_category"] = category
        item["review_group"] = group_key
        item["review_group_label"] = group_label
        item["shared_validation"] = shared_validation_for(item)
    return items

def category_progress(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    present = {review_category(item) for item in items}
    ordered = [x for x in REVIEW_CATEGORY_ORDER if x in present]
    ordered += sorted(present.difference(ordered))
    for category in ordered:
        group = [item for item in items if review_category(item) == category]
        completed = sum(1 for item in group if str(item.get("status") or "PENDING") != "PENDING")
        rows.append({"category": category, "total": len(group), "completed": completed, "pending": len(group)-completed})
    return rows


def _q(value: str) -> str:
    return shlex.quote(str(value))
VALID_STATUSES = {"PENDING", "VALIDATED", "NOT APPLICABLE", "INFORMATIONAL"}


def stable_review_identity(category: str, identity: str) -> str:
    """Return the persistent identity used to correlate review tasks across reports."""
    digest = hashlib.sha256(f"{category}\0{identity}".encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{category.upper()}-{digest}"


def _stable_identity(category: str, identity: str) -> str:
    return stable_review_identity(category, identity)


def _listener_object_identity(text: str) -> str | None:
    parts = str(text).split()
    proto = next((part.casefold() for part in parts if part.casefold() in {"tcp", "udp"}), "")
    local = ""
    for idx, part in enumerate(parts):
        if part.upper() in {"LISTEN", "UNCONN"} and idx + 3 < len(parts):
            local = parts[idx + 3]
            break
    if not local and len(parts) >= 5:
        local = parts[4]
    if not local or ":" not in local:
        return None
    return f"{proto or 'inet'}:{local}"


def _path_object_identity(text: str) -> str | None:
    match = re.search(r"(?<![A-Za-z0-9_.-])(/[^\s;,]+)", str(text))
    return match.group(1).rstrip(")]}") if match else None


def _runtime_match(existing: list[dict[str, Any]], candidate: dict[str, Any]) -> dict[str, Any] | None:
    object_type = str(candidate.get("object_type") or "")
    object_identity = str(candidate.get("object_identity") or "")
    if not object_type or not object_identity:
        return None
    for item in existing:
        existing_type = str(item.get("object_type") or "")
        existing_identity = str(item.get("object_identity") or "")
        if not existing_type or not existing_identity:
            # Backward-compatible inference for state generated before v1.4.2.
            title = str(item.get("title") or "").casefold()
            condition = str(item.get("condition") or "")
            if "listener" in title:
                existing_type, existing_identity = "listener", _listener_object_identity(condition) or ""
            elif "unix socket" in title or "ipc authorization" in title:
                existing_type, existing_identity = "unix_socket", _path_object_identity(condition) or ""
            elif "fifo" in title:
                existing_type, existing_identity = "fifo", _path_object_identity(condition) or ""
        if existing_type == object_type and existing_identity == object_identity:
            return item
    return None


def _merge_runtime_confirmation(target: dict[str, Any], candidate: dict[str, Any]) -> None:
    target["runtime_confirmed"] = True
    observations = [str(x) for x in (target.get("runtime_observations") or []) if str(x)]
    observation = str(candidate.get("condition") or "").strip()
    if observation and observation not in observations:
        observations.append(observation)
    target["runtime_observations"] = observations[:20]
    target["related_reports"] = sorted(set(target.get("related_reports", []) or []).union(candidate.get("related_reports", []) or []))
    if PRIORITY_ORDER.get(str(candidate.get("priority") or "LOW"), 9) < PRIORITY_ORDER.get(str(target.get("priority") or "LOW"), 9):
        target["priority"] = candidate.get("priority")


def _add(
    items: list[dict[str, Any]],
    seen: set[str],
    *,
    category: str,
    identity: str,
    priority: str,
    title: str,
    condition: str,
    why: str,
    validation: list[str],
    related_reports: list[str],
    evidence: list[str] | None = None,
) -> dict[str, Any] | None:
    key = _stable_identity(category, identity)
    if key in seen:
        return None
    seen.add(key)
    record = {
        "identity": key,
        "category": category,
        "priority": priority if priority in PRIORITY_ORDER else "MEDIUM",
        "title": title,
        "condition": condition,
        "why_it_matters": why,
        "validation": validation,
        "related_reports": related_reports,
        "evidence": evidence or [],
    }
    items.append(record)
    return record



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


CORRELATION_OWNED_KINDS = {
    "privileged_service_writable_path",
    "writable_elf_search_path",
    "cleartext_update_path",
    "unix_socket_authorization_boundary",
    "fifo_authorization_boundary",
    "dbus_authorization_boundary",
    "polkit_authorization_boundary",
    "permission_boundary",
    "file_capability_boundary",
    "suid_sgid_helper_boundary",
    "sudoers_policy_change",
    "unsafe_sudo_policy",
    "credential_token_storage",
    "cleartext_application_endpoint",
    "runtime_application_listener",
    "exposed_local_ca_private_key",
}


def _correlation_review_items(model: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Render the authoritative structured-correlation review slice."""
    if not isinstance(model, dict):
        return []
    objects = {str(item.get("id")): item for item in model.get("objects", []) or []}
    observations = {str(item.get("id")): item for item in model.get("observations", []) or []}
    generated: list[dict[str, Any]] = []

    for corr in model.get("correlations", []) or []:
        kind = str(corr.get("kind") or "")
        if kind not in CORRELATION_OWNED_KINDS or not corr.get("drives_review"):
            continue
        review_identity = str(corr.get("review_identity") or "")
        if not review_identity:
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
            item = {
                "identity": review_identity, "category": "SVC", "priority": "HIGH",
                "title": "Privileged Service Path Requires Validation",
                "condition": f"{unit} execution chain consumes {role_label} {path}: {concerns}.",
                "why_it_matters": "A lower-privileged user who can influence a path consumed by a root-running service may be able to cross a local privilege boundary.",
                "validation": [
                    f"Confirm the effective service identity and configuration with: systemctl show {_q(unit)} -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory",
                    f"Validate effective file and parent-directory access for: {path}",
                    "If writable by the test account, determine whether the service actually consumes the modified content before treating it as a finding.",
                ],
                "related_reports": ["service_review.txt", "permissions_review.txt"],
                "evidence": [f"systemctl cat {_q(unit)}", f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}"],
                "service_unit": unit, "service_path": path, "service_path_type": path_type,
                **provenance,
            }
            generated.append(item)

        elif kind == "writable_elf_search_path":
            binaries = sorted(str(objects[x].get("identity")) for x in obj_ids if x in objects and objects[x].get("kind") == "binary")
            directory = next((str(objects[x].get("identity")) for x in obj_ids if x in objects and objects[x].get("kind") == "directory"), "")
            elf_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "elf_search_path"), {})
            attrs = elf_obs.get("attributes") or {}
            search_kind = str(attrs.get("kind") or "RPATH")
            search_path = str(attrs.get("search_path") if attrs.get("search_path") is not None else directory)
            concern = str(attrs.get("concern") or "unsafe search-path condition")
            listed = ", ".join(binaries)
            condition = (
                f"{binaries[0]}: {search_kind}={search_path or '<empty/current directory>'}; {concern}."
                if len(binaries) == 1 else
                f"{len(binaries)} binaries use {search_kind}={search_path or '<empty/current directory>'}: {listed}; {concern}."
            )
            evidence: list[str] = []
            for binary in binaries:
                evidence.extend([f"readelf -d {_q(binary)}", f"checksec --file={_q(binary)}"])
            generated.append({
                "identity": review_identity, "category": "ELF", "priority": "HIGH",
                "title": "ELF Library Search Path Requires Validation" if len(binaries) == 1 else "ELF Library Search Paths Require Validation",
                "condition": condition,
                "why_it_matters": "A writable, relative, or current-directory library search path can permit library substitution. Impact depends on who executes the binary and with what privilege.",
                "validation": ["Determine how and by whom each affected binary is executed.", "Confirm the test account can influence the relevant search directory.", "Identify an actually loaded dependency from that location before treating the condition as exploitable."],
                "related_reports": ["binary_security_review.txt", "permissions_review.txt", "service_review.txt"],
                "evidence": evidence, "validation_targets": binaries, "search_path": search_path, "search_kind": search_kind,
                **provenance,
            })

        elif kind == "cleartext_update_path":
            endpoint_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "update_endpoint"), {})
            url = str(endpoint_obj.get("identity") or "")
            generated.append({
                "identity": review_identity, "category": "UPD", "priority": "HIGH",
                "title": "Cleartext Software Update Path Requires Validation",
                "condition": f"Probable update endpoint: {url}",
                "why_it_matters": "If privileged software updates are actually retrieved over cleartext transport, an on-path attacker may be able to influence update delivery unless independent cryptographic authentication is enforced.",
                "validation": ["Exercise the real updater and confirm whether the endpoint is contacted.", "Determine whether packages/manifests are cryptographically authenticated independent of transport.", "Assess downgrade/rollback behavior where authorized."],
                "related_reports": ["update_review.txt", "network_surface_review.txt"],
                "evidence": ["Capture the updater process, destination, transport, and signature/checksum validation behavior."],
                **provenance,
            })

        elif kind == "permission_boundary":
            path_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") in {"file", "directory", "fifo", "unix_socket", "symlink"}), {})
            path = str(path_obj.get("identity") or "")
            perm_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "filesystem_permission"), {})
            attrs = perm_obs.get("attributes") or {}
            concerns_list = attrs.get("concerns") or []
            concerns = "; ".join(str(x) for x in concerns_list) if isinstance(concerns_list, list) else str(concerns_list)
            level = str(attrs.get("level") or "REVIEW")
            priority = "HIGH" if level == "HIGH INTEREST" else "MEDIUM"
            generated.append({
                "identity": review_identity, "category": "PERM", "priority": priority,
                "title": "Application Permission Boundary Requires Review",
                "condition": f"{path}: {concerns or 'permission condition'}.",
                "why_it_matters": "Unexpected write access, ACLs, SUID/SGID state, or sensitive-file exposure can allow local tampering or unauthorized data access when the object participates in a trust boundary.",
                "validation": ["Confirm the test account's effective access rather than relying only on mode bits.", "Review the complete parent-directory chain and any named ACL entries.", "Identify the process or privileged component that consumes the object before escalating it to a finding."],
                "related_reports": ["permissions_review.txt"],
                "evidence": [f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}"],
                "object_type": str(path_obj.get("kind") or "file"), "object_identity": path,
                **provenance,
            })

        elif kind == "file_capability_boundary":
            binary_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "binary"), {})
            cap_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "file_capability"), {})
            raw = str((cap_obs.get("attributes") or {}).get("raw_entry") or cap_obs.get("summary") or "")
            binary = str(binary_obj.get("identity") or (raw.split()[0] if raw.split() else raw))
            generated.append({
                "identity": review_identity, "category": "CAP", "priority": "MEDIUM",
                "title": "Application File Capability Requires Review", "condition": raw,
                "why_it_matters": "Linux capabilities can grant a helper privileges beyond the invoking user's normal rights and may create an exploitable boundary if its inputs are weakly controlled.",
                "validation": ["Identify the exact capability and owning executable.", "Exercise only the exposed application functionality as a low-privileged user and validate argument, file, path, and environment handling."],
                "related_reports": ["permissions_review.txt"], "evidence": [f"getcap {_q(binary)}"],
                **provenance,
            })

        elif kind == "suid_sgid_helper_boundary":
            binary_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "binary"), {})
            helper_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "suid_sgid_helper"), {})
            raw = str((helper_obs.get("attributes") or {}).get("raw_entry") or helper_obs.get("summary") or "")
            binary = str(binary_obj.get("identity") or (raw.split()[0] if raw.split() else raw))
            generated.append({
                "identity": review_identity, "category": "SUID", "priority": "HIGH",
                "title": "Application SUID/SGID Helper Requires Review", "condition": raw,
                "why_it_matters": "Application-controlled SUID/SGID helpers cross a local privilege boundary and warrant targeted input, environment, and path-manipulation testing.",
                "validation": ["Confirm ownership/mode and whether the helper is application-owned.", "Review accepted arguments, environment variables, file paths, command execution, and library resolution as an unprivileged user."],
                "related_reports": ["permissions_review.txt", "binary_security_review.txt"], "evidence": [f"stat {_q(binary)}"],
                **provenance,
            })

        elif kind == "sudoers_policy_change":
            policy_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "sudoers_policy"), {})
            policy_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "sudoers_policy_change"), {})
            attrs = policy_obs.get("attributes") or {}
            title = str(attrs.get("title") or "Changed sudoers Policy Requires Manual Review")
            condition = str(policy_obs.get("summary") or "Application introduced or changed a privileged sudoers policy file.")
            action = str(attrs.get("action") or "Inspect the effective policy and determine what an unprivileged user can cause a privileged component to execute.")
            path = str(policy_obj.get("identity") or "")
            generated.append({
                "identity": review_identity, "category": "PERS", "priority": "HIGH",
                "title": title, "condition": condition,
                "why_it_matters": "Persistence and privilege-policy changes can create durable privilege boundaries and should be validated before closeout.",
                "validation": [action],
                "related_reports": ["persistence_review.txt", "permissions_review.txt"],
                "evidence": ["Capture the effective policy and the low-privileged user's resulting rights."],
                "object_type": "sudoers_policy", "object_identity": path,
                **provenance,
            })

        elif kind == "unsafe_sudo_policy":
            sudo_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "sudo_rule"), {})
            sudo_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "sudo_policy"), {})
            attrs = sudo_obs.get("attributes") or {}
            object_attrs = sudo_obj.get("attributes") or {}
            runas = str(object_attrs.get("runas") or "root")
            command = str(object_attrs.get("command") or "unknown")
            concerns = "; ".join(str(x) for x in (attrs.get("concerns") or [])) or "Privileged sudo rule requires validation"
            generated.append({
                "identity": review_identity, "category": "PERS", "priority": "HIGH",
                "title": "Potentially Unsafe sudoers Rule Requires Validation",
                "condition": f"Run as {runas}: {command} ({concerns})",
                "why_it_matters": "A sudo rule can create an unintended privilege path when its command, arguments, environment, wildcard handling, or execution chain can be influenced by the invoking user.",
                "validation": ["Inspect the effective sudo rule with sudo -l.", "Validate the complete executable/input chain and determine whether the rule permits unintended privileged behavior."],
                "related_reports": ["persistence_review.txt", "permissions_review.txt"],
                "evidence": ["sudo visudo -c", "sudo -l", "Capture the exact effective rule and benign proof of impact if validated."],
                **provenance,
            })

        elif kind == "exposed_local_ca_private_key":
            key_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") in {"file", "directory", "symlink"}), {})
            crypto_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "cryptographic_material"), {})
            attrs = crypto_obs.get("attributes") or {}
            path = str(key_obj.get("identity") or "")
            related_certs = sorted(str(objects[x].get("identity")) for x in obj_ids if x in objects and objects[x].get("kind") == "certificate")
            permission = str(attrs.get("permission") or "not identified")
            generated.append({
                "identity": review_identity, "category": "CRYPTO", "priority": "HIGH",
                "title": "Local CA / Private Key Material Requires Review",
                "condition": f"{path} contains private signing material; permission context: {permission}; related CA certificate(s): {', '.join(related_certs)}.",
                "why_it_matters": "Locally generated private signing material can create a high-impact trust boundary if a lower-privileged user can recover or use it. A certificate or cryptographic salt alone is not a secret vulnerability.",
                "validation": ["Determine whether the material is an actual private signing key and whether any related certificate is a CA trusted by the application/system.", "Validate effective read/write access to the private-key or key-protection material.", "Determine whether possession/use of the key would allow certificate issuance across a meaningful trust boundary."],
                "related_reports": ["local_storage_review.txt", "permissions_review.txt"],
                "evidence": [f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}"],
                "crypto_path": path, "crypto_certificates": related_certs, "crypto_salt_present": bool(attrs.get("salt")),
                **provenance,
            })

        elif kind == "unix_socket_authorization_boundary":
            socket_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "unix_socket"), {})
            path = str(socket_obj.get("identity") or "")
            socket_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "unix_socket"), {})
            attrs = socket_obs.get("attributes") or {}
            raw = str(attrs.get("raw_observation") or path)
            priority = "HIGH" if str(attrs.get("review_level") or "").upper() == "HIGH" else "MEDIUM"
            generated.append({
                "identity": review_identity, "category": "IPC", "priority": priority,
                "title": "Application Unix Socket Trust Boundary",
                "condition": raw,
                "why_it_matters": "A local IPC endpoint can cross user or privilege boundaries. Filesystem permissions alone do not prove that peer authorization is enforced by the service.",
                "validation": ["Identify the owning process/service and its privilege.", "Inspect socket and parent-directory permissions.", "Determine how clients authenticate/authorize requests before attempting protocol-level tests."],
                "related_reports": ["ipc_review.txt", "service_review.txt"],
                "evidence": ["ss -lxnp", "lsof -U"],
                "object_type": "unix_socket", "object_identity": path,
                **provenance,
            })

        elif kind == "fifo_authorization_boundary":
            fifo_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "fifo"), {})
            path = str(fifo_obj.get("identity") or "")
            generated.append({
                "identity": review_identity, "category": "IPC", "priority": "MEDIUM",
                "title": "Named FIFO Trust Boundary", "condition": path,
                "why_it_matters": "A FIFO used by a privileged component may permit request injection or spoofing if writers are not constrained and authenticated.",
                "validation": ["Identify producer and consumer processes.", "Confirm ownership/mode/ACL of the FIFO and its parent directory.", "Observe legitimate message flow before attempting harmless unauthorized input."],
                "related_reports": ["ipc_review.txt", "permissions_review.txt"],
                "evidence": [f"stat {_q(path)}", f"getfacl {_q(path)}"],
                "object_type": "fifo", "object_identity": path,
                **provenance,
            })

        elif kind == "dbus_authorization_boundary":
            bus_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "dbus_name"), {})
            name = str(bus_obj.get("identity") or "")
            dbus_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "dbus_name"), {})
            attrs = dbus_obs.get("attributes") or {}
            active_note = " Active during assessment." if attrs.get("active") else ""
            generated.append({
                "identity": review_identity, "category": "DBUS", "priority": "MEDIUM",
                "title": "D-Bus Interface Requires Authorization Review",
                "condition": f"Referenced bus name: {name}.{active_note}",
                "why_it_matters": "D-Bus interfaces can expose privileged operations to local callers; method-level authorization must match the intended trust boundary.",
                "validation": ["Identify whether the name is on the system or user bus.", "Introspect exported objects/methods where permitted.", "Review D-Bus and PolicyKit authorization before invoking state-changing methods."],
                "related_reports": ["ipc_review.txt"],
                "evidence": [f"busctl --system introspect {_q(name)} /", f"busctl --user introspect {_q(name)} /"],
                **provenance,
            })

        elif kind == "polkit_authorization_boundary":
            polkit_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "polkit_action"), {})
            action = str(polkit_obj.get("identity") or "unknown-action")
            polkit_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "polkit_policy"), {})
            attrs = polkit_obs.get("attributes") or {}
            path = str(attrs.get("path") or (polkit_obj.get("attributes") or {}).get("path") or "")
            defaults = attrs.get("defaults") or (polkit_obj.get("attributes") or {}).get("defaults") or {}
            defaults_text = ", ".join(f"{k}={v}" for k, v in defaults.items())
            generated.append({
                "identity": review_identity, "category": "POLKIT", "priority": "HIGH",
                "title": "PolicyKit Authorization Requires Validation",
                "condition": f"Action {action} in {path}; defaults: {defaults_text or 'not parsed'}",
                "why_it_matters": "Permissive PolicyKit behavior can expose privileged application operations to untrusted local callers, but the protected operation and any secondary authorization must still be validated.",
                "validation": ["Identify the exact privileged operation protected by the action.", "Map the action to its D-Bus/service/helper call path.", "Test a harmless instance as the normal low-privileged user and verify whether authorization is enforced."],
                "related_reports": ["ipc_review.txt", "service_review.txt"],
                "evidence": [f"Review {_q(path)}", f"pkcheck --action-id {_q(action)} --process $$ 2>/dev/null || true"],
                **provenance,
            })

        elif kind == "credential_token_storage":
            storage_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") in {"file", "directory", "symlink"}), {})
            path = str(storage_obj.get("identity") or "")
            storage_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "credential_token_storage"), {})
            attrs = storage_obs.get("attributes") or {}
            indicators = ", ".join(str(x) for x in (attrs.get("indicators") or [])) or "credential-style assignment"
            permission = str(attrs.get("permission") or "not identified") or "not identified"
            priority = "HIGH" if permission in {"world-readable", "world-writable"} else "MEDIUM"
            generated.append({
                "identity": review_identity, "category": "STOR", "priority": priority,
                "title": "Potential Credential or Token Storage",
                "condition": f"{path} contains {indicators}; value intentionally redacted. Observed permission context: {permission}.",
                "why_it_matters": "The detected assignment may represent authentication material, but the value must be validated as real and its accessibility/lifetime/privilege determined before reporting.",
                "validation": ["Inspect the original file on the assessment VM; do not copy the secret into tester artifacts.", "Determine whether the value is a real credential/token and whether it is still usable.", "Validate file and parent-directory access for other local users and determine the credential's scope/lifetime."],
                "related_reports": ["local_storage_review.txt", "permissions_review.txt"],
                "evidence": [f"stat {_q(path)}", f"getfacl {_q(path)}", "Capture only the minimum redacted evidence needed for the final report."],
                "object_type": str(storage_obj.get("kind") or "file"), "object_identity": path,
                **provenance,
            })

        elif kind == "cleartext_application_endpoint":
            endpoint_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "application_endpoint"), {})
            endpoint = str(endpoint_obj.get("identity") or "")
            generated.append({
                "identity": review_identity, "category": "COMM", "priority": "MEDIUM",
                "title": "Cleartext Application Endpoint Requires Runtime Validation",
                "condition": f"Static/config endpoint indicator: {endpoint}",
                "why_it_matters": "Cleartext transport may expose application data or control traffic, but static references can also be unused documentation or compatibility strings.",
                "validation": ["Exercise the corresponding application workflow and confirm whether this endpoint is contacted.", "Determine what data is transmitted and whether an authenticated TLS alternative is expected."],
                "related_reports": ["network_surface_review.txt", "runtime_review.txt"],
                "evidence": ["Capture the owning process and request/response during the relevant workflow."],
                "object_type": "application_endpoint", "object_identity": endpoint,
                **provenance,
            })

        elif kind == "runtime_application_listener":
            endpoint_obj = next((objects[x] for x in obj_ids if x in objects and objects[x].get("kind") == "network_endpoint"), {})
            listener_obs = next((observations[x] for x in obs_ids if x in observations and observations[x].get("category") == "runtime_listener"), {})
            endpoint = str(endpoint_obj.get("identity") or (listener_obs.get("attributes") or {}).get("canonical_endpoint") or "")
            raw = str(listener_obs.get("summary") or endpoint)
            generated.append({
                "identity": review_identity, "category": "RUNTIME", "priority": "MEDIUM",
                "title": "Runtime Application Listener Requires Validation", "condition": raw,
                "why_it_matters": "A listener observed while the application is running represents confirmed runtime attack surface and should be validated for intended exposure and access control.",
                "validation": ["Confirm the owning application process and bind scope.", "Validate authentication/authorization and expected remote accessibility within scope.", "Compare the runtime listener with static/network configuration evidence."],
                "related_reports": ["runtime_review.txt", "network_surface_review.txt"],
                "evidence": ["Capture ss/lsof ownership and the application workflow that caused the listener to appear."],
                "object_type": "listener", "object_identity": endpoint, "runtime_confirmed": True,
                **provenance,
            })
    return generated


def _apply_correlation_review_ownership(items: list[dict[str, Any]], model: dict[str, Any] | None) -> list[dict[str, Any]]:
    generated = _correlation_review_items(model)
    if not generated:
        return items
    by_identity = {str(item.get("identity")): item for item in generated}
    by_object = {
        (str(item.get("object_type") or ""), str(item.get("object_identity") or "")): item
        for item in generated if item.get("object_type") and item.get("object_identity")
    }
    retained: list[dict[str, Any]] = []
    for item in items:
        target = by_identity.get(str(item.get("identity")))
        object_key = (str(item.get("object_type") or ""), str(item.get("object_identity") or ""))
        if target is None and object_key != ("", ""):
            target = by_object.get(object_key)
        if target is not None:
            # Preserve live confirmation/priority enrichment even when a runtime
            # candidate is superseded by the authoritative correlation item.
            if item.get("runtime_confirmed"):
                _merge_runtime_confirmation(target, item)
            continue
        retained.append(item)
    return retained + generated

def _build_legacy_review_items(
    permission_data: dict[str, Any] | None = None,
    network_data: dict[str, Any] | None = None,
    service_data: dict[str, Any] | None = None,
    elf_data: dict[str, Any] | None = None,
    ipc_data: dict[str, Any] | None = None,
    storage_data: dict[str, Any] | None = None,
    update_data: dict[str, Any] | None = None,
    persistence_data: dict[str, Any] | None = None,
    profile_data: dict[str, Any] | None = None,
    runtime_data: dict[str, Any] | None = None,
    correlation_model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build a concise, deduplicated tester triage queue from module results.

    Priority is *testing priority*, not vulnerability severity. Nothing in this
    queue is a confirmed vulnerability until a tester validates exploitability,
    authorization impact, and application context.
    """
    permission_data = permission_data or {}
    network_data = network_data or {}
    service_data = service_data or {}
    elf_data = elf_data or {}
    ipc_data = ipc_data or {}
    storage_data = storage_data or {}
    update_data = update_data or {}
    persistence_data = persistence_data or {}
    profile_data = profile_data or {}
    runtime_data = runtime_data or {}

    items: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Privileged service/path correlations are the strongest local privilege
    # review signal and intentionally supersede generic permission entries for
    # the same path.
    service_paths: set[str] = set()
    for candidate in service_data.get("risk_candidates", []):
        unit = str(candidate.get("unit") or "unknown.service")
        path = str(candidate.get("path") or "unknown path")
        path_type = str(candidate.get("path_type") or "ReferencedPath")
        concerns = str(candidate.get("concerns") or "writable path condition")
        privileged = bool(candidate.get("privileged"))
        role_label = _service_path_label(path_type)
        service_paths.add(path)
        svc_item = _add(
            items, seen,
            category="SVC",
            identity=f"{unit}:{path_type}:{path}",
            priority="HIGH" if privileged else "MEDIUM",
            title="Privileged Service Path Requires Validation" if privileged else "Service-Referenced Writable Path",
            condition=f"{unit} execution chain consumes {role_label} {path}: {concerns}.",
            why=(
                "A lower-privileged user who can influence a path consumed by a root-running service may be able to cross a local privilege boundary."
                if privileged else
                "A service references a path that may be influenced by another local principal; validate whether that crosses an intended trust boundary."
            ),
            validation=[
                f"Confirm the effective service identity and configuration with: systemctl show {_q(unit)} -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory",
                f"Validate effective file and parent-directory access for: {path}",
                "If writable by the test account, determine whether the service actually consumes the modified content before treating it as a finding.",
            ],
            related_reports=["service_review.txt", "permissions_review.txt"],
            evidence=[
                f"systemctl cat {_q(unit)}",
                f"stat {_q(path)}",
                f"namei -l {_q(path)}",
                f"getfacl {_q(path)}",
            ],
        )
        if svc_item is not None:
            svc_item["service_unit"] = unit
            svc_item["service_path"] = path
            svc_item["service_path_type"] = path_type

    for candidate in permission_data.get("high_interest_candidates", []) + permission_data.get("review_candidates", []):
        path = str(candidate.get("path") or "")
        if not path or path in service_paths:
            continue
        concerns = str(candidate.get("concerns") or "permission condition")
        level = str(candidate.get("level") or "REVIEW")
        priority = "HIGH" if level == "HIGH INTEREST" else "MEDIUM"
        _add(
            items, seen,
            category="PERM",
            identity=path,
            priority=priority,
            title="Application Permission Boundary Requires Review",
            condition=f"{path}: {concerns}.",
            why="Unexpected write access, ACLs, SUID/SGID state, or sensitive-file exposure can allow local tampering or unauthorized data access when the object participates in a trust boundary.",
            validation=[
                "Confirm the test account's effective access rather than relying only on mode bits.",
                "Review the complete parent-directory chain and any named ACL entries.",
                "Identify the process or privileged component that consumes the object before escalating it to a finding.",
            ],
            related_reports=["permissions_review.txt"],
            evidence=[f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}"],
        )

    for entry in permission_data.get("capability_candidates", []):
        raw = str(entry.get("entry") or "").strip()
        if raw:
            _add(
                items, seen, category="CAP", identity=raw, priority="MEDIUM",
                title="Application File Capability Requires Review",
                condition=raw,
                why="Linux capabilities can grant a helper privileges beyond the invoking user's normal rights and may create an exploitable boundary if its inputs are weakly controlled.",
                validation=["Identify the exact capability and owning executable.", "Exercise only the exposed application functionality as a low-privileged user and validate argument, file, path, and environment handling."],
                related_reports=["permissions_review.txt"], evidence=[f"getcap {_q(raw.split()[0])}"],
            )
    for entry in permission_data.get("suid_candidates", []):
        raw = str(entry.get("entry") or "").strip()
        if raw:
            _add(
                items, seen, category="SUID", identity=raw, priority="HIGH",
                title="Application SUID/SGID Helper Requires Review", condition=raw,
                why="Application-controlled SUID/SGID helpers cross a local privilege boundary and warrant targeted input, environment, and path-manipulation testing.",
                validation=["Confirm ownership/mode and whether the helper is application-owned.", "Review accepted arguments, environment variables, file paths, command execution, and library resolution as an unprivileged user."],
                related_reports=["permissions_review.txt", "binary_security_review.txt"], evidence=[f"stat {_q(raw.split()[0])}"],
            )

    # Group only truly equivalent ELF search-path observations: the search-path
    # kind, path, concern, and candidate strength must all match. Distinct RPATH/
    # RUNPATH values or concerns remain separate review tasks even if the titles
    # would otherwise be identical.
    elf_groups: dict[tuple[str, str, str, bool], list[str]] = {}
    for entry in elf_data.get("finding_candidates", []):
        binary = str(entry.get("binary") or "")
        if not binary:
            continue
        kind = str(entry.get("kind") or "RPATH")
        search_path = str(entry.get("path") or "")
        concern = str(entry.get("concern") or "unsafe search-path condition")
        finding_candidate = bool(entry.get("finding_candidate"))
        elf_groups.setdefault((kind, search_path, concern, finding_candidate), []).append(binary)

    for (kind, search_path, concern, finding_candidate), binaries in sorted(elf_groups.items()):
        unique_binaries = sorted(set(binaries))
        priority = "HIGH" if finding_candidate else "MEDIUM"
        if len(unique_binaries) == 1:
            binary = unique_binaries[0]
            identity = f"{binary}:{kind}:{search_path}"
            title = "ELF Library Search Path Requires Validation"
            condition = f"{binary}: {kind}={search_path or '<empty/current directory>'}; {concern}."
        else:
            identity = f"group:{kind}:{search_path}:{concern}:{priority}"
            title = "ELF Library Search Paths Require Validation"
            listed = ", ".join(unique_binaries)
            condition = f"{len(unique_binaries)} binaries use {kind}={search_path or '<empty/current directory>'}: {listed}; {concern}."
        evidence: list[str] = []
        for binary in unique_binaries:
            evidence.extend([f"readelf -d {_q(binary)}", f"checksec --file={_q(binary)}"])
        before_count = len(items)
        _add(
            items, seen, category="ELF", identity=identity, priority=priority,
            title=title,
            condition=condition,
            why="A writable, relative, or current-directory library search path can permit library substitution. Impact depends on who executes the binary and with what privilege.",
            validation=["Determine how and by whom each affected binary is executed.", "Confirm the test account can influence the relevant search directory.", "Identify an actually loaded dependency from that location before treating the condition as exploitable."],
            related_reports=["binary_security_review.txt", "permissions_review.txt", "service_review.txt"],
            evidence=evidence,
        )
        if len(items) > before_count:
            items[-1]["validation_targets"] = unique_binaries
            items[-1]["search_path"] = search_path
            items[-1]["search_kind"] = kind

    for listener in network_data.get("exposed_listener_candidates", []):
        listener = str(listener)
        net_item = _add(
            items, seen, category="NET", identity=f"listener:{listener}", priority="MEDIUM",
            title="Externally Reachable Application Listener",
            condition=listener,
            why="A listener reachable beyond loopback expands the application's attack surface and should be validated for intended exposure, authentication, authorization, and input handling.",
            validation=["Confirm the owning application process and intended bind scope.", "Test authentication/authorization and malformed input only within assessment scope.", "Verify whether remote access is necessary for normal product operation."],
            related_reports=["network_surface_review.txt"], evidence=["ss -lntupn", "lsof -i -n -P"],
        )
        if net_item is not None:
            net_item["object_type"] = "listener"
            net_item["object_identity"] = _listener_object_identity(listener) or listener
    for item in network_data.get("cleartext_endpoint_candidates", []):
        endpoint = str(item.get("endpoint") or item.get("url") or "")
        if not endpoint:
            continue
        _add(
            items, seen, category="COMM", identity=endpoint, priority="MEDIUM",
            title="Cleartext Application Endpoint Requires Runtime Validation",
            condition=f"Static/config endpoint indicator: {endpoint}",
            why="Cleartext transport may expose application data or control traffic, but static references can also be unused documentation or compatibility strings.",
            validation=["Exercise the corresponding application workflow and confirm whether this endpoint is contacted.", "Determine what data is transmitted and whether an authenticated TLS alternative is expected."],
            related_reports=["network_surface_review.txt", "runtime_review.txt"], evidence=["Capture the owning process and request/response during the relevant workflow."],
        )

    for socket in ipc_data.get("unix_sockets", []):
        socket = str(socket)
        ipc_item = _add(
            items, seen, category="IPC", identity=f"socket:{socket}", priority="MEDIUM",
            title="Application Unix Socket Trust Boundary",
            condition=socket,
            why="A local IPC endpoint can cross user or privilege boundaries. Filesystem permissions alone do not prove that peer authorization is enforced by the service.",
            validation=["Identify the owning process/service and its privilege.", "Inspect socket and parent-directory permissions.", "Determine how clients authenticate/authorize requests before attempting protocol-level tests."],
            related_reports=["ipc_review.txt", "service_review.txt"], evidence=["ss -lxnp", "lsof -U"],
        )
        if ipc_item is not None:
            ipc_item["object_type"] = "unix_socket"
            ipc_item["object_identity"] = _path_object_identity(socket) or socket
    for path in ipc_data.get("fifo_candidates", []):
        path = str(path)
        fifo_item = _add(
            items, seen, category="IPC", identity=f"fifo:{path}", priority="MEDIUM",
            title="Named FIFO Trust Boundary", condition=path,
            why="A FIFO used by a privileged component may permit request injection or spoofing if writers are not constrained and authenticated.",
            validation=["Identify producer and consumer processes.", "Confirm ownership/mode/ACL of the FIFO and its parent directory.", "Observe legitimate message flow before attempting harmless unauthorized input."],
            related_reports=["ipc_review.txt", "permissions_review.txt"], evidence=[f"stat {_q(path)}", f"getfacl {_q(path)}"],
        )
        if fifo_item is not None:
            fifo_item["object_type"] = "fifo"
            fifo_item["object_identity"] = path
    for name in ipc_data.get("dbus_names", []):
        name = str(name)
        _add(
            items, seen, category="DBUS", identity=name, priority="MEDIUM",
            title="D-Bus Interface Requires Authorization Review", condition=f"Referenced bus name: {name}",
            why="D-Bus interfaces can expose privileged operations to local callers; method-level authorization must match the intended trust boundary.",
            validation=["Identify whether the name is on the system or user bus.", "Introspect exported objects/methods where permitted.", "Review D-Bus and PolicyKit authorization before invoking state-changing methods."],
            related_reports=["ipc_review.txt"], evidence=[f"busctl --system introspect {_q(name)} /", f"busctl --user introspect {_q(name)} /"],
        )

    for detail in ipc_data.get("polkit_details", []) or []:
        if not detail.get("permissive_review"):
            continue
        action = str(detail.get("action") or "unknown-action")
        path = str(detail.get("path") or "")
        defaults = ", ".join(f"{k}={v}" for k, v in (detail.get("defaults") or {}).items())
        _add(
            items, seen, category="POLKIT", identity=f"{action}:{path}", priority="HIGH",
            title="PolicyKit Authorization Requires Validation",
            condition=f"Action {action} in {path}; defaults: {defaults or 'not parsed'}",
            why="Permissive PolicyKit defaults can expose privileged application operations to untrusted local callers, but the protected operation and any secondary authorization must be validated.",
            validation=["Identify the exact privileged operation protected by the action.", "Map the action to its D-Bus/service/helper call path.", "Test a harmless instance as the normal low-privileged user and verify whether authorization is enforced."],
            related_reports=["ipc_review.txt", "service_review.txt"],
            evidence=[f"Review {_q(path)}", f"pkcheck --action-id {_q(action)} --process $$ 2>/dev/null || true"],
        )

    for hit in storage_data.get("secret_hits", []):
        path = str(hit.get("path") or "")
        if not path:
            continue
        indicators = ", ".join(str(x) for x in hit.get("indicators", [])) or "credential-style assignment"
        perm = str(hit.get("permission") or "not identified")
        _add(
            items, seen, category="STOR", identity=path, priority="HIGH" if perm in {"world-readable", "world-writable"} else "MEDIUM",
            title="Potential Credential or Token Storage",
            condition=f"{path} contains {indicators}; value intentionally redacted. Observed permission context: {perm}.",
            why="The detected assignment may represent authentication material, but the value must be validated as real and its accessibility/lifetime/privilege determined before reporting.",
            validation=["Inspect the original file on the assessment VM; do not copy the secret into tester artifacts.", "Determine whether the value is a real credential/token and whether it is still usable.", "Validate file and parent-directory access for other local users and determine the credential's scope/lifetime."],
            related_reports=["local_storage_review.txt", "permissions_review.txt"], evidence=[f"stat {_q(path)}", f"getfacl {_q(path)}", "Capture only the minimum redacted evidence needed for the final report."],
        )
    for crypto in storage_data.get("crypto_material", []) or []:
        path = str(crypto.get("path") or "")
        if not path or not crypto.get("private_key"):
            continue
        indicators = ", ".join(str(x) for x in (crypto.get("indicators") or [])) or "cryptographic material"
        permission = str(crypto.get("permission") or "not identified")
        related_certs = [str(x) for x in (crypto.get("related_ca_certificates") or []) if str(x)]
        priority = "HIGH" if permission in {"world-readable", "world-writable"} and related_certs else "MEDIUM"
        crypto_item = _add(
            items, seen, category="CRYPTO", identity=path, priority=priority,
            title="Local CA / Private Key Material Requires Review" if related_certs else "Private Key Material Requires Review",
            condition=f"{path} contains {indicators}; values intentionally redacted. Permission context: {permission}. Related CA certificate(s): {', '.join(related_certs) if related_certs else 'none automatically correlated'}.",
            why="Locally generated private signing material can create a high-impact trust boundary if a lower-privileged user can recover or use it. A certificate or cryptographic salt alone is not a secret vulnerability.",
            validation=["Determine whether the material is an actual private signing key and whether any related certificate is a CA trusted by the application/system.", "Validate effective read/write access to the private-key or key-protection material.", "Determine whether possession/use of the key would allow certificate issuance across a meaningful trust boundary."],
            related_reports=["local_storage_review.txt", "network_surface_review.txt", "permissions_review.txt"],
            evidence=[f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}"],
        )
        if crypto_item is not None:
            crypto_item["crypto_path"] = path
            crypto_item["crypto_certificates"] = related_certs
            crypto_item["crypto_salt_present"] = bool(crypto.get("salt"))

    for item in storage_data.get("configuration_risks", []):
        path = str(item.get("path") or "")
        indicator = str(item.get("indicator") or "insecure configuration")
        if path:
            _add(
                items, seen, category="STORCFG", identity=f"{path}:{indicator}", priority="MEDIUM",
                title="Sensitive Configuration Setting Requires Validation",
                condition=f"{path}: {indicator}",
                why="Static configuration can indicate disabled verification, insecure transport, or debug behavior, but actual runtime behavior must be confirmed.",
                validation=["Inspect the setting in context and determine whether it is active.", "Exercise the relevant application workflow and confirm the effective runtime behavior."],
                related_reports=["local_storage_review.txt", "runtime_review.txt"], evidence=[f"Review {_q(path)} with sensitive values redacted."],
            )

    for item in update_data.get("insecure_update_url_candidates", []):
        url = str(item.get("url") or "")
        if url:
            _add(
                items, seen, category="UPD", identity=url, priority="HIGH",
                title="Cleartext Software Update Path Requires Validation",
                condition=f"Probable update endpoint: {url}",
                why="If privileged software updates are actually retrieved over cleartext transport, an on-path attacker may be able to influence update delivery unless independent cryptographic authentication is enforced.",
                validation=["Exercise the real updater and confirm whether the endpoint is contacted.", "Determine whether packages/manifests are cryptographically authenticated independent of transport.", "Assess downgrade/rollback behavior where authorized."],
                related_reports=["update_review.txt", "network_surface_review.txt"], evidence=["Capture the updater process, destination, transport, and signature/checksum validation behavior."],
            )
    for item in update_data.get("repository_security_candidates", []):
        path = str(item.get("path") or "")
        indicator = str(item.get("indicator") or "repository security setting")
        if path:
            _add(
                items, seen, category="UPD", identity=f"repo:{path}:{indicator}", priority="HIGH",
                title="Repository Security Configuration Requires Review", condition=f"{path}: {indicator}",
                why="Weak repository transport or disabled package verification can undermine the integrity of privileged software updates.",
                validation=["Confirm the repository is actually used by the application update workflow.", "Verify repository metadata/package authentication and transport protections."],
                related_reports=["update_review.txt"], evidence=[f"Review {_q(path)} with credentials redacted."],
            )

    for item in persistence_data.get("review_required", []):
        title = str(item.get("title") or "Privileged Persistence Policy Requires Review")
        evidence_text = str(item.get("evidence") or "")
        _add(
            items, seen, category="PERS", identity=str(item.get("identity") or evidence_text or title), priority="HIGH",
            title=title, condition=evidence_text or "Application introduced or changed a privileged persistence/policy mechanism.",
            why="Persistence and privilege-policy changes can create durable privilege boundaries and should be validated before closeout.",
            validation=[str(item.get("action") or "Inspect the effective policy and determine what an unprivileged user can cause a privileged component to execute.")],
            related_reports=["persistence_review.txt", "permissions_review.txt"], evidence=["Capture the effective policy and the low-privileged user's resulting rights."],
        )

    # Effective sudo rules that rise to automatic finding-candidate strength
    # receive their own review task so candidate disposition can be tracked
    # explicitly instead of being inferred from the generic sudoers-file review.
    for item in persistence_data.get("sudo_policy_candidates", []):
        if not item.get("finding_candidate"):
            continue
        command = str(item.get("command") or item.get("raw") or "unknown")
        runas = str(item.get("runas") or "root")
        concerns = "; ".join(str(x) for x in (item.get("concerns") or [])) or "Privileged sudo rule requires validation"
        raw_identity = f"sudo-candidate:{runas}:{command}"
        _add(
            items, seen, category="PERS", identity=raw_identity, priority="HIGH",
            title="Potentially Unsafe sudoers Rule Requires Validation",
            condition=f"Run as {runas}: {command} ({concerns})",
            why="A sudo rule can create an unintended privilege path when its command, arguments, environment, wildcard handling, or execution chain can be influenced by the invoking user.",
            validation=["Inspect the effective sudo rule with sudo -l.", "Validate the complete executable/input chain and determine whether the rule permits unintended privileged behavior."],
            related_reports=["persistence_review.txt", "permissions_review.txt"],
            evidence=["sudo visudo -c", "sudo -l", "Capture the exact effective rule and benign proof of impact if validated."],
        )

    primary = str(profile_data.get("primary_technology") or "").strip()
    if primary:
        supporting = ", ".join(str(x) for x in profile_data.get("supporting_technologies", []) if x) or "none identified"
        tech = next((item for item in profile_data.get("technologies", []) if item.get("technology") == primary), {})
        validation = list(tech.get("guidance", []))[:3] or ["Validate the detected framework and apply its applicable security review procedures."]
        _add(
            items, seen, category="TECH", identity=f"primary:{primary}", priority="LOW",
            title="Technology-Specific Review Plan",
            condition=f"Primary technology: {primary}; supporting technologies: {supporting}.",
            why="Framework-aware review helps focus testing on the application's actual trust boundaries without treating technology presence as a vulnerability.",
            validation=validation,
            related_reports=["application_profile.txt", "runtime_review.txt", "ipc_review.txt"],
            evidence=["Use application_profile.txt to record the technology evidence used to scope manual testing."],
        )

    for listener in runtime_data.get("externally_bound_listeners", []) or []:
        runtime_listener = _add(
            items, seen, category="RUNTIME", identity=f"runtime-listener:{listener}", priority="MEDIUM",
            title="Runtime Application Listener Requires Validation", condition=str(listener),
            why="A listener observed while the application is running represents confirmed runtime attack surface and should be validated for intended exposure and access control.",
            validation=["Confirm the owning application process and bind scope.", "Validate authentication/authorization and expected remote accessibility within scope.", "Compare the runtime listener with static/network configuration evidence."],
            related_reports=["runtime_review.txt", "network_surface_review.txt"], evidence=["Capture ss/lsof ownership and the application workflow that caused the listener to appear."],
        )
        if runtime_listener is not None:
            runtime_listener["object_type"] = "listener"
            runtime_listener["object_identity"] = _listener_object_identity(str(listener)) or str(listener)
            runtime_listener["runtime_confirmed"] = True
    for proc in runtime_data.get("shell_children", []) or []:
        pid = proc.get("pid")
        priority = "HIGH" if str(proc.get("user")) == "root" else "MEDIUM"
        _add(
            items, seen, category="RUNTIME", identity=f"shell-child:{proc.get('comm')}:{proc.get('args')}", priority=priority,
            title="Runtime Child Shell Execution",
            condition=f"PID {pid} {proc.get('user')} {proc.get('comm')} | {proc.get('args')}",
            why="Application-spawned shells can create command/argument injection or privilege-boundary risk when inputs are attacker influenced.",
            validation=["Identify the parent application action that triggered the shell.", "Determine whether untrusted input can influence the command, arguments, environment, or working directory.", "If privileged, validate the authorization boundary before attempting harmless input manipulation."],
            related_reports=["runtime_review.txt", "permissions_review.txt"], evidence=["Capture the parent/child process tree and sanitized command line."],
        )
    for item in runtime_data.get("socket_analysis", []) or []:
        if item.get("review_level") not in {"HIGH", "MEDIUM"}:
            continue
        path = str(item.get("path") or item.get("line") or "runtime socket")
        priority = "HIGH" if item.get("review_level") == "HIGH" else "MEDIUM"
        runtime_socket = _add(
            items, seen, category="RUNTIME-IPC", identity=f"runtime-socket:{path}", priority=priority,
            title="Runtime IPC Authorization Boundary", condition=str(item.get("line") or path),
            why="A live application IPC endpoint was observed; privileged or broadly writable endpoints require validation of peer identity, authorization, symlink/path handling, and request trust.",
            validation=["Identify the owning process/service and effective privilege.", "Validate socket and parent-directory permissions where pathname-based.", "Observe legitimate client/server traffic and determine whether unauthorized local callers can submit accepted requests."],
            related_reports=["ipc_review.txt", "runtime_review.txt"], evidence=["Capture socket ownership/permissions and the corresponding process/service identity."],
        )
        if runtime_socket is not None:
            runtime_socket["object_type"] = "unix_socket"
            runtime_socket["object_identity"] = str(item.get("path") or _path_object_identity(str(item.get("line") or path)) or path)
            runtime_socket["runtime_confirmed"] = True

    for fifo_path in runtime_data.get("fifo_paths", []) or []:
        fifo_path = str(fifo_path)
        runtime_fifo = _add(
            items, seen, category="RUNTIME-IPC", identity=f"runtime-fifo:{fifo_path}", priority="MEDIUM",
            title="Runtime FIFO Trust Boundary", condition=fifo_path,
            why="A named FIFO was confirmed during live application execution; writers/readers and message authorization should be validated when the endpoint crosses a privilege boundary.",
            validation=["Identify the FIFO reader/writer processes and their privilege.", "Validate effective filesystem permissions and observe legitimate message format before harmless input testing."],
            related_reports=["ipc_review.txt", "runtime_review.txt", "permissions_review.txt"], evidence=[f"stat {_q(fifo_path)}", f"getfacl {_q(fifo_path)}"],
        )
        if runtime_fifo is not None:
            runtime_fifo["object_type"] = "fifo"
            runtime_fifo["object_identity"] = fifo_path
            runtime_fifo["runtime_confirmed"] = True

    # v1.6.0: mature discovered security-condition review items are generated from
    # the structured correlation engine, including runtime-discovered externally
    # bound listeners. Technology-specific planning remains workflow guidance.
    items = _apply_correlation_review_ownership(items, correlation_model)

    # Deterministic order makes numeric review IDs stable for an assessment.
    items.sort(key=lambda item: (PRIORITY_ORDER[item["priority"]], item["category"], item["title"].casefold(), item["identity"]))
    for index, item in enumerate(items, 1):
        item["id"] = f"TRQ-{index:03d}"
    return items



def _review_source(item: dict[str, Any]) -> str:
    source = str(item.get("generation_source") or "")
    if source == "correlation_engine":
        return "correlation_engine"
    if str(item.get("category") or "") == "TECH":
        return "workflow_guidance"
    return source or "compatibility_fallback"


def build_review_items(
    permission_data: dict[str, Any] | None = None,
    network_data: dict[str, Any] | None = None,
    service_data: dict[str, Any] | None = None,
    elf_data: dict[str, Any] | None = None,
    ipc_data: dict[str, Any] | None = None,
    storage_data: dict[str, Any] | None = None,
    update_data: dict[str, Any] | None = None,
    persistence_data: dict[str, Any] | None = None,
    profile_data: dict[str, Any] | None = None,
    runtime_data: dict[str, Any] | None = None,
    correlation_model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build the tester queue from the structured model when available.

    v1.6.2 retires the normal generate-legacy-then-replace ownership path.  Current
    assessments render correlation-owned items directly from security_model.json.
    The legacy candidate builder remains a compatibility bridge for assessments
    without a structured model and for edge categories that have not yet been
    promoted to correlation ownership.
    """
    if not isinstance(correlation_model, dict) or not correlation_model.get("correlations"):
        return decorate_review_items(_build_legacy_review_items(
            permission_data, network_data, service_data, elf_data, ipc_data,
            storage_data, update_data, persistence_data, profile_data, runtime_data,
            correlation_model,
        ))

    structured = _correlation_review_items(correlation_model)
    structured_ids = {str(item.get("identity") or "") for item in structured}
    structured_objects = {
        (str(item.get("object_type") or ""), str(item.get("object_identity") or "")): item
        for item in structured if item.get("object_type") and item.get("object_identity")
    }

    # Compatibility candidates are synthesized only to preserve genuinely
    # unmigrated edge categories (for example technology planning, framework-
    # specific config review, static-only listener review, or runtime shell-child
    # observations). Correlation-owned identities are never admitted from this path.
    compatibility = _build_legacy_review_items(
        permission_data, network_data, service_data, elf_data, ipc_data,
        storage_data, update_data, persistence_data, profile_data, runtime_data,
        None,
    )
    retained: list[dict[str, Any]] = []
    for item in compatibility:
        if str(item.get("identity") or "") in structured_ids:
            continue
        object_key = (str(item.get("object_type") or ""), str(item.get("object_identity") or ""))
        if object_key != ("", "") and object_key in structured_objects:
            target = structured_objects[object_key]
            if item.get("runtime_confirmed"):
                _merge_runtime_confirmation(target, item)
            continue
        item = dict(item)
        item.pop("id", None)
        item["generation_source"] = _review_source(item)
        retained.append(item)

    items = [dict(item) for item in structured] + retained
    items.sort(key=lambda item: (PRIORITY_ORDER[item["priority"]], item["category"], item["title"].casefold(), item["identity"]))
    for index, item in enumerate(items, 1):
        item["id"] = f"TRQ-{index:03d}"
    return decorate_review_items(items)

def _state_path(output_dir: Path) -> Path:
    return working_dir(output_dir) / "tester_review_state.json"


def _new_state(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "framework_version": VERSION,
        "generated_at": now_iso(),
        "updated_at": now_iso(),
        "items": [dict(item, status="PENDING", notes="") for item in items],
    }


def _merge_state(items: list[dict[str, Any]], existing: dict[str, Any] | None) -> dict[str, Any]:
    old_by_identity: dict[str, dict[str, Any]] = {}
    if isinstance(existing, dict):
        for item in existing.get("items", []):
            if isinstance(item, dict) and item.get("identity"):
                old_by_identity[str(item["identity"])] = item
    merged = _new_state(items)
    for item in merged["items"]:
        old = old_by_identity.get(str(item["identity"]))
        if not old:
            continue
        status = str(old.get("status") or "PENDING").upper()
        if status in VALID_STATUSES:
            item["status"] = status
        item["notes"] = redact_sensitive_text(str(old.get("notes") or ""))[:4000]
    return merged


def _render_queue(state: dict[str, Any]) -> str:
    items = list(state.get("items", []))
    counts = Counter(str(item.get("priority") or "MEDIUM") for item in items)
    statuses = Counter(str(item.get("status") or "PENDING") for item in items)
    lines = [
        "UbuntuClientAssess Tester Review Queue",
        "========================================",
        "",
        "This is a prioritized testing queue, not a vulnerability list. Priority indicates where tester time is likely to be most valuable; it is not CVSS/severity.",
        "Review is organized by security area and related-item groups so shared context can be established once and reused where it remains applicable.",
        "Validate exploitability, authorization impact, application context, and concrete security impact before moving any item into the final client report.",
        "",
        "Summary",
        "-------",
        f"Total review items:       {len(items)}",
        f"High priority:            {counts.get('HIGH', 0)}",
        f"Medium priority:          {counts.get('MEDIUM', 0)}",
        f"Low priority:             {counts.get('LOW', 0)}",
        f"Pending:                  {statuses.get('PENDING', 0)}",
        f"Validated:                {statuses.get('VALIDATED', 0)}",
        f"Not applicable:           {statuses.get('NOT APPLICABLE', 0)}",
        f"Informational:            {statuses.get('INFORMATIONAL', 0)}",
        "",
        "Category Progress",
        "-----------------",
    ]
    for row in category_progress(items):
        lines.append(f"{row['category']:<28} {row['completed']:>2} / {row['total']:<2} complete | {row['pending']} pending")
    lines.append("")
    coverage_limitations = list(state.get("coverage_limitations", []) or [])
    if coverage_limitations:
        lines += [
            "Static Application File Coverage",
            "--------------------------------",
            "LIMITED - one or more identified application installation roots could not be recursively inspected by the assessment user.",
            "No review candidate generated from inaccessible content should be interpreted as evidence that the content is secure.",
        ]
        for gap in coverage_limitations:
            lines.append(f"- {gap.get('path')} | owner={gap.get('owner')} group={gap.get('group')} mode={gap.get('mode')}")
        lines.append("")
    if not items:
        lines += ["No prioritized review candidates were generated.", "This does not establish that the assessed application has no vulnerabilities."]
        return "\n".join(lines)

    for row in category_progress(items):
        category = row["category"]
        heading = category
        lines += [heading, "=" * len(heading), ""]
        category_items = [item for item in items if review_category(item) == category]
        group_keys = []
        for item in category_items:
            key = str(item.get("review_group") or review_group(item)[0])
            if key not in group_keys:
                group_keys.append(key)
        for key in group_keys:
            group_items = [item for item in category_items if str(item.get("review_group") or review_group(item)[0]) == key]
            group_label = str(group_items[0].get("review_group_label") or review_group(group_items[0])[1])
            lines += [f"Group: {group_label}", "-" * (7 + len(group_label))]
            shared = list(group_items[0].get("shared_validation") or shared_validation_for(group_items[0]))
            if len(group_items) > 1 and shared:
                lines += ["Shared Validation Context:"] + [f"  - {x}" for x in shared] + [""]
            for item in group_items:
                lines += [
                    f"[{item.get('id')}] {item.get('title')}",
                    f"Priority:    {item.get('priority')}",
                    f"Status:      {item.get('status', 'PENDING')}",
                    f"Condition:   {item.get('condition', '')}",
                ]
                if item.get("generation_source") == "correlation_engine":
                    lines += [
                        "Generation:  Correlation Engine",
                        f"Rule:        {item.get('correlation_rule') or 'structured correlation'}",
                        f"Correlation: {item.get('correlation_id') or ''}",
                    ]
                    supporting = [str(x) for x in (item.get("supporting_observation_ids") or []) if str(x)]
                    if supporting:
                        lines += ["Supporting Observations: " + ", ".join(supporting)]
                elif item.get("generation_source") == "workflow_guidance":
                    lines += ["Generation:  Workflow Guidance"]
                if item.get("runtime_confirmed"):
                    lines += ["Runtime Confirmation: YES"]
                    lines += [f"  - {obs}" for obs in (item.get("runtime_observations") or [])[:10]]
                lines += ["", "Why It Matters:", f"  {item.get('why_it_matters', '')}", "", "Detailed Validation Procedure:"]
                lines += render_playbook_lines(playbook_for(item), indent="  ")
                lines += ["Related Reports:"]
                lines += [f"  - {name}" for name in item.get("related_reports", [])] or ["  - None"]
                if item.get("notes"):
                    lines += ["", "Tester Notes:", f"  {item['notes']}"]
                lines.append("")
    return "\n".join(lines)


def _render_evidence_guide(state: dict[str, Any]) -> str:
    items = list(state.get("items", []))
    lines = [
        "UbuntuClientAssess Evidence Guide",
        "===================================",
        "",
        "This guide suggests evidence that may be useful when a review item becomes a validated finding. Screenshots/evidence belong in the final Word report, not in this text file.",
        "Capture only the minimum necessary evidence and redact credentials, tokens, personal data, and unrelated client information.",
        "",
    ]
    actionable = [item for item in items if item.get("status") != "NOT APPLICABLE"]
    if not actionable:
        lines.append("No applicable evidence bookmarks are currently present.")
        return "\n".join(lines)
    for item in actionable:
        lines += [
            f"[{item.get('id')}] {item.get('title')}",
            "-" * (len(str(item.get('id'))) + len(str(item.get('title'))) + 3),
            f"Priority:  {item.get('priority')}",
            f"Status:    {item.get('status')}",
            f"Condition: {item.get('condition')}",
            "",
            "Suggested Evidence:",
        ]
        playbook = playbook_for(item)
        lines += [f"  - {entry}" for entry in playbook.get("evidence", [])] or ["  - Capture the effective configuration and a harmless validation of the security boundary."]
        lines += ["", "Supporting Reports:"]
        lines += [f"  - {name}" for name in item.get("related_reports", [])] or ["  - None"]
        if item.get("notes"):
            lines += ["", "Tester Notes:", f"  {item['notes']}"]
        lines.append("")
    return "\n".join(lines)


def write_review_outputs(output_dir: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = now_iso()
    write_json(_state_path(output_dir), state)
    write_text(report_path(output_dir, "tester_review.txt"), _render_queue(state))
    write_text(report_path(output_dir, "evidence_guide.txt"), _render_evidence_guide(state))


def refresh_review_reports(output_dir: Path) -> dict[str, Any]:
    """Regenerate tester-facing review reports without changing authoritative state."""
    state = load_review_state(output_dir)
    write_text(report_path(output_dir, "tester_review.txt"), _render_queue(state))
    write_text(report_path(output_dir, "evidence_guide.txt"), _render_evidence_guide(state))
    return state


def generate_tester_review(
    output_dir: Path,
    permission_data: dict[str, Any] | None = None,
    network_data: dict[str, Any] | None = None,
    service_data: dict[str, Any] | None = None,
    elf_data: dict[str, Any] | None = None,
    ipc_data: dict[str, Any] | None = None,
    storage_data: dict[str, Any] | None = None,
    update_data: dict[str, Any] | None = None,
    persistence_data: dict[str, Any] | None = None,
    profile_data: dict[str, Any] | None = None,
    runtime_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    model_path = working_dir(output_dir) / "security_model.json"
    correlation_model = read_json(model_path) if model_path.is_file() else None
    items = build_review_items(permission_data, network_data, service_data, elf_data, ipc_data, storage_data, update_data, persistence_data, profile_data, runtime_data, correlation_model)
    existing = None
    path = _state_path(output_dir)
    if path.is_file():
        try:
            existing = read_json(path)
        except Exception:
            existing = None
    state = _merge_state(items, existing)
    state["coverage_limitations"] = list((profile_data or {}).get("coverage_limitations", []) or [])
    write_review_outputs(output_dir, state)
    return state


def merge_additional_review_items(
    output_dir: Path,
    *,
    profile_data: dict[str, Any] | None = None,
    runtime_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge post-assessment review candidates without renumbering existing items."""
    existing = load_review_state(output_dir)
    model_path = working_dir(output_dir) / "security_model.json"
    correlation_model = read_json(model_path) if model_path.is_file() else None
    candidates = build_review_items(profile_data=profile_data, runtime_data=runtime_data, correlation_model=correlation_model)
    existing_by_identity = {str(item.get("identity")): item for item in existing.get("items", []) if item.get("identity")}
    max_id = 0
    for item in existing.get("items", []):
        try:
            max_id = max(max_id, int(str(item.get("id", "")).split("-")[-1]))
        except ValueError:
            pass
    for candidate in candidates:
        identity = str(candidate.get("identity"))
        if identity in existing_by_identity:
            # Refresh descriptive fields while preserving tester disposition/notes/ID.
            old = existing_by_identity[identity]
            status, notes, item_id = old.get("status", "PENDING"), old.get("notes", ""), old.get("id")
            old.update(candidate)
            old["status"], old["notes"], old["id"] = status, redact_sensitive_text(str(notes))[:4000], item_id
            continue
        equivalent = _runtime_match(existing.get("items", []), candidate)
        if equivalent is not None:
            if candidate.get("generation_source") == "correlation_engine":
                status, notes, item_id = equivalent.get("status", "PENDING"), equivalent.get("notes", ""), equivalent.get("id")
                runtime_before = bool(equivalent.get("runtime_confirmed"))
                previous_observations = list(equivalent.get("runtime_observations") or [])
                equivalent.update(candidate)
                equivalent["status"], equivalent["notes"], equivalent["id"] = status, redact_sensitive_text(str(notes))[:4000], item_id
                if runtime_before:
                    equivalent["runtime_confirmed"] = True
                    equivalent["runtime_observations"] = previous_observations
            _merge_runtime_confirmation(equivalent, candidate)
            continue
        max_id += 1
        candidate = dict(candidate)
        candidate["id"] = f"TRQ-{max_id:03d}"
        candidate["status"] = "PENDING"
        candidate["notes"] = ""
        existing.setdefault("items", []).append(candidate)
        existing_by_identity[identity] = candidate
    write_review_outputs(output_dir, existing)
    return existing


def load_review_state(output_dir: Path) -> dict[str, Any]:
    path = _state_path(output_dir)
    if not path.is_file():
        raise RuntimeError("working/tester_review_state.json is missing; this assessment does not contain a v1.2 tester review queue")
    state = read_json(path)
    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise RuntimeError(f"Unsupported tester review state schema: {state.get('schema_version')}")
    return state


def update_review_item(output_dir: Path, identity: str, *, status: str | None = None, notes: str | None = None) -> dict[str, Any]:
    state = load_review_state(output_dir)
    target = None
    for item in state.get("items", []):
        if item.get("identity") == identity:
            target = item
            break
    if target is None:
        raise RuntimeError("Selected review item is no longer present")
    if status is not None:
        normalized = status.upper()
        if normalized not in VALID_STATUSES:
            raise ValueError(f"Unsupported review status: {status}")
        target["status"] = normalized
    if notes is not None:
        target["notes"] = redact_sensitive_text(notes.strip())[:4000]
    write_review_outputs(output_dir, state)
    return state
