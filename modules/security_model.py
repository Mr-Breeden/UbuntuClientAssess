from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable

from .common import now_iso, read_json, working_dir, write_json
from .tester_review import stable_review_identity

MODEL_SCHEMA_VERSION = 10
MODEL_FILENAME = "security_model.json"


def _digest(*parts: str, length: int = 16) -> str:
    raw = "\0".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:length]


def canonical_object_id(kind: str, identity: str) -> str:
    kind = str(kind or "object").strip().casefold().replace(" ", "_")
    identity = str(identity or "unknown").strip()
    return f"{kind}:{identity}"


def _observation_id(category: str, object_id: str, source: str, discriminator: str = "") -> str:
    return f"OBS-{_digest(category, object_id, source, discriminator, length=14)}"


def _relationship_id(source: str, relation: str, target: str) -> str:
    return f"REL-{_digest(source, relation, target, length=14)}"


def _correlation_id(kind: str, identity: str) -> str:
    return f"COR-{_digest(kind, identity, length=14)}"


def _evidence_ref(bookmark: str, source_module: str, category: str, object_id: str) -> dict[str, str]:
    bookmark = str(bookmark or "").strip()
    return {
        "id": f"EVR-{_digest(source_module, category, object_id, bookmark, length=14)}",
        "bookmark": bookmark,
        "source_module": str(source_module or ""),
        "category": str(category or ""),
        "object_id": str(object_id or ""),
    }


def _required_finding_categories(kind: str) -> set[str]:
    return {
        "privileged_service_writable_path": {"service_dependency"},
        "writable_elf_search_path": {"elf_search_path"},
        "cleartext_update_path": {"cleartext_update_endpoint"},
        "unsafe_sudo_policy": {"sudo_policy"},
        "exposed_local_ca_private_key": {"cryptographic_material"},
    }.get(kind, set())



def canonical_network_endpoint(text: str) -> str:
    """Reduce volatile ss rows to protocol + local listener identity when possible."""
    parts = str(text).split()
    proto = next((part.casefold() for part in parts if part.casefold() in {"tcp", "udp"}), "inet")
    for index, part in enumerate(parts):
        if part.upper() in {"LISTEN", "UNCONN"} and index + 3 < len(parts):
            local = parts[index + 3]
            if ":" in local:
                return f"{proto}:{local}"
    if len(parts) >= 5 and ":" in parts[4]:
        return f"{proto}:{parts[4]}"
    return str(text).strip()




def canonical_unix_socket_identity(value: Any) -> str:
    """Return a stable Unix-socket identity from a path, mapping, or ss row."""
    if isinstance(value, dict):
        explicit = str(value.get("path") or "").strip()
        if explicit:
            return explicit
        value = value.get("line") or value.get("raw") or ""
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("/") or (text.startswith("@") and " " not in text):
        return text
    for token in text.split():
        token = token.strip()
        if token.startswith("/"):
            return token
        if token.startswith("@") and len(token) > 1:
            return token
    return ""


def filesystem_object_kind(type_hint: Any, path: str = "") -> str:
    """Normalize filesystem entities to canonical object kinds."""
    hint = str(type_hint or "").strip().casefold().replace("-", "_")
    mapping = {
        "directory": "directory", "dir": "directory",
        "fifo": "fifo", "named_pipe": "fifo", "pipe": "fifo",
        "socket": "unix_socket", "unix_socket": "unix_socket",
        "symlink": "symlink", "link": "symlink",
        "file": "file", "regular": "file", "regular_file": "file",
    }
    if hint in mapping:
        return mapping[hint]
    try:
        candidate = Path(path)
        if candidate.exists():
            if candidate.is_dir():
                return "directory"
            if candidate.is_symlink():
                return "symlink"
    except OSError:
        pass
    return "file"


def _filesystem_object(builder: "SecurityModelBuilder", path: str, type_hint: Any = None, **attributes: Any) -> str:
    kind = filesystem_object_kind(type_hint, path)
    return builder.object(kind, path, filesystem_type=str(type_hint or "") or None, **attributes)


def _find_existing_filesystem_object(builder: "SecurityModelBuilder", path: str) -> str | None:
    for kind in ("file", "directory", "fifo", "unix_socket", "symlink"):
        object_id = canonical_object_id(kind, path)
        if object_id in builder.objects:
            return object_id
    return None

def _as_strings(values: Iterable[Any] | None) -> list[str]:
    return sorted({str(value) for value in (values or []) if str(value).strip()})


class SecurityModelBuilder:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}
        self.observations: dict[str, dict[str, Any]] = {}
        self.relationships: dict[str, dict[str, Any]] = {}
        self.correlations: dict[str, dict[str, Any]] = {}

    def object(self, kind: str, identity: str, **attributes: Any) -> str:
        object_id = canonical_object_id(kind, identity)
        record = self.objects.setdefault(
            object_id,
            {"id": object_id, "kind": kind, "identity": str(identity), "attributes": {}},
        )
        for key, value in attributes.items():
            if value not in (None, "", [], {}):
                record["attributes"][key] = value
        return object_id

    def observation(
        self,
        category: str,
        object_id: str,
        source: str,
        *,
        summary: str,
        attributes: dict[str, Any] | None = None,
        evidence: list[str] | None = None,
        discriminator: str = "",
    ) -> str:
        obs_id = _observation_id(category, object_id, source, discriminator or summary)
        bookmarks = _as_strings(evidence)
        self.observations[obs_id] = {
            "id": obs_id,
            "category": category,
            "object_id": object_id,
            "source_module": source,
            "summary": summary,
            "attributes": attributes or {},
            "evidence_bookmarks": bookmarks,
            "evidence_refs": [_evidence_ref(x, source, category, object_id) for x in bookmarks],
        }
        return obs_id

    def relationship(self, source: str, relation: str, target: str, **attributes: Any) -> str:
        rel_id = _relationship_id(source, relation, target)
        record = {
            "id": rel_id,
            "source": source,
            "relation": relation,
            "target": target,
        }
        if attributes:
            record["attributes"] = {k: v for k, v in attributes.items() if v not in (None, "", [], {})}
        self.relationships[rel_id] = record
        return rel_id

    def correlation(
        self,
        kind: str,
        identity: str,
        *,
        strength: str,
        title: str,
        summary: str,
        object_ids: list[str],
        observation_ids: list[str],
        review_identity: str | None = None,
        finding_identity: str | None = None,
    ) -> str:
        correlation_id = _correlation_id(kind, identity)
        review_rule_ids = {
            "privileged_service_writable_path": "CORR-SVC-WRITABLE-PATH",
            "writable_elf_search_path": "CORR-ELF-WRITABLE-SEARCH-PATH",
            "cleartext_update_path": "CORR-UPD-CLEARTEXT",
            "unix_socket_authorization_boundary": "CORR-IPC-UNIX-SOCKET",
            "fifo_authorization_boundary": "CORR-IPC-FIFO",
            "dbus_authorization_boundary": "CORR-DBUS-AUTHZ",
            "polkit_authorization_boundary": "CORR-POLKIT-AUTHZ",
            "permission_boundary": "CORR-PERM-BOUNDARY",
            "file_capability_boundary": "CORR-CAP-FILE",
            "suid_sgid_helper_boundary": "CORR-SUID-HELPER",
            "sudoers_policy_change": "CORR-SUDO-POLICY",
            "unsafe_sudo_policy": "CORR-SUDO-RULE",
            "credential_token_storage": "CORR-STOR-CREDENTIAL",
            "cleartext_application_endpoint": "CORR-COMM-CLEARTEXT",
            "runtime_application_listener": "CORR-NET-RUNTIME-LISTENER",
            "exposed_local_ca_private_key": "CORR-CRYPTO-LOCAL-CA",
        }
        finding_owned = kind in {
            "privileged_service_writable_path",
            "writable_elf_search_path",
            "cleartext_update_path",
            "unsafe_sudo_policy",
            "exposed_local_ca_private_key",
        }
        engine_owned = kind in review_rule_ids
        clean_object_ids = _as_strings(object_ids)
        clean_observation_ids = _as_strings(observation_ids)
        obs_records = [self.observations[x] for x in clean_observation_ids if x in self.observations]
        source_modules = sorted({str(x.get("source_module") or "") for x in obs_records if str(x.get("source_module") or "")})
        relationship_ids = sorted(
            rel_id for rel_id, rel in self.relationships.items()
            if str(rel.get("source") or "") in clean_object_ids or str(rel.get("target") or "") in clean_object_ids
        )
        evidence_refs: dict[str, dict[str, Any]] = {}
        for obs in obs_records:
            for ref in obs.get("evidence_refs", []) or []:
                if isinstance(ref, dict) and ref.get("id"):
                    evidence_refs[str(ref["id"])] = dict(ref)
        categories = {str(x.get("category") or "") for x in obs_records}
        suppression_reasons: list[str] = []
        if not clean_object_ids:
            suppression_reasons.append("No canonical object supports the correlation.")
        if not clean_observation_ids:
            suppression_reasons.append("No structured observation supports the correlation.")
        required_categories = _required_finding_categories(kind) if finding_owned and finding_identity else set()
        missing_categories = sorted(required_categories - categories)
        if missing_categories:
            suppression_reasons.append("Required structured evidence is missing: " + ", ".join(missing_categories) + ".")
        suppressed = bool(suppression_reasons)
        if len(source_modules) >= 2:
            evidence_quality = "HIGH"
        elif clean_observation_ids and clean_object_ids:
            evidence_quality = "MODERATE"
        else:
            evidence_quality = "LOW"
        rationale = (
            f"{title} is supported by {len(clean_observation_ids)} structured observation(s) "
            f"across {len(source_modules)} source module(s), {len(clean_object_ids)} canonical object(s), "
            f"and {len(relationship_ids)} related model relationship(s)."
        )
        self.correlations[correlation_id] = {
            "id": correlation_id,
            "kind": kind,
            "rule_id": review_rule_ids.get(kind, ""),
            "strength": strength,
            "title": title,
            "summary": summary,
            "rationale": rationale,
            "object_ids": clean_object_ids,
            "observation_ids": clean_observation_ids,
            "relationship_ids": relationship_ids,
            "source_modules": source_modules,
            "cross_module": len(source_modules) >= 2,
            "evidence_refs": sorted(evidence_refs.values(), key=lambda x: str(x.get("id") or "")),
            "evidence_quality": evidence_quality,
            "suppressed": suppressed,
            "suppression_reasons": suppression_reasons,
            "review_identity": review_identity or "",
            "finding_identity": finding_identity or "",
            "generation_source": "correlation_engine" if engine_owned else "legacy_bridge",
            "drives_review": bool(engine_owned and review_identity and not suppressed),
            "drives_finding": bool(finding_owned and finding_identity and not suppressed),
            "review_status": "PENDING" if review_identity else "",
        }
        return correlation_id

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": MODEL_SCHEMA_VERSION,
            "generated_at": now_iso(),
            "model_purpose": "Structured application-security observations, canonical objects, relationships, and cross-module correlations.",
            "objects": sorted(self.objects.values(), key=lambda x: x["id"]),
            "observations": sorted(self.observations.values(), key=lambda x: x["id"]),
            "relationships": sorted(self.relationships.values(), key=lambda x: x["id"]),
            "correlations": sorted(self.correlations.values(), key=lambda x: x["id"]),
        }


def normalize_existing_model_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Migrate older structured models to the current canonical schema."""
    id_map: dict[str, str | None] = {}
    normalized_objects: dict[str, dict[str, Any]] = {}

    for item in payload.get("objects", []) or []:
        old_id = str(item.get("id") or "")
        kind = str(item.get("kind") or "object")
        identity = str(item.get("identity") or "")
        attributes = dict(item.get("attributes") or {})

        if kind == "unix_socket":
            canonical_identity = canonical_unix_socket_identity(identity or attributes.get("raw_runtime_observation") or "")
            if not canonical_identity:
                id_map[old_id] = None
                continue
            kind = "unix_socket"
            identity = canonical_identity
        elif kind == "file":
            kind = filesystem_object_kind(attributes.get("type") or attributes.get("filesystem_type"), identity)

        new_id = canonical_object_id(kind, identity)
        id_map[old_id] = new_id
        existing = normalized_objects.setdefault(new_id, {"id": new_id, "kind": kind, "identity": identity, "attributes": {}})
        existing["attributes"].update(attributes)

    normalized_observations: list[dict[str, Any]] = []
    for item in payload.get("observations", []) or []:
        record = dict(item)
        old_object = str(record.get("object_id") or "")
        new_object = id_map.get(old_object, old_object)
        if new_object is None:
            continue
        record["object_id"] = new_object
        bookmarks = _as_strings(record.get("evidence_bookmarks") or [])
        record["evidence_bookmarks"] = bookmarks
        if not record.get("evidence_refs"):
            record["evidence_refs"] = [
                _evidence_ref(x, str(record.get("source_module") or ""), str(record.get("category") or ""), str(new_object))
                for x in bookmarks
            ]
        normalized_observations.append(record)

    normalized_relationships: list[dict[str, Any]] = []
    for item in payload.get("relationships", []) or []:
        record = dict(item)
        source = id_map.get(str(record.get("source") or ""), str(record.get("source") or ""))
        target = id_map.get(str(record.get("target") or ""), str(record.get("target") or ""))
        if source is None or target is None:
            continue
        record["source"] = source
        record["target"] = target
        record["id"] = _relationship_id(source, str(record.get("relation") or ""), target)
        normalized_relationships.append(record)

    normalized_correlations: list[dict[str, Any]] = []
    authoritative_rules = {
        "privileged_service_writable_path": "CORR-SVC-WRITABLE-PATH",
        "writable_elf_search_path": "CORR-ELF-WRITABLE-SEARCH-PATH",
        "cleartext_update_path": "CORR-UPD-CLEARTEXT",
        "unix_socket_authorization_boundary": "CORR-IPC-UNIX-SOCKET",
        "fifo_authorization_boundary": "CORR-IPC-FIFO",
        "dbus_authorization_boundary": "CORR-DBUS-AUTHZ",
        "polkit_authorization_boundary": "CORR-POLKIT-AUTHZ",
        "permission_boundary": "CORR-PERM-BOUNDARY",
        "file_capability_boundary": "CORR-CAP-FILE",
        "suid_sgid_helper_boundary": "CORR-SUID-HELPER",
        "sudoers_policy_change": "CORR-SUDO-POLICY",
        "unsafe_sudo_policy": "CORR-SUDO-RULE",
        "credential_token_storage": "CORR-STOR-CREDENTIAL",
        "cleartext_application_endpoint": "CORR-COMM-CLEARTEXT",
        "runtime_application_listener": "CORR-NET-RUNTIME-LISTENER",
        "exposed_local_ca_private_key": "CORR-CRYPTO-LOCAL-CA",
    }
    finding_rules = {
        "privileged_service_writable_path",
        "writable_elf_search_path",
        "cleartext_update_path",
        "unsafe_sudo_policy",
        "exposed_local_ca_private_key",
    }
    for item in payload.get("correlations", []) or []:
        record = dict(item)
        kind = str(record.get("kind") or "")
        engine_owned = kind in authoritative_rules
        record.setdefault("rule_id", authoritative_rules.get(kind, ""))
        record["generation_source"] = "correlation_engine" if engine_owned else str(record.get("generation_source") or "legacy_bridge")
        record["drives_review"] = bool(engine_owned and record.get("review_identity"))
        record["drives_finding"] = bool(kind in finding_rules and record.get("finding_identity"))
        remapped: list[str] = []
        for object_id in record.get("object_ids", []) or []:
            mapped = id_map.get(str(object_id), str(object_id))
            if mapped is not None:
                remapped.append(mapped)
        record["object_ids"] = _as_strings(remapped)
        obs_index = {str(x.get("id") or ""): x for x in normalized_observations}
        rel_index = {str(x.get("id") or ""): x for x in normalized_relationships}
        obs_records = [obs_index[x] for x in (record.get("observation_ids") or []) if x in obs_index]
        record["source_modules"] = sorted({str(x.get("source_module") or "") for x in obs_records if str(x.get("source_module") or "")})
        record["cross_module"] = len(record["source_modules"]) >= 2
        record["relationship_ids"] = sorted(
            rel_id for rel_id, rel in rel_index.items()
            if str(rel.get("source") or "") in record["object_ids"] or str(rel.get("target") or "") in record["object_ids"]
        )
        refs = {}
        for obs in obs_records:
            for ref in obs.get("evidence_refs", []) or []:
                if isinstance(ref, dict) and ref.get("id"):
                    refs[str(ref["id"])] = dict(ref)
        record["evidence_refs"] = sorted(refs.values(), key=lambda x: str(x.get("id") or ""))
        record.setdefault("evidence_quality", "HIGH" if record["cross_module"] else ("MODERATE" if obs_records and record["object_ids"] else "LOW"))
        record.setdefault("suppressed", False)
        record.setdefault("suppression_reasons", [])
        record.setdefault("rationale", f"{record.get('title') or kind} is supported by {len(obs_records)} structured observation(s) across {len(record['source_modules'])} source module(s).")
        if record.get("suppressed"):
            record["drives_review"] = False
            record["drives_finding"] = False
        normalized_correlations.append(record)

    result = dict(payload)
    result["schema_version"] = MODEL_SCHEMA_VERSION
    result["objects"] = sorted(normalized_objects.values(), key=lambda x: x["id"])
    result["observations"] = sorted(normalized_observations, key=lambda x: str(x.get("id") or ""))
    result["relationships"] = sorted({str(r.get("id")): r for r in normalized_relationships}.values(), key=lambda x: str(x.get("id") or ""))
    result["correlations"] = sorted(normalized_correlations, key=lambda x: str(x.get("id") or ""))
    return result


def _find_observations(builder: SecurityModelBuilder, object_id: str, category: str | None = None) -> list[str]:
    return [
        obs_id for obs_id, item in builder.observations.items()
        if item.get("object_id") == object_id and (category is None or item.get("category") == category)
    ]


def build_security_model(
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
    """Build the primary structured assessment model.

    v1.7.1 retains this normalized object/observation/relationship model as the primary
    assessment engine consumed by review, finding, coverage, tester-dashboard, and
    client-dashboard renderers. Compatibility generation is retained only for older
    assessment state and explicitly unmigrated workflow guidance.
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

    b = SecurityModelBuilder()
    app_name = str(profile_data.get("application_name") or output_dir.name)
    app_obj = b.object(
        "application",
        app_name,
        primary_technology=profile_data.get("primary_technology"),
        supporting_technologies=profile_data.get("supporting_technologies", []),
    )

    permission_by_path: dict[str, str] = {}
    filesystem_object_by_path: dict[str, str] = {}
    for item in list(permission_data.get("high_interest_candidates", [])) + list(permission_data.get("review_candidates", [])):
        path = str(item.get("path") or "").strip()
        if not path:
            continue
        obj = _filesystem_object(b, path, item.get("type"), owner=item.get("owner"), group=item.get("group"), mode=item.get("mode"))
        b.relationship(app_obj, "contains_or_uses", obj)
        obs = b.observation(
            "filesystem_permission",
            obj,
            "permissions_review",
            summary=str(item.get("concerns") or "Application permission boundary requires review"),
            attributes={
                "level": item.get("level"),
                "concerns": item.get("concern_list") or str(item.get("concerns") or "").split("; "),
                "resolved_path": item.get("resolved_path") or "",
                "acl_entries": item.get("acl_entries") or [],
            },
            evidence=[f"permissions_review.txt::{path}"],
        )
        permission_by_path[path] = obs
        filesystem_object_by_path[path] = obj

    # v1.5.5: permission-boundary review generation is correlation-owned, except
    # for paths already represented by the more specific service-consumption rule.
    service_paths = {str(item.get("path") or "").strip() for item in (service_data.get("risk_candidates", []) or []) if str(item.get("path") or "").strip()}
    for item in list(permission_data.get("high_interest_candidates", [])) + list(permission_data.get("review_candidates", [])):
        path = str(item.get("path") or "").strip()
        if not path or path in service_paths:
            continue
        obj = filesystem_object_by_path.get(path) or _filesystem_object(b, path, item.get("type"))
        obs_ids = _find_observations(b, obj, "filesystem_permission")
        b.correlation(
            "permission_boundary", path, strength="REVIEW",
            title="Application Permission Boundary Requires Review",
            summary=str(item.get("concerns") or "Application permission boundary requires review"),
            object_ids=[obj], observation_ids=obs_ids,
            review_identity=stable_review_identity("PERM", path),
        )

    for entry in permission_data.get("capability_candidates", []) or []:
        raw = str(entry.get("entry") or "").strip()
        if not raw:
            continue
        binary = raw.split()[0] if raw.split() else raw
        obj = b.object("binary", binary, capability_entry=raw)
        b.relationship(app_obj, "grants_file_capability_to", obj)
        obs = b.observation(
            "file_capability", obj, "permissions_review", summary=raw,
            attributes={"raw_entry": raw}, evidence=[f"permissions_review.txt::{binary}"],
        )
        b.correlation(
            "file_capability_boundary", raw, strength="REVIEW",
            title="Application File Capability Requires Review",
            summary="An application executable received Linux file capabilities that cross the invoking user's normal privilege boundary.",
            object_ids=[obj], observation_ids=[obs],
            review_identity=stable_review_identity("CAP", raw),
        )

    for entry in permission_data.get("suid_candidates", []) or []:
        raw = str(entry.get("entry") or "").strip()
        if not raw:
            continue
        binary = raw.split()[0] if raw.split() else raw
        obj = b.object("binary", binary, suid_sgid_entry=raw)
        b.relationship(app_obj, "introduces_privileged_helper", obj)
        obs = b.observation(
            "suid_sgid_helper", obj, "permissions_review", summary=raw,
            attributes={"raw_entry": raw}, evidence=[f"permissions_review.txt::{binary}"],
        )
        b.correlation(
            "suid_sgid_helper_boundary", raw, strength="REVIEW",
            title="Application SUID/SGID Helper Requires Review",
            summary="An application-controlled SUID/SGID helper crosses a local privilege boundary and requires targeted input and execution-path validation.",
            object_ids=[obj], observation_ids=[obs],
            review_identity=stable_review_identity("SUID", raw),
        )

    for item in service_data.get("risk_candidates", []) or []:
        unit = str(item.get("unit") or "unknown.service")
        path = str(item.get("path") or "unknown path")
        path_type = str(item.get("path_type") or "ReferencedPath")
        service = b.object("service", unit, privileged=bool(item.get("privileged")))
        file_obj = filesystem_object_by_path.get(path) or _filesystem_object(b, path)
        b.relationship(app_obj, "owns_or_introduces", service)
        b.relationship(service, "consumes", file_obj, role=path_type)
        obs = b.observation(
            "service_dependency",
            service,
            "service_review",
            summary=f"{unit} consumes {path_type} {path}",
            attributes={"privileged": bool(item.get("privileged")), "path": path, "path_type": path_type, "concerns": item.get("concerns")},
            evidence=[f"service_review.txt::{unit}", f"permissions_review.txt::{path}"],
            discriminator=f"{path_type}:{path}",
        )
        if item.get("privileged") and item.get("concerns"):
            review_raw = f"{unit}:{path_type}:{path}"
            review_identity = stable_review_identity("SVC", review_raw)
            b.correlation(
                "privileged_service_writable_path",
                review_raw,
                strength="STRONG",
                title="Writable Path Referenced by Privileged systemd Service",
                summary=f"A privileged service consumes {path_type} {path}, which has a lower-privileged write concern.",
                object_ids=[service, file_obj],
                observation_ids=[obs, permission_by_path.get(path, "")],
                review_identity=review_identity,
                finding_identity=f"service:{review_raw}",
            )

    elf_groups: dict[tuple[str, str, str], list[str]] = {}
    for item in elf_data.get("finding_candidates", []) or []:
        if not item.get("finding_candidate"):
            continue
        kind = str(item.get("kind") or "RPATH")
        search_path = str(item.get("path") or "")
        concern = str(item.get("concern") or "unsafe search-path condition")
        binary = str(item.get("binary") or "")
        if binary:
            elf_groups.setdefault((kind, search_path, concern), []).append(binary)
    for (kind, search_path, concern), binaries in sorted(elf_groups.items()):
        binaries = sorted(set(binaries))
        search_obj = b.object("directory", search_path or "<empty/current-directory>")
        obs_ids: list[str] = []
        object_ids = [search_obj]
        for binary in binaries:
            binary_obj = b.object("binary", binary)
            object_ids.append(binary_obj)
            b.relationship(app_obj, "contains_or_uses", binary_obj)
            b.relationship(binary_obj, "searches_library_path", search_obj, kind=kind)
            obs_ids.append(b.observation(
                "elf_search_path",
                binary_obj,
                "elf_security_review",
                summary=f"{binary} uses {kind}={search_path or '<empty/current directory>'}; {concern}",
                attributes={"kind": kind, "search_path": search_path, "concern": concern},
                evidence=[f"binary_security_review.txt::{binary}"],
                discriminator=f"{kind}:{search_path}:{concern}",
            ))
        if len(binaries) == 1:
            review_raw = f"{binaries[0]}:{kind}:{search_path}"
        else:
            review_raw = f"group:{kind}:{search_path}:{concern}:HIGH"
        b.correlation(
            "writable_elf_search_path",
            f"{kind}:{search_path}:{concern}",
            strength="STRONG",
            title="Writable ELF Library Search Path",
            summary=f"{len(binaries)} application binary/binaries share a writable {kind} search path.",
            object_ids=object_ids,
            observation_ids=obs_ids,
            review_identity=stable_review_identity("ELF", review_raw),
            finding_identity=f"elf-group:{kind}:{search_path}:{concern}",
        )

    for listener in network_data.get("new_listeners", []) or []:
        text = str(listener)
        endpoint = canonical_network_endpoint(text)
        obj = b.object("network_endpoint", endpoint, raw_observation=text)
        b.relationship(app_obj, "listens_on", obj)
        b.observation("network_listener", obj, "network_surface_review", summary=text, attributes={"canonical_endpoint": endpoint}, evidence=[f"network_surface_review.txt::{endpoint}"])
    for connection in network_data.get("new_connections", []) or []:
        text = str(connection)
        obj = b.object("network_connection", text)
        b.relationship(app_obj, "connects_via", obj)
        b.observation("network_connection", obj, "network_surface_review", summary=text, evidence=[f"network_surface_review.txt::{text}"])

    # v1.5.6: credential/token-storage review is correlation-owned. Values remain
    # redacted; the model stores only indicator labels, occurrence metadata, and
    # permission context needed for tester validation.
    for hit in storage_data.get("secret_hits", []) or []:
        path = str(hit.get("path") or "").strip()
        if not path:
            continue
        obj = filesystem_object_by_path.get(path) or _filesystem_object(b, path, "file")
        b.relationship(app_obj, "stores_potential_auth_material_in", obj)
        indicators = [str(x) for x in (hit.get("indicators") or []) if str(x)]
        permission = str(hit.get("permission") or "")
        obs = b.observation(
            "credential_token_storage", obj, "local_storage_review",
            summary=f"Potential credential/token material detected in {path}; value redacted.",
            attributes={
                "indicators": indicators,
                "occurrences": hit.get("occurrences"),
                "first_lines": hit.get("first_lines") or {},
                "permission": permission,
                "values_redacted": True,
            },
            evidence=[f"local_storage_review.txt::{path}", f"permissions_review.txt::{path}"],
        )
        b.correlation(
            "credential_token_storage", path, strength="REVIEW",
            title="Potential Credential or Token Storage",
            summary="Potential authentication material was detected in application storage; value remains redacted and requires tester validation of authenticity, accessibility, scope, and lifetime.",
            object_ids=[obj], observation_ids=[obs],
            review_identity=stable_review_identity("STOR", path),
        )

    # v1.5.6: static/config cleartext application endpoints are correlation-owned.
    # Software-update endpoints retain the more specific CORR-UPD-CLEARTEXT rule.
    for item in network_data.get("cleartext_endpoint_candidates", []) or []:
        endpoint = str(item.get("endpoint") or item.get("url") or "").strip()
        if not endpoint:
            continue
        obj = b.object("application_endpoint", endpoint)
        b.relationship(app_obj, "references_cleartext_endpoint", obj)
        evidence_locations = item.get("evidence") or []
        obs = b.observation(
            "cleartext_application_endpoint", obj, "network_surface_review",
            summary=f"Static/config cleartext endpoint indicator: {endpoint}",
            attributes={
                "path": item.get("path"), "line": item.get("line"),
                "source": item.get("source"), "evidence_locations": evidence_locations,
            },
            evidence=[f"network_surface_review.txt::{endpoint}"],
        )
        b.correlation(
            "cleartext_application_endpoint", endpoint, strength="REVIEW",
            title="Cleartext Application Endpoint Requires Runtime Validation",
            summary="Static/configuration evidence references a cleartext application endpoint; runtime use and transmitted data sensitivity require validation.",
            object_ids=[obj], observation_ids=[obs],
            review_identity=stable_review_identity("COMM", endpoint),
        )

    update_observations: dict[str, list[str]] = {}
    update_objects: dict[str, str] = {}
    for item in update_data.get("insecure_update_url_candidates", []) or []:
        url = str(item.get("url") or "")
        if not url:
            continue
        obj = update_objects.setdefault(url, b.object("update_endpoint", url))
        b.relationship(app_obj, "may_retrieve_updates_from", obj)
        location_key = f"{item.get('path') or ''}:{item.get('line') or ''}"
        obs = b.observation(
            "cleartext_update_endpoint", obj, "update_review",
            summary=f"Probable cleartext update endpoint: {url}",
            attributes={"path": item.get("path"), "line": item.get("line"), "confidence": item.get("confidence")},
            evidence=[f"update_review.txt::{url}"],
            discriminator=location_key,
        )
        update_observations.setdefault(url, []).append(obs)
    for url, obs_ids in sorted(update_observations.items()):
        b.correlation(
            "cleartext_update_path",
            url,
            strength="REVIEW",
            title="Potential Software Update Retrieval over Cleartext HTTP",
            summary="Static evidence indicates a probable cleartext update endpoint; runtime use and independent package authentication require validation.",
            object_ids=[update_objects[url]], observation_ids=obs_ids,
            review_identity=stable_review_identity("UPD", url), finding_identity=f"update:{url}",
        )

    for item in persistence_data.get("review_required", []) or []:
        raw_identity = str(item.get("identity") or item.get("evidence") or item.get("title") or "sudoers-review")
        policy_path = raw_identity.split("sudoers-review:", 1)[-1] if raw_identity.startswith("sudoers-review:") else raw_identity
        obj = b.object("sudoers_policy", policy_path, title=item.get("title"), action=item.get("action"))
        b.relationship(app_obj, "introduces_privileged_policy", obj)
        obs = b.observation(
            "sudoers_policy_change", obj, "persistence_review",
            summary=str(item.get("evidence") or "Changed sudoers policy requires manual review"),
            attributes={"identity": raw_identity, "title": item.get("title"), "action": item.get("action")},
            evidence=[f"persistence_review.txt::{policy_path}"],
        )
        b.correlation(
            "sudoers_policy_change", raw_identity, strength="REVIEW",
            title=str(item.get("title") or "Changed sudoers Policy Requires Manual Review"),
            summary=str(item.get("evidence") or "Application introduced or changed a privileged sudoers policy file."),
            object_ids=[obj], observation_ids=[obs],
            review_identity=stable_review_identity("PERS", raw_identity),
        )

    for item in persistence_data.get("sudo_policy_candidates", []) or []:
        command = str(item.get("command") or item.get("raw") or "unknown")
        runas = str(item.get("runas") or "root")
        obj = b.object("sudo_rule", f"{runas}:{command}", runas=runas, command=command)
        b.relationship(app_obj, "introduces_privileged_policy", obj)
        obs = b.observation(
            "sudo_policy", obj, "persistence_review", summary=f"Run as {runas}: {command}",
            attributes={
                "concerns": item.get("concerns") or [],
                "finding_candidate": bool(item.get("finding_candidate")),
                "raw": item.get("raw") or "",
            },
            evidence=["persistence_review.txt::sudoers"],
        )
        # Preserve the existing explicit review identity only for rules that
        # previously received a dedicated review task. Lower-risk correlated
        # rules remain structured observations without adding queue noise.
        if item.get("finding_candidate"):
            raw_review = f"sudo-candidate:{runas}:{command}"
            b.correlation(
                "unsafe_sudo_policy", raw_review, strength="STRONG",
                title="Potentially Unsafe sudoers Rule Requires Validation",
                summary="The application introduced an effective sudo policy that requires privilege-boundary validation.",
                object_ids=[obj], observation_ids=[obs],
                review_identity=stable_review_identity("PERS", raw_review), finding_identity=f"sudo:{runas}:{command}",
            )

    for item in storage_data.get("crypto_material", []) or []:
        path = str(item.get("path") or "")
        if not path:
            continue
        obj = filesystem_object_by_path.get(path) or _filesystem_object(b, path)
        cert_objs = [b.object("certificate", cert) for cert in _as_strings(item.get("related_ca_certificates"))]
        obs = b.observation(
            "cryptographic_material", obj, "local_storage_review",
            summary="Private-key material detected; secret value redacted.",
            attributes={"private_key": bool(item.get("private_key")), "salt": bool(item.get("salt")), "permission": item.get("permission"), "related_ca_certificates": _as_strings(item.get("related_ca_certificates"))},
            evidence=[f"local_storage_review.txt::{path}"],
        )
        for cert_obj in cert_objs:
            b.relationship(obj, "private_key_for", cert_obj)
        if item.get("private_key") and cert_objs and str(item.get("permission") or "") in {"world-readable", "world-writable"}:
            b.correlation(
                "exposed_local_ca_private_key", path, strength="STRONG",
                title="Potential Exposure of Local CA Private Signing Material",
                summary="Private signing material is accessible across a local trust boundary and is correlated with a CA certificate.",
                object_ids=[obj, *cert_objs], observation_ids=[obs],
                review_identity=stable_review_identity("CRYPTO", path), finding_identity=f"crypto-ca:{path}",
            )

    socket_analysis_by_path: dict[str, dict[str, Any]] = {}
    for detail in ipc_data.get("socket_analysis", []) or []:
        path = canonical_unix_socket_identity(detail.get("path") or detail.get("line") or "")
        if path:
            socket_analysis_by_path[path] = detail

    for entry in ipc_data.get("unix_sockets", []) or []:
        path = canonical_unix_socket_identity(entry)
        if not path:
            continue
        detail = socket_analysis_by_path.get(path, {})
        obj = b.object("unix_socket", path)
        b.relationship(app_obj, "exposes_ipc", obj)
        obs = b.observation(
            "unix_socket", obj, "ipc_review", summary=path,
            attributes={
                "raw_observation": str(entry),
                "review_level": detail.get("review_level"),
                "privileged_process": bool(detail.get("privileged_process")),
                "abstract": bool(detail.get("abstract")),
                "filesystem": detail.get("filesystem") or {},
            },
            evidence=[f"ipc_review.txt::{path}"],
        )
        b.correlation(
            "unix_socket_authorization_boundary", path, strength="REVIEW",
            title="Application Unix Socket Trust Boundary",
            summary="Application-scoped Unix socket requires validation of peer identity, authorization, and filesystem trust boundaries.",
            object_ids=[obj], observation_ids=[obs],
            review_identity=stable_review_identity("IPC", f"socket:{path}"),
        )

    for entry in ipc_data.get("fifo_candidates", []) or []:
        path = str(entry.get("path") if isinstance(entry, dict) else entry).strip()
        if not path:
            continue
        obj = b.object("fifo", path)
        b.relationship(app_obj, "exposes_ipc", obj)
        obs = b.observation("fifo", obj, "ipc_review", summary=path, evidence=[f"ipc_review.txt::{path}"])
        b.correlation(
            "fifo_authorization_boundary", path, strength="REVIEW",
            title="Named FIFO Trust Boundary",
            summary="Application-scoped FIFO requires validation of reader/writer privilege and message authorization.",
            object_ids=[obj], observation_ids=[obs],
            review_identity=stable_review_identity("IPC", f"fifo:{path}"),
        )

    active_names = {str(item).split(": ", 1)[-1] for item in (ipc_data.get("active_bus_matches", []) or [])}
    introspection_by_name = {str(item.get("name") or ""): item for item in (ipc_data.get("dbus_introspection", []) or [])}
    for name in ipc_data.get("dbus_names", []) or []:
        name = str(name)
        bus_obj = b.object("dbus_name", name, active=name in active_names)
        b.relationship(app_obj, "exposes_dbus_name", bus_obj)
        intro = introspection_by_name.get(name) or {}
        obs = b.observation(
            "dbus_name", bus_obj, "ipc_review", summary=name,
            attributes={
                "active": name in active_names,
                "bus": intro.get("bus") or "",
                "objects": intro.get("objects") or [],
                "introspection_available": bool(intro.get("introspection")),
            },
            evidence=[f"ipc_review.txt::{name}"],
        )
        b.correlation(
            "dbus_authorization_boundary", name, strength="REVIEW",
            title="D-Bus Interface Requires Authorization Review",
            summary="Application-referenced D-Bus interface requires method-level caller authorization validation.",
            object_ids=[bus_obj], observation_ids=[obs],
            review_identity=stable_review_identity("DBUS", name),
        )

    for detail in ipc_data.get("polkit_details", []) or []:
        if not detail.get("permissive_review"):
            continue
        action = str(detail.get("action") or "unknown-action")
        policy_path = str(detail.get("path") or "")
        identity = f"{action}:{policy_path}"
        polkit_obj = b.object("polkit_action", action, path=policy_path, defaults=detail.get("defaults") or {})
        b.relationship(app_obj, "uses_polkit_action", polkit_obj)
        obs = b.observation(
            "polkit_policy", polkit_obj, "ipc_review", summary=f"{action}: {policy_path}",
            attributes={
                "permissive_review": True,
                "path": policy_path,
                "defaults": detail.get("defaults") or {},
                "rule_returns_yes": bool(detail.get("rule_returns_yes")),
                "subject_constraint_observed": bool(detail.get("subject_constraint_observed")),
            },
            evidence=[f"ipc_review.txt::{action}"],
        )
        b.correlation(
            "polkit_authorization_boundary", identity, strength="REVIEW",
            title="PolicyKit Authorization Requires Validation",
            summary="PolicyKit configuration contains permissive authorization behavior that requires mapping to the protected privileged operation.",
            object_ids=[polkit_obj], observation_ids=[obs],
            review_identity=stable_review_identity("POLKIT", identity),
        )

    _add_runtime(b, app_obj, runtime_data)
    payload = b.payload()
    write_json(working_dir(output_dir) / MODEL_FILENAME, payload)
    return payload


def _add_runtime(builder: SecurityModelBuilder, app_obj: str, runtime_data: dict[str, Any]) -> None:
    if not runtime_data:
        return
    for proc in runtime_data.get("application_processes", []) or []:
        if not isinstance(proc, dict):
            continue
        pid = str(proc.get("pid") or "unknown")
        command = str(proc.get("command") or proc.get("cmdline") or proc.get("name") or "")
        obj = builder.object("process", pid, command=command, user=proc.get("user"), uid=proc.get("uid"))
        builder.relationship(app_obj, "runs_process", obj)
        builder.observation("runtime_process", obj, "guided_runtime_observation", summary=f"PID {pid}: {command}", attributes=dict(proc), evidence=["runtime_review.txt::Application Processes"])
    for listener in runtime_data.get("listeners", []) or []:
        text = str(listener.get("line") if isinstance(listener, dict) and listener.get("line") else listener)
        endpoint = canonical_network_endpoint(text)
        obj = builder.object("network_endpoint", endpoint, raw_runtime_observation=text)
        builder.relationship(app_obj, "runtime_listens_on", obj)
        obs = builder.observation("runtime_listener", obj, "guided_runtime_observation", summary=text, attributes={"canonical_endpoint": endpoint}, evidence=["runtime_review.txt::Listeners"])
        # v1.6.0: a genuinely runtime-discovered externally bound application listener
        # is a structured review condition. It remains review-only because exposure
        # alone does not establish weak authentication/authorization.
        external_rows = {str(x.get("line") if isinstance(x, dict) and x.get("line") else x) for x in (runtime_data.get("externally_bound_listeners", []) or [])}
        if text in external_rows:
            review_identity = stable_review_identity("RUNTIME", f"runtime-listener:{text}")
            builder.correlation(
                "runtime_application_listener", endpoint, strength="REVIEW",
                title="Runtime Application Listener Requires Validation",
                summary=f"Application listener confirmed at runtime: {text}",
                object_ids=[obj], observation_ids=[obs], review_identity=review_identity,
            )
    for connection in runtime_data.get("connections", []) or []:
        text = str(connection.get("line") if isinstance(connection, dict) and connection.get("line") else connection)
        obj = builder.object("network_connection", text)
        builder.relationship(app_obj, "runtime_connects_via", obj)
        builder.observation("runtime_connection", obj, "guided_runtime_observation", summary=text, evidence=["runtime_review.txt::Connections"])
    for path in runtime_data.get("unix_sockets", []) or []:
        raw_text = str(path.get("line") if isinstance(path, dict) and path.get("line") else path)
        text = canonical_unix_socket_identity(path)
        if not text:
            continue
        obj = builder.object("unix_socket", text, raw_runtime_observation=raw_text)
        builder.relationship(app_obj, "runtime_confirms_ipc", obj)
        builder.observation("runtime_unix_socket", obj, "guided_runtime_observation", summary=text, attributes={"raw_observation": raw_text}, evidence=["runtime_review.txt::Unix Sockets"])
    for path in runtime_data.get("fifo_paths", []) or []:
        text = str(path.get("path") if isinstance(path, dict) else path)
        obj = builder.object("fifo", text)
        builder.relationship(app_obj, "runtime_confirms_ipc", obj)
        builder.observation("runtime_fifo", obj, "guided_runtime_observation", summary=text, evidence=["runtime_review.txt::FIFOs"])
    file_activity = runtime_data.get("file_activity") or {}
    for action in ("created", "modified", "deleted"):
        for path in file_activity.get(action, []) or []:
            text = str(path)
            obj = _find_existing_filesystem_object(builder, text) or _filesystem_object(builder, text)
            builder.relationship(app_obj, f"runtime_{action}", obj)
            builder.observation("runtime_file_activity", obj, "guided_runtime_observation", summary=f"{action.title()}: {text}", attributes={"action": action}, evidence=["runtime_review.txt::File Activity"], discriminator=action)


def synchronize_security_model(output_dir: Path) -> dict[str, Any]:
    """Link correlation records to authoritative review/finding state after generation."""
    path = working_dir(output_dir) / MODEL_FILENAME
    if not path.is_file():
        return {}
    payload = read_json(path)
    review_path = working_dir(output_dir) / "tester_review_state.json"
    finding_path = working_dir(output_dir) / "finding_candidates.json"
    review_by_identity: dict[str, dict[str, Any]] = {}
    findings_by_identity: dict[str, dict[str, Any]] = {}
    if review_path.is_file():
        review_state = read_json(review_path)
        review_by_identity = {str(item.get("identity")): item for item in review_state.get("items", []) if item.get("identity")}
    if finding_path.is_file():
        finding_state = read_json(finding_path)
        findings_by_identity = {str(item.get("identity")): item for item in finding_state.get("findings", []) if item.get("identity")}
    for correlation in payload.get("correlations", []):
        review_identity = str(correlation.get("review_identity") or "")
        finding_identity = str(correlation.get("finding_identity") or "")
        if review_identity and review_identity in review_by_identity:
            item = review_by_identity[review_identity]
            correlation["review_id"] = item.get("id") or ""
            correlation["review_status"] = item.get("status") or "PENDING"
        if finding_identity and finding_identity in findings_by_identity:
            item = findings_by_identity[finding_identity]
            correlation["finding_id"] = item.get("id") or ""
    payload["updated_at"] = now_iso()
    write_json(path, payload)
    return payload


def merge_runtime_security_model(output_dir: Path, runtime_data: dict[str, Any], profile_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Enrich an existing security model with runtime-only observations.

    This preserves static correlation records and adds canonical runtime objects.
    """
    path = working_dir(output_dir) / MODEL_FILENAME
    if not path.is_file():
        return build_security_model(output_dir, profile_data=profile_data, runtime_data=runtime_data)
    payload = normalize_existing_model_payload(read_json(path))
    b = SecurityModelBuilder()
    for item in payload.get("objects", []):
        b.objects[str(item.get("id"))] = item
    for item in payload.get("observations", []):
        b.observations[str(item.get("id"))] = item
    for item in payload.get("relationships", []):
        b.relationships[str(item.get("id"))] = item
    for item in payload.get("correlations", []):
        b.correlations[str(item.get("id"))] = item
    app_obj = next((obj_id for obj_id, item in b.objects.items() if item.get("kind") == "application"), None)
    if not app_obj:
        app_obj = b.object("application", output_dir.name, primary_technology=(profile_data or {}).get("primary_technology"))
    _add_runtime(b, app_obj, runtime_data)
    merged = b.payload()
    merged["generated_at"] = payload.get("generated_at") or merged["generated_at"]
    merged["updated_at"] = now_iso()
    write_json(path, merged)
    return synchronize_security_model(output_dir)


def build_and_synchronize_security_model(
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
) -> dict[str, Any]:
    build_security_model(
        output_dir,
        permission_data,
        network_data,
        service_data,
        elf_data,
        ipc_data,
        storage_data,
        update_data,
        persistence_data,
        profile_data,
    )
    return synchronize_security_model(output_dir)
