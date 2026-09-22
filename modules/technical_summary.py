from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .common import read_json, working_dir


def build_technical_summary(assessment_dir: Path) -> dict[str, Any]:
    """Build a client-safe technical summary from the authoritative structured model.

    This deliberately exposes counts and concrete technical surface facts, not tester
    dispositions, finding candidates, TRQ/UAF/OBS/CORR identifiers, or tester notes.
    """
    model_path = working_dir(assessment_dir) / "security_model.json"
    model = read_json(model_path) if model_path.is_file() else {}
    objects = list(model.get("objects", []) or [])
    observations = list(model.get("observations", []) or [])
    obj_counts = Counter(str(x.get("kind") or "unknown") for x in objects)
    obs_counts = Counter(str(x.get("category") or "unknown") for x in observations)

    def identities(kind: str, limit: int = 12) -> list[str]:
        vals = sorted({str(x.get("identity") or "") for x in objects if x.get("kind") == kind and x.get("identity")})
        return vals[:limit]

    runtime = {k: v for k, v in obs_counts.items() if k.startswith("runtime_")}
    privileged_processes = 0
    for obj in objects:
        if obj.get("kind") != "process":
            continue
        attrs = obj.get("attributes") or {}
        if attrs.get("privileged") or str(attrs.get("user") or "").casefold() in {"root", "0"}:
            privileged_processes += 1

    return {
        "model_schema": model.get("schema_version"),
        "object_count": len(objects),
        "observation_count": len(observations),
        "service_count": obj_counts.get("service", 0),
        "binary_count": obj_counts.get("binary", 0),
        "network_listener_count": obj_counts.get("network_endpoint", 0),
        "network_connection_count": obj_counts.get("network_connection", 0),
        "application_endpoint_count": obj_counts.get("application_endpoint", 0),
        "cleartext_endpoint_count": obs_counts.get("cleartext_application_endpoint", 0),
        "update_endpoint_count": obj_counts.get("update_endpoint", 0),
        "cleartext_update_count": obs_counts.get("cleartext_update_endpoint", 0),
        "unix_socket_count": obj_counts.get("unix_socket", 0),
        "fifo_count": obj_counts.get("fifo", 0),
        "dbus_count": obj_counts.get("dbus_name", 0),
        "polkit_count": obj_counts.get("polkit_action", 0),
        "credential_storage_count": obs_counts.get("credential_token_storage", 0),
        "permission_observation_count": obs_counts.get("filesystem_permission", 0),
        "suid_helper_count": obs_counts.get("suid_sgid_helper", 0),
        "capability_count": obs_counts.get("file_capability", 0),
        "privileged_process_count": privileged_processes,
        "runtime_observed": bool(runtime),
        "runtime_process_count": obs_counts.get("runtime_process", 0),
        "runtime_listener_count": obs_counts.get("runtime_listener", 0),
        "runtime_connection_observation_count": obs_counts.get("runtime_connection", 0),
        "runtime_socket_count": obs_counts.get("runtime_unix_socket", 0),
        "runtime_fifo_count": obs_counts.get("runtime_fifo", 0),
        "runtime_file_activity_count": obs_counts.get("runtime_file_activity", 0),
        "listeners": identities("network_endpoint"),
        "application_endpoints": identities("application_endpoint"),
        "update_endpoints": identities("update_endpoint"),
        "unix_sockets": identities("unix_socket"),
        "dbus_names": identities("dbus_name"),
        "polkit_actions": identities("polkit_action"),
    }
