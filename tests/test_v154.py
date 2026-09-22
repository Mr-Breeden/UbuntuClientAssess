from pathlib import Path

from modules.common import ensure_assessment_layout
from modules.security_model import build_security_model
from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION
from modules.security_model import MODEL_SCHEMA_VERSION
from modules.tester_review import generate_tester_review, stable_review_identity, merge_additional_review_items


def test_v154_version_and_model_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")
    assert MODEL_SCHEMA_VERSION == 10


def _setup(tmp_path: Path) -> None:
    ensure_assessment_layout(tmp_path)


def test_unix_socket_review_is_owned_by_correlation_engine(tmp_path: Path):
    _setup(tmp_path)
    path = "/run/vendor/control.sock"
    line = f'u_str LISTEN 0 4 {path} 123 * 0'
    ipc_data = {
        "unix_sockets": [line],
        "socket_analysis": [{
            "line": line, "path": path, "review_level": "MEDIUM",
            "privileged_process": False, "abstract": False,
            "filesystem": {"exists": True, "mode": "0666", "interactive_write": True},
        }],
    }
    model = build_security_model(tmp_path, ipc_data=ipc_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "unix_socket_authorization_boundary")
    assert corr["rule_id"] == "CORR-IPC-UNIX-SOCKET"
    assert corr["generation_source"] == "correlation_engine"
    assert corr["drives_review"] is True
    assert corr["drives_finding"] is False

    state = generate_tester_review(tmp_path, ipc_data=ipc_data)
    matches = [x for x in state["items"] if x.get("object_type") == "unix_socket" and x.get("object_identity") == path]
    assert len(matches) == 1
    assert matches[0]["generation_source"] == "correlation_engine"
    assert matches[0]["correlation_rule"] == "CORR-IPC-UNIX-SOCKET"


def test_fifo_review_is_owned_by_correlation_engine(tmp_path: Path):
    _setup(tmp_path)
    path = "/run/vendor/commands.fifo"
    ipc_data = {"fifo_candidates": [path]}
    model = build_security_model(tmp_path, ipc_data=ipc_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "fifo_authorization_boundary")
    assert corr["rule_id"] == "CORR-IPC-FIFO"
    assert corr["drives_review"] is True and corr["drives_finding"] is False

    state = generate_tester_review(tmp_path, ipc_data=ipc_data)
    item = next(x for x in state["items"] if x.get("object_type") == "fifo" and x.get("object_identity") == path)
    assert item["generation_source"] == "correlation_engine"


def test_dbus_review_is_owned_and_preserves_active_context(tmp_path: Path):
    _setup(tmp_path)
    name = "com.vendor.Service"
    ipc_data = {
        "dbus_names": [name],
        "active_bus_matches": [f"system: {name}"],
        "dbus_introspection": [{"bus": "system", "name": name, "objects": ["/com/vendor/Service"], "introspection": [{"object": "/com/vendor/Service", "detail": "METHOD Ping"}]}],
    }
    model = build_security_model(tmp_path, ipc_data=ipc_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "dbus_authorization_boundary")
    assert corr["rule_id"] == "CORR-DBUS-AUTHZ"
    obs = next(x for x in model["observations"] if x["id"] in corr["observation_ids"])
    assert obs["attributes"]["active"] is True
    assert obs["attributes"]["introspection_available"] is True

    state = generate_tester_review(tmp_path, ipc_data=ipc_data)
    item = next(x for x in state["items"] if x["identity"] == stable_review_identity("DBUS", name))
    assert item["generation_source"] == "correlation_engine"
    assert "Active during assessment" in item["condition"]


def test_permissive_polkit_review_is_owned_but_not_finding_driven(tmp_path: Path):
    _setup(tmp_path)
    action = "com.vendor.admin"
    path = "/usr/share/polkit-1/actions/com.vendor.policy"
    ipc_data = {"polkit_details": [{
        "action": action, "path": path,
        "defaults": {"allow_active": "yes"},
        "permissive_review": True,
    }]}
    model = build_security_model(tmp_path, ipc_data=ipc_data)
    corr = next(x for x in model["correlations"] if x["kind"] == "polkit_authorization_boundary")
    assert corr["rule_id"] == "CORR-POLKIT-AUTHZ"
    assert corr["strength"] == "REVIEW"
    assert corr["drives_review"] is True
    assert corr["drives_finding"] is False

    state = generate_tester_review(tmp_path, ipc_data=ipc_data)
    identity = stable_review_identity("POLKIT", f"{action}:{path}")
    item = next(x for x in state["items"] if x["identity"] == identity)
    assert item["generation_source"] == "correlation_engine"
    assert item["priority"] == "HIGH"


def test_nonpermissive_polkit_remains_observation_only(tmp_path: Path):
    _setup(tmp_path)
    ipc_data = {"polkit_details": [{
        "action": "com.vendor.safe", "path": "/usr/share/polkit-1/actions/com.vendor.policy",
        "defaults": {"allow_active": "auth_admin"}, "permissive_review": False,
    }]}
    model = build_security_model(tmp_path, ipc_data=ipc_data)
    assert not [x for x in model["correlations"] if x["kind"] == "polkit_authorization_boundary"]
    state = generate_tester_review(tmp_path, ipc_data=ipc_data)
    assert not [x for x in state["items"] if x["category"] == "POLKIT"]


def test_runtime_socket_confirmation_enriches_correlation_owned_static_item(tmp_path: Path):
    _setup(tmp_path)
    path = "/run/vendor/control.sock"
    line = f'u_str LISTEN 0 4 {path} 123 * 0'
    ipc_data = {"unix_sockets": [line], "socket_analysis": [{"line": line, "path": path, "review_level": "MEDIUM", "filesystem": {}}]}
    build_security_model(tmp_path, ipc_data=ipc_data)
    initial = generate_tester_review(tmp_path, ipc_data=ipc_data)
    assert len([x for x in initial["items"] if x.get("object_identity") == path]) == 1

    runtime = {"socket_analysis": [{"line": f'{line} users:(("vendor",pid=42,fd=4))', "path": path, "review_level": "HIGH"}]}
    merged = merge_additional_review_items(tmp_path, runtime_data=runtime)
    matches = [x for x in merged["items"] if x.get("object_type") == "unix_socket" and x.get("object_identity") == path]
    assert len(matches) == 1
    assert matches[0]["generation_source"] == "correlation_engine"
    assert matches[0]["runtime_confirmed"] is True
    assert matches[0]["priority"] == "HIGH"
