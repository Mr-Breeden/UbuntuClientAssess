from pathlib import Path

from modules.common import METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, VERSION
from modules.ipc import review_ipc
from modules.security_model import build_security_model, merge_runtime_security_model


def test_v151_version_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")


def test_static_ipc_drops_pathless_ambient_host_socket_when_scoped(tmp_path: Path):
    app = tmp_path / "opt" / "vendor"
    app.mkdir(parents=True)
    own = app / "control.sock"
    ambient = 'u_dgr UNCONN 0 0 * 12345 * 0 users:(("localsearch-3",pid=42,fd=9))'
    own_line = f'u_str LISTEN 0 4 {own} 987 * 0'
    data = review_ipc({"unix_sockets_added": [ambient, own_line]}, tmp_path / "assessment", [app])
    assert data["unix_sockets"] == [own_line]
    report = (tmp_path / "assessment" / "reports" / "ipc_review.txt").read_text(encoding="utf-8")
    assert "localsearch-3" not in report
    assert str(own) in report


def test_security_model_canonicalizes_static_and_runtime_socket_rows_to_path(tmp_path: Path):
    static_line = 'u_str LISTEN <RECV-Q> <SEND-Q> /run/vendor/control.sock <INO> * <PEER-INO>'
    model = build_security_model(tmp_path, ipc_data={"unix_sockets": [static_line]})
    assert any(o["id"] == "unix_socket:/run/vendor/control.sock" for o in model["objects"])
    assert not any(static_line in o["id"] for o in model["objects"])

    runtime_line = 'u_str LISTEN 0 4 /run/vendor/control.sock 59831 * 0 users:(("python3",pid=1234,fd=3))'
    merged = merge_runtime_security_model(tmp_path, {"unix_sockets": [runtime_line]})
    sockets = [o for o in merged["objects"] if o["kind"] == "unix_socket" and o["identity"] == "/run/vendor/control.sock"]
    assert len(sockets) == 1
    socket_id = "unix_socket:/run/vendor/control.sock"
    assert any(r["relation"] == "exposes_ipc" and r["target"] == socket_id for r in merged["relationships"])
    assert any(r["relation"] == "runtime_confirms_ipc" and r["target"] == socket_id for r in merged["relationships"])
    assert any(obs["category"] == "unix_socket" and obs["object_id"] == socket_id for obs in merged["observations"])
    assert any(obs["category"] == "runtime_unix_socket" and obs["object_id"] == socket_id for obs in merged["observations"])


def test_security_model_normalizes_filesystem_kinds_and_avoids_duplicate_directory_identity(tmp_path: Path):
    permission_data = {
        "high_interest_candidates": [
            {"path": "/opt/vendor/lib", "type": "directory", "owner": "root", "group": "root", "mode": "0o2777", "concerns": "writable"},
            {"path": "/run/vendor/control.sock", "type": "socket", "owner": "root", "group": "root", "mode": "0o666", "concerns": "writable"},
            {"path": "/run/vendor/commands.fifo", "type": "fifo", "owner": "root", "group": "root", "mode": "0o666", "concerns": "writable"},
        ]
    }
    elf_data = {"finding_candidates": [
        {"finding_candidate": True, "binary": "/opt/vendor/bin/a", "kind": "RPATH", "path": "/opt/vendor/lib", "concern": "writable search path"}
    ]}
    ipc_data = {
        "unix_sockets": ["u_str LISTEN 0 4 /run/vendor/control.sock 1 * 0"],
        "fifo_candidates": ["/run/vendor/commands.fifo"],
    }
    model = build_security_model(tmp_path, permission_data=permission_data, elf_data=elf_data, ipc_data=ipc_data)
    ids = {o["id"] for o in model["objects"]}
    assert "directory:/opt/vendor/lib" in ids
    assert "file:/opt/vendor/lib" not in ids
    assert "unix_socket:/run/vendor/control.sock" in ids
    assert "file:/run/vendor/control.sock" not in ids
    assert "fifo:/run/vendor/commands.fifo" in ids
    assert "file:/run/vendor/commands.fifo" not in ids


def test_v151_migrates_v150_model_objects_before_runtime_enrichment(tmp_path: Path):
    from modules.common import write_json
    from modules.security_model import merge_runtime_security_model

    working = tmp_path / "working"
    working.mkdir(parents=True)
    static_socket = 'u_str LISTEN <RECV-Q> <SEND-Q> /run/vendor/control.sock <INO> * <PEER-INO>'
    ambient = 'u_dgr UNCONN <RECV-Q> <SEND-Q> * <INO> * <PEER-INO> users:(("localsearch-3",pid=<PID>,fd=<FD>))'
    write_json(working / "security_model.json", {
        "schema_version": 1,
        "objects": [
            {"id": f"unix_socket:{static_socket}", "kind": "unix_socket", "identity": static_socket, "attributes": {}},
            {"id": f"unix_socket:{ambient}", "kind": "unix_socket", "identity": ambient, "attributes": {}},
            {"id": "file:/opt/vendor/lib", "kind": "file", "identity": "/opt/vendor/lib", "attributes": {"type": "directory"}},
        ],
        "observations": [
            {"id": "OBS-static", "category": "unix_socket", "object_id": f"unix_socket:{static_socket}", "source_module": "ipc_review", "summary": static_socket, "attributes": {}, "evidence_bookmarks": []},
            {"id": "OBS-ambient", "category": "unix_socket", "object_id": f"unix_socket:{ambient}", "source_module": "ipc_review", "summary": ambient, "attributes": {}, "evidence_bookmarks": []},
        ],
        "relationships": [],
        "correlations": [],
    })
    runtime_line = 'u_str LISTEN 0 4 /run/vendor/control.sock 555 * 0 users:(("python3",pid=55,fd=3))'
    merged = merge_runtime_security_model(tmp_path, {"unix_sockets": [runtime_line]})
    ids = {o["id"] for o in merged["objects"]}
    assert merged["schema_version"] == 10
    assert "unix_socket:/run/vendor/control.sock" in ids
    assert "directory:/opt/vendor/lib" in ids
    assert "file:/opt/vendor/lib" not in ids
    assert not any("localsearch-3" in object_id for object_id in ids)
    assert sum(1 for object_id in ids if object_id == "unix_socket:/run/vendor/control.sock") == 1
    assert not any(obs["id"] == "OBS-ambient" for obs in merged["observations"])
