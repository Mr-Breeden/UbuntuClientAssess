from pathlib import Path

from modules.common import METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION, VERSION, read_json
from modules.security_model import build_security_model, merge_runtime_security_model, synchronize_security_model
from modules.tester_review import stable_review_identity


def test_v150_version_contract():
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ("2.0.6", "2.4", "1.1")


def test_security_model_correlates_privileged_service_and_writable_path(tmp_path: Path):
    permission_data = {
        "high_interest_candidates": [{
            "path": "/opt/vendor/config/client.conf",
            "type": "file",
            "owner": "root",
            "group": "root",
            "mode": "0o666",
            "level": "HIGH INTEREST",
            "concerns": "World-writable object",
            "concern_list": ["World-writable object"],
        }]
    }
    service_data = {
        "risk_candidates": [{
            "unit": "vendor.service",
            "path": "/opt/vendor/config/client.conf",
            "path_type": "EnvironmentFile",
            "privileged": True,
            "concerns": "World-writable object",
        }]
    }
    model = build_security_model(tmp_path, permission_data=permission_data, service_data=service_data)
    assert (tmp_path / "working" / "security_model.json").is_file()
    assert any(o["id"] == "file:/opt/vendor/config/client.conf" for o in model["objects"])
    assert any(o["id"] == "service:vendor.service" for o in model["objects"])
    assert any(r["relation"] == "consumes" and r["target"] == "file:/opt/vendor/config/client.conf" for r in model["relationships"])
    correlation = next(c for c in model["correlations"] if c["kind"] == "privileged_service_writable_path")
    assert correlation["strength"] == "STRONG"
    assert correlation["review_identity"] == stable_review_identity("SVC", "vendor.service:EnvironmentFile:/opt/vendor/config/client.conf")
    assert correlation["finding_identity"].startswith("service:")
    assert len(correlation["observation_ids"]) >= 2


def test_security_model_groups_equivalent_elf_root_cause(tmp_path: Path):
    elf_data = {
        "finding_candidates": [
            {"finding_candidate": True, "binary": "/opt/vendor/a", "kind": "RPATH", "path": "/opt/vendor/lib", "concern": "writable search path"},
            {"finding_candidate": True, "binary": "/opt/vendor/b", "kind": "RPATH", "path": "/opt/vendor/lib", "concern": "writable search path"},
        ]
    }
    model = build_security_model(tmp_path, elf_data=elf_data)
    correlations = [c for c in model["correlations"] if c["kind"] == "writable_elf_search_path"]
    assert len(correlations) == 1
    assert "binary:/opt/vendor/a" in correlations[0]["object_ids"]
    assert "binary:/opt/vendor/b" in correlations[0]["object_ids"]
    assert correlations[0]["review_identity"] == stable_review_identity("ELF", "group:RPATH:/opt/vendor/lib:writable search path:HIGH")


def test_security_model_preserves_review_and_finding_links(tmp_path: Path):
    service_data = {"risk_candidates": [{
        "unit": "vendor.service", "path": "/etc/vendor.conf", "path_type": "EnvironmentFile",
        "privileged": True, "concerns": "tester writable",
    }]}
    build_security_model(tmp_path, service_data=service_data)
    review_identity = stable_review_identity("SVC", "vendor.service:EnvironmentFile:/etc/vendor.conf")
    (tmp_path / "working").mkdir(parents=True, exist_ok=True)
    from modules.common import write_json
    write_json(tmp_path / "working" / "tester_review_state.json", {
        "schema_version": 1,
        "items": [{"id": "TRQ-001", "identity": review_identity, "status": "VALIDATED"}],
    })
    write_json(tmp_path / "working" / "finding_candidates.json", {
        "schema_version": 1,
        "findings": [{"id": "UAF-001", "identity": "service:vendor.service:EnvironmentFile:/etc/vendor.conf"}],
    })
    synced = synchronize_security_model(tmp_path)
    correlation = next(c for c in synced["correlations"] if c["kind"] == "privileged_service_writable_path")
    assert correlation["review_id"] == "TRQ-001"
    assert correlation["review_status"] == "VALIDATED"
    assert correlation["finding_id"] == "UAF-001"


def test_runtime_enrichment_adds_canonical_runtime_objects_without_losing_static_correlations(tmp_path: Path):
    service_data = {"risk_candidates": [{
        "unit": "vendor.service", "path": "/etc/vendor.conf", "path_type": "EnvironmentFile",
        "privileged": True, "concerns": "tester writable",
    }]}
    build_security_model(tmp_path, service_data=service_data)
    runtime = {
        "application_processes": [{"pid": 1234, "user": "root", "command": "/opt/vendor/bin/vendor"}],
        "listeners": ["tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*"],
        "connections": ["tcp ESTAB 0 0 127.0.0.1:8443 127.0.0.1:54000"],
        "unix_sockets": ["/run/vendor/control.sock"],
        "fifo_paths": ["/run/vendor/commands.fifo"],
        "file_activity": {"created": [], "modified": ["/home/test/.local/share/vendor/state.json"], "deleted": []},
    }
    merged = merge_runtime_security_model(tmp_path, runtime)
    assert any(o["id"] == "process:1234" for o in merged["objects"])
    assert any(o["id"] == "unix_socket:/run/vendor/control.sock" for o in merged["objects"])
    assert any(o["id"] == "fifo:/run/vendor/commands.fifo" for o in merged["objects"])
    assert any(o["id"] == "file:/home/test/.local/share/vendor/state.json" for o in merged["objects"])
    assert any(c["kind"] == "privileged_service_writable_path" for c in merged["correlations"])
    assert any(obs["category"] == "runtime_file_activity" for obs in merged["observations"])


def test_security_model_does_not_turn_salt_alone_into_correlation(tmp_path: Path):
    storage_data = {"crypto_material": [{
        "path": "/opt/vendor/security.conf", "private_key": False, "salt": True,
        "permission": "world-readable", "related_ca_certificates": [],
    }]}
    model = build_security_model(tmp_path, storage_data=storage_data)
    assert any(obs["category"] == "cryptographic_material" for obs in model["observations"])
    assert not any(c["kind"] == "exposed_local_ca_private_key" for c in model["correlations"])
