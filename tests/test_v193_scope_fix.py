from pathlib import Path

from modules.network import review_network
from modules.runtime_observation import analyze_samples


def test_scoped_python_app_does_not_claim_unrelated_python_listener(tmp_path):
    app_root = tmp_path / "opt" / "sample-app"
    app_root.mkdir(parents=True)
    launcher = tmp_path / "usr" / "bin" / "sample-app"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/usr/bin/python3\n", encoding="utf-8")
    launcher.chmod(0o755)

    listener = 'udp UNCONN 0 0 0.0.0.0:3702 0.0.0.0:* users:(("python3",pid=<PID>,fd=<FD>))'
    diff = {
        "files_added": [str(launcher)],
        "files_changed": [],
        "post_filesystem": {str(launcher): {"mode": "-rwxr-xr-x"}},
        "post_processes": [
            f"tester tester python3 python3 {launcher}",
            "root root python3 python3 /usr/bin/unrelated-daemon --discovery",
        ],
        "listening_sockets_added": [listener],
        "listening_sockets_removed": [],
        "network_connections_added": [],
    }

    data = review_network(diff, tmp_path / "assessment", [app_root, launcher])
    assert data["application_correlated_listeners"] == []
    assert data["exposed_listener_candidates"] == []
    report = (tmp_path / "assessment" / "reports" / "network_surface_review.txt").read_text(encoding="utf-8")
    assert "[UNATTRIBUTED]" in report


def test_scoped_native_process_name_still_correlates_listener(tmp_path):
    app_root = tmp_path / "opt" / "sample-app"
    app_root.mkdir(parents=True)
    launcher = tmp_path / "usr" / "bin" / "sample-app"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("binary", encoding="utf-8")
    launcher.chmod(0o755)

    listener = 'tcp LISTEN 0 8 0.0.0.0:8443 0.0.0.0:* users:(("sample-app",pid=<PID>,fd=<FD>))'
    diff = {
        "files_added": [str(launcher)],
        "files_changed": [],
        "post_filesystem": {str(launcher): {"mode": "-rwxr-xr-x"}},
        "post_processes": [f"tester tester sample-app {launcher}"],
        "listening_sockets_added": [listener],
        "listening_sockets_removed": [],
        "network_connections_added": [],
    }

    data = review_network(diff, tmp_path / "assessment", [app_root, launcher])
    assert data["application_correlated_listeners"] == [listener]
    assert data["exposed_listener_candidates"] == [listener]


def test_runtime_pid_correlation_still_attributes_python_application_listener():
    listener = 'tcp LISTEN 0 8 0.0.0.0:18080 0.0.0.0:* users:(("python3",pid=101,fd=7))'
    unrelated = 'udp UNCONN 0 0 0.0.0.0:3702 0.0.0.0:* users:(("python3",pid=202,fd=8))'
    samples = [{
        "processes": [
            {"pid": 101, "ppid": 1, "user": "tester", "group": "tester", "comm": "python3", "args": "python3 /usr/bin/sample-app"},
            {"pid": 202, "ppid": 1, "user": "root", "group": "root", "comm": "python3", "args": "python3 /usr/bin/unrelated-daemon --discovery"},
        ],
        "listeners": [listener, unrelated],
        "connections": [],
        "unix_sockets": [],
    }]

    data = analyze_samples(samples, application_hints=["/usr/bin/sample-app", "/opt/sample-app"])
    assert listener in data["listeners"]
    assert unrelated not in data["listeners"]
