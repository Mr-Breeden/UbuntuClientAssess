from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def test_interactive_main_menu_start_new_assessment(monkeypatch):
    import ubuntuclientassess as uca

    monkeypatch.setattr(uca.Prompt, "ask", lambda *args, **kwargs: "1")
    action, path = uca._interactive_main_menu()
    assert action == "assessment"
    assert path is None


def test_interactive_main_menu_review_uses_assessment_path(monkeypatch, tmp_path):
    import ubuntuclientassess as uca

    monkeypatch.setattr(uca.Prompt, "ask", lambda *args, **kwargs: "2")
    monkeypatch.setattr(uca, "ask_path", lambda *args, **kwargs: tmp_path)
    action, path = uca._interactive_main_menu()
    assert action == "review"
    assert path == tmp_path


def test_interactive_main_menu_appendix_and_verify_routes(monkeypatch, tmp_path):
    import ubuntuclientassess as uca

    for choice, expected in (("3", "appendix"), ("4", "verify")):
        monkeypatch.setattr(uca.Prompt, "ask", lambda *args, _choice=choice, **kwargs: _choice)
        monkeypatch.setattr(uca, "ask_path", lambda *args, **kwargs: tmp_path)
        action, path = uca._interactive_main_menu()
        assert action == expected
        assert path == tmp_path


def test_no_argument_cli_shows_main_menu_and_can_exit():
    script = Path(__file__).resolve().parents[1] / "ubuntuclientassess.py"
    proc = subprocess.run(
        [sys.executable, str(script)],
        input="6\n",
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0
    combined = proc.stdout + proc.stderr
    assert "Main Menu" in combined
    assert "Start New Assessment" in combined
    assert "Review Completed Assessment" in combined
    assert "Create Client Appendix" in combined
    assert "Verify Assessment Integrity" in combined
    assert "Exiting UbuntuClientAssess" in combined


def test_explicit_version_flag_bypasses_main_menu():
    script = Path(__file__).resolve().parents[1] / "ubuntuclientassess.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    assert "2.0.6" in proc.stdout
    assert "Main Menu" not in proc.stdout
