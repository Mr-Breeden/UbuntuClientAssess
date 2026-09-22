import sys
from pathlib import Path

import modules.web_gui as web_gui
from modules.common import VERSION, write_json
from modules.web_gui import GuiState


def test_v206_release_contract():
    assert VERSION == "2.0.6"


def test_privileged_launcher_preserves_virtualenv_python_symlink(monkeypatch, tmp_path: Path):
    """The sudo launcher must not resolve .venv/bin/python to /usr/bin/python3.

    Virtual-environment Python launchers are commonly symlinks.  Resolving that
    symlink before sudo discards the venv context and can make project-only
    dependencies such as prompt_toolkit unavailable to the privileged helper.
    """
    assessment = tmp_path / "assessment"
    assessment.mkdir()
    write_json(
        assessment / "assessment_metadata.json",
        {
            "mode": "full",
            "application_file_coverage": {
                "limited": True,
                "gaps": [{"path": "/opt/example-app"}],
            },
        },
    )

    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    venv_python = venv_bin / "python"
    venv_python.symlink_to(Path(sys.executable))

    launched = []
    monkeypatch.setattr(web_gui.sys, "executable", str(venv_python))
    monkeypatch.setattr(web_gui.sys, "argv", [str(tmp_path / "ubuntuclientassess.py")])
    monkeypatch.setattr(web_gui.shutil, "which", lambda name: "/usr/bin/x-terminal-emulator" if name == "x-terminal-emulator" else None)
    monkeypatch.setattr(web_gui.subprocess, "Popen", lambda argv, **kwargs: launched.append((argv, kwargs)))

    state = GuiState(tmp_path)
    result = state.launch_privileged_review(assessment)

    assert result["launched"] is True
    assert f"sudo {venv_python}" in result["command"]
    assert str(venv_python.resolve()) not in result["command"] or str(venv_python.resolve()) == str(venv_python)
    assert launched


def test_privileged_launcher_does_not_use_resolve_for_python_executable():
    source = Path("modules/web_gui.py").read_text(encoding="utf-8")
    assert "Path(sys.executable).resolve()" not in source
    assert "Path(sys.executable).expanduser().absolute()" in source
