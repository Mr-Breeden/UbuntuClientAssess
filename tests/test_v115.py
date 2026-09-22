from __future__ import annotations
import os, shutil, subprocess
from pathlib import Path

def _exe(path: Path, body: str): path.write_text(body, encoding='utf-8'); path.chmod(0o755)
def _project(tmp_path: Path):
    src=Path(__file__).resolve().parents[1]; project=tmp_path/'project'; project.mkdir(); shutil.copy2(src/'install_dependencies.sh', project/'install_dependencies.sh'); (project/'install_dependencies.sh').chmod(0o755); (project/'requirements.txt').write_text('rich>=13.7.0\nprompt_toolkit>=3.0.43\n')
    b=tmp_path/'bin'; b.mkdir(); cap=tmp_path/'calls.txt'
    _exe(b/'apt', '#!/usr/bin/env bash\nprintf \'apt %s\\n\' "$*" >> "$UCA_TEST_CAPTURE"\necho APT-VERBOSE-NOISE\nif [[ "${UCA_FAIL_CORE:-0}" == 1 && "$1" == install ]]; then for a in "$@"; do [[ "$a" == python3 ]] && { echo "E: simulated required package failure" >&2; exit 42; }; done; fi\nexit 0\n')
    _exe(b/'apt-cache', '#!/usr/bin/env bash\n[[ "$1" == show && -n "${UCA_UNAVAILABLE:-}" && "$2" == "$UCA_UNAVAILABLE" ]] && exit 1\nexit 0\n')
    _exe(b/'apt-file', '#!/usr/bin/env bash\necho APT-FILE-VERBOSE-NOISE\nexit 0\n')
    _exe(b/'sudo', '#!/usr/bin/env bash\n[[ "${1:-}" == -v ]] && exit 0\nexec "$@"\n')
    _exe(b/'python3', '#!/usr/bin/env bash\nif [[ "${1:-}" == -m && "${2:-}" == venv ]]; then mkdir -p "$3/bin"; printf ":\\n" > "$3/bin/activate"; exit 0; fi\nif [[ "${1:-}" == -m && "${2:-}" == pip ]]; then echo PIP-VERBOSE-NOISE; exit 0; fi\nexit 0\n')
    env=os.environ.copy(); env['PATH']=f'{b}:{env.get("PATH","")}'; env['UCA_TEST_CAPTURE']=str(cap); return project,env,cap

def test_setup_quiet_grouped(tmp_path):
    p,e,c=_project(tmp_path); r=subprocess.run(['bash',str(p/'install_dependencies.sh')],cwd=p,env=e,capture_output=True,text=True,check=True); out=r.stdout+r.stderr
    assert '[1/5]' in out and '[5/5]' in out and 'Setup status:            READY' in out
    assert 'APT-VERBOSE-NOISE' not in out and 'PIP-VERBOSE-NOISE' not in out
    log=(p/'setup_logs/install_dependencies.log').read_text(); assert 'APT-VERBOSE-NOISE' in log and 'PIP-VERBOSE-NOISE' in log
    installs=[x for x in c.read_text().splitlines() if x.startswith('apt install ')]; assert len(installs)==2 and 'flatpak' in installs[1]

def test_setup_optional_warning(tmp_path):
    p,e,_=_project(tmp_path); e['UCA_UNAVAILABLE']='flatpak'; r=subprocess.run(['bash',str(p/'install_dependencies.sh')],cwd=p,env=e,capture_output=True,text=True,check=True); out=r.stdout+r.stderr
    assert '[WARN] Optional packages unavailable: flatpak' in out and 'READY WITH REDUCED COVERAGE' in out and 'APT-VERBOSE-NOISE' not in out

def test_setup_required_failure_fatal(tmp_path):
    p,e,_=_project(tmp_path); e['UCA_FAIL_CORE']='1'; r=subprocess.run(['bash',str(p/'install_dependencies.sh')],cwd=p,env=e,capture_output=True,text=True); out=r.stdout+r.stderr
    assert r.returncode != 0 and 'Unable to install one or more required system packages.' in out and 'simulated required package failure' in out
    assert 'simulated required package failure' in (p/'setup_logs/install_dependencies.log').read_text()
