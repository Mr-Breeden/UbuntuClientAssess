from __future__ import annotations

"""Localhost web interface for UbuntuClientAssess.

The GUI is deliberately loopback-only and calls the same presentation-neutral
application service used by the CLI.  It does not weaken assessment locking,
revision checks, integrity verification, or ClientAppendix gating.
"""

import json
import mimetypes
import secrets
import threading
import time
import uuid
import subprocess
import sys
import shlex
import shutil
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from modules.application_profile import load_machine_profile
from modules.application_service import ServiceResult, UbuntuClientAssessService
from modules.common import VERSION, read_json
from modules.runtime_observation import MAX_OBSERVATION_SECONDS, collect_runtime_observation

DEFAULT_GUI_PORT = 9001
DEFAULT_GUI_HOST = "127.0.0.1"
MAX_REPORT_BYTES = 2 * 1024 * 1024


@dataclass
class GuiJob:
    id: str
    kind: str
    assessment: str
    status: str = "queued"
    message: str = "Queued"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    progress: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    stop_event: threading.Event = field(default_factory=threading.Event, repr=False)
    cancel_requested: bool = field(default=False, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "assessment": self.assessment,
            "status": self.status,
            "message": self.message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "progress": dict(self.progress),
            "result": self.result,
        }


class GuiState:
    def __init__(self, assessment_root: Path, token: str | None = None) -> None:
        self.assessment_root = Path(assessment_root).expanduser().resolve()
        self.token = token or secrets.token_urlsafe(24)
        self.service = UbuntuClientAssessService()
        self.jobs: dict[str, GuiJob] = {}
        self.jobs_lock = threading.Lock()

    def set_root(self, raw: str) -> Path:
        root = Path(raw).expanduser().resolve()
        self.assessment_root = root
        return root

    def discover_assessments(self, root: Path | None = None) -> list[dict[str, Any]]:
        root = (root or self.assessment_root).expanduser().resolve()
        if not root.is_dir():
            return []
        found: list[dict[str, Any]] = []
        for child in sorted(root.iterdir(), key=lambda p: p.name.casefold()):
            if not child.is_dir() or not (child / "assessment_metadata.json").is_file():
                continue
            overview = self.service.assessment_overview(child)
            if overview.ok:
                item = dict(overview.data)
                item["ok"] = True
            else:
                item = {
                    "assessment": str(child),
                    "assessment_name": child.name,
                    "ok": False,
                    "error": overview.message,
                    "errors": list(overview.errors),
                }
            found.append(item)
        return found

    def launch_privileged_review(self, assessment: Path) -> dict[str, Any]:
        assessment = assessment.expanduser().resolve()
        metadata_path = assessment / "assessment_metadata.json"
        if not metadata_path.is_file():
            raise ValueError("Assessment metadata is missing")
        metadata = read_json(metadata_path)
        coverage = metadata.get("application_file_coverage") or {}
        gaps = list(coverage.get("gaps", []) or [])
        if not coverage.get("limited") or not gaps:
            raise ValueError("This assessment does not currently require privileged static collection")
        # No password or arbitrary command is accepted from the browser. The helper
        # is fixed to the selected assessment and obtains credentials in a terminal.
        script = Path(sys.argv[0]).expanduser().resolve()
        python_bin = Path(sys.executable).expanduser().absolute()
        command = f"sudo {shlex.quote(str(python_bin))} {shlex.quote(str(script))} --privileged-static-review {shlex.quote(str(assessment))}"
        shell_command = command + '; rc=$?; echo; echo "UbuntuClientAssess privileged static review finished with exit code $rc."; echo "Return to the browser and refresh the assessment."; read -r -p "Press Enter to close..."'
        launchers = []
        if shutil.which("x-terminal-emulator"):
            launchers.append(["x-terminal-emulator", "-e", "bash", "-lc", shell_command])
        if shutil.which("gnome-terminal"):
            launchers.append(["gnome-terminal", "--", "bash", "-lc", shell_command])
        if shutil.which("konsole"):
            launchers.append(["konsole", "-e", "bash", "-lc", shell_command])
        for argv in launchers:
            try:
                subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                return {"launched": True, "command": command, "protected_roots": [str(x.get("path") or "") for x in gaps]}
            except OSError:
                continue
        return {"launched": False, "command": command, "protected_roots": [str(x.get("path") or "") for x in gaps]}

    def create_runtime_job(self, assessment: Path) -> GuiJob:
        assessment = assessment.expanduser().resolve()
        with self.jobs_lock:
            for existing in self.jobs.values():
                if (
                    existing.kind == "runtime-observation"
                    and existing.assessment == str(assessment)
                    and existing.status in {"queued", "running", "stopping", "cancelling"}
                ):
                    raise ValueError("A Runtime Observation is already active for this assessment")
            job = GuiJob(id=uuid.uuid4().hex, kind="runtime-observation", assessment=str(assessment))
            self.jobs[job.id] = job
        thread = threading.Thread(target=self._run_runtime_job, args=(job.id, assessment), daemon=True)
        thread.start()
        return job

    def stop_runtime_job(self, job_id: str, *, cancel: bool = False) -> GuiJob:
        with self.jobs_lock:
            job = self.jobs.get(job_id)
            if not job or job.kind != "runtime-observation":
                raise ValueError("Unknown Runtime Observation job")
            if job.status not in {"queued", "running", "stopping", "cancelling"}:
                raise ValueError("Runtime Observation is not currently running")
            job.cancel_requested = bool(cancel)
            job.status = "cancelling" if cancel else "stopping"
            job.message = "Cancelling Runtime Observation" if cancel else "Stopping and saving Runtime Observation"
            job.updated_at = time.time()
            job.stop_event.set()
            return job

    def create_assessment_job(self, payload: dict[str, Any]) -> GuiJob:
        name = str(payload.get("assessment_name") or "UbuntuClientAssess")
        job = GuiJob(id=uuid.uuid4().hex, kind="assessment-start", assessment=name)
        with self.jobs_lock:
            self.jobs[job.id] = job
        threading.Thread(target=self._run_assessment_start_job, args=(job.id, payload), daemon=True).start()
        return job

    def create_continue_job(self, assessment: Path, include_discovered_home: bool = True) -> GuiJob:
        job = GuiJob(id=uuid.uuid4().hex, kind="assessment-continue", assessment=str(assessment))
        with self.jobs_lock:
            self.jobs[job.id] = job
        threading.Thread(target=self._run_assessment_continue_job, args=(job.id, assessment, include_discovered_home), daemon=True).start()
        return job

    def _run_assessment_start_job(self, job_id: str, payload: dict[str, Any]) -> None:
        self._update_job(job_id, status="running", message="Preparing assessment", progress={"phase": "preparing", "module": "Initialize Assessment", "percent": 0})

        def progress(data: dict[str, Any]) -> None:
            phase = str(data.get("phase") or "running")
            module = str(data.get("module") or "Assessment processing")
            message = str(data.get("message") or module)
            self._update_job(job_id, status="running", message=message, progress=dict(data))

        result = self.service.start_assessment(
            assessment_name=str(payload.get("assessment_name") or "UbuntuClientAssess"),
            output_root=Path(str(payload.get("output_root") or self.assessment_root)),
            installer=Path(str(payload.get("installer") or "")),
            mode=str(payload.get("mode") or "full"),
            application_root=Path(str(payload["application_root"])) if payload.get("application_root") else None,
            application_path=str(payload.get("application_path") or "") or None,
            network_observation_seconds=float(payload.get("network_observation_seconds") or 5),
            allow_installed_deb=bool(payload.get("allow_installed_deb", False)),
            progress_callback=progress,
        )
        if result.ok and result.data.get("assessment"):
            self._update_job(job_id, assessment=str(result.data["assessment"]))
        waiting = bool(result.ok and result.data.get("status") == "waiting-for-installation")
        self._update_job(job_id, status="waiting" if waiting else ("completed" if result.ok else "failed"), message=result.message, result=result.as_dict())

    def _run_assessment_continue_job(self, job_id: str, assessment: Path, include_discovered_home: bool) -> None:
        self._update_job(job_id, status="running", message="Confirming installation/setup", progress={"phase": "installation-verification", "module": "Installation / Setup Confirmation", "percent": 19})

        def progress(data: dict[str, Any]) -> None:
            module = str(data.get("module") or "Assessment processing")
            message = str(data.get("message") or module)
            self._update_job(job_id, status="running", message=message, progress=dict(data))

        result = self.service.continue_assessment(assessment, include_discovered_home=include_discovered_home, progress_callback=progress)
        self._update_job(job_id, status="completed" if result.ok else "failed", message=result.message, result=result.as_dict())

    def get_job(self, job_id: str) -> GuiJob | None:
        with self.jobs_lock:
            return self.jobs.get(job_id)

    def active_runtime_job(self, assessment: Path) -> GuiJob | None:
        target = str(assessment.expanduser().resolve())
        with self.jobs_lock:
            matches = [
                job for job in self.jobs.values()
                if job.kind == "runtime-observation"
                and job.assessment == target
                and job.status in {"queued", "running", "stopping", "cancelling"}
            ]
        return max(matches, key=lambda job: job.created_at) if matches else None

    def _update_job(self, job_id: str, **changes: Any) -> None:
        with self.jobs_lock:
            job = self.jobs[job_id]
            for key, value in changes.items():
                setattr(job, key, value)
            job.updated_at = time.time()

    def _runtime_context(self, assessment: Path, metadata: dict[str, Any]) -> tuple[list[str], list[Path]]:
        hints: list[str] = []
        roots: list[Path] = []
        for key in ("application_path", "application_root"):
            value = metadata.get(key)
            if value:
                hints.append(str(value))
        scope = metadata.get("application_scope") if isinstance(metadata.get("application_scope"), dict) else {}
        for key in ("application_path", "application_root"):
            value = scope.get(key)
            if value:
                hints.append(str(value))
        for key in ("application_roots", "analysis_roots", "data_roots", "expected_runtime_roots"):
            for raw in metadata.get(key, []) or []:
                try:
                    roots.append(Path(str(raw)).expanduser().resolve(strict=False))
                except Exception:
                    continue
        app_root = metadata.get("application_root")
        if app_root:
            roots.append(Path(str(app_root)).expanduser().resolve(strict=False))
        hints = sorted(set(x for x in hints if x))
        roots = sorted(set(roots), key=str)
        return hints, roots

    def _run_runtime_job(self, job_id: str, assessment: Path) -> None:
        runtime_started = time.monotonic()
        timed_out = False
        self._update_job(
            job_id,
            status="running",
            message="Runtime Observation is running. Exercise the application, then choose Stop & Save.",
            progress={
                "phase": "runtime-observation",
                "module": "Runtime Observation",
                "elapsed_seconds": 0,
                "manual_control": True,
                "sample_count": 0,
                "application_processes": 0,
                "connections": 0,
                "listeners": 0,
                "unix_sockets": 0,
                "fifos": 0,
            },
        )
        verify = self.service.verify_assessment(assessment)
        if not verify.ok:
            self._update_job(job_id, status="failed", message=verify.message, result=verify.as_dict())
            return
        base_revision = str(verify.data.get("revision") or "")
        try:
            metadata = read_json(assessment / "assessment_metadata.json")
            if str(metadata.get("mode") or "") != "full":
                raise ValueError("Runtime observation is available only for completed Full Assessments")
            profile = load_machine_profile(assessment)
            hints, roots = self._runtime_context(assessment, metadata)

            def progress(data: dict[str, Any]) -> None:
                elapsed = max(0.0, time.monotonic() - runtime_started)
                self._update_job(job_id, progress={
                    "phase": "runtime-observation",
                    "module": "Runtime Observation",
                    "elapsed_seconds": round(elapsed, 1),
                    "manual_control": True,
                    "sample_count": int(data.get("sample_count", 0)),
                    "application_processes": len(data.get("application_processes") or []),
                    "connections": len(data.get("connections") or []),
                    "listeners": len(data.get("listeners") or []),
                    "unix_sockets": len(data.get("unix_sockets") or []),
                    "fifos": len(data.get("fifo_paths") or []),
                })

            def wait_for_stop() -> None:
                nonlocal timed_out
                job = self.get_job(job_id)
                if not job:
                    return
                if not job.stop_event.wait(MAX_OBSERVATION_SECONDS):
                    timed_out = True

            observation = collect_runtime_observation(
                assessment,
                application_hints=hints,
                filesystem_roots=roots,
                duration_seconds=None,
                wait_for_stop=wait_for_stop,
                elevated_visibility=False,
                progress_callback=progress,
                persist=False,
            )
            job = self.get_job(job_id)
            if job and job.cancel_requested:
                self._update_job(
                    job_id,
                    status="cancelled",
                    message="Runtime Observation cancelled; collected evidence was discarded",
                    progress={**job.progress, "elapsed_seconds": round(time.monotonic() - runtime_started, 1), "cancelled": True},
                    result={"ok": True, "code": "runtime-cancelled", "message": "Runtime Observation cancelled; no runtime evidence was committed", "data": {}, "errors": []},
                )
                return

            metadata_updates = {
                key: metadata.get(key) for key in (
                    "application_path", "application_root", "application_scope", "application_roots",
                    "analysis_roots", "data_roots", "expected_runtime_roots",
                ) if key in metadata
            }
            commit_verify = self.service.verify_assessment(assessment)
            if not commit_verify.ok:
                self._update_job(job_id, status="failed", message=commit_verify.message, result=commit_verify.as_dict())
                return
            commit_revision = str(commit_verify.data.get("revision") or "")
            changed_during_observation = bool(base_revision and commit_revision and base_revision != commit_revision)
            result = self.service.finalize_runtime_observation(
                assessment,
                observation,
                profile,
                application_path=metadata.get("application_path"),
                metadata_updates=metadata_updates,
                expected_revision=commit_revision or None,
            )
            final_progress = {
                "phase": "runtime-observation",
                "module": "Runtime Observation",
                "elapsed_seconds": round(float(observation.get("duration_seconds", time.monotonic() - runtime_started)), 1),
                "manual_control": True,
                "sample_count": int(observation.get("sample_count", 0)),
                "application_processes": len(observation.get("application_processes") or []),
                "connections": len(observation.get("connections") or []),
                "listeners": len(observation.get("listeners") or []),
                "unix_sockets": len(observation.get("unix_sockets") or []),
                "fifos": len(observation.get("fifo_paths") or []),
                "rebased": changed_during_observation,
                "safety_limit_reached": timed_out,
            }
            if timed_out and result.ok:
                message = f"Safety limit of {int(MAX_OBSERVATION_SECONDS // 60)} minutes reached; Runtime Observation was stopped and saved"
            else:
                message = result.message
            self._update_job(job_id, status="completed" if result.ok else "failed", message=message, progress=final_progress, result=result.as_dict())
        except Exception as exc:
            self._update_job(job_id, status="failed", message=str(exc), result={"ok": False, "code": "runtime-error", "message": str(exc), "data": {}, "errors": [str(exc)]})


INDEX_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>UbuntuClientAssess</title>
<style>
:root{--b:#0b1020;--p:#141b2d;--p2:#1b2438;--t:#e8edf7;--m:#9da9bd;--l:#2b3650;--a:#63b3ff;--g:#55d187;--w:#f1be5c;--r:#ff6b75}*{box-sizing:border-box}body{margin:0;background:var(--b);color:var(--t);font:14px/1.45 system-ui}.shell{display:grid;grid-template-columns:250px 1fr;min-height:100vh}.side{background:#0e1526;border-right:1px solid var(--l);padding:20px}.brand{font-size:19px;font-weight:800;margin-bottom:20px}.brand small{display:block;color:var(--m);font-size:12px;font-weight:500}.nav button,.btn{border:1px solid var(--l);background:var(--p2);color:var(--t);padding:9px 12px;border-radius:8px;cursor:pointer}.nav button{display:block;width:100%;text-align:left;margin:5px 0;border-color:transparent;background:transparent;color:var(--m)}.nav button.active,.nav button:hover{background:var(--p2);color:var(--t)}.main{padding:24px;max-width:1500px;width:100%}.top,.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.top{justify-content:space-between;margin-bottom:12px}.context{background:#0e1526;border:1px solid var(--l);border-radius:10px;padding:10px 12px;margin-bottom:16px;display:flex;gap:16px;align-items:center;flex-wrap:wrap}.context .grow{flex:1;min-width:300px}.card{background:var(--p);border:1px solid var(--l);border-radius:12px;padding:16px;margin-bottom:14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}.view{display:none}.view.active{display:block}input,select,textarea{background:#0d1424;color:var(--t);border:1px solid var(--l);border-radius:8px;padding:9px}input{min-width:240px}select{min-width:220px}label{display:grid;gap:5px;color:var(--m)}.help{font-size:12px;color:var(--m)}.btn.primary{background:#153658;border-color:#245b8c}.btn.good{background:#123c2d;border-color:#246d50}.btn.warn{background:#4a3518;border-color:#7a5724}.muted{color:var(--m)}.danger{color:var(--r)}.coverageWarn{margin-top:12px;padding:12px;border:1px solid var(--w);border-radius:8px;background:rgba(241,190,92,.08)}.warningBtn{border-color:var(--w);color:var(--t)}.success{color:var(--g)}.warning{color:var(--w)}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid var(--l);text-align:left;vertical-align:top}pre{white-space:pre-wrap;word-break:break-word;background:#09101d;border:1px solid var(--l);padding:12px;border-radius:8px;max-height:60vh;overflow:auto}.split{display:grid;grid-template-columns:minmax(330px,.85fr) minmax(440px,1.45fr);gap:14px}.item{border:1px solid var(--l);padding:9px;border-radius:8px;margin:7px 0;cursor:pointer}.item:hover,.item.active{border-color:#3c6d9b;background:#101a2d}.modal{display:none;position:fixed;inset:0;background:#0009;z-index:20;align-items:center;justify-content:center}.modal.show{display:flex}.modalbox{width:min(850px,94vw);max-height:82vh;overflow:auto;background:var(--p);border:1px solid var(--l);border-radius:12px;padding:16px}.pathitem{display:flex;justify-content:space-between;gap:10px;padding:8px;border-bottom:1px solid var(--l)}.toast{position:fixed;right:20px;bottom:20px;background:var(--p2);border:1px solid var(--l);padding:12px;border-radius:8px;display:none;max-width:520px}.toast.show{display:block}.pill{display:inline-block;border:1px solid var(--l);border-radius:999px;padding:3px 8px;color:var(--m)}.progressbar{height:10px;background:#0b1220;border:1px solid var(--l);border-radius:999px;overflow:hidden}.progressbar>div{height:100%;background:#2d78b8;width:0}.runtimeActivity{height:8px;margin-top:12px;border-radius:999px;background:linear-gradient(90deg,rgba(99,179,255,.18),rgba(99,179,255,.95),rgba(99,179,255,.18));background-size:220% 100%;animation:runtimePulse 1.4s linear infinite}@keyframes runtimePulse{from{background-position:100% 0}to{background-position:-120% 0}}.stage{font-size:18px;font-weight:700;margin-bottom:3px}.statusCard{border:1px solid var(--l);background:#0e1526;border-radius:10px;padding:14px;margin-top:14px}.selectedName{font-weight:750}.empty{padding:18px;border:1px dashed var(--l);border-radius:9px;color:var(--m)}details{margin-top:10px}summary{cursor:pointer;color:var(--m)}.reviewSplit{height:calc(100vh - 300px);min-height:560px;align-items:stretch}.reviewQueueCard,.reviewDetailCard{margin-bottom:0;min-height:0;display:flex;flex-direction:column;overflow:hidden}.reviewFilters{display:grid;grid-template-columns:1fr 1fr;gap:8px;flex:none}.reviewProgressBar{flex:none}.reviewList{overflow-y:auto;overscroll-behavior:contain;min-height:0;flex:1;padding-right:4px}.reviewDetail{height:100%;min-height:0;display:flex;flex-direction:column;overflow:hidden}.reviewHeader{flex:none}.reviewGuide{flex:1;min-height:180px;overflow-y:auto;overscroll-behavior:contain;white-space:pre-wrap;word-break:break-word;line-height:1.55;padding:14px;background:#09101d;border:1px solid var(--l);border-radius:8px}.reviewActions{flex:none;background:var(--p);padding-top:12px;border-top:1px solid var(--l)}.review-item-pending{border-left:4px solid #667085}.review-item-validated{border-left:4px solid var(--g);background:rgba(85,209,135,.07)}.review-item-na{border-left:4px solid #7b8496;background:rgba(123,132,150,.08)}.review-item-informational{border-left:4px solid var(--a);background:rgba(99,179,255,.07)}@media(max-width:900px){.shell{grid-template-columns:1fr}.split{grid-template-columns:1fr}.reviewSplit{height:auto;min-height:0}.reviewQueueCard,.reviewDetailCard{max-height:none;overflow:visible}.reviewList{max-height:45vh}.reviewDetail{height:auto}.reviewGuide{max-height:55vh}.main{padding:14px}}
</style></head>
<body><div class="shell"><aside class="side"><div class="brand">UbuntuClientAssess<small>v2.0.6 · localhost console</small></div><div class="nav">
<button data-view="dashboard" class="active">Dashboard</button><button data-view="new">New Assessment</button><button data-view="review">Guided Review</button><button data-view="runtime">Runtime Observation</button><button data-view="reports">Reports</button><button data-view="recovery">Integrity & Recovery</button><button data-view="appendix">Client Appendix</button><button data-view="about">About</button></div></aside>
<main class="main"><div class="top"><div><h1 id="viewTitle">Dashboard</h1><div id="subtitle" class="muted">Local assessment administration.</div></div></div>
<div class="context"><div class="grow"><div class="muted">Assessment Root</div><div class="row"><input id="root" style="flex:1;min-width:360px"><button class="btn" onclick="browseInto('root','directory')">Browse</button><button class="btn" onclick="refreshAssessments()">Load</button><button class="btn" onclick="refreshAssessments()">Refresh</button></div></div><div class="grow"><div class="muted">Selected Assessment</div><div class="row"><select id="assessmentPicker" style="flex:1;min-width:360px"><option value="">Select an assessment</option></select><button class="btn" onclick="reloadSelected()">Reload</button></div></div></div>
<section id="dashboard" class="view active"><div class="card"><div class="row" style="justify-content:space-between"><div><h3>Assessments</h3><div class="muted">Completed and in-progress assessments under the configured root.</div></div><button class="btn primary" onclick="goView('new')">+ New Assessment</button></div><table><thead><tr><th>Assessment</th><th>Mode</th><th>Status</th><th>Review</th><th></th></tr></thead><tbody id="assessments"></tbody></table></div></section>
<section id="new" class="view"><div class="card"><h3>Start New Assessment</h3><p class="muted">Full Assessment pauses after the pre-install snapshot. Install/configure the application in your terminal, then return here to continue. UbuntuClientAssess never requests your sudo password or application credentials in the browser.</p><div class="grid">
<label>Assessment Name<input id="newName" placeholder="Ubuntu Client Assessment"></label>
<label>Assessment Output Root<div class="row"><input id="newRoot"><button class="btn" onclick="browseInto('newRoot','directory')">Browse</button></div></label>
<label>Installer / Package<div class="row"><input id="newInstaller" placeholder="/path/to/installer (.deb, .sh, .run, AppImage, archive...)"><button class="btn" onclick="browseInto('newInstaller','installer')">Browse</button></div></label>
<label>Execution Mode<select id="newMode"><option value="full">Full Assessment</option><option value="installer-analysis-only">Installer Analysis Only</option></select></label>
<label>Application Root (optional — auto-detected if blank)<input id="newAppRoot" placeholder="Auto-detect"><span class="help">Advanced override for the application's primary installation directory, such as /opt/vendor-app.</span></label>
<label>Application Launcher (optional — auto-detected if blank)<input id="newAppPath" placeholder="Auto-detect"><span class="help">Advanced override for the executable/script used to launch the application, such as /usr/bin/vendor-app.</span></label>
<label>Post-install network sample seconds<input id="newNetSecs" type="number" min="0" max="60" value="5"></label></div><div class="row" style="margin-top:14px"><button class="btn primary" onclick="startAssessment()">Start Assessment</button></div><div id="newJob"></div></div></section>
<section id="review" class="view"><div id="reviewAssessment" class="statusCard"></div><div class="split reviewSplit"><div class="card reviewQueueCard"><h3>Review Queue</h3><div class="reviewFilters"><label>Category<select id="categoryFilter"><option>Select an assessment</option></select></label><label>Status<select id="statusFilter"><option value="">All statuses</option><option value="PENDING">Pending</option><option value="VALIDATED">Validated</option><option value="NOT APPLICABLE">Not Applicable</option><option value="INFORMATIONAL">Informational</option></select></label></div><div id="reviewProgress" class="reviewProgressBar"></div><div id="reviewFilterCount" class="muted reviewProgressBar"></div><div id="reviewList" class="reviewList"></div></div><div class="card reviewDetailCard"><div id="reviewDetail" class="reviewDetail muted">Select a Full Assessment to load Guided Review.</div></div></div></section>
<section id="runtime" class="view"><div id="runtimeAssessment" class="statusCard"></div><div class="card"><h3>Runtime Observation</h3><p class="muted">Start observation, exercise the application for as long as needed, then choose Stop & Save. The GUI does not request sudo; use the CLI runtime workflow when elevated process/socket ownership visibility is required. An internal 60-minute safety limit prevents abandoned captures from running indefinitely.</p><div class="row"><button id="runtimeStartBtn" class="btn primary" onclick="startRuntime()">Start Observation</button><button id="runtimeStopBtn" class="btn good" style="display:none" onclick="stopRuntime(false)">Stop & Save Observation</button><button id="runtimeCancelBtn" class="btn warn" style="display:none" onclick="stopRuntime(true)">Cancel Observation</button></div><div id="runtimeJob"></div></div></section>
<section id="reports" class="view"><div id="reportsAssessment" class="statusCard"></div><div class="split"><div class="card"><h3>Reports</h3><div id="reportList"></div></div><div class="card"><h3 id="reportTitle">Report Viewer</h3><pre id="reportContent">Select a report.</pre></div></div></section>
<section id="recovery" class="view"><div id="recoveryAssessment" class="statusCard"></div><div class="grid"><div class="card"><h3>Integrity</h3><p id="integrityState" class="muted">Select an assessment.</p><button class="btn primary" onclick="verifySelected()">Verify Integrity</button></div><div class="card"><h3>Recovery</h3><p id="recoveryState" class="muted">Select an assessment.</p><button class="btn warn" onclick="repairReports()">Repair Generated Reports</button> <button class="btn" onclick="recoverInterrupted()">Recover Interrupted Write</button></div></div></section>
<section id="appendix" class="view"><div id="appendixAssessment" class="statusCard"></div><div class="card"><h3>Client Appendix</h3><p class="muted">Client Appendix creation requires a completed Full Assessment with no pending Guided Review items and passing integrity checks.</p><button class="btn good" onclick="createAppendix()">Create / Refresh Client Appendix</button><div id="appendixState" style="margin-top:12px"></div></div></section>
<section id="about" class="view"><div class="card"><h3>Capabilities</h3><pre id="capabilities"></pre></div></section></main></div>
<div id="browserModal" class="modal"><div class="modalbox"><div class="row" style="justify-content:space-between"><h3>Browse Filesystem</h3><button class="btn" onclick="closeBrowser()">Close</button></div><div id="browserPath" class="muted"></div><div id="browserItems"></div><div class="row" style="margin-top:12px"><button id="selectFolder" class="btn good" onclick="selectCurrentFolder()">Select This Folder</button></div></div></div><div id="toast" class="toast"></div>
<script>
const TOKEN='__TOKEN__';const headers={'Content-Type':'application/json','X-UCA-Token':TOKEN};let activeRoot='__ROOT__',selected=null,selectedOverview=null,reviewData=null,selectedReview=null,browseTarget=null,browseMode='directory',browseCurrent='',assessmentsCache=[];
async function api(u,o={}){o.headers={...(o.headers||{}),...headers};const r=await fetch(u,o);let j={};try{j=await r.json()}catch(e){j={ok:false,message:'Invalid server response',errors:[String(e)]}}return j}function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function toast(m,k=''){const t=document.getElementById('toast');t.textContent=m;t.className='toast show '+k;setTimeout(()=>t.className='toast',4200)}
function selectedHtml(){if(!selected)return '<span class="warning">No assessment selected.</span> Choose one from the selector above or Dashboard.';const a=selectedOverview||{};const rv=a.review||{};const cov=a.application_file_coverage||{};const coverage=cov.limited?`<div class="coverageWarn"><b>Privileged Static Review Required</b><div>UbuntuClientAssess could not recursively inspect ${Number((cov.gaps||[]).length)} protected application root(s). Affected static-analysis modules remain ATTN until targeted privileged collection completes.</div><button class="btn warningBtn" style="margin-top:8px" onclick="launchPrivilegedReview()">Run Privileged Collection</button></div>`:'';return `<span class="selectedName">${esc(a.assessment_name||selected.split('/').pop())}</span> <span class="pill">${esc(a.mode||'')}</span> <span class="pill">${esc((a.run_state||{}).stage||(a.run_state||{}).status||'')}</span><div class="muted">${esc(selected)}</div>${rv.available?(rv.total?`<div class="muted">Review: ${rv.completed}/${rv.total} complete · ${rv.pending} pending</div>`:`<div class="muted">Review: no prioritized review items generated</div>`):''}${coverage}`}
function updateSelectedCards(){for(const id of ['reviewAssessment','runtimeAssessment','reportsAssessment','recoveryAssessment','appendixAssessment'])document.getElementById(id).innerHTML=selectedHtml()}
async function goView(v){document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.nav button').forEach(x=>x.classList.toggle('active',x.dataset.view===v));document.getElementById(v).classList.add('active');document.getElementById('viewTitle').textContent=[...document.querySelectorAll('.nav button')].find(x=>x.dataset.view===v)?.textContent||v;updateSelectedCards();if(v==='review')await loadReview();if(v==='runtime')await loadRuntimeContext();if(v==='reports')await loadReports();if(v==='recovery')await loadIntegrityStatus();if(v==='appendix')await loadAppendixContext()}
async function browseInto(target,mode){browseTarget=target;browseMode=mode;let start=document.getElementById(target).value||'__HOME__';await browse(start)}async function browse(path){const j=await api('/api/fs/list?path='+encodeURIComponent(path)+'&mode='+encodeURIComponent(browseMode));if(!j.ok)return toast((j.errors||[]).join('; ')||j.message,'danger');browseCurrent=j.data.path;document.getElementById('browserPath').textContent=browseCurrent;document.getElementById('selectFolder').style.display=browseMode==='directory'?'inline-block':'none';let h='';if(j.data.parent)h+=`<div class="pathitem"><span>📁 ..</span><button class="btn" onclick='browse(${JSON.stringify(j.data.parent)})'>Open</button></div>`;for(const d of j.data.directories)h+=`<div class="pathitem"><span>📁 ${esc(d.name)}</span><button class="btn" onclick='browse(${JSON.stringify(d.path)})'>Open</button></div>`;for(const f of j.data.files||[])h+=`<div class="pathitem"><span>📦 ${esc(f.name)}</span><button class="btn good" onclick='chooseFile(${JSON.stringify(f.path)})'>Select</button></div>`;document.getElementById('browserItems').innerHTML=h||'<p class="muted">No matching entries.</p>';document.getElementById('browserModal').classList.add('show')}function closeBrowser(){document.getElementById('browserModal').classList.remove('show')}function selectCurrentFolder(){document.getElementById(browseTarget).value=browseCurrent;closeBrowser()}function chooseFile(p){document.getElementById(browseTarget).value=p;closeBrowser()}
async function refreshAssessments(){const requested=document.getElementById('root').value||activeRoot;const j=await api('/api/assessments?root='+encodeURIComponent(requested));if(!j.ok)return toast(j.message,'danger');activeRoot=j.data.root;document.getElementById('root').value=activeRoot;document.getElementById('newRoot').value=activeRoot;assessmentsCache=j.data.assessments||[];renderAssessmentPicker();renderDashboard();if(selected){const match=assessmentsCache.find(a=>a.assessment===selected);if(match){selectedOverview=match;document.getElementById('assessmentPicker').value=selected}else{selected=null;selectedOverview=null;sessionStorage.removeItem('ucaSelectedAssessment')}}updateSelectedCards()}
function renderAssessmentPicker(){const p=document.getElementById('assessmentPicker');p.innerHTML='<option value="">Select an assessment</option>'+assessmentsCache.map(a=>`<option value="${esc(a.assessment)}">${esc(a.assessment_name)} — ${esc(a.mode||'unknown')}</option>`).join('');p.onchange=async()=>{if(p.value)await selectAssessment(p.value);else{selected=null;selectedOverview=null;sessionStorage.removeItem('ucaSelectedAssessment');updateSelectedCards()}}}
function reviewText(a){const rv=a.review||{};if(a.mode!=='full')return 'N/A';if(!rv.available)return 'Not ready';return rv.total?`${rv.completed}/${rv.total}`:'No review items'}function statusText(a){const rs=a.run_state||{};return rs.stage||rs.status||'unknown'}function renderDashboard(){const tb=document.getElementById('assessments');tb.innerHTML='';if(!assessmentsCache.length){tb.innerHTML='<tr><td colspan="5" class="muted">No UbuntuClientAssess assessments were found under this root.</td></tr>';return}for(const a of assessmentsCache){const tr=document.createElement('tr');tr.innerHTML=`<td><b>${esc(a.assessment_name)}</b><div class="muted">${esc(a.assessment)}</div></td><td>${esc(a.mode||'')}</td><td>${esc(statusText(a))}</td><td>${esc(reviewText(a))}</td><td><button class="btn" onclick='selectAssessment(${JSON.stringify(a.assessment)})'>Open</button></td>`;tb.appendChild(tr)}}
async function selectAssessment(p){selected=p;sessionStorage.setItem('ucaSelectedAssessment',p);const cached=assessmentsCache.find(a=>a.assessment===p);selectedOverview=cached||null;document.getElementById('assessmentPicker').value=p;if(!selectedOverview){const o=await api('/api/overview?path='+encodeURIComponent(p));if(o.ok)selectedOverview=o.data}document.getElementById('subtitle').textContent='Selected: '+(selectedOverview?.assessment_name||p);updateSelectedCards();await loadAssessment();toast('Assessment selected','success')}
async function reloadSelected(){if(!selected)return toast('Select an assessment first','warning');const o=await api('/api/overview?path='+encodeURIComponent(selected));if(o.ok)selectedOverview=o.data;await loadAssessment();updateSelectedCards();toast('Assessment reloaded','success')}
async function loadAssessment(){if(!selected)return;await Promise.all([loadReports(),loadIntegrityStatus()]);if(selectedOverview?.mode==='full')await loadReview();else showReviewUnavailable('Guided Review is not applicable to Installer Analysis Only assessments.');const s=await api('/api/status?path='+encodeURIComponent(selected));if(s.ok&&s.data.action==='continue-installation'){document.getElementById('newJob').innerHTML=waitingHtml(s.data.install_command||'',selected);await goView('new')}}
function waitingHtml(cmd,path){return `<div class="statusCard"><div class="stage">Waiting for Installation / Setup</div><p><b>UbuntuClientAssess has not executed the installer.</b> Use the vendor-approved installation procedure in a terminal, complete first-run setup/sign-in, exercise the application, and wait for background services to start. The command below is a convenience suggestion and may require vendor-specific arguments. Do not enter credentials in this browser.</p><pre>${esc(cmd)}</pre><div class="row"><button class="btn" onclick='copyText(${JSON.stringify(cmd)})'>Copy Command</button><button class="btn good" onclick='continueAssessment(${JSON.stringify(path)})'>Installation and Setup Complete — Continue</button></div></div>`}async function copyText(t){try{await navigator.clipboard.writeText(t);toast('Command copied','success')}catch(e){toast('Copy unavailable; select the command manually','warning')}}
function progressHtml(x){const p=x.progress||{};const runtime=p.phase==='runtime-observation';const pct=Number.isFinite(Number(p.percent))?Math.max(0,Math.min(100,Number(p.percent))):0;const phase=(p.phase||x.status||'running').replaceAll('-',' ');const module=p.module||x.message||'Assessment processing';const runtimeStats=runtime?`<div class="muted" style="margin-top:10px">Elapsed: ${esc(p.elapsed_seconds??0)} seconds · Samples: ${esc(p.sample_count??0)} · App processes: ${esc(p.application_processes??0)} · Connections: ${esc(p.connections??0)} · Listeners: ${esc(p.listeners??0)} · Unix sockets: ${esc(p.unix_sockets??0)} · FIFOs: ${esc(p.fifos??0)}</div>`:'';const progress=runtime?'<div class="runtimeActivity" aria-label="Runtime Observation active"></div>':`<div class="progressbar" style="margin-top:12px"><div style="width:${pct}%"></div></div><div class="muted" style="margin-top:6px">${pct}%${p.completed!=null&&p.total?` · ${p.completed}/${p.total} stages`:''}</div>`;return `<div class="statusCard"><div class="row" style="justify-content:space-between"><div><div class="stage">${esc(phase.toUpperCase())}</div><div>${esc(module)}</div></div><span class="pill">${esc(x.status)}</span></div>${progress}${runtimeStats}${p.safety_limit_reached?'<p class="warning">The 60-minute safety limit was reached and the observation was saved automatically.</p>':''}${p.message?`<p class="muted">${esc(p.message)}</p>`:''}<details><summary>Technical Details</summary><pre>${esc(JSON.stringify({job:x.id,assessment:x.assessment,progress:p,result:x.result},null,2))}</pre></details></div>`}
function completedHtml(x){const d=x.result?.data||{};return `<div class="statusCard"><div class="stage success">Assessment Completed</div><div class="grid"><div><span class="muted">Assessment</span><br><b>${esc((d.assessment||x.assessment).split('/').pop())}</b></div><div><span class="muted">Mode</span><br>${esc(d.mode||'')}</div><div><span class="muted">Status</span><br>COMPLETED</div></div><div class="row" style="margin-top:12px"><button class="btn primary" onclick='openCompletedAssessment(${JSON.stringify(d.assessment||x.assessment)})'>Open Assessment</button><button class="btn" onclick="goView('reports')">View Reports</button></div></div>`}
async function openCompletedAssessment(p){await refreshAssessments();await selectAssessment(p);await goView('dashboard')}
async function startAssessment(){const body={assessment_name:document.getElementById('newName').value,output_root:document.getElementById('newRoot').value,installer:document.getElementById('newInstaller').value,mode:document.getElementById('newMode').value,application_root:document.getElementById('newAppRoot').value,application_path:document.getElementById('newAppPath').value,network_observation_seconds:Number(document.getElementById('newNetSecs').value)};const j=await api('/api/assessment/start',{method:'POST',body:JSON.stringify(body)});if(!j.ok)return toast(j.message+': '+(j.errors||[]).join('; '),'danger');document.getElementById('newJob').innerHTML=progressHtml(j.data.job);pollAssessmentJob(j.data.job.id)}async function continueAssessment(path){const j=await api('/api/assessment/continue',{method:'POST',body:JSON.stringify({path,include_discovered_home:true})});if(!j.ok)return toast(j.message,'danger');document.getElementById('newJob').innerHTML=progressHtml(j.data.job);pollAssessmentJob(j.data.job.id)}async function pollAssessmentJob(id){const j=await api('/api/job?id='+encodeURIComponent(id));if(!j.ok)return toast(j.message,'danger');const x=j.data.job;document.getElementById('newJob').innerHTML=progressHtml(x);if(x.status==='queued'||x.status==='running')return setTimeout(()=>pollAssessmentJob(id),700);if(x.status==='waiting'&&x.result?.ok){const d=x.result.data||{};if(d.assessment){selected=d.assessment;sessionStorage.setItem('ucaSelectedAssessment',selected)}document.getElementById('newJob').innerHTML=waitingHtml(d.install_command||'',d.assessment);await refreshAssessments();return}if(x.status==='completed'&&x.result?.ok){const d=x.result.data||{};if(d.assessment){selected=d.assessment;sessionStorage.setItem('ucaSelectedAssessment',selected)}document.getElementById('newJob').innerHTML=completedHtml(x);toast('Assessment completed','success');await refreshAssessments();if(selected){const o=await api('/api/overview?path='+encodeURIComponent(selected));if(o.ok)selectedOverview=o.data;updateSelectedCards()}}else{document.getElementById('newJob').innerHTML=progressHtml(x);toast(x.message+': '+(x.result?.errors||[]).join('; '),'danger')}}
function showReviewUnavailable(message){reviewData=null;selectedReview=null;document.getElementById('categoryFilter').innerHTML='<option>Not applicable</option>';document.getElementById('statusFilter').value='';document.getElementById('reviewProgress').innerHTML='';document.getElementById('reviewFilterCount').textContent='';document.getElementById('reviewList').innerHTML=`<div class="empty">${esc(message)}</div>`;document.getElementById('reviewDetail').innerHTML='<div class="empty">No Guided Review queue is available for this assessment.</div>'}
async function loadReview(){updateSelectedCards();if(!selected)return showReviewUnavailable('Select a Full Assessment from the selector above.');if(selectedOverview?.mode&&selectedOverview.mode!=='full')return showReviewUnavailable('Guided Review is not applicable to Installer Analysis Only assessments.');const oldCategory=document.getElementById('categoryFilter').value||'';const oldStatus=document.getElementById('statusFilter').value||'';const j=await api('/api/review?path='+encodeURIComponent(selected));if(!j.ok)return showReviewUnavailable(j.message||'Guided Review is not available for the current assessment state.');reviewData=j.data;document.getElementById('reviewProgress').innerHTML=`<p><b>${j.data.progress.completed}/${j.data.progress.total}</b> completed · ${j.data.progress.pending} pending</p>`;const cats=[...new Set(j.data.items.map(x=>x.category||'Other'))];document.getElementById('categoryFilter').innerHTML='<option value="">All categories</option>'+cats.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');if(cats.includes(oldCategory))document.getElementById('categoryFilter').value=oldCategory;document.getElementById('statusFilter').value=oldStatus;document.getElementById('categoryFilter').onchange=renderReviewList;document.getElementById('statusFilter').onchange=renderReviewList;renderReviewList();document.getElementById('reviewDetail').innerHTML='<div class="muted">Choose a review item.</div>'}
function filteredReviewItems(){if(!reviewData)return[];const category=document.getElementById('categoryFilter').value;const status=document.getElementById('statusFilter').value;return reviewData.items.filter(x=>(!category||x.category===category)&&(!status||x.status===status))}
function reviewStatusClass(status){if(status==='VALIDATED')return'review-item-validated';if(status==='NOT APPLICABLE')return'review-item-na';if(status==='INFORMATIONAL')return'review-item-informational';return'review-item-pending'}
function renderReviewList(){if(!reviewData)return;const items=filteredReviewItems();document.getElementById('reviewFilterCount').textContent=`Showing ${items.length} of ${reviewData.items.length} items`;document.getElementById('reviewList').innerHTML=items.map(x=>`<div class="item ${reviewStatusClass(x.status)} ${selectedReview===(x.identity||x.id)?'active':''}" data-review-id="${esc(x.identity||x.id)}" onclick='showReview(${JSON.stringify(x.identity||x.id)})'><b>${esc(x.id||x.identity)}</b> ${esc(x.title||'')}<div class="muted">${esc(x.status)} · ${esc(x.priority||'')}</div></div>`).join('')||'<div class="empty">No review items match the selected filters.</div>'}
function reviewProcedure(x){const parts=[];for(const [label,key] of [['Condition','condition'],['Why it matters','why_it_matters'],['Detailed Validation Procedure','validation_procedure'],['Expected Secure Behavior','expected_secure_behavior'],['Potentially Vulnerable Behavior','potentially_vulnerable_behavior'],['Do Not Report / Stop If','do_not_report']]){if(x[key])parts.push(`\n${label}\n${'-'.repeat(label.length)}\n${x[key]}`)}return parts.join('\n').trim()||x.summary||''}
function showReview(identity){selectedReview=identity;renderReviewList();const x=reviewData.items.find(y=>(y.identity||y.id)===identity);if(!x)return;document.getElementById('reviewDetail').innerHTML=`<div class="reviewHeader"><h3>${esc(x.id||x.identity)} — ${esc(x.title||'')}</h3><div class="muted">${esc(x.category||'')} · ${esc(x.priority||'')}</div></div><div class="reviewGuide">${esc(reviewProcedure(x))}</div><div class="reviewActions"><label>Status<select id="reviewStatus"><option>PENDING</option><option>VALIDATED</option><option>NOT APPLICABLE</option><option>INFORMATIONAL</option></select></label><label style="margin-top:10px">Tester Notes<textarea id="reviewNotes" style="width:100%;min-height:96px;max-height:150px"></textarea></label><button class="btn primary" style="margin-top:10px" onclick="saveReview()">Save Review Item</button></div>`;document.getElementById('reviewStatus').value=x.status||'PENDING';document.getElementById('reviewNotes').value=x.tester_notes||x.notes||''}
async function saveReview(){if(!selected||!reviewData||!selectedReview)return;const list=document.getElementById('reviewList');const oldScroll=list.scrollTop;const saved=selectedReview;const newStatus=document.getElementById('reviewStatus').value;const j=await api('/api/review/save',{method:'POST',body:JSON.stringify({path:selected,identity:saved,status:newStatus,notes:document.getElementById('reviewNotes').value,expected_revision:reviewData.revision})});toast(j.message,j.ok?'success':'danger');if(j.ok){await loadReview();const visible=filteredReviewItems();const stillVisible=visible.some(x=>(x.identity||x.id)===saved);if(stillVisible){showReview(saved);requestAnimationFrame(()=>{document.getElementById('reviewList').scrollTop=oldScroll})}else if(visible.length){showReview(visible[0].identity||visible[0].id);requestAnimationFrame(()=>document.querySelector('[data-review-id="'+CSS.escape(selectedReview)+'"]')?.scrollIntoView({block:'nearest'}))}else{selectedReview=null;document.getElementById('reviewDetail').innerHTML='<div class="empty">No review items match the selected filters.</div>';renderReviewList()}await refreshSelectedOverview()}}
async function refreshSelectedOverview(){if(!selected)return;const o=await api('/api/overview?path='+encodeURIComponent(selected));if(o.ok){selectedOverview=o.data;const i=assessmentsCache.findIndex(a=>a.assessment===selected);if(i>=0)assessmentsCache[i]=o.data;updateSelectedCards();renderDashboard()}}
async function launchPrivilegedReview(){if(!selected)return toast('Select an assessment','warning');const j=await api('/api/privileged-review/launch',{method:'POST',body:JSON.stringify({path:selected})});if(!j.ok)return toast((j.errors||[]).join('; ')||j.message,'danger');const d=j.data||{};if(d.launched){toast('Authentication terminal opened. Complete sudo authentication there.','success');pollPrivilegedCoverage(0)}else{const msg='No supported terminal launcher was found. Run this exact command in a terminal:\n\n'+(d.command||'');window.prompt('Privileged collection command',d.command||'');toast('Run the displayed sudo command in a terminal, then refresh the assessment.','warning')}}
async function pollPrivilegedCoverage(attempt){if(attempt>180)return;await new Promise(r=>setTimeout(r,2000));await refreshSelectedOverview();if(!(selectedOverview?.application_file_coverage||{}).limited){toast('Privileged static review completed; affected analyses were regenerated.','success');await loadReports();return}pollPrivilegedCoverage(attempt+1)}
async function loadReports(){updateSelectedCards();if(!selected){document.getElementById('reportList').innerHTML='<div class="empty">Select an assessment.</div>';return}const r=await api('/api/reports?path='+encodeURIComponent(selected));if(!r.ok){document.getElementById('reportList').innerHTML='<div class="empty">Reports could not be loaded.</div>';return}renderReports(r.data.reports||[])}function renderReports(names){document.getElementById('reportList').innerHTML=names.length?names.map(n=>`<div class="item" onclick='openReport(${JSON.stringify(n)})'>${esc(n)}</div>`).join(''):'<div class="empty">No reports are available yet.</div>'}async function openReport(n){if(!selected)return;const j=await api('/api/report?path='+encodeURIComponent(selected)+'&name='+encodeURIComponent(n));if(!j.ok)return toast(j.message,'danger');document.getElementById('reportTitle').textContent=n;document.getElementById('reportContent').textContent=j.data.content||''}
let runtimeCurrentJob=null;
function setRuntimeButtons(running){document.getElementById('runtimeStartBtn').style.display=running?'none':'inline-block';document.getElementById('runtimeStopBtn').style.display=running?'inline-block':'none';document.getElementById('runtimeCancelBtn').style.display=running?'inline-block':'none'}
async function loadRuntimeContext(){updateSelectedCards();if(!selected){runtimeCurrentJob=null;document.getElementById('runtimeJob').innerHTML='<div class="empty">Select a Full Assessment before starting runtime observation.</div>';setRuntimeButtons(false);return}if(selectedOverview?.mode&&selectedOverview.mode!=='full'){runtimeCurrentJob=null;document.getElementById('runtimeJob').innerHTML='<div class="empty">Runtime Observation is not applicable to Installer Analysis Only assessments.</div>';setRuntimeButtons(false);return}const active=await api('/api/runtime/active?path='+encodeURIComponent(selected));if(active.ok&&active.data.job){runtimeCurrentJob=active.data.job.id;setRuntimeButtons(true);document.getElementById('runtimeJob').innerHTML=progressHtml(active.data.job);pollRuntime(runtimeCurrentJob);return}runtimeCurrentJob=null;setRuntimeButtons(false);document.getElementById('runtimeJob').innerHTML='<div class="muted">Ready. Start observation, exercise the application, then choose Stop & Save.</div>'}
async function startRuntime(){if(!selected)return toast('Select an assessment','warning');if(selectedOverview?.mode!=='full')return toast('Runtime Observation requires a Full Assessment','warning');const j=await api('/api/runtime/start',{method:'POST',body:JSON.stringify({path:selected})});if(j.ok){runtimeCurrentJob=j.data.job.id;setRuntimeButtons(true);pollRuntime(runtimeCurrentJob)}else toast(j.message,'danger')}
async function stopRuntime(cancel){if(!runtimeCurrentJob)return toast('No Runtime Observation is active','warning');const route=cancel?'/api/runtime/cancel':'/api/runtime/stop';const j=await api(route,{method:'POST',body:JSON.stringify({job:runtimeCurrentJob})});if(!j.ok)return toast(j.message,'danger');document.getElementById('runtimeStopBtn').disabled=true;document.getElementById('runtimeCancelBtn').disabled=true;toast(j.message,cancel?'warning':'success')}
async function pollRuntime(id){const j=await api('/api/job?id='+encodeURIComponent(id));if(!j.ok)return;const x=j.data.job;document.getElementById('runtimeJob').innerHTML=progressHtml(x);const active=['queued','running','stopping','cancelling'].includes(x.status);setRuntimeButtons(active);document.getElementById('runtimeStopBtn').disabled=x.status==='stopping'||x.status==='cancelling';document.getElementById('runtimeCancelBtn').disabled=x.status==='stopping'||x.status==='cancelling';if(active)setTimeout(()=>pollRuntime(id),700);else{runtimeCurrentJob=null;setRuntimeButtons(false);toast(x.message,x.status==='completed'?'success':(x.status==='cancelled'?'warning':'danger'));await refreshSelectedOverview();await loadReports()}}
async function loadIntegrityStatus(){updateSelectedCards();if(!selected){document.getElementById('integrityState').textContent='Select an assessment.';document.getElementById('recoveryState').textContent='Select an assessment.';return}const s=await api('/api/status?path='+encodeURIComponent(selected));document.getElementById('integrityState').textContent=s.ok?'Assessment state loaded. Use Verify Integrity for a current hash check.':s.message;document.getElementById('recoveryState').textContent=s.ok?(s.data.detail||s.data.status||'No recovery action currently required.'):(s.errors||[]).join('; ')}
async function verifySelected(){if(!selected)return toast('Select an assessment','warning');const j=await api('/api/verify',{method:'POST',body:JSON.stringify({path:selected})});document.getElementById('integrityState').textContent=j.ok?'PASS — assessment verification passed':('FAIL — '+((j.errors||[]).join('; ')||j.message));toast(j.message,j.ok?'success':'danger')}async function repairReports(){if(!selected)return toast('Select an assessment','warning');const j=await api('/api/repair',{method:'POST',body:JSON.stringify({path:selected})});toast(j.message,j.ok?'success':'danger');await loadIntegrityStatus();await loadReports()}async function recoverInterrupted(){if(!selected)return toast('Select an assessment','warning');const j=await api('/api/recover',{method:'POST',body:JSON.stringify({path:selected})});toast(j.message,j.ok?'success':'danger');await loadIntegrityStatus();await refreshSelectedOverview()}
async function loadAppendixContext(){updateSelectedCards();document.getElementById('appendixState').innerHTML=!selected?'<div class="empty">Select a completed Full Assessment.</div>':(selectedOverview?.mode&&selectedOverview.mode!=='full'?'<div class="empty">Client Appendix is not applicable to Installer Analysis Only assessments.</div>':'')}
async function createAppendix(){if(!selected)return toast('Select an assessment','warning');if(selectedOverview?.mode!=='full')return toast('Client Appendix requires a Full Assessment','warning');const j=await api('/api/appendix',{method:'POST',body:JSON.stringify({path:selected})});document.getElementById('appendixState').innerHTML=`<div class="${j.ok?'success':'danger'}">${esc(j.message)}</div>${j.errors?.length?`<pre>${esc(j.errors.join('\n'))}</pre>`:''}`;toast(j.message,j.ok?'success':'danger')}
document.querySelectorAll('.nav button').forEach(b=>b.onclick=()=>goView(b.dataset.view));document.getElementById('assessmentPicker').onchange=async e=>{if(e.target.value)await selectAssessment(e.target.value)};(async()=>{document.getElementById('root').value='__ROOT__';document.getElementById('newRoot').value='__ROOT__';const c=await api('/api/capabilities');document.getElementById('capabilities').textContent=JSON.stringify(c.data,null,2);await refreshAssessments();const remembered=sessionStorage.getItem('ucaSelectedAssessment');if(remembered&&assessmentsCache.some(a=>a.assessment===remembered))await selectAssessment(remembered)})().catch(e=>toast(e.message,'danger'));
</script></body></html>
'''


class UcaGuiHandler(BaseHTTPRequestHandler):
    server_version = "UbuntuClientAssessGUI/2.0.6"

    @property
    def state(self) -> GuiState:
        return self.server.gui_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep the terminal useful without printing request tokens/query strings.
        print(f"[GUI] {self.address_string()} - {fmt % args}")

    def _headers(self, status: int, content_type: str = "application/json; charset=utf-8", length: int | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._headers(status, length=len(body))
        self.wfile.write(body)

    def _result(self, result: ServiceResult, success_status: int = 200) -> None:
        self._json(result.as_dict(), success_status if result.ok else 409)

    def _authorized(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-UCA-Token", ""), self.state.token)

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        self._json({"ok": False, "code": "unauthorized", "message": "Missing or invalid GUI request token", "data": {}, "errors": []}, 403)
        return False

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 1024 * 1024:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _path_from(raw: Any) -> Path:
        return Path(str(raw or "")).expanduser().resolve()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            token = parse_qs(parsed.query).get("token", [""])[0]
            if not secrets.compare_digest(token, self.state.token):
                self._headers(403, "text/plain; charset=utf-8")
                self.wfile.write(b"Forbidden")
                return
            body = INDEX_HTML.replace("__TOKEN__", self.state.token).replace("__ROOT__", str(self.state.assessment_root)).replace("__HOME__", str(Path.home())).encode("utf-8")
            self._headers(200, "text/html; charset=utf-8", len(body))
            self.wfile.write(body)
            return
        if not parsed.path.startswith("/api/") or not self._require_auth():
            return
        q = parse_qs(parsed.query)
        try:
            if parsed.path == "/api/capabilities":
                self._result(self.state.service.capabilities())
            elif parsed.path == "/api/assessments":
                raw_root = q.get("root", [str(self.state.assessment_root)])[0] or str(self.state.assessment_root)
                root = Path(raw_root).expanduser().resolve()
                self._json({"ok": True, "code": "assessments-ready", "message": "Assessments loaded", "data": {"root": str(root), "assessments": self.state.discover_assessments(root)}, "errors": []})
            elif parsed.path == "/api/fs/list":
                raw = q.get("path", [str(Path.home())])[0] or str(Path.home())
                current = Path(raw).expanduser().resolve()
                if not current.is_dir():
                    current = current.parent if current.parent.is_dir() else Path.home().resolve()
                mode = q.get("mode", ["directory"])[0]
                directories = []
                files = []
                try:
                    entries = sorted(current.iterdir(), key=lambda x: (not x.is_dir(), x.name.casefold()))
                except (OSError, PermissionError) as exc:
                    raise ValueError(f"Directory cannot be read: {exc}") from exc
                for entry in entries:
                    try:
                        if entry.is_dir():
                            directories.append({"name": entry.name, "path": str(entry.resolve())})
                        elif mode == "installer" and entry.is_file() and entry.suffix.lower() in {".deb", ".snap", ".zip", ".7z", ".tar", ".tgz", ".gz", ".xz", ".bz2", ".txz", ".tbz", ".tbz2", ".appimage", ".sh", ".run", ".flatpak", ".flatpakref", ".flatpakrepo"}:
                            files.append({"name": entry.name, "path": str(entry.resolve())})
                    except OSError:
                        continue
                parent = str(current.parent) if current.parent != current else ""
                self._json({"ok": True, "code": "filesystem-ready", "message": "Filesystem entries loaded", "data": {"path": str(current), "parent": parent, "directories": directories, "files": files}, "errors": []})
            elif parsed.path == "/api/overview":
                self._result(self.state.service.assessment_overview(self._path_from(q.get("path", [""])[0])))
            elif parsed.path == "/api/status":
                self._result(self.state.service.assessment_status(self._path_from(q.get("path", [""])[0])))
            elif parsed.path == "/api/review":
                self._result(self.state.service.review_snapshot(self._path_from(q.get("path", [""])[0])))
            elif parsed.path == "/api/reports":
                assessment = self._path_from(q.get("path", [""])[0])
                reports = assessment / "reports"
                names = sorted([p.name for p in reports.iterdir() if p.is_file()]) if reports.is_dir() else []
                self._json({"ok": True, "code": "reports-ready", "message": "Reports loaded", "data": {"reports": names}, "errors": []})
            elif parsed.path == "/api/report":
                assessment = self._path_from(q.get("path", [""])[0])
                name = q.get("name", [""])[0]
                candidate = (assessment / "reports" / name).resolve()
                reports_root = (assessment / "reports").resolve()
                if reports_root not in candidate.parents or not candidate.is_file():
                    raise ValueError("Requested report is not available")
                if candidate.stat().st_size > MAX_REPORT_BYTES:
                    raise ValueError("Report is too large for the browser viewer")
                content = candidate.read_text(encoding="utf-8", errors="replace")
                self._json({"ok": True, "code": "report-ready", "message": "Report loaded", "data": {"name": name, "content": content}, "errors": []})
            elif parsed.path == "/api/job":
                job = self.state.get_job(q.get("id", [""])[0])
                if not job:
                    raise ValueError("Unknown job")
                self._json({"ok": True, "code": "job-ready", "message": "Job loaded", "data": {"job": job.as_dict()}, "errors": []})
            elif parsed.path == "/api/runtime/active":
                assessment = self._path_from(q.get("path", [""])[0])
                job = self.state.active_runtime_job(assessment)
                self._json({"ok": True, "code": "runtime-active", "message": "Runtime Observation state loaded", "data": {"job": job.as_dict() if job else None}, "errors": []})
            else:
                self._json({"ok": False, "code": "not-found", "message": "API route not found", "data": {}, "errors": []}, 404)
        except Exception as exc:
            self._json({"ok": False, "code": "request-failed", "message": "Request failed", "data": {}, "errors": [str(exc)]}, 400)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/") or not self._require_auth():
            return
        body = self._body()
        assessment = self._path_from(body.get("path"))
        try:
            if parsed.path == "/api/assessment/start":
                job = self.state.create_assessment_job(body)
                self._json({"ok": True, "code": "assessment-started", "message": "Assessment job started", "data": {"job": job.as_dict()}, "errors": []}, 202)
            elif parsed.path == "/api/assessment/continue":
                job = self.state.create_continue_job(assessment, bool(body.get("include_discovered_home", True)))
                self._json({"ok": True, "code": "assessment-continue-started", "message": "Assessment continuation started", "data": {"job": job.as_dict()}, "errors": []}, 202)
            elif parsed.path == "/api/privileged-review/launch":
                data = self.state.launch_privileged_review(assessment)
                self._json({"ok": True, "code": "privileged-review-launched" if data.get("launched") else "privileged-review-command-ready", "message": "Privileged collection authentication opened in a terminal" if data.get("launched") else "Run the generated command in a terminal", "data": data, "errors": []}, 202)
            elif parsed.path == "/api/review/save":
                result = self.state.service.save_review_item(
                    assessment,
                    str(body.get("identity") or ""),
                    status=str(body.get("status") or "PENDING"),
                    notes=str(body.get("notes") or ""),
                    expected_revision=str(body.get("expected_revision") or "") or None,
                )
                self._result(result)
            elif parsed.path == "/api/verify":
                self._result(self.state.service.verify_assessment(assessment))
            elif parsed.path == "/api/repair":
                self._result(self.state.service.repair_generated_reports(assessment))
            elif parsed.path == "/api/recover":
                self._result(self.state.service.recover_interrupted_operation(assessment))
            elif parsed.path == "/api/appendix":
                self._result(self.state.service.create_client_appendix(assessment))
            elif parsed.path == "/api/runtime/start":
                job = self.state.create_runtime_job(assessment)
                self._json({"ok": True, "code": "runtime-started", "message": "Runtime Observation started", "data": {"job": job.as_dict()}, "errors": []}, 202)
            elif parsed.path in {"/api/runtime/stop", "/api/runtime/cancel"}:
                job_id = str(body.get("job") or "")
                job = self.state.stop_runtime_job(job_id, cancel=parsed.path.endswith("/cancel"))
                code = "runtime-cancel-requested" if parsed.path.endswith("/cancel") else "runtime-stop-requested"
                self._json({"ok": True, "code": code, "message": job.message, "data": {"job": job.as_dict()}, "errors": []}, 202)
            else:
                self._json({"ok": False, "code": "not-found", "message": "API route not found", "data": {}, "errors": []}, 404)
        except Exception as exc:
            self._json({"ok": False, "code": "request-failed", "message": "Request failed", "data": {}, "errors": [str(exc)]}, 400)


class UcaGuiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: GuiState):
        super().__init__(address, UcaGuiHandler)
        self.gui_state = state


def validate_gui_port(port: int) -> int:
    value = int(port)
    if value < 1 or value > 65535:
        raise ValueError("GUI port must be between 1 and 65535")
    return value


def run_gui(*, port: int = DEFAULT_GUI_PORT, assessment_root: Path | None = None, open_browser: bool = True) -> int:
    port = validate_gui_port(port)
    root = (assessment_root or (Path.cwd() / "Assessments")).expanduser().resolve()
    state = GuiState(root)
    server = UcaGuiServer((DEFAULT_GUI_HOST, port), state)
    url = f"http://{DEFAULT_GUI_HOST}:{port}/?token={quote(state.token)}"
    print(f"UbuntuClientAssess v{VERSION} Web UI")
    print(f"Listening on {DEFAULT_GUI_HOST}:{port} (loopback only)")
    print(f"Assessment root: {root}")
    print(f"Open: {url}")
    print("Press Ctrl+C to stop the web server.")
    if open_browser:
        def _open_quietly() -> None:
            try:
                subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            except (OSError, FileNotFoundError):
                pass
        threading.Timer(0.35, _open_quietly).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping UbuntuClientAssess Web UI.")
    finally:
        server.server_close()
    return 0
