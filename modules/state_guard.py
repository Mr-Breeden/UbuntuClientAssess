from __future__ import annotations

"""Assessment-state locking, revision, and rollback helpers.

The helpers in this module are intentionally presentation-neutral. They protect
state-changing service operations from concurrent writers, expose stable state
revisions for optimistic stale-write detection, and retain enough rollback
material to recover from an interrupted multi-file transaction.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import Iterable, Iterator

from .common import now_iso, sha256_file, write_json


class AssessmentBusyError(RuntimeError):
    """Raised when another process currently owns an incompatible assessment lock."""


class StaleStateError(RuntimeError):
    """Raised when a caller attempts to write against an out-of-date revision."""


LOCK_ROOT = Path(tempfile.gettempdir()) / "ubuntuclientassess-locks"
TRANSACTION_DIRNAME = ".state_transaction"


def _lock_path(assessment_dir: Path) -> Path:
    canonical = str(Path(assessment_dir).expanduser().resolve()).encode("utf-8", errors="surrogateescape")
    token = hashlib.sha256(canonical).hexdigest()
    LOCK_ROOT.mkdir(parents=True, exist_ok=True)
    return LOCK_ROOT / f"{token}.lock"


def _lock_owner_text(handle) -> str:
    try:
        handle.seek(0)
        raw = handle.read().strip()
        if not raw:
            return "another UbuntuClientAssess process"
        payload = json.loads(raw)
        pid = payload.get("pid")
        operation = payload.get("operation") or "assessment operation"
        started = payload.get("acquired_at") or "unknown time"
        return f"PID {pid} running {operation} since {started}"
    except Exception:
        return "another UbuntuClientAssess process"


@contextmanager
def assessment_lock(assessment_dir: Path, operation: str, *, exclusive: bool) -> Iterator[None]:
    """Acquire a fail-fast cross-process lock for one assessment.

    Locks live in the OS temporary directory so read-only verification does not
    add files to the assessment itself. Shared locks protect stable reads;
    exclusive locks serialize all state-changing operations.
    """

    path = _lock_path(assessment_dir)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as handle:
        flag = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        try:
            fcntl.flock(handle.fileno(), flag | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            owner = _lock_owner_text(handle)
            raise AssessmentBusyError(f"Assessment is busy: {owner}") from exc
        try:
            if exclusive:
                handle.seek(0)
                handle.truncate()
                json.dump({
                    "pid": os.getpid(),
                    "operation": operation,
                    "acquired_at": now_iso(),
                    "assessment": str(Path(assessment_dir).expanduser().resolve()),
                }, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass


def assessment_revision(assessment_dir: Path) -> str:
    """Return a stable optimistic-concurrency token for finalized assessment state."""

    root = Path(assessment_dir).expanduser().resolve()
    manifest = root / "assessment_manifest.json"
    if manifest.is_file():
        return sha256_file(manifest)

    # Recovery/incomplete assessments may not yet have a manifest. Hash the
    # authoritative checkpoints that can exist before finalization.
    digest = hashlib.sha256()
    candidates = [
        root / "assessment_metadata.json",
        root / "working" / "snapshot_pre.json",
        root / "working" / "snapshot_post.json",
        root / "working" / "tester_review_state.json",
        root / "working" / "runtime_observation.json",
        root / "working" / "security_model.json",
    ]
    for path in candidates:
        rel = str(path.relative_to(root))
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update((sha256_file(path) if path.is_file() else "MISSING").encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def require_revision(assessment_dir: Path, expected_revision: str | None) -> str:
    current = assessment_revision(assessment_dir)
    if expected_revision and expected_revision != current:
        raise StaleStateError(
            "Assessment state changed after it was loaded. Refresh the assessment before saving so newer state is not overwritten."
        )
    return current


def transaction_path(assessment_dir: Path) -> Path:
    return Path(assessment_dir).expanduser().resolve() / "working" / TRANSACTION_DIRNAME


def pending_transaction(assessment_dir: Path) -> dict | None:
    tx_dir = transaction_path(assessment_dir)
    journal = tx_dir / "journal.json"
    if not tx_dir.exists():
        return None
    if not journal.is_file():
        # Transaction setup snapshots files before control returns to the caller,
        # so no assessment mutation can have started when the journal is absent.
        return {"operation": "transaction setup", "status": "incomplete-journal", "started_at": "unknown"}
    try:
        return json.loads(journal.read_text(encoding="utf-8"))
    except Exception:
        return {"operation": "unknown", "status": "unreadable", "started_at": "unknown"}


def _atomic_restore(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            temp.unlink()
        except OSError:
            pass
        raise


def recover_interrupted_transaction(assessment_dir: Path) -> dict | None:
    """Restore the last pre-transaction snapshot when a prior writer was interrupted."""

    root = Path(assessment_dir).expanduser().resolve()
    tx_dir = transaction_path(root)
    journal_path = tx_dir / "journal.json"
    if not tx_dir.exists():
        return None
    if not journal_path.is_file():
        # No mutation can begin until StateTransaction.__enter__ completes. An
        # orphaned setup directory without a journal is therefore safe to drop.
        shutil.rmtree(tx_dir, ignore_errors=False)
        return {"operation": "transaction setup", "started_at": "unknown", "base_revision": "", "cleanup_only": True}
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Interrupted transaction journal is unreadable: {exc}") from exc
    if journal.get("status") == "committed":
        recovered = {
            "operation": journal.get("operation") or "unknown",
            "started_at": journal.get("started_at") or "unknown",
            "base_revision": journal.get("base_revision") or "",
            "cleanup_only": True,
        }
        shutil.rmtree(tx_dir, ignore_errors=False)
        return recovered
    for entry in journal.get("files", []):
        rel = Path(str(entry.get("path") or ""))
        if rel.is_absolute() or ".." in rel.parts:
            raise RuntimeError(f"Unsafe transaction recovery path: {rel}")
        target = (root / rel).resolve(strict=False)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise RuntimeError(f"Unsafe transaction recovery path: {rel}") from exc
        if entry.get("existed"):
            backup = tx_dir / "backups" / str(entry.get("backup"))
            if not backup.is_file():
                raise RuntimeError(f"Transaction backup is missing for {rel}")
            _atomic_restore(target, backup.read_bytes(), int(entry.get("mode") or 0o644))
        else:
            try:
                if target.is_file() or target.is_symlink():
                    target.unlink()
            except OSError as exc:
                raise RuntimeError(f"Unable to remove transaction-created file {rel}: {exc}") from exc
    recovered = {
        "operation": journal.get("operation") or "unknown",
        "started_at": journal.get("started_at") or "unknown",
        "base_revision": journal.get("base_revision") or "",
    }
    shutil.rmtree(tx_dir, ignore_errors=False)
    return recovered


@dataclass
class StateTransaction:
    """Rollback envelope for a bounded set of assessment files."""

    assessment_dir: Path
    operation: str
    files: Iterable[Path]
    base_revision: str = ""

    def __post_init__(self) -> None:
        self.assessment_dir = Path(self.assessment_dir).expanduser().resolve()
        self._tx_dir = transaction_path(self.assessment_dir)
        self._committed = False

    def __enter__(self) -> "StateTransaction":
        if self._tx_dir.exists():
            raise RuntimeError("An interrupted assessment transaction requires recovery before a new write can begin")
        backups = self._tx_dir / "backups"
        backups.mkdir(parents=True, exist_ok=False)
        entries = []
        seen: set[str] = set()
        for raw in self.files:
            path = Path(raw)
            if not path.is_absolute():
                path = self.assessment_dir / path
            path = path.resolve(strict=False)
            try:
                rel = path.relative_to(self.assessment_dir)
            except ValueError as exc:
                raise RuntimeError(f"Transaction path is outside assessment root: {path}") from exc
            rel_text = str(rel)
            if rel_text in seen:
                continue
            seen.add(rel_text)
            existed = path.is_file()
            backup_name = hashlib.sha256(rel_text.encode("utf-8")).hexdigest() + ".bak"
            mode = 0o644
            if existed:
                mode = stat.S_IMODE(path.stat().st_mode)
                shutil.copyfile(path, backups / backup_name)
            entries.append({
                "path": rel_text,
                "existed": existed,
                "backup": backup_name if existed else "",
                "mode": mode,
            })
        write_json(self._tx_dir / "journal.json", {
            "schema_version": 1,
            "status": "in_progress",
            "operation": self.operation,
            "started_at": now_iso(),
            "pid": os.getpid(),
            "base_revision": self.base_revision,
            "files": entries,
        })
        return self

    def commit(self) -> None:
        # Mark the transaction committed before cleanup. If the process dies
        # after this point, recovery removes only the journal/backup directory
        # instead of rolling back a fully verified state change.
        journal_path = self._tx_dir / "journal.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["status"] = "committed"
        journal["committed_at"] = now_iso()
        write_json(journal_path, journal)
        self._committed = True

    def rollback(self) -> None:
        if self._tx_dir.exists():
            recover_interrupted_transaction(self.assessment_dir)

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None or not self._committed:
            self.rollback()
        else:
            shutil.rmtree(self._tx_dir, ignore_errors=False)
        return False
