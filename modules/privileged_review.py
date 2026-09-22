from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .common import now_iso, read_json, working_dir, write_json
from .snapshot import _collect_filesystem

_ALLOWED_PREFIXES = ("/opt/", "/usr/local/", "/usr/lib/", "/usr/libexec/", "/var/opt/", "/var/lib/")


def _within_allowed_root(path: Path) -> bool:
    text = str(path.resolve(strict=False))
    return any(text.startswith(prefix) for prefix in _ALLOWED_PREFIXES)


def privileged_roots(assessment_dir: Path) -> list[Path]:
    metadata = read_json(Path(assessment_dir) / "assessment_metadata.json")
    coverage = metadata.get("application_file_coverage") or {}
    roots: list[Path] = []
    for gap in coverage.get("gaps", []) or []:
        raw = str(gap.get("path") or "")
        if not raw:
            continue
        root = Path(raw).expanduser().resolve(strict=False)
        if _within_allowed_root(root):
            roots.append(root)
    return sorted(set(roots), key=str)


def collect_protected_application_roots(assessment_dir: Path) -> dict[str, Any]:
    """Collect only application roots already identified as coverage gaps.

    This helper is intentionally narrow: it accepts no arbitrary path input and
    never executes application content. It augments the post-install snapshot
    with metadata/hashes that the unprivileged collection could not obtain.
    """
    assessment_dir = Path(assessment_dir).expanduser().resolve()
    if os.geteuid() != 0:
        raise PermissionError("Privileged static collection must be run with sudo/root privileges")
    metadata_path = assessment_dir / "assessment_metadata.json"
    post_path = working_dir(assessment_dir) / "snapshot_post.json"
    if not metadata_path.is_file() or not post_path.is_file():
        raise RuntimeError("Assessment metadata or post-install snapshot is missing")
    metadata = read_json(metadata_path)
    if metadata.get("mode") != "full":
        raise RuntimeError("Privileged static collection is available only for Full Assessments")
    roots = privileged_roots(assessment_dir)
    if not roots:
        raise RuntimeError("No protected application roots are currently recorded for this assessment")
    for root in roots:
        if not root.exists() or not root.is_dir() or not _within_allowed_root(root):
            raise RuntimeError(f"Recorded protected application root is no longer valid: {root}")

    gaps: list[dict[str, Any]] = []
    collected = _collect_filesystem(roots, [], gaps)
    post = read_json(post_path)
    filesystem = post.get("filesystem") if isinstance(post.get("filesystem"), dict) else {}
    filesystem.update(collected)
    post["filesystem"] = filesystem

    root_texts = [str(r) for r in roots]
    def under_recorded_root(raw: Any) -> bool:
        text = str(raw or "")
        return any(text == root or text.startswith(root.rstrip("/") + "/") for root in root_texts)

    prior_gaps = list(post.get("filesystem_collection_gaps", []) or [])
    post["filesystem_collection_gaps"] = [g for g in prior_gaps if not under_recorded_root(g.get("path"))] + gaps
    write_json(post_path, post)

    state = {
        "completed_at": now_iso(),
        "roots": root_texts,
        "objects_collected": len(collected),
        "remaining_collection_gaps": gaps,
        "scope": "recorded-protected-application-roots-only",
        "executed_application_content": False,
    }
    write_json(working_dir(assessment_dir) / "privileged_static_collection.json", state)
    metadata["privileged_static_collection"] = state
    write_json(metadata_path, metadata)
    return state


def restore_assessment_ownership(assessment_dir: Path, uid: int, gid: int) -> None:
    """Return framework-owned assessment artifacts to the original tester owner."""
    assessment_dir = Path(assessment_dir)
    for root, dirs, files in os.walk(assessment_dir, followlinks=False):
        for name in dirs + files:
            path = Path(root) / name
            try:
                os.lchown(path, uid, gid)
            except OSError:
                pass
    try:
        os.lchown(assessment_dir, uid, gid)
    except OSError:
        pass
