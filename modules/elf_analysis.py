from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

from .common import command_exists, report_path, run_cmd, strip_ansi, user_can_write, write_text


def _is_elf(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def _extract_dynamic(path: Path) -> dict[str, Any]:
    result = run_cmd(["readelf", "-d", str(path)], timeout=30)
    data: dict[str, Any] = {"needed": [], "rpath": [], "runpath": [], "soname": ""}
    if result["returncode"] != 0:
        return data
    for line in result["stdout"].splitlines():
        m = re.search(r"\((NEEDED|RPATH|RUNPATH|SONAME)\).*?\[([^\]]+)\]", line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if key == "NEEDED":
            data["needed"].append(value)
        elif key == "RPATH":
            data["rpath"].extend(value.split(":"))
        elif key == "RUNPATH":
            data["runpath"].extend(value.split(":"))
        elif key == "SONAME":
            data["soname"] = value
    return data


def _search_path_concern(binary: Path, raw: str) -> tuple[str | None, bool]:
    if raw == "":
        return "Empty library search-path component resolves to the current working directory", True
    if "$ORIGIN" in raw:
        resolved_text = raw.replace("${ORIGIN}", str(binary.parent)).replace("$ORIGIN", str(binary.parent))
    elif raw.startswith("/"):
        resolved_text = raw
    else:
        return f"Relative library search path: {raw}", False
    p = Path(resolved_text)
    if not p.exists():
        return None, False
    try:
        st = p.stat()
    except OSError:
        return None, False
    if st.st_mode & stat.S_IWOTH:
        return f"Library search directory is world-writable: {p}", True
    if user_can_write(p):
        return f"Current tester has write access to library search directory: {p}", True
    return None, False


def _parse_checksec(text: str, path: Path) -> dict[str, Any]:
    clean = strip_ansi(text)
    data: dict[str, Any] = {
        "relro": "Unknown", "canary": "Unknown", "nx": "Unknown", "pie": "Unknown",
        "fortify": "Unknown", "fortified": None, "fortifiable": None, "symbols": "Unknown",
    }
    if "Full RELRO" in clean: data["relro"] = "Full"
    elif "Partial RELRO" in clean: data["relro"] = "Partial"
    elif "No RELRO" in clean: data["relro"] = "Disabled"
    if "Canary found" in clean: data["canary"] = "Enabled"
    elif "No canary found" in clean: data["canary"] = "Disabled"
    if "NX enabled" in clean: data["nx"] = "Enabled"
    elif "NX disabled" in clean: data["nx"] = "Disabled"
    if "No PIE" in clean: data["pie"] = "Disabled"
    elif "PIE enabled" in clean: data["pie"] = "Enabled"
    elif re.search(r"\bDSO\b", clean): data["pie"] = "DSO"
    if "No Symbols" in clean: data["symbols"] = "Stripped/No Symbols"
    elif re.search(r"\bSymbols\b", clean): data["symbols"] = "Present"

    for line in clean.splitlines():
        if str(path) not in line:
            continue
        m = re.search(r"\b(Yes|No)\s+(\d+)\s+(\d+)\s+" + re.escape(str(path)) + r"\s*$", line)
        if m:
            data["fortify"] = "Enabled" if m.group(1) == "Yes" else "Disabled"
            data["fortified"] = int(m.group(2))
            data["fortifiable"] = int(m.group(3))
            break
    return data


def _interpreter(path: Path) -> str:
    result = run_cmd(["readelf", "-l", str(path)], timeout=30)
    for line in result["stdout"].splitlines():
        m = re.search(r"Requesting program interpreter:\s*([^\]]+)", line)
        if m:
            return m.group(1).strip()
    return ""


def _review_notes(record: dict[str, Any]) -> list[str]:
    """Return expanded review notes without flooding reports with routine DSOs."""
    cs = record["checksec"]
    notes: list[str] = []
    if not record["shared_object"] and cs.get("pie") == "Disabled":
        notes.append("PIE disabled")
    if not record["shared_object"] and cs.get("canary") == "Disabled":
        notes.append("Stack canary not present")
    if cs.get("nx") == "Disabled":
        notes.append("NX disabled")
    if cs.get("relro") == "Disabled":
        notes.append("RELRO: Disabled")
    elif not record["shared_object"] and cs.get("relro") == "Partial":
        notes.append("RELRO: Partial")
    if not record["shared_object"] and record["dynamic"].get("rpath"):
        notes.append("RPATH present")
    if not record["shared_object"] and record["dynamic"].get("runpath"):
        notes.append("RUNPATH present")
    notes.extend(x["concern"] for x in record["search_path_concerns"])
    return notes


def analyze_elf(diff: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    changed_paths = sorted(set(diff.get("files_added", [])) | set(diff.get("files_changed", [])))
    elf_files = [Path(p) for p in changed_paths if Path(p).exists() and _is_elf(Path(p))]
    records: list[dict[str, Any]] = []
    rpath_candidates: list[dict[str, Any]] = []
    finding_candidates: list[dict[str, Any]] = []

    for path in elf_files:
        file_info = run_cmd(["file", "-b", str(path)])["stdout"].strip()
        dynamic = _extract_dynamic(path)
        checksec = {"relro": "Unavailable", "canary": "Unavailable", "nx": "Unavailable", "pie": "Unavailable", "fortify": "Unavailable", "fortified": None, "fortifiable": None, "symbols": "Unknown"}
        if command_exists("checksec"):
            cs = run_cmd(["checksec", "--file=" + str(path)], timeout=30)
            checksec = _parse_checksec(cs["stdout"] or cs["stderr"], path)

        concerns: list[dict[str, Any]] = []
        for kind in ("rpath", "runpath"):
            for raw in dynamic[kind]:
                concern, finding_level = _search_path_concern(path, raw)
                if concern:
                    item = {"binary": str(path), "path": raw, "kind": kind.upper(), "concern": concern, "finding_candidate": finding_level}
                    concerns.append(item)
                    rpath_candidates.append(item)
                    if finding_level:
                        finding_candidates.append(item)

        record = {
            "path": str(path), "file": file_info, "dynamic": dynamic, "checksec": checksec,
            "interpreter": _interpreter(path), "search_path_concerns": concerns,
            "shared_object": "shared object" in file_info.lower(),
        }
        records.append(record)

    summary = {
        "total": len(records),
        "executables": sum(1 for r in records if not r["shared_object"]),
        "shared_libraries": sum(1 for r in records if r["shared_object"]),
        "missing_pie": sum(1 for r in records if not r["shared_object"] and r["checksec"].get("pie") == "Disabled"),
        "missing_canary": sum(1 for r in records if r["checksec"].get("canary") == "Disabled"),
        "nx_disabled": sum(1 for r in records if r["checksec"].get("nx") == "Disabled"),
        "partial_relro": sum(1 for r in records if r["checksec"].get("relro") == "Partial"),
        "no_relro": sum(1 for r in records if r["checksec"].get("relro") == "Disabled"),
        "rpath_present": sum(1 for r in records if r["dynamic"].get("rpath")),
        "runpath_present": sum(1 for r in records if r["dynamic"].get("runpath")),
        "unsafe_search_paths": len(finding_candidates),
    }

    review_records = []
    for r in records:
        notes = _review_notes(r)
        if notes:
            review_records.append((r, notes))

    lines = [
        "ELF / Binary Security Review", "=" * 28, "",
        "This report presents parsed ELF hardening and dynamic-loader information. Raw ANSI-formatted checksec tables are intentionally not embedded.",
        "Missing compiler/linker hardening is normally a review consideration, not an automatic penetration-test finding. Writable/unsafe library search paths receive higher priority.",
        "", "Summary", "-------",
        f"ELF binaries analyzed:        {summary['total']}",
        f"Executables:                  {summary['executables']}",
        f"Shared libraries:             {summary['shared_libraries']}",
        f"Missing PIE (executables):    {summary['missing_pie']}",
        f"Missing stack canary:         {summary['missing_canary']}",
        f"NX disabled:                  {summary['nx_disabled']}",
        f"Partial RELRO:                {summary['partial_relro']}",
        f"No RELRO:                     {summary['no_relro']}",
        f"RPATH present:                {summary['rpath_present']}",
        f"RUNPATH present:              {summary['runpath_present']}",
        f"Writable search-path issues:  {summary['unsafe_search_paths']}",
        f"Expanded review candidates:   {len(review_records)}",
        "", "High-Interest / Review Candidates", "---------------------------------",
    ]
    if review_records:
        for r, notes in review_records[:120]:
            lines.append(f"[REVIEW] {r['path']}")
            for note in notes:
                lines.append(f"  - {note}")
        if len(review_records) > 120:
            lines.append(f"... {len(review_records) - 120} additional review entries suppressed from the summary.")
    else:
        lines.append("No hardening/search-path review candidates identified.")

    detail_records = [
        r for r in records
        if (not r["shared_object"])
        or r["search_path_concerns"]
        or r["checksec"].get("nx") == "Disabled"
        or r["checksec"].get("relro") == "Disabled"
    ]
    routine_shared = max(0, len(records) - len(detail_records))

    lines += [
        "",
        "Detailed Analysis - Executables / Higher-Interest Binaries",
        "========================================================",
        "",
        f"Detailed records shown: {len(detail_records)}",
        f"Routine shared-library records summarized only: {routine_shared}",
        "Shared libraries with common hardening observations such as Partial RELRO or no stack canary remain represented in the summary/review-candidate counts and are not expanded into repetitive multi-line sections unless another higher-interest condition exists.",
        "",
    ]
    for idx, r in enumerate(detail_records, 1):
        cs = r["checksec"]
        dyn = r["dynamic"]
        lines += [
            f"Binary {idx} of {len(detail_records)}", "-" * (12 + len(str(idx)) + len(str(len(detail_records)))),
            f"Path:         {r['path']}",
            f"File:         {r['file']}",
            f"Interpreter:  {r['interpreter'] or 'N/A / not identified'}",
            "", "Security Protections", "--------------------",
            f"RELRO:            {cs.get('relro')}",
            f"Stack Canary:     {cs.get('canary')}",
            f"NX:               {cs.get('nx')}",
            f"PIE:              {cs.get('pie')}",
            f"FORTIFY:          {cs.get('fortify')}",
            f"Fortified:        {cs.get('fortified') if cs.get('fortified') is not None else 'Unknown'}",
            f"Fortifiable:      {cs.get('fortifiable') if cs.get('fortifiable') is not None else 'Unknown'}",
            f"Symbols:          {cs.get('symbols')}",
            "", "Library Search Paths", "--------------------",
            "RPATH:",
        ]
        lines += [f"  {x if x else '<empty: current working directory>'}" for x in dyn.get("rpath", [])] or ["  None"]
        lines.append("RUNPATH:")
        lines += [f"  {x if x else '<empty: current working directory>'}" for x in dyn.get("runpath", [])] or ["  None"]
        if r["search_path_concerns"]:
            lines += ["", "Security Notes", "--------------"]
            for item in r["search_path_concerns"]:
                marker = "HIGH INTEREST" if item["finding_candidate"] else "REVIEW"
                lines.append(f"[{marker}] {item['concern']}")
        lines += ["", "Dynamic Dependencies", "--------------------"]
        deps = dyn.get("needed", [])
        lines += [f"  {x}" for x in deps[:60]] or ["  None identified"]
        if len(deps) > 60:
            lines.append(f"  ... {len(deps) - 60} additional dependencies suppressed.")
        lines.append("")

    if not records:
        lines += ["No changed ELF binaries were identified within tracked installation paths.", ""]

    write_text(report_path(output_dir, "binary_security_review.txt"), "\n".join(lines))
    return {"elf_files": records, "rpath_candidates": rpath_candidates, "finding_candidates": finding_candidates, "summary": summary}
