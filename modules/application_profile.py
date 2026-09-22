from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
import struct
from typing import Any

from .common import command_exists, report_path, run_cmd, working_dir, write_json, write_text
from .app_scope import path_within_scope

EVIDENCE_LIMIT = 30
MAX_MAGIC_READ = 4096
MAX_BINARY_HEADER_OFFSET = 16 * 1024 * 1024
MAX_OPTIONAL_HEADER_SIZE = 4096


TECHNOLOGIES: dict[str, dict[str, Any]] = {
    "Electron / Chromium": {
        "kind": "framework",
        "guidance": [
            "Inspect app.asar/preload scripts and Electron BrowserWindow settings such as contextIsolation, sandbox, nodeIntegration, and webSecurity.",
            "Review custom URL protocols, navigation/window-open handlers, IPC channels, renderer-to-main trust boundaries, and exposed Node.js APIs.",
            "Validate Chromium profile storage (Cookies, Login Data, Local Storage, IndexedDB, and LevelDB) and the application update mechanism.",
        ],
        "runtime_focus": [
            "Observe Electron/Chromium child-process creation, renderer/helper processes, profile storage, and update activity.",
            "Correlate renderer/main-process network connections and privileged helper launches.",
        ],
        "ipc_focus": [
            "Review Electron IPC/preload bridges and any local Unix-socket or D-Bus helpers used outside the renderer sandbox.",
        ],
    },
    "Java / JVM": {
        "kind": "framework",
        "guidance": [
            "Inspect JAR/WAR manifests, class paths, bundled JVMs, JNI libraries, serialized input handling, and process-launch behavior.",
            "Review trust stores, keystores, TLS settings, Java preferences, logging configuration, and update/download verification.",
        ],
        "runtime_focus": ["Observe JVM child processes, JNI/native-library loading, temporary files, and external command execution."],
        "ipc_focus": ["Identify local sockets/RMI/D-Bus/native helpers and validate caller authorization across privilege boundaries."],
    },
    "Python": {
        "kind": "framework",
        "guidance": [
            "Identify bundled source/bytecode, PyInstaller or other frozen-runtime artifacts, import paths, writable module locations, and native extensions.",
            "Review subprocess/shell use, temporary-file handling, deserialization, local configuration/secrets, and certificate bundles.",
        ],
        "runtime_focus": ["Observe Python child processes, subprocess/shell execution, runtime imports, and file access."],
        "ipc_focus": ["Validate authorization independently for local sockets/FIFOs/D-Bus used by Python components or privileged helpers."],
    },
    "Qt": {
        "kind": "framework",
        "guidance": [
            "Review Qt plugins, platform plugins, QML/resources, writable plugin/search paths, settings storage, and helper-process execution.",
            "Inspect QtNetwork/TLS behavior, custom URL handlers, local sockets, D-Bus integration, and update/download verification where present.",
        ],
        "runtime_focus": ["Observe Qt plugin/library loading, helper processes, settings/cache writes, and QtNetwork connections."],
        "ipc_focus": ["Review QLocalSocket/Unix-socket and QtDBus interfaces for peer/caller authorization and privileged helper boundaries."],
    },
    ".NET / Mono": {
        "kind": "framework",
        "guidance": [
            "Inspect assemblies, .deps.json/.runtimeconfig.json files, bundled CoreCLR/Mono runtimes, P/Invoke libraries, and application configuration.",
            "Review deserialization, certificate validation, secret storage, update channels, and writable assembly/probing paths.",
        ],
        "runtime_focus": ["Observe CoreCLR/Mono child processes, native P/Invoke loads, configuration access, and external command execution."],
        "ipc_focus": ["Review named/Unix sockets, D-Bus/native helpers, and any privileged broker used by managed components."],
    },
    "Native ELF": {
        "kind": "supporting",
        "guidance": [
            "Use binary_security_review.txt for PIE, NX, RELRO, canaries, RPATH/RUNPATH, interpreter, dependency, and writable library-path analysis.",
            "Correlate privileged helpers, Linux capabilities, SUID/SGID bits, service execution, configuration ownership, and runtime-loaded libraries.",
        ],
        "runtime_focus": ["Observe child processes, library loading, privileged execution, and runtime paths for native components."],
        "ipc_focus": ["Correlate native privileged services/helpers with local sockets, D-Bus, FIFOs, and filesystem IPC permissions."],
    },
    "Snap": {
        "kind": "packaging",
        "guidance": [
            "Review meta/snap.yaml, confinement mode, interfaces/plugs/slots, daemon definitions, hooks, layouts, and classic-confinement use.",
            "Confirm granted interfaces with snap connections and inspect application data under ~/snap and /var/snap where assessment scope permits.",
        ],
        "runtime_focus": ["Correlate observed behavior with Snap confinement and granted interfaces."],
        "ipc_focus": ["Review socket/D-Bus access granted by Snap interfaces and any classic-confinement implications."],
    },
    "Flatpak": {
        "kind": "packaging",
        "guidance": [
            "Review metadata permissions/finish-args, filesystem and device access, sockets, D-Bus names, portals, environment overrides, and persistent data.",
            "Confirm effective permissions with flatpak info --show-permissions and inspect remotes/update trust configuration.",
        ],
        "runtime_focus": ["Correlate observed behavior with Flatpak permissions, portals, filesystem access, and network settings."],
        "ipc_focus": ["Review D-Bus ownership/talk permissions, portals, and sockets exposed by Flatpak finish-args."],
    },
}


def _iter_files(paths: set[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        try:
            if path.is_file():
                files.add(path)
            elif path.is_dir():
                for item in path.rglob("*"):
                    if item.is_file():
                        files.add(item)
        except (OSError, PermissionError):
            continue
    return sorted(files, key=str)


def _add(signals: dict[str, list[dict[str, Any]]], technology: str, path: Path, indicator: str, weight: int) -> None:
    if len(signals[technology]) >= EVIDENCE_LIMIT:
        return
    record = {"path": str(path), "indicator": indicator, "weight": weight}
    # Avoid exact duplicates while still allowing multiple distinct files to contribute.
    if record not in signals[technology]:
        signals[technology].append(record)


def _file_magic(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(MAX_MAGIC_READ)
    except OSError:
        return b""


def _is_managed_pe(path: Path) -> bool:
    """Return True only when a PE file has a non-empty CLI header directory."""
    try:
        with path.open("rb") as handle:
            dos = handle.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return False
            pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
            if pe_offset < 64 or pe_offset > MAX_BINARY_HEADER_OFFSET:
                return False
            handle.seek(pe_offset)
            pe_header = handle.read(24)
            if len(pe_header) != 24 or pe_header[:4] != b"PE\0\0":
                return False
            optional_size = struct.unpack_from("<H", pe_header, 20)[0]
            if optional_size < 120 or optional_size > MAX_OPTIONAL_HEADER_SIZE:
                return False
            optional = handle.read(optional_size)
    except (OSError, struct.error):
        return False

    try:
        magic = struct.unpack_from("<H", optional, 0)[0]
        if magic == 0x10B:
            directory_offset, count_offset = 96, 92
        elif magic == 0x20B:
            directory_offset, count_offset = 112, 108
        else:
            return False
        directory_count = struct.unpack_from("<I", optional, count_offset)[0]
        cli_offset = directory_offset + (14 * 8)
        if directory_count <= 14 or cli_offset + 8 > len(optional):
            return False
        cli_rva, cli_size = struct.unpack_from("<II", optional, cli_offset)
        return cli_rva != 0 and cli_size != 0
    except struct.error:
        return False


def _version_hints(technology: str, evidence: list[dict[str, Any]]) -> list[str]:
    text = "\n".join(f"{item['path']} {item['indicator']}" for item in evidence)
    hints: set[str] = set()
    if technology == "Qt":
        for major in re.findall(r"(?:libQt|Qt)([5-7])", text, re.I):
            hints.add(f"Qt {major}.x")
    elif technology == "Python":
        for major, minor in re.findall(r"(?:libpython|python)([23])\.?([0-9]{1,2})?", text, re.I):
            hints.add(f"Python {major}{'.' + minor if minor else '.x'}")
    elif technology == ".NET / Mono":
        if re.search(r"coreclr|hostfxr|runtimeconfig", text, re.I):
            hints.add(".NET / CoreCLR")
        if re.search(r"(?:^|[/\\])mono(?:$|[/\\. ])", text, re.I):
            hints.add("Mono")
    elif technology == "Java / JVM":
        if re.search(r"libjvm|[/\\](?:jre|jdk)[/\\]", text, re.I):
            hints.add("Bundled JVM")
    elif technology == "Electron / Chromium":
        for version in re.findall(r"electron[-_/ ]v?(\d+(?:\.\d+){1,3})", text, re.I):
            hints.add(f"Electron {version}")
    return sorted(hints)


def _confidence(evidence: list[dict[str, Any]]) -> tuple[int, str, int, int]:
    score = sum(int(item["weight"]) for item in evidence)
    max_weight = max((int(item["weight"]) for item in evidence), default=0)
    diversity = len({str(item["indicator"]) for item in evidence})
    # HIGH requires either one definitive/strong marker or multiple independent
    # medium-strength indicators. Repetition of a weak source-file indicator is
    # useful evidence but cannot become HIGH merely through volume.
    high = max_weight >= 6 or (score >= 8 and max_weight >= 3 and diversity >= 2)
    confidence = "HIGH" if high else "MEDIUM" if score >= 3 else "LOW"
    return score, confidence, max_weight, diversity


def _primary_sort_key(item: dict[str, Any]) -> tuple[int, int, int, int, str]:
    confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(item.get("confidence")), 0)
    return (
        confidence_rank,
        int(item.get("max_weight", 0)),
        int(item.get("evidence_diversity", 0)),
        int(item.get("score", 0)),
        str(item.get("technology", "")),
    )


def load_machine_profile(output_dir: Path) -> dict[str, Any]:
    path = working_dir(output_dir) / "application_profile.json"
    if not path.is_file():
        return {}
    try:
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def profile_application(
    output_dir: Path,
    diff: dict[str, Any] | None = None,
    installer_data: dict[str, Any] | None = None,
    extra_roots: list[Path] | None = None,
) -> dict[str, Any]:
    """Identify application technologies without importing or executing target code."""
    diff = diff or {}
    installer_data = installer_data or {}
    differential_roots = {Path(p) for p in (*diff.get("files_added", []), *diff.get("files_changed", []))}
    scoped_roots = [Path(p) for p in (extra_roots or [])]
    # Once application roots are known, unrelated desktop/profile churn must not
    # influence technology classification. Without scope we retain legacy behavior.
    if scoped_roots:
        differential_roots = {path for path in differential_roots if path_within_scope(path, scoped_roots)}
    roots: set[Path] = set(scoped_roots)
    roots.update(differential_roots)
    extracted_root = installer_data.get("extracted_root")
    if extracted_root and not diff:
        roots.add(Path(extracted_root))
    elif extracted_root and not differential_roots and not scoped_roots:
        roots.add(Path(extracted_root))

    signals: dict[str, list[dict[str, Any]]] = defaultdict(list)
    package_permissions: list[dict[str, Any]] = []
    package_type = str(installer_data.get("type") or "unknown")
    installer_path = Path(str(installer_data.get("path") or "installer"))
    if package_type == "snap":
        _add(signals, "Snap", installer_path, "Snap package format", 10)
    elif package_type == "flatpak":
        _add(signals, "Flatpak", installer_path, "Flatpak package/reference format", 10)

    for entry in diff.get("snap_packages_added", []):
        name = entry.split()[0] if entry.split() else entry
        _add(signals, "Snap", Path(f"[installed snap]/{name}"), "Snap inventory addition", 10)
        if name and command_exists("snap"):
            result = run_cmd(["snap", "connections", name], timeout=30)
            package_permissions.append({"format": "Snap", "application": name, "detail": result["stdout"].strip() if result["returncode"] == 0 else result["stderr"].strip()})
    for entry in diff.get("flatpak_packages_added", []):
        app_id = entry.split("\t", 1)[0].split()[0] if entry.strip() else entry
        _add(signals, "Flatpak", Path(f"[installed flatpak]/{app_id}"), "Flatpak inventory addition", 10)
        if app_id and command_exists("flatpak"):
            permissions = run_cmd(["flatpak", "info", "--show-permissions", app_id], timeout=30)
            metadata = run_cmd(["flatpak", "info", "--show-metadata", app_id], timeout=30)
            detail = "\n".join(x for x in (permissions["stdout"].strip(), metadata["stdout"].strip()) if x)
            package_permissions.append({"format": "Flatpak", "application": app_id, "detail": detail or (permissions["stderr"] or metadata["stderr"]).strip()})

    files = _iter_files(roots)
    extracted_available = bool(extracted_root and Path(extracted_root).is_dir())
    virtual_members = [] if differential_roots or extracted_available else [str(name) for name in installer_data.get("member_paths", [])]
    for member in virtual_members:
        virtual = Path(f"[archive]/{member.lstrip('/')}")
        lower = member.lower()
        if lower.endswith("app.asar") or "chrome-sandbox" in lower:
            _add(signals, "Electron / Chromium", virtual, "Archive member indicates Electron/Chromium", 5)
        if lower.endswith((".jar", ".war", ".ear")) or "libjvm.so" in lower:
            _add(signals, "Java / JVM", virtual, "Archive member indicates Java/JVM", 3)
        if lower.endswith((".py", ".pyc")) or "site-packages/" in lower or "libpython" in lower:
            _add(signals, "Python", virtual, "Archive member indicates Python", 2)
        if lower.endswith((".runtimeconfig.json", ".deps.json")) or "libcoreclr.so" in lower:
            _add(signals, ".NET / Mono", virtual, "Archive member indicates .NET/Mono", 5)
        if re.search(r"(?:^|/)(?:lib)?qt[5-7].*\.so", lower) or "/qml/" in lower or "/plugins/platforms/" in lower:
            _add(signals, "Qt", virtual, "Archive member indicates Qt", 5)
        if lower.endswith("meta/snap.yaml"):
            _add(signals, "Snap", virtual, "Archive includes Snap metadata", 8)

    for path in files:
        name = path.name.lower()
        text = str(path).lower()
        suffix = path.suffix.lower()

        if name == "app.asar":
            _add(signals, "Electron / Chromium", path, "Electron app.asar bundle", 8)
        elif name in {"chrome-sandbox", "resources.pak", "icudtl.dat", "snapshot_blob.bin", "v8_context_snapshot.bin"}:
            _add(signals, "Electron / Chromium", path, f"Chromium runtime artifact: {name}", 3)
        elif any(part in text for part in ("/local storage/", "/indexeddb/", "/session storage/")):
            _add(signals, "Electron / Chromium", path, "Chromium profile-storage path", 2)

        if suffix in {".jar", ".war", ".ear"}:
            _add(signals, "Java / JVM", path, f"JVM archive ({suffix})", 3)
        elif name in {"libjvm.so", "java", "javaw"} or "/jre/" in text or "/jdk/" in text:
            _add(signals, "Java / JVM", path, "Bundled JVM/runtime artifact", 5)

        if suffix in {".py", ".pyc", ".pyo"} or "site-packages" in text or "dist-packages" in text:
            _add(signals, "Python", path, "Python source/bytecode/package path", 1)
        elif name in {"base_library.zip", "python3.zip"} or name.startswith("libpython"):
            _add(signals, "Python", path, "Bundled/frozen Python runtime artifact", 5)

        if name.endswith((".runtimeconfig.json", ".deps.json")) or name in {"libcoreclr.so", "libhostfxr.so", "mono"}:
            _add(signals, ".NET / Mono", path, ".NET/Mono runtime metadata or library", 6)
        elif suffix in {".dll", ".exe"} and _is_managed_pe(path):
            _add(signals, ".NET / Mono", path, "Managed PE with CLI header", 3)

        if re.match(r"libqt[5-7].*\.so(?:\..*)?$", name, re.I):
            _add(signals, "Qt", path, "Qt shared library/runtime", 7)
        elif name in {"qmake", "qt.conf"} or "/plugins/platforms/" in text or "/qml/" in text:
            _add(signals, "Qt", path, "Qt runtime/plugin/QML artifact", 4)

        if text.endswith("/meta/snap.yaml") or "/snap/" in text or "/var/snap/" in text:
            _add(signals, "Snap", path, "Snap metadata/data path", 5)
        if name in {".flatpak-info", "metadata"} and ("flatpak" in text or "/app/" in text):
            _add(signals, "Flatpak", path, "Flatpak metadata path", 5)

        if _file_magic(path).startswith(b"\x7fELF"):
            _add(signals, "Native ELF", path, "ELF file signature", 2)

    technologies: list[dict[str, Any]] = []
    for technology, evidence in signals.items():
        score, confidence, max_weight, diversity = _confidence(evidence)
        meta = TECHNOLOGIES[technology]
        technologies.append({
            "technology": technology,
            "confidence": confidence,
            "score": score,
            "max_weight": max_weight,
            "evidence_diversity": diversity,
            "kind": meta["kind"],
            "evidence": evidence,
            "version_hints": _version_hints(technology, evidence),
            "guidance": meta["guidance"],
            "runtime_focus": meta["runtime_focus"],
            "ipc_focus": meta["ipc_focus"],
        })

    technologies.sort(key=lambda item: (-{"HIGH": 3, "MEDIUM": 2, "LOW": 1}[item["confidence"]], -item["max_weight"], -item["evidence_diversity"], -item["score"], item["technology"]))
    frameworks = [item for item in technologies if item["kind"] == "framework" and item["confidence"] in {"HIGH", "MEDIUM"}]
    primary = max(frameworks, key=_primary_sort_key)["technology"] if frameworks else None
    supporting = [
        item["technology"] for item in technologies
        if item["technology"] != primary and item["kind"] != "packaging" and item["confidence"] in {"HIGH", "MEDIUM"}
    ]
    packaging = [item["technology"] for item in technologies if item["kind"] == "packaging" and item["confidence"] in {"HIGH", "MEDIUM"}]

    data = {
        "schema_version": 1,
        "package_type": package_type,
        "files_considered": len(files),
        "archive_members_considered": len(virtual_members),
        "primary_technology": primary,
        "supporting_technologies": supporting,
        "packaging_context": packaging,
        "technologies": technologies,
        "package_permissions": package_permissions,
        "analysis_roots": [str(path) for path in sorted(set(scoped_roots), key=str)],
    }

    lines = [
        "Application / Framework Profile", "=" * 31, "",
        "This report fingerprints packaging and application technologies without importing or executing target code. Detection confidence reflects static/differential evidence strength, not vulnerability severity.",
        "", "Summary", "-------",
        f"Installer/package type: {package_type}",
        f"Application files/archive members considered: {len(files) + len(virtual_members)}",
        f"Technologies identified: {len(technologies)}",
        f"Primary technology: {primary or 'not confidently identified'}",
        f"Supporting technologies: {', '.join(supporting) if supporting else 'none identified'}",
        f"Packaging/container context: {', '.join(packaging) if packaging else 'none identified'}",
        f"Application scope roots: {', '.join(str(path) for path in sorted(set(scoped_roots), key=str)) if scoped_roots else 'not explicitly scoped'}", "",
        "Detection Score Guidance", "------------------------",
        "Detection Score is a technology-confidence heuristic only. It is not a vulnerability score, risk rating, or cross-technology ranking.", "",
    ]
    if technologies:
        for item in technologies:
            role = "PRIMARY" if item["technology"] == primary else "PACKAGING" if item["kind"] == "packaging" else "SUPPORTING"
            title = f"{item['technology']} [{item['confidence']} - {role}]"
            lines += [title, "-" * len(title), f"Detection score: {item['score']}"]
            if item["version_hints"]:
                lines.append(f"Version/runtime hints: {', '.join(item['version_hints'])}")
            lines.append("Evidence:")
            for evidence in item["evidence"][:10]:
                lines.append(f"- {evidence['path']} ({evidence['indicator']})")
            if len(item["evidence"]) > 10:
                lines.append(f"- ... {len(item['evidence']) - 10} additional indicators suppressed.")
            lines += ["Testing guidance:"] + [f"- {entry}" for entry in item["guidance"]]
            lines += ["Runtime focus:"] + [f"- {entry}" for entry in item["runtime_focus"]]
            lines += ["IPC focus:"] + [f"- {entry}" for entry in item["ipc_focus"]] + [""]
    else:
        lines += [
            "No supported application framework was identified with useful confidence.",
            "Continue with the generic ELF, permissions, storage, network, IPC, update, and runtime reviews.", "",
        ]

    lines += ["Container Package Permissions", "-----------------------------"]
    if package_permissions:
        for item in package_permissions:
            lines += [f"[{item['format']}] {item['application']}", item["detail"][:20000] or "Permission details unavailable.", ""]
    else:
        lines += ["No newly installed Snap/Flatpak application required an effective-permission inventory.", ""]

    write_text(report_path(output_dir, "application_profile.txt"), "\n".join(lines))
    write_json(working_dir(output_dir) / "application_profile.json", data)
    return data
