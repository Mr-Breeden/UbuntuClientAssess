from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .app_scope import path_within_scope
from .common import command_exists, report_path, run_cmd, sanitize_url, write_text

MAX_TEXT_SIZE = 4 * 1024 * 1024
MAX_BINARY_SIZE = 100 * 1024 * 1024
URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>]+", re.I)
HOST_PORT_RE = re.compile(r"(?<![\w.-])((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3}|localhost):([1-9]\d{0,4})(?!\d)", re.I)
PROXY_RE = re.compile(r"(?i)\b(?:https?_proxy|all_proxy|no_proxy|proxy[_-]?(?:url|host|port|server)|pac[_-]?url)\b")
TLS_RE = re.compile(r"(?i)\b(?:tls|ssl|certificate|cert(?:ificate)?[_-]?pin|pinned[_-]?key|ca[_-]?(?:file|path|bundle)|trust[_-]?store)\b")
CONFIG_SUFFIXES = {".conf", ".config", ".ini", ".json", ".yaml", ".yml", ".xml", ".toml", ".properties", ".env", ".txt", ".desktop", ".service"}
SCRIPT_SUFFIXES = {".sh", ".run", ".js", ".mjs", ".cjs", ".py"}
EXCLUDED_PARTS = {
    "node_modules", "site-packages", "dist-packages", "docs", "documentation",
    "sboms", "__pycache__", "test", "tests", "examples", "botocore", "boto3", "locales", "translations",
}
EXCLUDED_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
THIRD_PARTY_NAMES = {"all-min.js", "jstree.js", "jquery.jscrollpane.js"}
REFERENCE_HOSTS = {
    "example.com", "example.net", "example.org", "iana.org", "ietf.org",
    "ns.adobe.com", "peps.python.org", "readthedocs.io", "schema.org",
    "unicode.org", "w3.org", "anglebug.com", "crbug.com", "registry.npmjs.org",
    "chromium.googlesource.com", "qt.io", "cairographics.org", "brynosaurus.com",
    "freedesktop.org",
}
CERT_ROOTS = ("/etc/ssl/certs/", "/usr/local/share/ca-certificates/", "/etc/pki/", "/etc/ca-certificates/")

# Socket rows from ``ss`` expose only the short process ``comm`` plus volatile
# PIDs. Snapshot normalization deliberately removes those PIDs, so a generic
# interpreter name cannot safely prove that a socket belongs to the assessed
# application. A scoped Python application, for example, must not inherit every
# listener owned by an unrelated ``python3`` process on the host. Runtime
# observation retains PID/argv context and can make the stronger attribution.
GENERIC_SOCKET_OWNER_NAMES = {
    "python", "python2", "python3", "pypy", "pypy3",
    "java", "node", "nodejs", "ruby", "perl",
    "sh", "bash", "dash", "zsh", "ksh", "fish",
}


def _local_listener_host(line: str) -> str | None:
    parts = line.split()
    # `ss -H -lntupn` renders: netid state recv-q send-q local peer ...
    if len(parts) < 5:
        return None
    endpoint = parts[4]
    if endpoint.startswith("[") and "]" in endpoint:
        host = endpoint[1:endpoint.index("]")]
    elif ":" in endpoint:
        host = endpoint.rsplit(":", 1)[0]
    else:
        return None
    return host.split("%", 1)[0]


def _is_externally_bound(line: str) -> bool:
    host = _local_listener_host(line)
    if not host:
        return False
    if host in {"*", "0.0.0.0", "::"}:
        return True
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Named/non-IP bind targets should be reviewed unless they are the
        # conventional localhost name.
        return host.lower() not in {"localhost", "localhost.localdomain"}


def _process_names(line: str) -> list[str]:
    return sorted(set(re.findall(r'\(\("([^"\\]+)"', line)))


def _application_process_names(diff: dict[str, Any], extra_roots: list[Path] | None = None) -> set[str]:
    """Identify application process names for clean installs and upgrade/reinstall runs."""
    roots: set[str] = set()
    executable_names: set[str] = set()
    post_fs = diff.get("post_filesystem", {})
    changed_paths = sorted(set(diff.get("files_added", [])) | set(diff.get("files_changed", [])))
    for raw in changed_paths:
        path = Path(raw)
        parts = path.parts
        if len(parts) >= 3 and parts[1] == "opt":
            roots.add(str(Path("/opt") / parts[2]))
        elif len(parts) >= 4 and parts[1:3] in {("usr", "lib"), ("var", "lib"), ("var", "opt")}:
            roots.add(str(Path("/") / parts[1] / parts[2] / parts[3]))
        if str(path.parent) in {"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}:
            mode = str(post_fs.get(raw, {}).get("mode", ""))
            if "x" in mode:
                executable_names.add(path.name)
    for root in extra_roots or []:
        try:
            roots.add(str(root.resolve(strict=False)))
        except OSError:
            roots.add(str(root))

    names: set[str] = set()
    # Use all post-snapshot processes, not only newly added processes. During an
    # upgrade/reinstall the application process may exist in both snapshots even
    # though its executable/configuration and network behavior changed.
    process_lines = diff.get("post_processes", []) or diff.get("processes_added", [])
    for line in process_lines:
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue
        comm = parts[2]
        if comm in executable_names or (roots and any(root in line for root in roots)):
            # A generic interpreter/runtime is not a unique socket owner. The
            # process line can establish that *one* scoped process uses it, but
            # an ``ss`` row naming only ``python3``/``java``/etc. cannot tell
            # that process apart from unrelated host workloads. Leave those
            # rows unattributed here; Guided Runtime Observation can correlate
            # them by PID and application argv/path.
            if comm.casefold() not in GENERIC_SOCKET_OWNER_NAMES:
                names.add(comm)
    return names

def _excluded_discovery_path(path: Path) -> bool:
    lower_parts = {part.lower() for part in path.parts}
    # Exclude known dependency/runtime trees, but do not suppress a generic
    # application-owned `lib/` directory because it may contain real client
    # configuration or endpoints.
    runtime_parts = {"_internal", "lib-dynload", "jsmodules"}
    dependency_parts = {"dukpy", "cffi", "setuptools", "tldextract", "keyring", "cryptography", "docutils"}
    lower_text = str(path).lower()
    return path.name.lower() in EXCLUDED_NAMES | THIRD_PARTY_NAMES or bool(
        lower_parts.intersection(EXCLUDED_PARTS | runtime_parts)
        or ("lib" in lower_parts and lower_parts.intersection(dependency_parts))
        or "/ui/build/static/" in lower_text
        or "/lib/share/glib-2.0/schemas/" in lower_text
        or any(part.endswith(".dist-info") or part.endswith(".egg-info") for part in lower_parts)
    )


def _bundled_binary_dependency(path: Path) -> bool:
    lower_parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return (name.endswith(".so") or ".so." in name) and bool(
        lower_parts.intersection({"_internal", "lib-dynload"})
    )


def _reference_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == entry or host.endswith(f".{entry}") for entry in REFERENCE_HOSTS)


def _reference_url(raw: str) -> bool:
    if any(token in raw for token in ("%s", "%d", "${", "{{", "<host>")):
        return True
    try:
        parts = urlsplit(raw)
    except ValueError:
        return True
    host = parts.hostname or ""
    path = parts.path.lower()
    if _reference_host(host):
        return True
    host = host.lower()
    if host == "github.com" and (path.endswith("/issues") or "/issues/" in path):
        return True
    if (host == "go.dev" or host.endswith(".go.dev")) and "/issue/" in path:
        return True
    if (host == "python.org" or host.endswith(".python.org")) and (path.startswith("/psf/license") or path.startswith("/pep-")):
        return True
    if host == "web.mit.edu" and path.startswith("/kerberos/dist"):
        return True
    if host.startswith("docs.") or host == "docs.github.com":
        return True
    if host == "github.com" and path.rstrip("/") in {"/llvm/llvm-project"}:
        return True
    return any(marker in path for marker in (
        "/license/", "/licenses/", "/documentation/", "/docs/", "/commit/",
        "/blob/", "/show_bug", "/support/", "/standards/", "/projects/", "/guides/",
    )) or path.endswith(("license", "license.txt", "license.md"))


def _configuration_indicator_line(path: Path, line: str) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in CONFIG_SUFFIXES or name in {"config", "preferences", "sources.list"}:
        return bool(re.search(r"[:=]|<[^>]+>", line))
    if path.suffix.lower() in SCRIPT_SUFFIXES:
        return "=" in line
    return False


def _text(path: Path) -> str:
    try:
        if not path.is_file() or path.stat().st_size > MAX_TEXT_SIZE:
            return ""
        if _excluded_discovery_path(path) or path.name.lower().endswith(".min.js"):
            return ""
        if path.suffix.lower() not in CONFIG_SUFFIXES | SCRIPT_SUFFIXES and path.name.lower() not in {"config", "preferences", "sources.list"}:
            return ""
        data = path.read_bytes()
        if b"\x00" in data[:4096] and path.suffix.lower() not in CONFIG_SUFFIXES:
            return ""
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _strings(path: Path) -> str:
    try:
        if _excluded_discovery_path(path) or _bundled_binary_dependency(path) or not command_exists("strings") or not path.is_file() or path.stat().st_size > MAX_BINARY_SIZE:
            return ""
        with path.open("rb") as handle:
            if handle.read(4) != b"\x7fELF" and path.suffix.lower() not in {".so", ".bin"}:
                return ""
    except OSError:
        return ""
    result = run_cmd(["strings", "-a", "-n", "7", str(path)], timeout=20)
    return result["stdout"][:8 * 1024 * 1024] if result["returncode"] == 0 else ""


def _discover_endpoints(paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    endpoints: list[dict[str, Any]] = []
    proxies: list[dict[str, Any]] = []
    tls: list[dict[str, Any]] = []
    endpoint_by_value: dict[str, dict[str, Any]] = {}
    seen_proxy: set[tuple[str, str]] = set()
    seen_tls: set[tuple[str, str]] = set()
    binary_count = 0
    binary_bytes = 0
    for path in paths:
        source_kind = "configuration/text"
        content = _text(path)
        if not content:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            if binary_count >= 120 or binary_bytes + size > 512 * 1024 * 1024:
                continue
            content = _strings(path)
            source_kind = "binary strings"
            if content:
                binary_count += 1
                binary_bytes += size
        if not content:
            continue
        in_block_comment = False
        for line_no, line in enumerate(content.splitlines(), 1):
            if path.suffix.lower() in SCRIPT_SUFFIXES:
                stripped = line.lstrip()
                if in_block_comment:
                    if "*/" in stripped:
                        in_block_comment = False
                    continue
                if stripped.startswith("/*"):
                    in_block_comment = "*/" not in stripped
                    continue
                if stripped.startswith(("//", "*")):
                    continue
            for raw in URL_RE.findall(line):
                url = sanitize_url(raw)
                if _reference_url(url):
                    continue
                evidence = {"path": str(path), "line": line_no, "source": source_kind}
                if url not in endpoint_by_value:
                    item = {"path": str(path), "line": line_no, "endpoint": url, "source": source_kind, "evidence": [evidence]}
                    endpoint_by_value[url] = item
                    endpoints.append(item)
                elif evidence not in endpoint_by_value[url]["evidence"]:
                    endpoint_by_value[url]["evidence"].append(evidence)
            host_ports = [] if path.suffix.lower() in SCRIPT_SUFFIXES else HOST_PORT_RE.findall(line)
            for host, port in host_ports:
                if _reference_host(host):
                    continue
                endpoint = f"{host}:{port}"
                evidence = {"path": str(path), "line": line_no, "source": source_kind}
                if endpoint not in endpoint_by_value:
                    item = {"path": str(path), "line": line_no, "endpoint": endpoint, "source": source_kind, "evidence": [evidence]}
                    endpoint_by_value[endpoint] = item
                    endpoints.append(item)
                elif evidence not in endpoint_by_value[endpoint]["evidence"]:
                    endpoint_by_value[endpoint]["evidence"].append(evidence)
            if source_kind == "configuration/text" and _configuration_indicator_line(path, line):
                proxy_match = PROXY_RE.search(line)
                if proxy_match:
                    indicator = proxy_match.group(0).lower()
                    key = (str(path), indicator)
                    if key not in seen_proxy:
                        seen_proxy.add(key)
                        proxies.append({"path": str(path), "line": line_no, "indicator": proxy_match.group(0)})
                tls_match = TLS_RE.search(line)
                if tls_match:
                    indicator = tls_match.group(0).lower()
                    key = (str(path), indicator)
                    if key not in seen_tls:
                        seen_tls.add(key)
                        tls.append({"path": str(path), "line": line_no, "indicator": tls_match.group(0)})
    return endpoints[:200], proxies[:100], tls[:100]


def review_network(diff: dict[str, Any], output_dir: Path, extra_roots: list[Path] | None = None) -> dict[str, Any]:
    added = diff.get("listening_sockets_added", [])
    removed = diff.get("listening_sockets_removed", [])
    connections = diff.get("network_connections_added", [])
    application_processes = _application_process_names(diff, extra_roots)
    related_connections = [line for line in connections if set(_process_names(line)).intersection(application_processes)]
    ambient_connection_count = len(connections) - len(related_connections)
    candidates: list[str] = []
    related_listener_rows: list[str] = []
    changed = sorted(set(diff.get("files_added", [])) | set(diff.get("files_changed", [])))
    scope_roots = [Path(root) for root in (extra_roots or [])]
    discovery_paths = {
        Path(path) for path in changed
        if Path(path).is_file() and (not scope_roots or path_within_scope(Path(path), scope_roots))
    }
    for root in scope_roots:
        try:
            if root.is_file():
                discovery_paths.add(root)
            elif root.is_dir():
                discovery_paths.update(path for path in root.rglob("*") if path.is_file())
        except (OSError, PermissionError):
            continue
    changed_paths = sorted(discovery_paths, key=str)
    endpoints, proxy_indicators, tls_indicators = _discover_endpoints(changed_paths)
    tls_endpoints = [item for item in endpoints if item["endpoint"].lower().startswith(("https://", "wss://")) or item["endpoint"].endswith(":443")]
    cleartext_endpoints = [item for item in endpoints if item["endpoint"].lower().startswith(("http://", "ws://", "ftp://"))]
    certificate_changes = [path for path in changed if path.startswith(CERT_ROOTS) or Path(path).suffix.lower() in {".crt", ".cer", ".p12", ".pfx", ".jks"}]

    lines = [
        "Network and Application Communication Review", "=" * 44, "",
        "This report combines differential socket state with endpoint indicators from changed configuration/text files and static strings in changed ELF binaries. It does not initiate connections or execute the application.",
        "Socket inventory is normalized to reduce false positives caused only by PID/inode changes.",
        "", "Summary", "-------",
        f"New listeners:                       {len(added)}",
        f"Externally bound candidates:         {sum(1 for line in added if _is_externally_bound(line))}",
        f"Raw new network connections:          {len(connections)}",
        f"Application-correlated connections:   {len(related_connections)}",
        f"Ambient/unattributed churn suppressed: {ambient_connection_count}",
        f"Static/config endpoint indicators:   {len(endpoints)}",
        f"TLS endpoint indicators:             {len(tls_endpoints)}",
        f"Cleartext endpoint indicators:       {len(cleartext_endpoints)}",
        f"Proxy configuration indicators:      {len(proxy_indicators)}",
        f"Certificate/trust-store changes:     {len(certificate_changes)}", "",
        "New Listening Sockets", "---------------------",
    ]
    if added:
        for line in added:
            exposed = _is_externally_bound(line)
            owners_list = _process_names(line)
            related = bool(set(owners_list).intersection(application_processes))
            if related:
                related_listener_rows.append(line)
            reviewable = exposed and (related or not scope_roots)
            prefix = "[REVIEW] " if reviewable else "[UNATTRIBUTED] " if exposed else ""
            owners = ", ".join(owners_list) or "owner not exposed by ss"
            lines.append(f"{prefix}{line}\n  Process correlation: {owners}")
            if reviewable:
                candidates.append(line)
    else:
        lines.append("None observed.")

    lines += ["", "Removed Listening Sockets", "-------------------------"]
    lines += removed or ["None observed."]

    lines += ["", "Observed Application Connections", "--------------------------------"]
    if related_connections:
        for line in related_connections[:160]:
            owners = ", ".join(_process_names(line)) or "owner not exposed by ss"
            lines.append(f"{line}\n  Process correlation: {owners}")
    else:
        lines.append("No new non-listening INET connection correlated with an identified application process at snapshot time.")
    lines.append(f"Ambient/unattributed connection rows suppressed from this report: {ambient_connection_count}. Raw state remains in working snapshots.")

    lines += ["", "Discovered Endpoints", "--------------------"]
    if endpoints:
        for item in endpoints[:100]:
            marker = "[CLEARTEXT REVIEW] " if item in cleartext_endpoints else "[TLS] " if item in tls_endpoints else ""
            evidence_count = len(item.get("evidence", []))
            suffix = f"; {evidence_count - 1} additional occurrence(s) grouped" if evidence_count > 1 else ""
            lines.append(f"{marker}{item['endpoint']} - {item['path']}:{item['line']} ({item['source']}{suffix})")
        if len(endpoints) > 100:
            lines.append(f"... {len(endpoints) - 100} additional endpoint indicators suppressed.")
    else:
        lines.append("No endpoint indicators identified in prioritized changed files.")

    lines += ["", "Proxy Awareness", "---------------"]
    lines += [f"[REVIEW] {item['path']}:{item['line']} - {item['indicator']}" for item in proxy_indicators] or ["No proxy/PAC configuration indicators identified."]
    lines += ["", "TLS and Certificate Context", "---------------------------"]
    lines.append(f"TLS endpoints are listed once in Discovered Endpoints: {len(tls_endpoints)}")
    lines += [f"[TLS CONFIG] {item['path']}:{item['line']} - {item['indicator']}" for item in tls_indicators]
    lines += [f"[CERTIFICATE CHANGE] {path}" for path in certificate_changes] or ["No certificate/trust-store file changes identified."]

    lines += [
        "", "Client / Server Communication Test Guidance", "-------------------------------------------",
        "1. Map each observed/static endpoint to the owning process and user workflow; suppress third-party/bundled endpoints only after validation.",
        "2. Confirm intended listener scope, authentication, authorization, rate limiting, and input handling from local and permitted remote clients.",
        "3. Exercise direct and configured-proxy paths; verify proxy authentication, PAC handling, and no unintended proxy bypass.",
        "4. Validate TLS hostname verification, trust anchors, certificate-expiry handling, protocol/cipher policy, and pinning behavior where claimed.",
        "5. Test offline, DNS failure, connection reset, malformed response, replay, and server-error behavior without weakening the assessment host.",
        "6. Capture runtime traffic in scope to confirm whether static endpoints are actually used and whether sensitive values are protected.",
    ]
    write_text(report_path(output_dir, "network_surface_review.txt"), "\n".join(lines))
    return {
        "new_listeners": added,
        "application_correlated_listeners": related_listener_rows,
        "exposed_listener_candidates": candidates,
        "new_connections": related_connections,
        "raw_new_connections": connections,
        "endpoints": endpoints,
        "tls_endpoints": tls_endpoints,
        "cleartext_endpoint_candidates": cleartext_endpoints,
        "proxy_indicators": proxy_indicators,
        "certificate_changes": certificate_changes,
    }
