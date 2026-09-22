# UbuntuClientAssess

UbuntuClientAssess is a tester-controlled framework for assessing installable Ubuntu thick-client applications. It combines installer review, pre/post installation state capture, application-scoped static analysis, runtime correlation, guided manual validation, integrity-protected reporting, and client-safe technical export.

Current release: **2.0.6**  
Methodology: **2.4**  
Coverage catalog: **1.1**  
Security-model schema: **10**

Version 2.0.6 continues the localhost web interface introduced in 2.0.0 while retaining the terminal CLI. The GUI and CLI share the same presentation-neutral application-service layer for review state, integrity, runtime finalization, recovery, and ClientAppendix operations.

## What the framework does

A Full Assessment can:

- analyze supported installer/package formats without executing them during static inspection;
- capture a security-focused Ubuntu baseline before installation;
- pause for controlled installation, application setup, and sign-in;
- capture the post-installation state and produce an installation differential;
- review application-scoped permissions, ELF hardening/search paths, systemd services, persistence, network surface, IPC, local storage, update mechanisms, and technology context;
- build a structured security model of canonical objects, observations, relationships, and correlations;
- generate prioritized tester-review items and correlation-owned finding candidates;
- perform optional Guided Runtime Observation;
- guide manual validation through category/group-based Guided Review;
- protect generated reports and supporting state with an integrity manifest;
- recover safely from modified generated reports and interrupted state transactions; and
- create a client-safe technical `ClientAppendix/` after review completion.

UbuntuClientAssess does **not** replace tester judgment. Generated findings are candidates for validation, not final client-report conclusions.

## Authorized Use

UbuntuClientAssess is intended for authorized security testing, security research, and defensive assessment activities only.

Use this tool only on systems, applications, and environments that you own or for which you have explicit permission to test. You are responsible for ensuring that your use of the tool complies with applicable laws, regulations, contracts, and organizational policies.

The authors and contributors are not responsible for misuse of this software or for damage resulting from its use.

## Supported installer types

- `.deb` — metadata, package contents, maintainer scripts, bounded extraction, package-aware snapshot coverage, and optional framework-controlled installation.
- `.AppImage` — SquashFS identification and bounded extraction with `unsquashfs`; the AppImage is not executed during static analysis.
- `.snap` — safe SquashFS extraction, `meta/snap.yaml` review, and package/interface awareness.
- `.flatpak`, `.flatpakref`, `.flatpakrepo` — format/reference identification, repository metadata, installed inventory comparison, and effective-permission review when Flatpak tooling is available.
- `.run`, `.sh` — syntax/header review, high-interest pattern analysis, endpoint/install-path extraction, and self-extracting marker detection without execution.
- `.tar`, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`, `.tar.bz2`, `.tbz*`, `.zip`, `.7z` — bounded inventory, declared-size review, high-interest members, and unsafe/path-traversal member checks.

Non-`.deb` installers normally use a tester-controlled manual installation workflow.

For Full Assessments, post-installation scope is also learned from filesystem and process evidence. If an identified application installation root cannot be recursively read/traversed by the tester account, UbuntuClientAssess records the coverage limitation, marks affected static-analysis modules `ATTN`, and adds explicit notes to the relevant reports. A zero-result static section must not be treated as evidence that inaccessible application content contains no issues.

When protected application roots are detected, the GUI presents a **Run Privileged Collection** action. The browser never receives or stores a sudo password. UbuntuClientAssess opens a local terminal authentication flow and runs a narrowly scoped helper that inventories only the protected application roots already recorded by the assessment. The helper augments the post-install evidence, regenerates affected static analyses, refreshes the assessment manifest, and returns framework-owned artifacts to the tester account. It does not execute application content or accept arbitrary collection paths from the browser.

## Requirements and installation

Ubuntu 22.04 or 24.04 is recommended. Start from a disposable VM snapshot for Full Assessments.

The recommended setup path is:

```bash
chmod +x install_dependencies.sh
./install_dependencies.sh
source .venv/bin/activate
```

`install_dependencies.sh` installs/checks the required system packages, attempts to install the recommended/optional tools, creates the Python virtual environment, installs the Python requirements, and prints an environment-readiness summary. A normal result is `READY`; missing optional coverage tooling can result in `READY WITH REDUCED COVERAGE`. Missing required commands results in `FAILED`.

### Required system packages

These packages provide the baseline commands and libraries required for normal framework operation:

| Purpose | Packages |
| --- | --- |
| Python runtime | `python3`, `python3-pip`, `python3-venv` |
| File/package analysis | `file`, `binutils`, `dpkg`, `dpkg-dev` |
| Networking/base OS utilities | `iproute2`, `coreutils` |
| Retrieval/data handling | `git`, `curl`, `wget`, `jq`, `tree` |
| Archive handling | `unzip`, `zip`, `p7zip-full`, `tar`, `xz-utils` |
| Permission/capability analysis | `acl`, `libcap2-bin` |

### Recommended / optional coverage tools

The following packages are not all required for the framework to start, but they enable deeper or format-specific assessment coverage. If one or more are unavailable, applicable modules may have reduced depth and the setup helper reports the affected environment as reduced coverage.

| Coverage area | Packages |
| --- | --- |
| ELF / binary analysis | `elfutils`, `patchelf`, `pax-utils`, `checksec` |
| Runtime/process tracing | `strace`, `ltrace`, `lsof`, `procps`, `psmisc`, `inotify-tools` |
| Network analysis | `net-tools`, `dnsutils`, `tcpdump`, `nmap`, `socat`, `netcat-openbsd` |
| Debian/package validation | `debsums`, `apt-file`, `debsig-verify`, `debsigs` |
| Audit/system activity | `auditd`, `audispd-plugins` |
| D-Bus analysis | `dbus`, `dbus-user-session`, `libglib2.0-bin` |
| Debugging | `gdb` |
| Content/static analysis | `binwalk`, `yara`, `sqlite3` |
| Desktop integration | `desktop-file-utils`, `shared-mime-info` |
| Snap/SquashFS analysis | `squashfs-tools` |
| Signing/crypto inspection | `gnupg` |
| Flatpak analysis | `flatpak` |

The exact package lists used by the installer are maintained in `install_dependencies.sh`. The README dependency matrix is regression-checked against those lists so documentation drift is caught during the release gate.

### Environment-readiness checks

After installation, the helper validates practical capabilities rather than only package presence. Current readiness checks include:

- required commands (`python3`, `file`, `readelf`, `ss`, `dpkg`, `dpkg-deb`);
- ACL analysis (`getfacl`, `setfacl`);
- ELF analysis (`readelf`, `checksec`);
- network analysis (`ss`, `tcpdump`);
- runtime observation (`ps`, `lsof`, `inotifywait`); and
- D-Bus analysis (`busctl`, `gdbus`).

To install Python dependencies only:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

`requirements.txt` contains only Python packages; it does not replace the system-tool dependencies above. Development dependencies are installed with:

```bash
python3 -m pip install -r requirements-dev.txt
```


## Local web interface

Start the v2.0.6 browser interface with:

```bash
python3 ubuntuclientassess.py --gui
```

The web server binds to `127.0.0.1` only and uses **port 9001 by default**. A browser is opened automatically when possible. To use a different port:

```bash
python3 ubuntuclientassess.py --gui --port 8765
```

Useful web-interface options:

```text
--gui                 Start the localhost web interface
--port PORT           Override the default GUI port (9001)
--gui-root PATH       Initial assessment root (default: ./Assessments)
--no-browser          Start the server without opening a browser automatically
```

The page URL contains a random per-launch request token and state-changing API calls require the same token in a custom request header. The web server is intentionally loopback-only in v2.0.6; it is not intended to be exposed on a LAN or other network interface.

The GUI provides:

- navigable server-side folder selection for the assessment root;
- navigable installer/package selection instead of requiring a typed path;
- **New Assessment** for both Full Assessment and Installer Analysis Only modes;
- staged Full Assessment preparation through the pre-install snapshot;
- an exact `sudo apt install -y <package.deb>` command with a Copy Command action;
- a **Continue After Installation / Setup** action that captures the post-install state and completes analysis;
- assessment discovery and overview across completed, waiting, running, and failed assessments;
- a single globally selected assessment shared by Guided Review, Runtime Observation, Reports, Integrity & Recovery, and Client Appendix;
- automatic dashboard refresh after assessment jobs plus a manual Refresh action;
- Guided Review with independently scrollable queue/guidance panes, category + status filtering (including Pending-only), disposition-based queue highlighting, and tester-note updates;
- explicit `N/A` review state for Installer Analysis Only assessments instead of treating review absence as an error;
- manual Start / Stop & Save Guided Runtime Observation for completed Full Assessments;
- tester-report viewing for the selected assessment;
- assessment integrity verification;
- safe generated-report repair;
- interrupted-write recovery;
- a dedicated Client Appendix tab; and
- live staged job progress for pre/post snapshots, analysis, correlation, and finalization.

The browser never collects a sudo password or application credentials. During a GUI Full Assessment, UbuntuClientAssess pauses after the pre-install snapshot and provides a convenience installation command when the selected format has a safe generic form. For `.sh`, `.run`, AppImage, archive, or vendor-specific installers, follow the vendor-approved installation procedure and supply any required arguments outside the browser. Complete installation, first-run setup/sign-in, and the intended application exercise, then click **Installation and Setup Complete — Continue**. Installer Analysis Only can complete entirely in the browser because it does not alter the host package state.

Manual runtime collection launched from the browser does not request `sudo`. Start the observation, exercise the application for as long as needed, then choose **Stop & Save Observation**. **Cancel Observation** discards the current capture. An internal 60-minute safety limit prevents abandoned browser captures from running indefinitely. If elevated socket/process ownership visibility is needed, use the existing CLI runtime workflow or ensure the current process already has the required visibility. Automatic browser launch suppresses irrelevant child-browser/Snap/GTK diagnostic output; use `--no-browser` when you prefer to open the displayed URL manually. Filesystem browsing is intentionally separate from the configured Assessment Root: navigating in the picker does not redefine the dashboard root until you explicitly select/load a folder.

## Quick start

Interactive mode:

```bash
python3 ubuntuclientassess.py
```

Main menu:

```text
1) Start New Assessment
2) Review Completed Assessment
3) Create Client Appendix
4) Verify Assessment Integrity
5) Guided Runtime Observation
6) Exit
7) Assessment Status / Recovery
```

Typical Full Assessment sequence:

1. Revert/start a clean Ubuntu VM snapshot.
2. Run **Start New Assessment**.
3. Select Full Assessment and provide the installer/package.
4. Allow the pre-install snapshot to complete.
5. Install/configure the target application when instructed.
6. Launch it, sign in if required, and exercise representative functionality.
7. Confirm readiness for post-install capture.
8. Run Guided Runtime Observation when useful.
9. Complete Guided Review.
10. Verify assessment integrity.
11. Create the Client Appendix.
12. Use the tester's final penetration-test report as the authoritative client conclusion.

## Assessment modes

### Full Assessment

Full Assessment performs pre-install capture, installation/configuration, post-install capture, differential analysis, security correlation, Guided Review preparation, and reporting.

Example non-interactive parameters for a Debian package:

```bash
python3 ubuntuclientassess.py \
  --assessment-name "Example Assessment" \
  --installer ./application.deb \
  --output ./Assessments \
  --auto-install-deb
```

By default, a Debian package should not already be installed at baseline. Use `--allow-installed-deb` only for an intentional upgrade/reinstall scenario.

### Installer Analysis Only

Static package/installer analysis without the full pre/install/post workflow:

```bash
python3 ubuntuclientassess.py \
  --assessment-name "Example Assessment" \
  --installer ./application.deb \
  --output ./Assessments \
  --installer-analysis-only
```

## Application scope controls

UbuntuClientAssess derives application scope from package metadata, installed paths, desktop entries, services, runtime ownership, and observed state. Manual scope controls are available when metadata is incomplete:

```text
--application-path PATH
--application-root PATH
--data-root PATH            # repeatable
--include-path PATH         # repeatable
--exclude-path PATH         # repeatable
```

`--exclude-path` is intended for known assessment-runner noise, not target application storage.

## Guided Runtime Observation

Run after a completed Full Assessment:

```bash
python3 ubuntuclientassess.py --runtime-observe /path/to/assessment
```

For timed collection:

```bash
python3 ubuntuclientassess.py \
  --runtime-observe /path/to/assessment \
  --runtime-observe-seconds 30
```

The tester launches and exercises the application. UbuntuClientAssess passively correlates application processes/descendants, listeners and recent connections, pathname Unix sockets, named FIFOs, and scoped file activity. It does not automatically invoke D-Bus methods, send IPC requests, or attempt exploitation.

Runtime evidence is committed through the shared application service under assessment locking and revision checks. A stale runtime commit is rejected rather than overwriting newer state.

## Guided Review

Open a completed Full Assessment:

```bash
python3 ubuntuclientassess.py --review /path/to/assessment
```

Review is organized by security area and related groups. In the browser, the Review Queue and validation procedure scroll independently, Status/Tester Notes/Save controls remain available below the guidance pane, and category/status filters can be combined to focus on Pending or completed items. Disposition colors provide a quick visual completion cue. Shared validation facts can be reused where the underlying context is unchanged, but every distinct review item keeps its own disposition and impact validation.

Supported dispositions:

- `PENDING`
- `VALIDATED`
- `NOT APPLICABLE`
- `INFORMATIONAL`

Authoritative review state is stored in `working/tester_review_state.json`. Generated reports are derived from trusted state; manual edits to generated reports intentionally invalidate integrity.

## Review items, correlations, and findings

The security model stores:

- canonical objects;
- observations;
- relationships;
- correlations;
- evidence/provenance references; and
- suppression metadata for malformed/incomplete automatic correlations.

Current automatic finding candidates are correlation-owned. Evidence quality describes provenance/strength; it is **not** vulnerability severity and does not decide whether the tester should report a condition.

A review item may require manual validation without being an automatic finding candidate. The final penetration-test report remains authoritative.

## Assessment coverage

`reports/assessment_coverage.txt` is a read-only coverage map. It shows automated coverage, related review items, runtime evidence, supporting reports, and manual tester focus.

No generated review candidate does **not** mean an area was tested and found secure. Use coverage as a closeout aid alongside Guided Review and the tester's methodology.

## Integrity and recovery

Verify a finalized assessment:

```bash
python3 ubuntuclientassess.py --verify-assessment /path/to/assessment
```

Verification covers the assessment manifest, tester-facing reports, supporting state, retained extraction inventories, expected artifact inventory, and atomic-write cleanup.

If a generated tester report was modified externally, check status/recovery:

```bash
python3 ubuntuclientassess.py --assessment-status /path/to/assessment
```

Safe derived-report regeneration can be run directly:

```bash
python3 ubuntuclientassess.py --repair-generated-reports /path/to/assessment
```

If a state-changing transaction was interrupted, recover its pre-operation state before continuing:

```bash
python3 ubuntuclientassess.py \
  --recover-interrupted-operation /path/to/assessment
```

State-changing application-service operations use per-assessment locking, optimistic revision checks, bounded rollback transactions, and durable atomic writes.

## Client Appendix

After all Guided Review items are resolved and assessment integrity passes:

```bash
python3 ubuntuclientassess.py \
  --create-client-appendix /path/to/assessment
```

The appendix copies approved client-facing technical reports and generates its own hash inventory/dashboard. It intentionally excludes internal review state, working files, finding-candidate workflow state, tester notes, and internal correlation identifiers. The final penetration-test report remains the authoritative client report.

## Output structure

A Full Assessment uses the following primary structure:

```text
<assessment>/
├── assessment_metadata.json
├── assessment_manifest.json
├── reports/
│   ├── installer_analysis.txt
│   ├── application_profile.txt
│   ├── install_changes.txt
│   ├── permissions_review.txt
│   ├── binary_security_review.txt
│   ├── service_review.txt
│   ├── persistence_review.txt
│   ├── network_surface_review.txt
│   ├── ipc_review.txt
│   ├── local_storage_review.txt
│   ├── update_review.txt
│   ├── runtime_review.txt
│   ├── findings.txt
│   ├── findings_summary.txt
│   ├── module_status.txt
│   ├── tool_detection.txt
│   ├── assessment_coverage.txt
│   ├── tester_review.txt
│   ├── evidence_guide.txt
│   ├── assessment_report.html
│   └── artifact_manifest.txt
└── working/
    ├── snapshot_pre.json
    ├── snapshot_post.json
    ├── security_model.json
    ├── tester_review_state.json
    └── additional internal evidence/state
```

`reports/` contains tester-facing derived analyses. `working/` contains machine-readable authoritative/raw state used for correlation, regeneration, and integrity/recovery. The framework intentionally avoids duplicate JSON/CSV copies of reports that already have a tester-facing `.txt` representation.

## CLI reference

Operational actions:

```text
--verify-assessment PATH
--create-client-appendix PATH
--review PATH
--runtime-observe PATH
--assessment-status PATH
--resume-assessment PATH
--repair-generated-reports PATH
--recover-interrupted-operation PATH
```

Assessment configuration:

```text
-i, --installer PATH
-o, --output PATH
-n, --assessment-name NAME
--application-path PATH
--application-root PATH
--include-path PATH          repeatable
--data-root PATH             repeatable
--exclude-path PATH          repeatable
--installer-analysis-only
--auto-install-deb
--allow-installed-deb
--network-observation-seconds SECONDS
--runtime-observe-seconds SECONDS
--retain-payload
--non-interactive
-v, --verbose
--debug
--version
```

Use `python3 ubuntuclientassess.py --help` for the authoritative argument list.

## Application-service contract and GUI readiness

Version 2.0.6 consumes service contract **1.0** in `modules/application_service.py`. Presentation layers consume structured `ServiceResult` objects with:

```text
ok
code
message
data
errors
```

The service exposes read/write operations for assessment overview/status, state revision, integrity verification, Guided Review state, review saves, runtime finalization, report repair, interrupted-transaction recovery, and Client Appendix export. Service capability metadata is JSON-safe and contains no terminal rendering or prompting dependencies.

The terminal CLI and the v2.0.6 localhost browser interface are both supported presentation layers over the same backend/service contracts. The GUI does not bypass assessment locking, revision checks, integrity verification, review completion rules, or ClientAppendix gating.

## Data handling and safety

- Enter credentials only into the target application, not tester notes.
- Local-storage reports identify sensitive-data indicators without persisting detected secret values.
- Runtime and IPC collection is observational unless the tester performs separate authorized validation.
- Installer extraction is bounded and path-safety checked.
- Use a disposable assessment VM and revert between targets.
- Do not manually edit integrity-protected generated reports; use Guided Review or recovery/regeneration functions.

## Limitations

- Runtime observation is correlation-oriented periodic sampling, not a replacement for packet capture, auditd, `strace`, or `ltrace`.
- Very short-lived process/network/file activity can be missed.
- D-Bus discovery/introspection is read-only; authorization flaws require tester validation.
- Unix-socket/FIFO discovery identifies trust boundaries but does not infer application-protocol vulnerabilities.
- Static endpoint discovery can include dormant/third-party references; runtime validation is required before reporting.
- Update analysis cannot by itself prove runtime trust-anchor choice, downgrade handling, or failure enforcement.
- Application files outside derived/default scope may require `--data-root` or `--include-path`.
- The v2.0.6 web interface is loopback-only and is not a remote multi-user service.

## Development and release validation

Run the regression suite:

```bash
python3 -m pytest -q
```

Release packaging also checks Python compilation, shell syntax, CLI/version output, archive integrity/hygiene, documentation/client-name hygiene, and a fresh-extraction regression run.

## Documentation

- `README.md` — installation, operation, artifacts, recovery, CLI usage, and architecture overview.
- `METHODOLOGY.md` — current assessment methodology and decision boundaries.
- `CHANGELOG.md` — release history beginning at v1.0.0.
- `TESTER_GUIDE.md` — concise field workflow guidance.
