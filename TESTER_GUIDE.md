
## Web interface

Launch the local browser console with `python3 ubuntuclientassess.py --gui`. The default port is `9001`; override it with `--port PORT`. The server binds only to `127.0.0.1`. The GUI supports starting new assessments, browsing for the assessment root and installer package, completed-assessment overview, Guided Review, manual Start / Stop runtime observation, report viewing, integrity/recovery actions, and ClientAppendix export. For a Full Assessment, the GUI pauses after the pre-install snapshot and gives you the exact package-install command to run in a terminal; sudo passwords, sign-in credentials, and first-run setup stay outside the browser. Return to the GUI and choose **Installation and Setup Complete — Continue** to capture the post-install state and finish analysis.

# UbuntuClientAssess v2.0.6 Tester Guide

v2.0.6 uses the structured security model as the primary assessment engine and provides two purpose-built offline dashboards: an operational tester dashboard and a client-safe ClientAppendix technical dashboard. Use Guided Review for dispositions and notes; use Assessment Coverage to confirm breadth; use Verify Assessment Integrity to validate the frozen assessment artifact set before export.

v1.9.3 retains the `assessment_coverage.txt` model introduced in v1.6.1, a generated read-only map of automated coverage, related review items, runtime evidence, supporting reports, and remaining manual tester focus. Detailed validation belongs in Guided Review; the coverage map exists to prevent “no candidate generated” from being mistaken for “area tested and secure.” The HTML dashboard exposes the same coverage view.

State-changing administration actions are serialized per assessment in v2.0.6. If an operation is interrupted after its transaction begins, Assessment Status / Recovery identifies the interrupted write and the CLI can restore the pre-operation state with `--recover-interrupted-operation PATH`. A stale Guided Review or runtime view must be refreshed rather than forced over newer state.

v1.6.0 completes structured-correlation ownership for mature discovered security-condition review items by adding runtime-discovered externally bound application listeners. The technology-specific review plan remains workflow guidance rather than a detected security condition. Runtime listener, storage, communication, IPC/D-Bus/PolicyKit, and local privilege-boundary rules remain tester-validation tasks rather than automatic vulnerabilities unless a mature finding rule explicitly says otherwise. Guided Review remains the authoritative place to change PENDING / VALIDATED / NOT APPLICABLE / INFORMATIONAL state and tester notes. After each save, the CLI now shows a compact completed/pending counter, and the offline HTML dashboard search/filter controls now reorder and filter the left queue and select the first matching item.

The dashboard review workspace supports local search/filtering, Next Pending navigation, Correlation Engine / Workflow Guidance / Compatibility Fallback source filtering, runtime-confirmation filtering, and structured observation/canonical-object context without loading external resources.
### v1.7.1 Evidence provenance

When a Guided Review item or finding candidate is correlation-owned, open **Structured correlation details** in the tester dashboard to review the correlation rationale, evidence quality, contributing source modules, canonical objects, model relationships, supporting observations, and evidence bookmarks. `HIGH` evidence quality indicates contribution from multiple source modules; `MODERATE` indicates internally consistent structured support from one module. Evidence quality is a provenance aid, not a vulnerability severity or final validation decision.

Malformed automatic correlations that lack canonical objects, structured observations, or a required evidence category are marked suppressed in the model and cannot drive review/finding output. The tester remains responsible for validating all active candidates and for deciding what belongs in the final report.

## v1.8.0 Category-Based Guided Review

Guided Review now starts with a short security-area menu instead of a flat priority view. Choose the area you are working on, then select a TRQ from the related groups shown within that area. `Save & Next Pending in Category` stays inside the current area until its pending items are complete.

Related TRQs may show **Shared Validation Context**. Establish that common context once and reuse the same evidence only while the underlying user, service, path, runtime workflow, or authorization context remains unchanged. Shared context never collapses distinct TRQs: each item still requires its own disposition and any object-specific impact validation.

The tester HTML shows the same security-area progress and related-group labels. It remains read-only; dispositions and notes continue to be written through Guided Review in the CLI.


## Preparation

1. Use a disposable Ubuntu assessment VM and take a clean snapshot.
2. Confirm the target package is fully absent, including residual Debian package state, before Full Assessment.
3. Install framework dependencies with `./install_dependencies.sh` or the documented Python requirements. The setup script keeps normal APT/pip output concise and writes full troubleshooting output to `setup_logs/install_dependencies.log`.
4. Keep the installer on a tester-readable path such as `/tmp`; do not start the entire framework with `sudo`.
5. Exclude only known assessment-runner noise. Never exclude the target application's configuration or data paths.


## Main Menu

For normal interactive use, launch UbuntuClientAssess without arguments:

```bash
python3 ubuntuclientassess.py
```

The main menu provides:

1. Start New Assessment
2. Review Completed Assessment
3. Create Client Appendix
4. Verify Assessment Integrity
5. Guided Runtime Observation
6. Exit
7. Assessment Status / Recovery

Choose **Start New Assessment** to enter the standard assessment prompts. Review, appendix, verification, and runtime-observation selections prompt for an existing assessment directory with Tab completion. Existing command-line flags remain available and bypass the menu, which is useful for automation or direct tester workflows.

## Full Assessment

```bash
source .venv/bin/activate
python3 ubuntuclientassess.py
```

Add any known application-data location even when it does not yet exist, for example `--data-root ~/.vendor-client`. Choose Full Assessment, supply the installer, and confirm the intended installation method. Complete vendor setup/application exercise when prompted and continue exercising it during the short network-observation window. Newly created top-level home paths are shown for confirmation before post-capture.

A successful run must end with the completion banner, a `completed` run state, 21 tester reports, and both artifact manifests. `PASS` means a module executed successfully; `WARN` means the assessment continued with reduced coverage after a recoverable module failure; `ATTN` identifies a coverage/manual-validation limitation; `FAIL` prevents trustworthy finalization.

## Installer Analysis Only

Choose Installer Analysis Only when the package should be reviewed without installing or executing it. A successful run produces six passing modules, eight tester reports, extracted payload data when supported, and no pre/post snapshots. Full Assessment omits the extracted payload by default to avoid duplicating large installed trees; add `--retain-payload` only when manual payload inspection is needed.

For unattended static analysis:

```bash
python3 ubuntuclientassess.py \
  --non-interactive \
  --installer-analysis-only \
  --installer /path/to/package.deb \
  --output /path/to/assessment
```

## Guided Runtime Observation

For Full Assessment, perform guided runtime observation after the base assessment has finalized and before final review closeout when runtime testing is in scope:

In the browser, choose **Start Observation**, exercise all relevant application workflows without a countdown, then choose **Stop & Save Observation**. Use **Cancel Observation** to discard the current capture. The GUI applies a 60-minute safety limit to abandoned captures.

```bash
python3 ubuntuclientassess.py --runtime-observe /path/to/assessment
```

Or use a fixed observation window:

```bash
python3 ubuntuclientassess.py \
  --runtime-observe /path/to/assessment \
  --runtime-observe-seconds 30
```

The assessment must already verify successfully and must be a Full Assessment. UbuntuClientAssess does not launch the client for you. v1.4 uses the inferred application launcher/root when available, retains all package-specific application roots, discovers application-specific runtime/user-data roots, and may ask to use `sudo` for **read-only** socket/process ownership visibility when root-owned helpers would otherwise hide attribution. Review the recommended exercise checklist, start the observation, exercise the relevant application workflow in the normal desktop/session context, then stop capture when prompted. Observable events are marked automatically as they are seen; unchecked items are informational and are not test failures.

Review the updated `runtime_review.txt` and `ipc_review.txt`. Runtime capture enriches an existing listener/socket/FIFO review item when the same object was already identified statically, and adds a new PENDING item only for a genuinely new runtime object/security boundary. Existing review IDs, dispositions, and sanitized notes are preserved. Resolve any new queue items with `--review` before creating or refreshing `ClientAppendix/`.

Treat runtime correlation as supporting evidence. Faster sampling and recent TCP `TIME-WAIT` correlation improve visibility of short client/server exchanges, but short-lived process/socket activity can still fall between observable samples, and start/end filesystem metadata will not retain a file that is created and deleted entirely during the observation window. D-Bus inspection performed by the framework is read-only; authorization testing remains tester-driven.

## Review Order

1. `tester_review.txt` — start here. Work the HIGH-priority items first, then MEDIUM/LOW. Priority directs testing effort and is not vulnerability severity.
2. Use `python3 ubuntuclientassess.py --review /path/to/assessment`. Each v1.6.2 item includes a junior-friendly validation playbook with exact commands/procedure, interpretation guidance, secure/vulnerable outcomes, and stop/do-not-report conditions. Generic prerequisite and cleanup/restoration sections are intentionally omitted because the framework assumes authorized testing on disposable tester VMs. Sudoers, PolicyKit, D-Bus, Unix-socket/FIFO, ELF, privilege-helper, network/update, storage, and permission-boundary candidates receive category-specific guidance. Add sanitized notes, choose PENDING / VALIDATED / NOT APPLICABLE / INFORMATIONAL, then use Save & Next to continue.
3. `evidence_guide.txt` — use the suggested evidence bookmarks when a condition becomes a validated finding; add screenshots to the final Word report, not these text files.
4. `assessment_report.html` — use the live tester dashboard to review all queue items, automatic finding candidates, dispositions, tester notes, manual-review items, module status, and supporting evidence.
5. `module_status.txt` — confirm every expected module passed and resolve every `ATTN` limitation.
6. `artifact_manifest.txt` — confirm inventory status and mode-specific report count.
7. `installer_analysis.txt`, `install_changes.txt`, and `application_profile.txt` — understand package intent, observed changes, and the primary/supporting technology classification. Detection Score is confidence evidence, not vulnerability severity.
8. Permission, binary, service, persistence, network, IPC, storage, and update reports — use them as supporting evidence for queue items and for areas not automatically correlated.
9. `findings.txt` — treat severity-rated entries as candidates requiring proof, not final client findings, and close every item in its separate **Manual Review Required** section. Storage secret indicators remain in the review queue until usability/exposure is validated.
10. `assessment_coverage.txt` — use this generated coverage map to confirm every assessment area was considered, including areas where no specific TRQ was generated. Do not edit it; resolve detected conditions through Guided Review and document broader manual testing in normal engagement workpapers/final reporting.
11. `runtime_review.txt` — validate the guided runtime correlation results and perform deeper authorized tracing/protocol testing where warranted.

## Assessment Status and Recovery

Use the main-menu **Assessment Status / Recovery** option or:

```bash
python3 ubuntuclientassess.py --assessment-status /path/to/assessment
python3 ubuntuclientassess.py --resume-assessment /path/to/assessment
python3 ubuntuclientassess.py --repair-generated-reports /path/to/assessment
python3 ubuntuclientassess.py --recover-interrupted-operation /path/to/assessment
```

Recovery is deliberately conservative. If trustworthy pre- and post-installation snapshots exist, v1.4 can rerun post-analysis/finalization. If installation started or changed machine state but a trustworthy post-installation snapshot was not captured, the framework recommends reverting the disposable Ubuntu VM to its clean snapshot and restarting the assessment. Do not use resume to legitimize an unknown installation baseline.

If integrity verification shows that only generated tester reports such as `findings.txt` were modified, use Assessment Status / Recovery or `--repair-generated-reports` to rebuild those derived reports from trusted internal state. Do not manually edit disposition tags in `findings.txt`; use Guided Review. Repair is intentionally refused when snapshots, authoritative review/finding state, extracted evidence, or other supporting artifacts were modified.

## Cryptographic Material Review

`local_storage_review.txt` may identify locally scoped CA certificates, private/signing-key indicators, and cryptographic salt fields. Secret values are redacted. A salt is generally non-secret and a certificate is public material, so neither should be reported by itself. Follow the CRYPTO review playbook to determine whether a real private key is recoverable/usable, which principals can access it, where any related CA is trusted, and whether possession of the key would permit certificate issuance across a meaningful trust boundary.

## Integrity Verification

Run verification after copying, archiving, or transferring an assessment:

```bash
python3 ubuntuclientassess.py --verify-assessment /path/to/assessment
```

Exit code `0` means the finalized report set, required supporting files, and extracted-payload tree hashes match the manifest. Exit code `9` means the set is missing, unexpected, altered, or incompatible with the verifier version.

## Client Appendix Export

After the assessment is complete and reviewed, create the technical client-delivery appendix with:

```bash
python3 ubuntuclientassess.py --create-client-appendix /path/to/assessment
```

The command verifies source integrity first, confirms the guided tester review queue has no PENDING items, then refreshes `ClientAppendix/`. Resolve remaining items with `--review` before export. Full Assessment exports the package/application, installation/privilege, and runtime/surface technical reports. Installer Analysis Only exports the applicable installer/profile/runtime subset. The export intentionally omits automated finding candidates, tester workflow/coverage artifacts, module/tool QA output, manifests, snapshots, and all `working/` content.

Review `ClientAppendix/README.txt`, open its client-safe `assessment_report.html`, and retain `SHA256SUMS.txt` with the delivered files. Confirmed vulnerabilities remain authoritative only in the final Word penetration test report.

## Interrupted Runs

If execution is interrupted, inspect `assessment_metadata.json` and `working/INTERRUPTED_RUN.txt`. If interruption occurred after installation may have started, restore the clean VM snapshot before rerunning. Do not reuse partial tester reports as current evidence. Preserve partial snapshots separately only when needed for troubleshooting.

## Completion Checklist

- The process exited zero and displayed the appropriate success banner.
- `run_state.status` is `completed` and `run_state.stage` is `complete`.
- `module_status.txt` contains no `WARN` or `FAIL` entries. Any `ATTN` entry has been manually resolved and documented.
- The artifact manifest reports `COMPLETE` and `--verify-assessment` passes.
- The report count is exactly 21 for Full Assessment or eight for Installer Analysis Only.
- Full Assessment snapshots are schema 6 and record configured inclusions, data roots, exclusions, and the network observation stage.
- Installer Analysis Only contains no stale pre/post snapshots.
- Detected framework/network evidence is application-relevant rather than bundled reference noise.
- Guided runtime observation was performed when required by scope, and any new runtime/IPC queue items were resolved.
- Tester Review Queue contains no PENDING items before Client Appendix export.
- Test-case statuses and notes are completed before assessment closeout.
- `working/application_profile.json` is retained as internal correlation data; `working/runtime_observation.json` is present when guided runtime observation was performed.


## Protected application installation directories

After installation, review `module_status.txt` for **Application File Coverage**. If it is `ATTN`, one or more application roots could not be recursively inspected with the tester account. Treat zero-result ELF, permissions, static network/configuration, local-storage, update/component, or framework-profile sections as incomplete until you obtain additional authorized visibility. Do not report the permission boundary itself as a vulnerability solely because the tester cannot read it.

## Privileged Static Review

If the selected assessment shows **Privileged Static Review Required**, use **Run Privileged Collection**. Complete the operating-system sudo authentication in the terminal window that opens; do not enter privileged credentials into the browser. UbuntuClientAssess limits the operation to protected application roots already recorded by the assessment. After collection completes, the GUI refreshes the assessment and affected static-analysis modules are regenerated. If the GUI cannot open a supported terminal emulator, it displays the exact fixed helper command for the tester to run locally.
