# Changelog

UbuntuClientAssess release history is tracked from **v1.0.0 forward**. Pre-1.0 prototype history is intentionally not retained in this changelog.

## [2.0.6] - 2026-09-21

### Fixed
- Fixed the GUI **Run Privileged Collection** launcher so it preserves the Python interpreter path that started UbuntuClientAssess. Virtual-environment launchers such as `.venv/bin/python` are no longer dereferenced to the system interpreter before `sudo`, preventing false `Missing Python dependency: prompt_toolkit` failures when dependencies are installed only in the project virtual environment.
- Added regression coverage for symlinked virtual-environment Python launchers used by the privileged static-review workflow.

### Changed
- Kept methodology 2.4, coverage catalog 1.1, security-model schema 10, default GUI port 9001, and the v2.0.5 privileged-collection security model unchanged.

## [2.0.5] - 2026-09-21

### Added
- Added targeted privileged static collection for protected application installation roots. The GUI can launch a local terminal sudo authentication flow without collecting credentials in the browser.
- Privileged collection is constrained to application roots already recorded as static-coverage gaps, augments post-install evidence, and regenerates affected static analyses and integrity state.
- Added prominent GUI coverage guidance and a **Run Privileged Collection** action whenever protected roots leave static-analysis modules in `ATTN`.

### Changed
- Tightened post-install process-root inference so unrelated ambient applications under shared system locations are not pulled into assessment scope without corroborating filesystem-change evidence.
- Removed the README Roadmap section and expanded the Authorized Use notice.

### Security
- The browser never receives, stores, or forwards sudo credentials. Privileged work occurs in a local terminal and the helper rejects arbitrary paths outside the assessment-recorded protected roots.

## [2.0.4] - 2026-09-21

### Fixed
- Added `.sh` and `.run` (plus current Flatpak filename forms) to the GUI installer browser so supported script installers are selectable.
- Extended GUI Full Assessment staging beyond `.deb` packages: non-Debian installers use tester-confirmed vendor-managed installation instead of Debian package verification.
- Fixed Dashboard review state so a completed Full Assessment with a valid zero-item review queue displays **No review items** instead of **Not ready**.
- Detects application installation roots that cannot be recursively traversed/read by the assessment user and records the lost static-analysis coverage instead of allowing zero-result modules to appear fully complete.
- Strengthened post-install scope inference for non-package installers using filesystem and application-process evidence.

### Changed
- Added an **Application File Coverage** module status. Inaccessible application roots mark affected framework, permission, ELF, network-static, storage/configuration, update, and assessment-coverage modules `ATTN`.
- Relevant reports now explain inaccessible application-root coverage limitations and explicitly warn that zero results do not establish absence of issues.
- Clarified CLI and GUI installation pauses that UbuntuClientAssess has analyzed, but has not executed, tester-managed installers.
- Added an Authorized Use section to the README for repository publication.
- Kept methodology 2.4, coverage catalog 1.1, security-model schema 10, default GUI port 9001, and the v2.0.3 manual Runtime Observation workflow unchanged.

## [2.0.3] - 2026-09-21

### Changed
- Replaced the browser Runtime Observation countdown with tester-controlled **Start Observation**, **Stop & Save Observation**, and **Cancel Observation** actions so testers can exercise application workflows without a fixed time window.
- Preserved live elapsed-time and process/network/IPC counters during manual observation.
- Added a 60-minute backend safety limit for abandoned browser captures; reaching the limit stops and saves the observation automatically.
- Prevented more than one active browser Runtime Observation job for the same assessment.
- Added active-observation rediscovery so navigating away from the Runtime tab or reloading the page restores control of an in-progress capture.
- Kept CLI interactive/timed runtime workflows, assessment locking, revision checks, transaction protection, methodology 2.4, coverage catalog 1.1, security-model schema 10, and default GUI port 9001 unchanged.

## [2.0.2] - 2026-09-21

### Fixed
- Fixed Client Appendix creation through the web API by normalizing `pathlib.Path` and other common non-JSON-native service values before serialization.

### Changed
- Reworked Guided Review into a stable two-pane workspace with independent mouse-wheel scrolling for the Review Queue and validation procedure.
- Kept Status, Tester Notes, and Save Review Item controls outside the scrolling validation procedure so they remain readily accessible.
- Added disposition-based queue highlighting for PENDING, VALIDATED, NOT APPLICABLE, and INFORMATIONAL review items.
- Added a status filter, including Pending-only review, which can be combined with the existing category filter.
- Updated filtered queues immediately after saving a disposition and preserved the current queue position when the saved item remains visible.
- Kept methodology 2.4, coverage catalog 1.1, security-model schema 10, default GUI port 9001, and service contract 1.0 unchanged.

## [2.0.1] - 2026-09-21

### Changed
- Changed the New Assessment name from a pre-populated value to a placeholder so testers can type immediately without clearing default text.
- Exposed the complete Guided Review validation procedure through the application service and made long guidance scrollable/readable in the browser.
- Added elapsed-time Runtime Observation progress with live sample/process/socket counters.
- Re-verified the assessment immediately before runtime commit and safely applied additive runtime evidence to the latest verified assessment revision, preserving Guided Review changes while retaining assessment locking and transaction protection.
- Preserved the v2.0.0 dashboard, global selected-assessment context, standalone Client Appendix tab, staged Full Assessment workflow, loopback-only binding, and default port 9001.

## [2.0.0] - 2026-09-21

### Added
- Added the localhost browser interface launched with `--gui`.
- Defaulted the web server to `127.0.0.1:9001`; added `--port PORT` to override the port, `--gui-root PATH` to select the initial assessment root, and `--no-browser` for headless launch.
- Added browser workflows for New Assessment, navigable assessment-root/package selection, assessment discovery/overview, Guided Review, timed runtime observation, report viewing, integrity verification, generated-report repair, interrupted-write recovery, and ClientAppendix export.
- Added staged GUI Full Assessment orchestration: pre-install capture, terminal-only package installation/setup, package verification, post-install capture, analysis, and finalization. Installer Analysis Only can run end-to-end from the browser.
- Added per-launch request-token protection, loopback-only binding, restrictive browser security headers, and no external web assets.
- Added background assessment/runtime jobs with service-layer finalization and existing stale-state/locking protections.
- Suppressed irrelevant Snap/GTK child-browser diagnostics during automatic browser launch.
- Added persistent selected-assessment context across Guided Review, Runtime Observation, Reports, Integrity & Recovery, and a new standalone Client Appendix tab.
- Decoupled filesystem browsing from the configured Assessment Root so browsing into an assessment/report directory cannot silently redefine dashboard discovery scope.
- Added dashboard discovery/refresh behavior for completed and in-progress assessments and `N/A` review display for Installer Analysis Only assessments.
- Added structured live job progress for pre/post snapshot substages, analysis modules, correlation, and finalization; replaced raw job JSON with tester-facing progress/completion cards while retaining expandable technical details.

### Changed
- Kept the CLI fully supported and retained service contract 1.0 as the shared authority for stateful assessment operations.
- Updated README, methodology, and tester guidance for the GUI/CLI dual-interface model.
- Kept methodology 2.4, coverage catalog 1.1, and security-model schema 10 unchanged.

## [1.9.3] - 2026-09-18

### Changed
- Formalized application-service contract 1.0 for presentation-neutral GUI readiness.
- Added JSON-safe service capability metadata and a compact assessment-overview operation for future non-terminal front ends.
- Kept the CLI as the supported user interface; no web server/GUI is introduced in this release.
- Rewrote `README.md` around installation, field workflow, artifacts, recovery, CLI usage, and the service-layer architecture instead of release-by-release accumulation.
- Rewrote `METHODOLOGY.md` as the current methodology rather than a historical methodology log.
- Reworked this changelog so release history begins at v1.0.0.
- Added documentation hygiene regression checks for forbidden customer/product identifiers, retired artifact references, pre-1.0 changelog entries, and stale current-version documentation.
- Documented the complete required and recommended/optional system-tool inventory, coverage-purpose grouping, readiness states, and the distinction between system tools and Python requirements; added regression coverage to keep the README package matrix synchronized with `install_dependencies.sh`.

### Validation
- Final pre-GUI 1.x regression/package gate expanded to validate service contract serialization and documentation consistency.

## [1.9.2] - 2026-09-18

### Changed
- Added per-assessment locking, optimistic revision checks, multi-file rollback transactions, and interrupted-write recovery.
- Deferred runtime evidence persistence until locked service finalization.
- Added deterministic manifest inventory revisions and stronger durable atomic-write behavior.
- Added safe repair of externally modified generated reports from trusted internal state.

## [1.9.1] - 2026-09-18

### Changed
- Introduced `UbuntuClientAssessService` as a presentation-neutral application/service layer.
- Routed Guided Review state changes, runtime finalization, integrity verification, Client Appendix export, assessment status/recovery, and generated-report repair through shared backend operations.
- Standardized structured service results using `ok`, `code`, `message`, `data`, and `errors`.

## [1.9.0] - 2026-09-18

### Changed
- Completed structured-correlation ownership for current automatic finding categories, including the remaining sudo/local-CA compatibility-backed candidates.
- Fixed category-scoped Guided Review progress counters and All Review Items action wording.
- Added release hygiene checks for prohibited engagement/customer/product identifiers.
- Bumped methodology to 2.4 and security-model schema to 10.

## [1.8.0] - 2026-09-18

### Changed
- Reorganized Guided Review around security-area categories.
- Added related-item grouping, shared validation context/evidence reuse guidance, and category progress.
- Mirrored category/group structure in the read-only tester dashboard.

## [1.7.1] - 2026-09-18

### Changed
- Added structured evidence references, relationship provenance, source-module provenance, evidence quality, cross-module status, correlation rationale, and conservative suppression state.
- Bumped security-model schema to 9 and methodology to 2.3.

## [1.7.0] - 2026-09-18

### Changed
- Made the structured model the primary current-assessment review/finding engine.
- Added a richer client-safe technical dashboard and shared technical-summary layer.
- Expanded assessment integrity verification presentation and checks.

## [1.6.2] - 2026-09-18

### Changed
- Cleaned structured review ownership and separated workflow guidance from correlation/compatibility review items.
- Continued correlation-first review generation without changing the coverage catalog.

## [1.6.1] - 2026-09-18

### Changed
- Retired the editable/generated test-case artifact in favor of read-only `assessment_coverage.txt`.
- Made coverage reporting mode-aware and distinct from Guided Review validation.

## [1.6.0] - 2026-09-18

### Changed
- Added structured runtime-listener correlation and improved runtime/review workflow integration.
- Bumped methodology to 2.1 and security-model schema to 7.

## [1.5.6] - 2026-09-17

### Changed
- Migrated structured storage and cleartext communication review generation.
- Improved scoped storage/endpoint correlation and noise control.

## [1.5.5] - 2026-09-17

### Changed
- Migrated local privilege-boundary conditions including permissions, SUID/SGID, capabilities, and sudo-related review into structured correlation ownership.

## [1.5.4] - 2026-09-17

### Changed
- Migrated Unix socket, FIFO, D-Bus, and PolicyKit review conditions into the structured model/review workflow.

## [1.5.3] - 2026-09-17

### Changed
- Revamped the offline tester dashboard and structured review presentation.

## [1.5.2] - 2026-09-17

### Changed
- Promoted field-validated service writable-path, ELF search-path, and cleartext-update correlations to structured candidate ownership.

## [1.5.1] - 2026-09-17

### Changed
- Hardened correlation stability, canonical object relationships, and structured evidence synchronization.

## [1.5.0] - 2026-09-14

### Added
- Introduced `working/security_model.json` as structured internal assessment state.
- Added canonical objects, observations, relationships, and correlation scaffolding for progressive model-driven analysis.

## [1.4.3] - 2026-09-13

### Changed
- Refined package verification with `debsig-verify` and consolidated duplicate ELF search-path findings.
- Reduced SGID and other low-value tester noise.

## [1.4.2] - 2026-09-11

### Added
- Added runtime correlation/integrity recovery improvements and cryptographic material review.

### Changed
- Strengthened application-scoped runtime evidence and generated-report integrity recovery.

## [1.4.1] - 2026-09-11

### Changed
- Improved the review dashboard, validation workflow, evidence guidance, and report regeneration behavior.

## [1.4.0] - 2026-09-11

### Added
- Added stronger application scoping, reliability controls, guided validation, and assessment recovery semantics.

## [1.3.0] - 2026-09-10

### Added
- Expanded Guided Runtime Observation, local IPC analysis, and application technology profiling.

## [1.2.1] - 2026-09-09

### Changed
- Refined the interactive main-menu workflow and associated validation/report behavior.

## [1.2.0] - 2026-09-09

### Added
- Introduced Guided Tester Review with persistent dispositions/notes and validation guidance.

## [1.1.5] - 2026-09-09

### Changed
- Simplified dependency setup/readiness reporting and optional-tool handling.

## [1.1.4] - 2026-09-09

### Added
- Introduced Client Appendix export with source-assessment verification and controlled client-facing artifact selection.

## [1.1.3] - 2026-09-09

### Changed
- Hardened generated-artifact integrity, safety checks, and regression behavior.

## [1.1.2] - 2026-09-09

### Changed
- Improved assessment coverage, collection performance, signal quality, and output noise reduction.

## [1.1.1] - 2026-09-09

### Fixed
- Corrected workflow/snapshot edge cases and improved state/output consistency.

## [1.1.0] - 2026-09-08

### Added
- Added the offline HTML assessment dashboard and improved tester-facing reporting.

## [1.0.1] - 2026-08-31

### Changed
- Applied production-hardening fixes discovered during early field validation, including safer workflow handling and cleaner generated artifacts.

## [1.0.0] - 2026-08-28

### Added
- Established the supported 1.x baseline for Ubuntu thick-client installer analysis, Full Assessment pre/post snapshots, installation differential, security review modules, runtime guidance, findings, module status, and human-readable reports.
- Established versioned methodology/reporting contracts and release regression testing.
