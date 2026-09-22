# UbuntuClientAssess Methodology 2.4

UbuntuClientAssess methodology defines how the framework collects evidence, scopes analysis, builds structured security relationships, prepares tester-review work, generates automatic finding candidates, protects assessment state, and separates tester-facing from client-facing output.

Framework release 2.0.6 uses methodology **2.4**, coverage catalog **1.1**, and security-model schema **10**.

## 1. Purpose and decision boundary

UbuntuClientAssess is an assessment aid, not an autonomous vulnerability decision engine. It automates collection and correlation where reliable evidence exists and deliberately hands uncertain exploitability, authorization, trust, and business-impact decisions to the tester.

The framework distinguishes:

- **observations** — collected facts or indicators;
- **correlations** — structured relationships between relevant facts/objects;
- **review items** — conditions requiring tester validation;
- **finding candidates** — correlation-owned conditions with enough structured evidence to warrant potential report consideration; and
- **final findings** — conclusions made by the tester in the authoritative penetration-test report.

Automatic severity on a finding candidate is a framework triage value. Evidence quality is provenance/strength metadata and is not severity.

## 2. Supported workflows

### Full Assessment

A Full Assessment follows this lifecycle:

1. Validate tools and assessment inputs.
2. Analyze the installer/package without executing it during static analysis.
3. Capture the pre-installation system/application baseline.
4. Install/configure the application through an authorized tester-controlled workflow.
5. Allow sign-in/first-run setup and representative application exercise.
6. Capture the post-installation state.
7. Generate the installation differential and application/security analyses.
8. Synchronize the structured security model.
9. Generate the tester-review queue and finding candidates.
10. Optionally perform Guided Runtime Observation and merge runtime evidence.
11. Complete Guided Review.
12. Verify assessment integrity.
13. Create the client-safe technical appendix if required.

### Installer Analysis Only

Installer Analysis Only performs static installer/package analysis and application profiling without pre/post installation differential or the full runtime/review workflow.

## 3. Application scoping and noise control

Scope is derived from available evidence rather than hard-coded product paths. Sources can include:

- package manifests and metadata;
- inferred/explicit application roots and launchers;
- desktop entries;
- systemd units and service ownership;
- installation changes;
- application-created user/system data paths;
- runtime process ancestry and ownership;
- network/IPC ownership; and
- tester-supplied include/data roots.

Filesystem exclusions are reserved for known assessment-runner noise. A target-owned storage location should not be excluded merely to reduce output.

The framework avoids treating unrelated system/home-directory activity as target evidence solely because it occurred during the test window.

## 4. Tool availability and coverage depth

Methodology coverage is capability-aware. UbuntuClientAssess can operate when some recommended/optional tools are absent, but applicable modules may have reduced depth. `install_dependencies.sh` installs/checks the baseline packages, attempts to install recommended/optional coverage tools, and reports `READY`, `READY WITH REDUCED COVERAGE`, or `FAILED` based on the resulting environment.

Examples of capability areas affected by supporting tools include ELF/binary analysis, runtime/process tracing, network observation, Debian/package validation, audit collection, D-Bus inspection, debugging, content/static analysis, desktop integration, SquashFS/Snap inspection, signing/crypto inspection, and Flatpak analysis.

The complete required and recommended/optional package matrix is maintained in the **Requirements and installation** section of `README.md`. `requirements.txt` lists Python dependencies only and is not a complete system-tool inventory.

## 5. Static installer and package analysis

Static analysis identifies package metadata, scripts, declared files, install/update paths, embedded endpoints, technology indicators, and high-interest payload content. Extraction is bounded and path-safety checked. Executable/self-extracting formats are not blindly run for static inspection.

Package verification and available signature/trust information are recorded as evidence; absence/presence of a package signature alone is not automatically a vulnerability conclusion.

## 6. Baseline and installation differential

Pre/post snapshots collect security-relevant state needed to attribute changes to the application. Depending on tool/platform availability this includes:

- packages/remotes;
- filesystem metadata and selected hashes;
- processes;
- systemd services/timers;
- listening and active/recent network sockets;
- Unix sockets;
- mounts;
- users/groups;
- Linux capabilities;
- selected SUID/SGID state;
- cron/persistence locations; and
- application/package-specific roots.

The installation differential is evidence, not a finding list. Changes are filtered/scoped before security conclusions are generated.

## 7. Security review domains

### Permissions and local privilege boundaries

The framework reviews mode bits, ownership, ACLs, writable parent directories, SUID/SGID state, file capabilities, sudoers changes, and privilege-policy context. A writable object becomes reportable only when a meaningful trust/privilege boundary and attacker influence are validated.

### ELF/binary security

ELF analysis reviews applicable hardening properties and dynamic library search paths. Writable/relative/current-directory RPATH/RUNPATH indicators require validation of real dependency resolution and elevated execution context before reporting.

### Services and privileged execution

systemd units are correlated with executable/configuration paths and effective service identity. Writable paths are candidates only when the privileged service actually consumes the attacker-influenced object/path.

### Persistence and authorization policy

Persistence mechanisms, sudoers, PolicyKit, D-Bus service configuration, and related policy changes are reviewed for authorization/trust impact. Permissive-looking metadata alone does not prove a vulnerability.

### Network and communications

Static endpoints and runtime sockets/connections are correlated with application ownership. Cleartext or unexpected endpoints require runtime/context validation, including what data is transported, peer trust, and whether the endpoint participates in a security-sensitive workflow.

### Local IPC

Unix sockets, named FIFOs, D-Bus names/methods, and PolicyKit-linked operations are reviewed for local trust boundaries. The framework does not automatically invoke state-changing IPC methods or fuzz application-specific protocols.

### Local storage

Application-scoped files/databases/configuration are reviewed for credential/token/key indicators and effective access. Secret values are not persisted in tester-facing reports. Potentially sensitive filenames/content indicators require validation of actual sensitivity and exposure.

### Software update mechanisms

Update URLs/configuration/installers and local trust/signature evidence are correlated. Runtime validation remains necessary to establish actual transport, authenticity enforcement, downgrade behavior, trust-anchor selection, and failure handling.

### Technology-specific review

Detected technology/framework evidence informs a manual review plan. Technology detection confidence is not a security score.

## 8. Structured security model

`working/security_model.json` is the primary structured assessment model for current assessments. It contains:

- canonical objects;
- observations;
- relationships;
- correlations;
- source-module provenance;
- evidence references/bookmarks;
- evidence-quality metadata;
- cross-module correlation state; and
- suppression metadata.

Correlation rules are generic and evidence-driven. Production logic must not rely on fixture/client-specific names, paths, ports, or behavior.

### Conservative suppression

An automatic correlation can be suppressed when required structured state/evidence is malformed or incomplete. Suppression prevents malformed/incomplete structured data from driving review/finding output; it is not a conclusion that a real condition is harmless.

## 9. Finding candidate generation

For current schema-10 assessments, automatic finding candidates are correlation-owned. The framework retains compatibility behavior only where needed to interpret older/missing structured assessment state.

A candidate should represent a coherent security condition rather than duplicate every supporting observation. Distinct vulnerabilities remain distinct even when shared evidence/prerequisites are reused.

The known categories include mature privileged-service path, ELF search-path, update-path, sudo/local authorization, and cryptographic signing-material conditions where the required structured evidence exists. Review-only categories remain review-only until the tester validates the security impact required for reporting.

## 10. Guided Runtime Observation

Runtime collection is tester controlled. The tester launches/exercises the application while the framework observes application-correlated runtime state.

Runtime collection can include:

- application processes and descendants;
- privileged application/service processes;
- listeners and active/recent connections;
- pathname Unix sockets;
- application FIFOs; and
- scoped file activity.

The observer does not automatically exploit the target, invoke D-Bus methods, submit IPC requests, or replace specialist packet/syscall tracing tools.

In 2.0.6, each presentation layer owns runtime start/stop interaction while committed runtime evidence is finalized by the shared application service under locking, revision checking, and transaction protection. The browser UI uses tester-controlled Start / Stop & Save collection without prompting for sudo, with Cancel available to discard a capture and an internal 60-minute safety limit; the CLI retains its interactive/timed and elevated-visibility workflows.

## 11. Guided Review methodology

Guided Review is the authoritative tester workflow for dispositions/notes. Items are organized into security-area categories and related groups.

Shared group context may reduce repeated prerequisite work, but each distinct item retains its own disposition and impact validation. Validation of one item does not automatically validate another.

Allowed states:

- `PENDING` — still requires action;
- `VALIDATED` — tester validated the candidate/condition for continued reporting consideration;
- `NOT APPLICABLE` — condition does not apply after validation;
- `INFORMATIONAL` — useful context but not treated as a reportable vulnerability by the tester.

Tester notes are sanitized and must not contain passwords, tokens, or secret values.

## 12. Assessment coverage

Coverage catalog 1.1 maps broad security areas to automated coverage, review items, runtime evidence, supporting reports, and remaining manual focus.

`assessment_coverage.txt` is read-only and is not a completion checklist. A security area with no generated candidate still requires appropriate manual reasoning/testing where relevant.

## 13. Integrity, state authority, and recovery

Authoritative state is separated from derived reporting.

Key authoritative/supporting state includes the structured security model, tester-review state, snapshots, runtime evidence, finding-candidate state, metadata, and manifest inventories. Tester-facing reports are regenerated from trusted state.

Integrity controls include:

- assessment/report/supporting-file hashing;
- expected artifact inventory checks;
- extraction inventory verification;
- atomic file replacement;
- directory `fsync` after replacement;
- per-assessment read/write locking;
- optimistic state revision tokens;
- bounded multi-file transactions;
- rollback on failed state-changing operations; and
- interrupted-transaction journals/recovery.

Manual changes to generated reports intentionally fail verification. If trusted authoritative state remains intact, repair can regenerate affected derived reports and refresh the manifest.

## 14. Client Appendix methodology

Client Appendix creation is allowed only after required review completion and successful source assessment verification.

The appendix:

- copies approved technical reports rather than moving them;
- excludes internal review/correlation/working state;
- excludes tester notes and finding workflow state;
- produces an independent hash inventory; and
- provides a client-safe technical dashboard.

The appendix is supporting technical material. The tester's final penetration-test report is authoritative for vulnerabilities, severity, conclusions, and remediation.

## 15. Application-service / presentation separation

Service contract 1.0 provides presentation-neutral structured operations for assessment overview/status, revision/integrity checks, review retrieval/writes, runtime finalization, generated-report repair, interrupted-operation recovery, and Client Appendix export.

Service results contain `ok`, `code`, `message`, `data`, and `errors` and are JSON-safe. The service module contains no terminal prompting/rendering logic.

This separation is the compatibility boundary between presentation and assessment state. Version 2.0.6 adds a loopback browser interface that calls the same service operations as the CLI; neither presentation layer becomes independently authoritative over assessment state. The browser maintains one selected-assessment context across operational tabs; filesystem navigation and assessment-root discovery are separate presentation concerns and do not change authoritative assessment state. Background GUI jobs expose structured phase/module progress only; the underlying assessment artifacts and state transitions remain owned by the shared workflow/service layer.

## 16. Safety and limitations

- Use authorized disposable test systems/VM snapshots.
- Do not paste secrets into tester notes or reports.
- Runtime sampling can miss activity shorter than the observable sampling/state window.
- Static endpoint/configuration evidence may be dormant or third-party and requires contextual validation.
- IPC discovery does not prove unauthorized method/action access.
- Package/update trust evidence does not replace runtime update-path validation.
- Files outside derived/configured scope may require explicit inclusion.
- Generated finding candidates are not substitutes for tester-confirmed final findings.

## 17. Versioning

Framework, methodology, coverage-catalog, security-model schema, and application-service contract versions are independent where appropriate. A framework release does not require a methodology/schema bump when assessment semantics have not changed.

Methodology history belongs in the changelog when relevant; this document describes the **current** methodology rather than accumulating every historical implementation phase.


## Inaccessible application roots and reduced static coverage

For non-package and vendor-managed installers, UbuntuClientAssess supplements installer-declared scope with post-install filesystem and process evidence. When an application-specific installation root is identified but cannot be recursively traversed or read by the assessment user, the framework records that as a coverage limitation rather than interpreting absent child files as a clean result. Affected static-analysis modules are marked `ATTN`, relevant reports identify the inaccessible root and affected areas, and testers should obtain additional authorized filesystem visibility before treating those areas as complete. The framework does not automatically elevate the entire assessment process to root.

### Targeted privileged static collection

When a Full Assessment identifies an application installation root that cannot be recursively inspected by the tester account, the affected static-analysis areas remain reduced coverage rather than being treated as clean. Version 2.0.6 can launch a narrowly scoped privileged helper from the localhost GUI. Authentication occurs in a local terminal; no sudo credential is entered into or transmitted through the browser. The helper accepts only protected application roots already recorded by the assessment, collects filesystem metadata and hashes without executing application content, augments the post-install snapshot, and regenerates the affected analysis/report chain. The framework returns assessment artifacts to the original tester ownership after the privileged operation.
