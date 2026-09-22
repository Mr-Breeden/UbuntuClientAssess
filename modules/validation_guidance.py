from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any


def _q(value: str) -> str:
    return shlex.quote(str(value))


def _first_path(text: str) -> str | None:
    match = re.search(r'(/[^\s:;,]+)', text)
    return match.group(1).rstrip(').]') if match else None


def _service_name(text: str) -> str | None:
    match = re.search(r'\b([A-Za-z0-9_.@-]+\.service)\b', text)
    return match.group(1) if match else None


def _base(item: dict[str, Any]) -> dict[str, Any]:
    return {
        'goal': 'Determine whether the observed condition crosses an intended security boundary and can produce concrete security impact.',
        'steps': [],
        'secure_result': 'The lower-privileged tester cannot influence the security-sensitive operation, or an effective authorization/integrity control blocks the attempted influence.',
        'vulnerable_result': 'The lower-privileged tester can influence a security-sensitive operation across a meaningful privilege/trust boundary.',
        'evidence': list(item.get('evidence', []) or []),
        'stop_conditions': ['Do not report the observation as a vulnerability if no meaningful trust/privilege boundary or attacker-controlled influence can be demonstrated.'],
    }


def playbook_for(item: dict[str, Any]) -> dict[str, Any]:
    category = str(item.get('category') or '').upper()
    title = str(item.get('title') or '')
    condition = str(item.get('condition') or '')
    pb = _base(item)

    if category == 'ELF':
        targets = [str(value) for value in (item.get('validation_targets') or []) if str(value).strip()]
        if not targets:
            targets = [_first_path(condition) or '<binary>']
        path_match = re.search(r'(?:RPATH|RUNPATH)=([^;:]+)', condition)
        lib_path = str(item.get('search_path') or (path_match.group(1).strip() if path_match else '<library-search-directory>'))
        search_kind = str(item.get('search_kind') or ('RUNPATH' if 'RUNPATH=' in condition else 'RPATH'))
        confirm_cmds: list[str] = []
        resolution_cmds: list[str] = []
        context_cmds: list[str] = []
        evidence: list[str] = []
        for binary in targets:
            confirm_cmds.extend([f"file {_q(binary)}", f"readelf -d {_q(binary)} | grep -E 'RPATH|RUNPATH|NEEDED'"])
            resolution_cmds.extend([f"ldd {_q(binary)}", f"LD_DEBUG=libs {_q(binary)} 2>&1 | less"])
            context_cmds.extend([f"ls -l {_q(binary)}", f"getcap {_q(binary)}", f"grep -R --fixed-strings {_q(binary)} /etc/systemd/system /usr/lib/systemd/system /etc/sudoers /etc/sudoers.d 2>/dev/null"])
            evidence.append(f"readelf -d {_q(binary)}")
        if lib_path.startswith('<empty/current directory>'):
            access_cmds = [
                'readlink -f /proc/<PID>/cwd',
                "namei -l <ACTUAL_WORKING_DIRECTORY>",
                "getfacl <ACTUAL_WORKING_DIRECTORY>",
                "test -w <ACTUAL_WORKING_DIRECTORY> && echo WRITABLE || echo NOT_WRITABLE",
            ]
            access_look = 'An empty search-path component resolves to the process working directory. Identify the working directory of the real execution path (not merely your shell) and determine whether the low-privileged tester can create a library there.'
        else:
            access_cmds = [f"ls -ld {_q(lib_path)}", f"namei -l {_q(lib_path)}", f"getfacl {_q(lib_path)}", f"test -w {_q(lib_path)} && echo WRITABLE || echo NOT_WRITABLE"]
            access_look = 'Determine whether the low-privileged tester can create/replace a library in the searched directory. For a relative path, resolve it from the working directory used by the real execution path.'
        pb.update({
            'goal': 'Determine whether an unprivileged user can substitute a library that is actually loaded by the affected binary or binaries when execution crosses a privilege boundary.',
            'steps': [
                {'title': 'Confirm the configured search path on each affected binary', 'commands': confirm_cmds, 'look_for': f'Confirm the reported {search_kind} condition and note required libraries. Reported path: {lib_path}. Grouped entries must be validated for each listed binary.'},
                {'title': 'Check effective write access', 'commands': access_cmds, 'look_for': access_look},
                {'title': 'Confirm actual library resolution for each affected binary', 'commands': resolution_cmds, 'look_for': 'Verify that a required library is actually resolved from the writable/current-directory search location. Presence of RPATH/RUNPATH alone is insufficient.'},
                {'title': 'Establish execution privilege/context for each affected binary', 'commands': context_cmds, 'look_for': 'Identify SUID/SGID, capabilities, sudoers use, or a root/privileged service that invokes the binary.'},
                {'title': 'Perform controlled validation only if Steps 1-4 support impact', 'commands': [], 'look_for': 'Use a harmless test library or equivalent controlled marker appropriate to the dependency. Demonstrate only that controlled code would load in the assessed environment; do not alter unrelated OS files.'},
            ],
            'secure_result': "The search location is not attacker-writable, no affected binary loads a dependency from it, or the affected binaries execute only with the attacker's existing privileges.",
            'vulnerable_result': 'A low-privileged user can control a library that an affected binary loads when that binary executes with greater privilege.',
            'evidence': evidence + [f"namei -l {_q(lib_path)}", f"getfacl {_q(lib_path)}", 'Library-resolution output and evidence of the privileged execution path for each affected binary that contributes to the finding.'],
            'stop_conditions': ['Stop for any affected binary if the location is not effectively writable, that binary does not load from the location, or no meaningful elevated execution path exists. Report only the binaries for which the complete condition is validated.'],
        })
        return pb

    if category == 'SVC':
        unit = str(item.get('service_unit') or _service_name(condition) or '<unit.service>')
        target = str(item.get('service_path') or _first_path(condition) or '<referenced-path>')
        path_type = str(item.get('service_path_type') or 'ReferencedPath')
        role_text = {
            'ExecStart': 'an executable in the service execution chain',
            'EnvironmentFile': 'an EnvironmentFile consumed by the service',
            'WorkingDirectory': 'the service working directory',
            'UnitFile': 'the systemd unit file',
            'DropIn': 'a systemd drop-in configuration file',
            'ConfigurationDependency': 'configuration/data consumed by the service execution chain',
            'ReferencedPath': 'a filesystem path consumed by the service execution chain',
        }.get(path_type, f'a {path_type} path consumed by the service')
        pb.update({
            'goal': 'Determine whether an unprivileged user can alter content consumed by a privileged systemd service and thereby change privileged behavior.',
            'steps': [
                {'title': 'Confirm service identity and configuration', 'commands': [f"systemctl show {_q(unit)} -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory -p FragmentPath", f"systemctl cat {_q(unit)}"], 'look_for': f'An empty User= on a system service normally means root. The highlighted path is classified as {role_text}; confirm that classification in the real service execution path.'},
                {'title': 'Check file and parent-directory access', 'commands': [f"stat {_q(target)}", f"namei -l {_q(target)}", f"getfacl {_q(target)}", f"test -w {_q(target)} && echo WRITABLE || echo NOT_WRITABLE"], 'look_for': 'Confirm effective low-privileged write/replace access. A non-writable file may still be replaceable if its parent directory is writable.'},
                {'title': 'Understand how the service consumes the path', 'commands': [f"journalctl -u {_q(unit)} --since '10 minutes ago' --no-pager"], 'look_for': 'Determine whether the path controls an executable, arguments, environment, library/configuration, update source, or other security-sensitive input.'},
                {'title': 'Perform a controlled validation change', 'commands': [], 'look_for': 'Make a harmless protocol/configuration-valid marker change, trigger the normal service workflow, and observe whether the privileged process consumes it.'},
            ],
            'evidence': [f"systemctl cat {_q(unit)}", f"systemctl show {_q(unit)} -p User -p Group -p ExecStart", f"namei -l {_q(target)}", f"getfacl {_q(target)}", 'Sanitized evidence that the privileged service consumed the benign tester-controlled change.'],
            'stop_conditions': ['Do not report if the tester cannot effectively influence the path, the service does not consume it, or the service does not cross a meaningful privilege boundary.'],
        })
        return pb

    if category in {'SUID', 'CAP'}:
        target = _first_path(condition) or condition.split()[0] if condition.split() else '<helper>'
        pb.update({
            'goal': 'Determine whether the application helper grants capabilities/elevated identity in a way that untrusted input can abuse.',
            'steps': [
                {'title': 'Confirm privilege metadata', 'commands': [f"stat {_q(target)}", f"getcap {_q(target)}"], 'look_for': 'Confirm SUID/SGID ownership or the exact Linux capabilities.'},
                {'title': 'Understand intended invocation', 'commands': [f"strings {_q(target)} | head -n 200", f"ldd {_q(target)} 2>/dev/null || true"], 'look_for': 'Identify normal arguments, files, environment variables, external commands, libraries, and trust boundaries.'},
                {'title': 'Exercise as the low-privileged tester', 'commands': [], 'look_for': 'Use only normal/authorized application inputs. Check for unsafe path handling, argument injection, environment influence, arbitrary file read/write, or command execution.'},
            ],
            'stop_conditions': ['Do not report capability/SUID presence alone; demonstrate attacker influence and security impact.'],
        })
        return pb

    if category == 'PERS' and ('sudo' in title.casefold() or 'sudo' in condition.casefold()):
        pb.update({
            'goal': 'Determine the exact sudo privilege granted to the test user and whether command, argument, environment, wildcard, or executable-chain control allows unintended privileged behavior.',
            'steps': [
                {'title': 'Validate sudoers syntax', 'commands': ['sudo visudo -c'], 'look_for': 'The policy should parse cleanly. Record the policy file identified by the assessment.'},
                {'title': 'Inspect effective rights for the test user', 'commands': ['sudo -l'], 'look_for': 'Record the RunAs target, command path, allowed arguments, NOPASSWD/SETENV tags, wildcards, and environment behavior.'},
                {'title': 'Inspect the permitted executable chain', 'commands': [], 'look_for': 'Check ownership/permissions of the allowed executable, parent directories, scripts/interpreters, libraries, configs, plugins, and any files it consumes.'},
                {'title': 'Perform only benign authorized validation', 'commands': [], 'look_for': 'Use the exact allowed sudo rule. Determine whether permitted arguments/environment/input can cause an unintended privileged action without exceeding the rule.'},
            ],
            'secure_result': 'The rule is narrowly scoped, its complete execution chain is protected, and attacker-controlled arguments/environment/input cannot escape the intended action.',
            'vulnerable_result': 'The low-privileged user can leverage the granted sudo rule to perform unintended privileged actions or execute attacker-controlled content as the RunAs identity.',
            'evidence': ['sudo visudo -c', 'sudo -l', 'Relevant sudoers entry with secrets redacted', 'Ownership/permission evidence for the allowed executable chain', 'Benign proof of unintended privileged behavior if demonstrated.'],
            'stop_conditions': ['Do not report broad-looking syntax alone if effective sudo rights are constrained and no unintended privileged action can be demonstrated.'],
        })
        return pb

    if category in {'IPC', 'RUNTIME-IPC'} and ('fifo' in title.casefold() or 'fifo' in condition.casefold()):
        path = _first_path(condition) or '<fifo-path>'
        pb.update({
            'goal': 'Determine whether an unauthorized local user can write meaningful input to an application FIFO that is consumed by a more privileged process.',
            'steps': [
                {'title': 'Confirm FIFO and permissions', 'commands': [f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}", f"test -w {_q(path)} && echo WRITABLE || echo NOT_WRITABLE"], 'look_for': 'Confirm it is a FIFO and determine whether the low-privileged tester can write to it.'},
                {'title': 'Identify readers/writers', 'commands': [f"sudo lsof {_q(path)} 2>/dev/null || true", f"sudo fuser -v {_q(path)} 2>/dev/null || true"], 'look_for': 'Map the FIFO to the owning application/service and privilege level.'},
                {'title': 'Understand the expected message format', 'commands': [], 'look_for': 'Observe legitimate application behavior, logs, or documented protocol. Do not send arbitrary destructive data to an unknown privileged parser.'},
                {'title': 'Perform a benign protocol-valid write if authorized', 'commands': [], 'look_for': 'Use a harmless request/marker and determine whether an unauthorized caller can cause an accepted privileged action.'},
            ],
            'stop_conditions': ['Do not report world-writable FIFO permissions alone if unauthorized messages are rejected or the FIFO is not part of a meaningful privileged trust boundary.'],
        })
        return pb

    if category in {'IPC', 'RUNTIME-IPC'}:
        path = _first_path(condition) or '<socket-path>'
        pb.update({
            'goal': 'Determine whether an unauthorized local caller can interact with the Unix-domain socket and cause an action beyond its intended authorization.',
            'steps': [
                {'title': 'Confirm socket permissions and ownership', 'commands': [f"ls -l {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}", f"sudo ss -lxnp | grep -F {_q(path)} || true", f"sudo lsof -U | grep -F {_q(path)} || true"], 'look_for': 'Identify the owning process/service, its privilege, and whether the low-privileged tester can connect.'},
                {'title': 'Observe the legitimate protocol', 'commands': [], 'look_for': 'Use application logs or benign client activity to understand message framing and expected authorization.'},
                {'title': 'Connect as the low-privileged tester', 'commands': [f"nc -U {_q(path)}"], 'look_for': 'Expected secure behavior is rejection of unauthorized requests. Use only harmless requests consistent with the observed protocol.'},
            ],
            'stop_conditions': ['Do not report writable/connectable socket permissions alone if the service independently authenticates/authorizes callers and no unauthorized action is possible.'],
        })
        return pb

    if category == 'DBUS':
        bus_name = condition.split(':')[-1].strip() if ':' in condition else condition.strip()
        pb.update({
            'goal': 'Determine whether the application D-Bus service exposes methods/properties that an unauthorized caller can invoke across a trust boundary.',
            'steps': [
                {'title': 'Identify the correct bus and owning service', 'commands': [f"busctl --system list | grep -F {_q(bus_name)} || true", f"busctl --user list | grep -F {_q(bus_name)} || true"], 'look_for': 'Use the bus on which the name is actually present; do not assume system vs user bus.'},
                {'title': 'Read-only introspection', 'commands': [f"gdbus introspect --system --dest {_q(bus_name)} --object-path /", f"gdbus introspect --session --dest {_q(bus_name)} --object-path /"], 'look_for': 'Enumerate objects/interfaces/methods without invoking state-changing methods.'},
                {'title': 'Review authorization policy', 'commands': [], 'look_for': 'Inspect D-Bus policy and any PolicyKit action associated with sensitive methods. Identify which caller identity/authorization should be required.'},
                {'title': 'Perform authorized benign method validation', 'commands': [], 'look_for': 'Only after understanding the interface, invoke a harmless method as the low-privileged tester and verify unauthorized sensitive operations are rejected.'},
            ],
            'stop_conditions': ['Do not invoke unknown state-changing methods simply because introspection is available. Do not report service visibility alone.'],
        })
        return pb

    if category == 'POLKIT' or (category == 'PERS' and ('policykit' in title.casefold() or 'polkit' in condition.casefold())):
        pb.update({
            'goal': 'Determine whether a PolicyKit action permits an untrusted local caller to perform a sensitive privileged operation without the intended authentication/authorization.',
            'steps': [
                {'title': 'Inspect the action defaults', 'commands': ['grep -R -E "<action|allow_any|allow_inactive|allow_active" /usr/share/polkit-1/actions /etc/polkit-1 2>/dev/null'], 'look_for': 'Identify the exact action ID and effective allow_any/allow_inactive/allow_active values.'},
                {'title': 'Identify the privileged operation protected by the action', 'commands': [], 'look_for': 'Map the action to the D-Bus/service method or helper it authorizes.'},
                {'title': 'Validate as the normal low-privileged user', 'commands': [], 'look_for': 'Attempt only a harmless instance of the protected operation and confirm whether authentication or authorization is enforced.'},
            ],
            'stop_conditions': ['Do not report permissive-looking metadata alone if the action does not guard a meaningful privileged operation or another effective authorization check prevents abuse.'],
        })
        return pb

    if category in {'NET', 'RUNTIME'} and 'listener' in title.casefold():
        pb.update({
            'goal': 'Determine whether the application listener is intentionally exposed and whether remote/local clients are appropriately authenticated and authorized.',
            'steps': [
                {'title': 'Confirm owner and bind scope', 'commands': ['sudo ss -lntupn', 'sudo lsof -i -n -P'], 'look_for': 'Map the port to the assessed application process and confirm loopback vs wildcard/interface-specific binding.'},
                {'title': 'Identify the protocol and expected clients', 'commands': [], 'look_for': 'Use normal application traffic/documentation to determine protocol and expected trust boundary.'},
                {'title': 'Perform in-scope access-control/input testing', 'commands': [], 'look_for': 'Verify authentication/authorization and benign malformed-input handling from only permitted assessment locations.'},
            ],
            'stop_conditions': ['Do not report an externally bound listener solely because it is reachable; establish unintended exposure or a concrete control weakness.'],
        })
        return pb

    if category in {'COMM', 'UPD'}:
        pb.update({
            'goal': 'Determine whether the cleartext/update endpoint is used by a security-sensitive workflow and whether independent integrity/authentication controls prevent manipulation.',
            'steps': [
                {'title': 'Confirm runtime use', 'commands': ['sudo tcpdump -i any -nn -s0 -w uca-validation.pcap'], 'look_for': 'Exercise the relevant workflow and verify whether the application actually contacts the reported endpoint.'},
                {'title': 'Determine data/update sensitivity', 'commands': [], 'look_for': 'Identify credentials, session material, commands, manifests, binaries, or update metadata carried by the channel.'},
                {'title': 'Check independent integrity/authentication', 'commands': [], 'look_for': 'For updates, verify cryptographic signature/authentication of manifests/packages independent of transport. For ordinary endpoints, verify appropriate TLS/authentication expectations.'},
            ],
            'stop_conditions': ['Do not report a static URL merely because it uses http://; confirm the real workflow and security impact.'],
        })
        return pb

    if category == 'CRYPTO':
        path = str(item.get('crypto_path') or _first_path(condition) or '<cryptographic-material-path>')
        certs = [str(x) for x in (item.get('crypto_certificates') or []) if str(x).strip()]
        cert_cmds: list[str] = []
        for cert in certs[:5]:
            cert_cmds.append(f"openssl x509 -in {_q(cert)} -noout -subject -issuer -text")
        if not cert_cmds:
            cert_cmds = ['openssl x509 -in <CERTIFICATE> -noout -subject -issuer -text']
        pb.update({
            'goal': 'Determine whether locally generated certificate/private-key material can be recovered or used by a principal outside the intended application trust boundary.',
            'steps': [
                {'title': 'Identify the certificate and its role', 'commands': cert_cmds, 'look_for': 'Determine whether the certificate is a CA certificate (Basic Constraints CA:TRUE), whether it is self-signed/local, and where that CA is trusted. A certificate by itself is public material and is not a secret.'},
                {'title': 'Locate and classify associated private-key material', 'commands': [f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}"], 'look_for': 'Confirm whether the highlighted file contains or references private signing/key material. Do not copy raw private keys, passwords, or tokens into UbuntuClientAssess reports or tester notes.'},
                {'title': 'Determine who can read or modify the material', 'commands': [f"test -r {_q(path)} && echo READABLE || echo NOT_READABLE", f"test -w {_q(path)} && echo WRITABLE || echo NOT_WRITABLE"], 'look_for': 'Establish whether a lower-privileged local user can recover or alter the private key/key-protection material.'},
                {'title': 'Determine the role of any salt or key-protection fields', 'commands': [], 'look_for': 'A salt is normally non-secret KDF input. Determine whether the application also stores the password/key/derivation material needed to recover the private key; do not treat a salt stored in configuration as a vulnerability by itself.'},
                {'title': 'Establish trust-boundary impact', 'commands': [], 'look_for': 'Determine whether possession or use of the private key would allow the tester to issue certificates accepted by a more privileged application, service, local interception component, or other trust domain.'},
            ],
            'secure_result': 'Private signing material is protected from unauthorized local users, or possession of the highlighted material does not permit certificate issuance across a meaningful trust boundary.',
            'vulnerable_result': 'A lower-privileged user can recover or use CA/private signing material and issue certificates that are trusted by a more privileged application, service, or trust domain.',
            'stop_conditions': ['Do not report a CA certificate merely because it exists or is readable; certificates are public material.', 'Do not report a salt merely because it is stored in configuration; establish recoverable key material and security impact.', 'Stop if the private key is not accessible/usable by the lower-privileged tester or the generated certificate is not trusted across a meaningful boundary.'],
        })
        return pb

    if category in {'STOR', 'STORCFG'}:
        path = _first_path(condition) or '<storage-path>'
        pb.update({
            'goal': 'Determine whether the identified local data contains real sensitive material and whether it is exposed beyond the intended user/application trust boundary.',
            'steps': [
                {'title': 'Inspect metadata without copying secrets into reports', 'commands': [f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}"], 'look_for': 'Determine ownership, permissions, ACLs, and which users/processes can read or modify the data.'},
                {'title': 'Validate the indicator on the assessment VM', 'commands': [f"sudo less {_q(path)}"], 'look_for': 'Confirm whether the value is a real credential/token/session/configuration setting. Do not copy secrets into reports or tester notes, and do not paste raw values into the framework.'},
                {'title': 'Determine usability/exposure', 'commands': [], 'look_for': 'Establish whether another principal can access/use the material or whether the insecure setting is active at runtime.'},
            ],
            'stop_conditions': ['Do not report placeholder/example values, schema field names, or appropriately protected per-user secrets as vulnerabilities without additional impact.'],
        })
        return pb

    if category == 'PERM':
        path = _first_path(condition) or '<path>'
        pb.update({
            'goal': 'Determine whether the observed file/ACL permissions allow a lower-privileged user to alter or read a security-sensitive application object across an intended boundary.',
            'steps': [
                {'title': 'Inspect effective access', 'commands': [f"stat {_q(path)}", f"namei -l {_q(path)}", f"getfacl {_q(path)}", f"test -w {_q(path)} && echo WRITABLE || true", f"test -r {_q(path)} && echo READABLE || true"], 'look_for': 'Evaluate mode bits, parent traversal/replaceability, group membership, and named ACLs.'},
                {'title': 'Identify the consuming process/trust boundary', 'commands': [], 'look_for': 'Determine which application/service uses the object and with what identity/privilege.'},
                {'title': 'Perform controlled validation if needed', 'commands': [], 'look_for': 'Make only the harmless change/read test necessary to prove impact.'},
            ],
        })
        return pb

    # Generic fallback retains existing concise validation steps but makes the
    # interpretation explicit for junior testers.
    pb['steps'] = [
        {'title': f'Validation step {idx}', 'commands': [], 'look_for': str(step)}
        for idx, step in enumerate(item.get('validation', []) or ['Validate the condition in the actual application context.'], 1)
    ]
    return pb


def render_playbook_lines(playbook: dict[str, Any], *, indent: str = '') -> list[str]:
    lines: list[str] = [f"{indent}Goal", f"{indent}----", f"{indent}{playbook.get('goal', '')}", '']
    for idx, step in enumerate(playbook.get('steps', []) or [], 1):
        title = str(step.get('title') or f'Step {idx}')
        lines += [f"{indent}Step {idx} — {title}", f"{indent}{'-' * min(72, len('Step 00 — ') + len(title))}"]
        commands = list(step.get('commands', []) or [])
        if commands:
            lines.append(f"{indent}Commands:")
            lines += [f"{indent}  {cmd}" for cmd in commands]
        if step.get('look_for'):
            lines += [f"{indent}What to look for:", f"{indent}  {step['look_for']}"]
        lines.append('')
    lines += [f"{indent}Expected Secure Behavior", f"{indent}------------------------", f"{indent}{playbook.get('secure_result', '')}", '', f"{indent}Potentially Vulnerable Behavior", f"{indent}-------------------------------", f"{indent}{playbook.get('vulnerable_result', '')}", '']
    if playbook.get('stop_conditions'):
        lines += [f"{indent}Do Not Report / Stop If", f"{indent}-----------------------"] + [f"{indent}- {x}" for x in playbook['stop_conditions']] + ['']
    return lines
