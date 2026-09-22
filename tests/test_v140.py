from __future__ import annotations

from pathlib import Path
import json
import os
import socket


def _scope(monkeypatch):
    import modules.app_scope as scope
    monkeypatch.setattr(scope, 'run_cmd', lambda *a, **k: {'returncode': 0, 'stdout': 'uca-vulnerable-lab\n', 'stderr': ''})
    paths = [
        Path('/opt/uca-lab/bin/uca-lab-service.py'),
        Path('/etc/uca-lab/client.conf'),
        Path('/usr/lib/uca-lab/config.json'),
        Path('/var/lib/uca-lab/state.db'),
        Path('/usr/bin/uca-lab'),
        Path('/usr/lib/systemd/system/uca-lab.service'),
        Path('/usr/share/applications/uca-lab.desktop'),
    ]
    return scope.infer_debian_application_scope(Path('/tmp/fake.deb'), paths)


def test_v140_version_contract():
    from modules.common import VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION
    assert (VERSION, METHODOLOGY_VERSION, TEST_CASE_CATALOG_VERSION) == ('2.0.6', '2.4', '1.1')


def test_scope_infers_primary_root_and_launcher(monkeypatch):
    data = _scope(monkeypatch)
    assert data['application_root'] == '/opt/uca-lab'
    assert data['application_path'] == '/usr/bin/uca-lab'
    assert data['application_slug'] == 'uca-lab'


def test_scope_retains_application_specific_roots(monkeypatch):
    data = _scope(monkeypatch)
    assert data['application_roots'] == ['/etc/uca-lab', '/opt/uca-lab', '/usr/lib/uca-lab', '/var/lib/uca-lab']


def test_scope_excludes_generic_system_roots(monkeypatch):
    data = _scope(monkeypatch)
    assert '/usr/lib/systemd' not in data['application_roots']
    assert '/usr/share/applications' not in data['application_roots']


def test_runtime_roots_are_application_specific(monkeypatch, tmp_path):
    import modules.app_scope as scope
    monkeypatch.setattr(scope, 'get_interactive_home', lambda: tmp_path)
    data = _scope(monkeypatch)
    roots = scope.discover_runtime_roots(data, existing_only=False)
    assert Path('/run/uca-lab') in roots
    assert tmp_path / '.local/share/uca-lab' in roots
    assert tmp_path / '.config/uca-lab' in roots
    assert tmp_path / '.config' not in roots


def test_path_within_scope_matches_descendant(tmp_path):
    from modules.app_scope import path_within_scope
    root = tmp_path / 'vendor'; child = root / 'data' / 'x'
    assert path_within_scope(child, [root])
    assert not path_within_scope(tmp_path / 'other', [root])


def test_profile_scope_ignores_ambient_electron(tmp_path):
    from modules.application_profile import profile_application
    app = tmp_path / 'app'; ambient = tmp_path / 'ambient'
    app.mkdir(); ambient.mkdir()
    for name in ('client.py', 'service.py', 'helper.py'):
        (app / name).write_text('print("x")\n')
    (ambient / 'app.asar').write_bytes(b'asar')
    diff = {'files_added': [str(app/name) for name in ('client.py', 'service.py', 'helper.py')] + [str(ambient/'app.asar')], 'files_changed': []}
    data = profile_application(tmp_path/'assessment', diff=diff, extra_roots=[app])
    assert data['primary_technology'] == 'Python'
    assert all(item['technology'] != 'Electron / Chromium' for item in data['technologies'])


def test_profile_report_records_scope_roots(tmp_path):
    from modules.application_profile import profile_application
    app = tmp_path / 'app'; app.mkdir(); (app/'a.py').write_text('pass\n')
    profile_application(tmp_path/'assessment', extra_roots=[app])
    text = (tmp_path/'assessment/reports/application_profile.txt').read_text()
    assert 'Application scope roots:' in text and str(app) in text


def test_socket_normalization_removes_inet_queue_churn():
    from modules.snapshot import _normalize_socket_lines
    a = 'tcp LISTEN 0 8 0.0.0.0:18080 0.0.0.0:* users:(("python3",pid=1,fd=5))'
    b = 'tcp LISTEN 2 128 0.0.0.0:18080 0.0.0.0:* users:(("python3",pid=9,fd=7))'
    assert _normalize_socket_lines([a]) == _normalize_socket_lines([b])


def test_scoped_network_suppresses_unattributed_listener(tmp_path):
    from modules.network import review_network
    app = tmp_path/'app'; app.mkdir()
    data = review_network({'listening_sockets_added':['tcp LISTEN 0 8 0.0.0.0:5353 0.0.0.0:*']}, tmp_path/'out', [app])
    assert data['exposed_listener_candidates'] == []


def test_unscoped_network_preserves_listener_review(tmp_path):
    from modules.network import review_network
    data = review_network({'listening_sockets_added':['tcp LISTEN 0 8 0.0.0.0:9999 0.0.0.0:*']}, tmp_path)
    assert data['exposed_listener_candidates']


def test_ipc_scope_filters_unrelated_pathname_sockets(tmp_path):
    from modules.ipc import review_ipc
    app = tmp_path/'uca-lab'; app.mkdir()
    own = app/'control.sock'; other = tmp_path/'codex.sock'
    diff = {'unix_sockets_added':[f'u_str LISTEN 0 4 {own} 1 * 0', f'u_str LISTEN 0 4 {other} 2 * 0']}
    data = review_ipc(diff, tmp_path/'assessment', [app])
    assert len(data['unix_sockets']) == 1 and str(own) in data['unix_sockets'][0]


def test_dbus_systemdservice_is_not_bus_name(monkeypatch, tmp_path):
    import modules.ipc as ipc
    monkeypatch.setattr(ipc, 'command_exists', lambda name: False)
    d = tmp_path/'usr/share/dbus-1/system-services'; d.mkdir(parents=True)
    f=d/'com.example.Service.service'
    f.write_text('[D-BUS Service]\nName=com.example.Service\nSystemdService=example.service\n')
    data=ipc.review_ipc({'files_added':[str(f)]}, tmp_path/'assessment')
    assert data['dbus_names'] == ['com.example.Service']


def test_runtime_poll_interval_is_faster_than_v13():
    from modules.runtime_observation import DEFAULT_POLL_INTERVAL
    assert 0.1 <= DEFAULT_POLL_INTERVAL <= 0.5


def test_runtime_socket_path_scope_correlates_without_pid(tmp_path):
    from modules.runtime_observation import analyze_samples
    root=tmp_path/'run/uca-lab'; root.mkdir(parents=True)
    sock=root/'control.sock'
    samples=[{'processes':[], 'listeners':[], 'connections':[], 'unix_sockets':[f'u_str LISTEN 0 4 {sock} 123 * 0']}]
    data=analyze_samples(samples, [], [root])
    assert data['unix_sockets'] and str(sock) in data['unix_sockets'][0]


def test_runtime_recent_connection_correlates_by_application_listener_port():
    from modules.runtime_observation import analyze_samples
    samples=[{
        'processes':[{'pid':10,'ppid':1,'user':'root','group':'root','comm':'python3','args':'python3 /opt/uca-lab/bin/uca-lab-service.py'}],
        'listeners':['tcp LISTEN 0 8 0.0.0.0:18080 0.0.0.0:* users:(("python3",pid=10,fd=5))'],
        'connections':['tcp TIME-WAIT 0 0 127.0.0.1:18080 127.0.0.1:45000'],
        'unix_sockets':[],
    }]
    data=analyze_samples(samples, ['/opt/uca-lab'])
    assert data['connections'] and '18080' in data['connections'][0]


def test_fifo_discovery_under_runtime_root(tmp_path):
    from modules.runtime_observation import _fifo_paths
    root=tmp_path/'run'; root.mkdir(); fifo=root/'commands.fifo'; os.mkfifo(fifo)
    assert _fifo_paths([root]) == [str(fifo)]


def test_runtime_observation_records_fifo_paths(monkeypatch, tmp_path):
    import modules.runtime_observation as ro
    root=tmp_path/'run'; root.mkdir(); fifo=root/'commands.fifo'; os.mkfifo(fifo)
    monkeypatch.setattr(ro, '_sample', lambda **k: {'captured_at':'now','processes':[],'listeners':[],'connections':[],'unix_sockets':[]})
    data=ro.collect_runtime_observation(tmp_path/'assessment', filesystem_roots=[root], duration_seconds=0)
    assert str(fifo) in data['fifo_paths']


def test_elf_playbook_is_junior_detailed():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'ELF','title':'ELF Library Search Path Requires Validation','condition':'/opt/uca/bin/app: RPATH=/opt/uca/lib; directory world-writable','evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'readelf -d' in text and 'ldd ' in text and 'Do Not Report / Stop If' in text


def test_service_playbook_explains_systemd_and_permissions():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'SVC','title':'Privileged Service Path Requires Validation','condition':'uca.service references EnvironmentFile /opt/uca/config: writable','evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'systemctl show' in text and 'namei -l' in text and 'Potentially Vulnerable Behavior' in text


def test_sudo_playbook_has_effective_rights_validation():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'PERS','title':'Changed sudoers Policy Requires Manual Review','condition':'sudo rule','evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'sudo visudo -c' in text and 'sudo -l' in text


def test_unix_socket_playbook_has_peer_authorization_steps():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'IPC','title':'Application Unix Socket Trust Boundary','condition':'/run/uca/control.sock','evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'sudo ss -lxnp' in text and 'nc -U' in text


def test_fifo_playbook_is_separate_from_socket():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'IPC','title':'Named FIFO Trust Boundary','condition':'/run/uca/commands.fifo','evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'Identify readers/writers' in text and 'fuser -v' in text and 'nc -U' not in text


def test_dbus_playbook_checks_both_buses():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'DBUS','title':'D-Bus Interface Requires Authorization Review','condition':'Referenced bus name: com.example.Service','evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'busctl --system list' in text and 'busctl --user list' in text


def test_polkit_playbook_explains_action_mapping():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'POLKIT','title':'PolicyKit Authorization Requires Validation','condition':'Action com.example.admin','evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'PolicyKit' in text and 'privileged operation protected by the action' in text


def test_storage_playbook_warns_not_to_copy_secrets():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'STOR','title':'Potential Credential or Token Storage','condition':'/var/lib/uca/credentials.conf contains token','evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'do not copy secrets into reports' in text.lower() and 'sudo less' in text


def test_findings_use_recommended_validation_not_remediation(tmp_path):
    from modules.findings import generate_findings
    generate_findings(tmp_path, {}, {}, {'risk_candidates':[{'privileged':True,'unit':'uca.service','path_type':'EnvironmentFile','path':'/opt/uca/config','concerns':'world-writable'}]}, {}, {}, {}, {})
    text=(tmp_path/'reports/findings.txt').read_text()
    assert 'VALIDATION PROCEDURE' in text
    assert 'Recommendation:' not in text
    assert 'systemctl show' in text


def test_tester_review_report_renders_detailed_playbook(tmp_path):
    from modules.tester_review import generate_tester_review
    generate_tester_review(tmp_path, elf_data={'finding_candidates':[{'binary':'/opt/uca/app','kind':'RPATH','path':'/opt/uca/lib','concern':'writable','finding_candidate':True}]})
    text=(tmp_path/'reports/tester_review.txt').read_text()
    assert 'Detailed Validation Procedure' in text and 'Expected Secure Behavior' in text


def test_evidence_guide_reuses_playbook_evidence(tmp_path):
    from modules.tester_review import generate_tester_review
    generate_tester_review(tmp_path, service_data={'risk_candidates':[{'unit':'uca.service','path':'/opt/uca/config','path_type':'EnvironmentFile','concerns':'writable','privileged':True}]})
    text=(tmp_path/'reports/evidence_guide.txt').read_text()
    assert 'systemctl cat' in text and 'namei -l' in text


def test_review_queue_adds_permissive_polkit_item():
    from modules.tester_review import build_review_items
    items=build_review_items(ipc_data={'polkit_details':[{'action':'com.example.admin','path':'/usr/share/polkit-1/actions/example.policy','defaults':{'allow_any':'yes'},'permissive_review':True}]})
    assert any(x['category']=='POLKIT' and x['priority']=='HIGH' for x in items)


def test_recovery_info_allows_post_analysis_with_both_snapshots(tmp_path):
    import ubuntuclientassess as uca
    from modules.common import write_json
    (tmp_path/'working').mkdir()
    write_json(tmp_path/'assessment_metadata.json', {'mode':'full','run_state':{'status':'interrupted','stage':'post-analysis'},'installation':{'status':'completed'}})
    write_json(tmp_path/'working/snapshot_pre.json', {'schema_version':6})
    write_json(tmp_path/'working/snapshot_post.json', {'schema_version':6})
    info=uca._assessment_recovery_info(tmp_path)
    assert info['status']=='RECOVERABLE' and info['action']=='post-analysis'


def test_recovery_info_requires_vm_reset_after_partial_install(tmp_path):
    import ubuntuclientassess as uca
    from modules.common import write_json
    (tmp_path/'working').mkdir()
    write_json(tmp_path/'assessment_metadata.json', {'mode':'full','run_state':{'status':'interrupted','stage':'installation'},'installation':{'status':'interrupted'}})
    write_json(tmp_path/'working/snapshot_pre.json', {'schema_version':6})
    info=uca._assessment_recovery_info(tmp_path)
    assert info['status']=='VM RESET REQUIRED' and info['action']=='reset'


def test_cli_exposes_v140_recovery_flags():
    import subprocess, sys
    script=Path(__file__).resolve().parents[1]/'ubuntuclientassess.py'
    text=subprocess.run([sys.executable,str(script),'--help'],capture_output=True,text=True,check=True).stdout
    assert '--assessment-status' in text and '--resume-assessment' in text


def test_review_queue_groups_only_equivalent_elf_paths():
    from modules.tester_review import build_review_items
    elf = {
        'finding_candidates': [
            {'binary':'/opt/app/a','kind':'RPATH','path':'/opt/app/lib','concern':'Library search directory is world-writable','finding_candidate':True},
            {'binary':'/opt/app/b','kind':'RPATH','path':'/opt/app/lib','concern':'Library search directory is world-writable','finding_candidate':True},
            {'binary':'/opt/app/c','kind':'RUNPATH','path':'/opt/app/lib','concern':'Library search directory is world-writable','finding_candidate':True},
        ]
    }
    items = [item for item in build_review_items(elf_data=elf) if item['category'] == 'ELF']
    assert len(items) == 2
    grouped = next(item for item in items if item['title'] == 'ELF Library Search Paths Require Validation')
    assert '/opt/app/a' in grouped['condition'] and '/opt/app/b' in grouped['condition']
    assert '/opt/app/c' not in grouped['condition']


def test_runtime_context_keeps_expected_root_before_creation(tmp_path):
    import ubuntuclientassess as uca
    assessment = tmp_path / 'assessment'; assessment.mkdir()
    expected = tmp_path / 'home' / '.local' / 'share' / 'vendor-client'
    metadata = {'expected_runtime_roots': [str(expected)]}
    hints, roots = uca._runtime_application_context(assessment, metadata)
    assert expected.resolve(strict=False) in roots


def test_runtime_observation_captures_root_created_during_window(monkeypatch, tmp_path):
    import threading, time
    import modules.runtime_observation as ro
    root = tmp_path / 'not-yet-created'
    monkeypatch.setattr(ro, '_sample', lambda **kwargs: {'captured_at':'x','processes':[],'listeners':[],'connections':[],'unix_sockets':[]})
    def create_later():
        time.sleep(0.15)
        root.mkdir(parents=True)
        (root / 'state.json').write_text('{}')
    t = threading.Thread(target=create_later); t.start()
    data = ro.collect_runtime_observation(tmp_path/'assessment', filesystem_roots=[root], duration_seconds=0.35, poll_interval=0.1)
    t.join()
    assert str(root) in data['filesystem_roots']
    assert str(root / 'state.json') in data['file_activity']['created']


def test_runtime_progress_callback_includes_fifo(monkeypatch, tmp_path):
    import modules.runtime_observation as ro
    root = tmp_path / 'app'; root.mkdir()
    fifo = root / 'commands.fifo'; fifo.touch()
    monkeypatch.setattr(ro, '_fifo_paths', lambda roots: [str(fifo)])
    monkeypatch.setattr(ro, '_sample', lambda **kwargs: {'captured_at':'x','processes':[],'listeners':[],'connections':[],'unix_sockets':[]})
    seen=[]
    ro.collect_runtime_observation(tmp_path/'assessment', filesystem_roots=[root], duration_seconds=0.12, poll_interval=0.1, progress_callback=lambda data: seen.append(data))
    assert any(str(fifo) in item.get('fifo_paths', []) for item in seen)


def test_grouped_elf_playbook_validates_each_binary():
    from modules.tester_review import build_review_items
    from modules.validation_guidance import playbook_for, render_playbook_lines
    elf={'finding_candidates':[
        {'binary':'/opt/app/a','kind':'RPATH','path':'/opt/app/lib','concern':'Library search directory is world-writable','finding_candidate':True},
        {'binary':'/opt/app/b','kind':'RPATH','path':'/opt/app/lib','concern':'Library search directory is world-writable','finding_candidate':True},
    ]}
    item=next(x for x in build_review_items(elf_data=elf) if x['category']=='ELF')
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'readelf -d /opt/app/a' in text
    assert 'readelf -d /opt/app/b' in text
    assert 'Grouped entries must be validated for each listed binary.' in text


def test_empty_rpath_playbook_explains_real_working_directory():
    from modules.validation_guidance import playbook_for, render_playbook_lines
    item={'category':'ELF','title':'ELF Library Search Path Requires Validation','condition':'/opt/app/a: RPATH=<empty/current directory>; empty component','search_path':'','search_kind':'RPATH','validation_targets':['/opt/app/a'],'evidence':[]}
    text='\n'.join(render_playbook_lines(playbook_for(item)))
    assert 'readlink -f /proc/<PID>/cwd' in text
    assert 'working directory of the real execution path' in text
