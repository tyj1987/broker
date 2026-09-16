#!/usr/bin/env python3
"""Disposable GitHub-hosted Linux runner only; never deploy this fixture.

Uses real systemd, service UIDs, ACLs, AF_UNIX and native/Node processes, with
synthetic in-memory signing/store backends. No cloud or production evidence.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import time

BASE = Path('/opt/secret-broker')
CONFIG = Path('/etc/secret-broker')
DATA = Path('/var/lib/secret-broker')
RUN = [Path('/run/secret-broker-audit-anchor'), Path('/run/secret-broker-audit-store'), Path('/run/broker-ci-fixture')]
ACCOUNTS = ['broker', 'broker-audit-signer', 'broker-audit-store', 'broker-audit-exporter', 'broker-audit-recovery']
UNITS = ['secret-broker-audit-store.service', 'secret-broker-audit-signer.service', 'secret-broker-audit-exporter.service', 'secret-broker-audit-recovery.service']
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}

def run(*args, check=True, timeout=90):
    return subprocess.run([str(a) for a in args], check=check, timeout=timeout, env=ENV,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def require(value, message):
    if not value:
        raise RuntimeError(message)

def guard(source, node):
    expected = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': 'tyj1987/broker', 'GITHUB_EVENT_NAME': 'push', 'RUNNER_OS': 'Linux'}
    require(os.geteuid() == 0 and all(os.environ.get(k) == v for k, v in expected.items()), 'host guard refused')
    require(os.environ.get('GITHUB_REF', '').startswith('refs/heads/chatgpt/'), 'branch guard refused')
    require(re.fullmatch('[a-f0-9]{40}', os.environ.get('GITHUB_SHA', '')), 'SHA guard refused')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'systemd required')
    require(source.is_dir() and node.is_file() and not node.is_symlink(), 'build inputs unavailable')
    for path in [BASE, CONFIG, DATA, *RUN]:
        require(not path.exists() and not path.is_symlink(), 'existing host state refused')
    for name in ACCOUNTS:
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError('existing account refused')
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError('existing group refused')
    for name in UNITS:
        require(not Path('/etc/systemd/system', name).exists(), 'existing service refused')
        require(run('systemctl', 'show', name, '--property=LoadState', '--value').stdout.strip() == 'not-found', 'loaded service refused')

def save(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)

def package_acl(folder, user):
    for path in [folder, *folder.rglob('*')]:
        require(not path.is_symlink(), 'linked runtime refused')
        path.chmod(0o500 if path.is_dir() else 0o400)
        run('setfacl', '-m', f'u:{user}:r-x,m::r-x' if path.is_dir() else f'u:{user}:r--,m::r--', path)

def property_of(unit, prop):
    return run('systemctl', 'show', unit, f'--property={prop}', '--value').stdout.strip()

def wait_file(path):
    end = time.monotonic() + 8
    while not path.exists() and time.monotonic() < end:
        time.sleep(0.1)
    require(path.exists(), 'fixture startup failed')

def identity_check(unit, release, user):
    require(property_of(unit, 'ActiveState') == 'active', 'unit not active')
    pid = int(property_of(unit, 'MainPID'))
    require(Path(f'/proc/{pid}/exe').resolve() == release / 'bin' / unit.removesuffix('.service'), 'wrong native MainPID')
    status = Path(f'/proc/{pid}/status').read_text()
    require(f'Uid:\t{pwd.getpwnam(user).pw_uid}\t' in status, 'wrong UID')
    require(re.search(r'^NoNewPrivs:\s+1$', status, re.M), 'no-new-privileges absent')
    require(re.search(r'^CapEff:\s+0+$', status, re.M), 'effective capability present')
    require(re.search(r'^Seccomp:\s+2$', status, re.M), 'seccomp absent')
    require(os.readlink(f'/proc/{pid}/ns/net') != os.readlink('/proc/1/ns/net'), 'private network absent')
    require(property_of(unit, 'MemoryDenyWriteExecute') == 'yes', 'executable-memory restriction absent')
    require(property_of(unit, 'ProtectSystem') == 'strict', 'read-only system absent')

def integration(source, node, output):
    guard(source, node)
    created = []
    results = []
    sha = os.environ['GITHUB_SHA']
    release = BASE / 'releases' / sha
    try:
        for name in ACCOUNTS:
            run('useradd', '--system', '--no-create-home', '--user-group', '--shell', '/usr/sbin/nologin', name)
            created.append(name)
        for folder in [release / 'bin', BASE / 'runtime/node/bin', CONFIG / 'audit', DATA / 'audit', *RUN]:
            folder.mkdir(parents=True, exist_ok=True)
            folder.chmod(0o755)
        (BASE / 'broker').symlink_to(release, target_is_directory=True)
        shutil.copyfile(node, BASE / 'runtime/node/bin/node')
        (BASE / 'runtime/node/bin/node').chmod(0o755)
        for role in ['exporter', 'recovery']:
            binary = release / 'bin' / f'secret-broker-audit-{role}'
            shutil.copyfile(source / '.ci-audit' / binary.name, binary)
            binary.chmod(0o500)
            run('setfacl', '-m', f'u:broker-audit-{role}:r-x,m::r-x', binary)
            folder = release / f'{role}-runtime'
            shutil.copytree(source / 'broker' / f'{role}-runtime', folder)
            package_acl(folder, 'broker-audit-' + role)
            # Exact checked-in unit, no security-relaxing drop-in.
            save(Path('/etc/systemd/system', f'secret-broker-audit-{role}.service'),
                 (source / 'deploy/systemd' / f'secret-broker-audit-{role}.service').read_text())
        save(release / 'server.js', 'synthetic inaccessible Broker application\n', 0o400)
        for path, group in [(RUN[0], 'broker-audit-signer'), (RUN[1], 'broker-audit-store')]:
            os.chown(path, 0, grp.getgrnam(group).gr_gid)
            path.chmod(0o750)
        RUN[2].chmod(0o700)
        gids = [grp.getgrnam(n).gr_gid for n in ['broker-audit-exporter', 'broker-audit-recovery', 'broker-audit-signer', 'broker-audit-store']]
        fixture = source / 'broker-test/audit-process-fixture.mjs'
        require(not re.search(r'[\s%]', str(source)), 'unsupported CI workspace path')
        save(Path('/etc/systemd/system/secret-broker-audit-store.service'),
             '[Unit]\nDescription=CI synthetic in-memory audit fixture, NOT a production store\n[Service]\nType=simple\n'
             f'ExecStart={BASE}/runtime/node/bin/node {fixture} ' + ' '.join(map(str, gids)) + '\nKillMode=control-group\n')
        save(Path('/etc/systemd/system/secret-broker-audit-signer.service'),
             '[Unit]\nDescription=CI dependency marker, NOT a production signer\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', UNITS[0])
        wait_file(RUN[1] / 'store.sock')
        wait_file(CONFIG / 'audit/exporter.json')
        for path in [DATA, DATA / 'audit', DATA / 'audit/audit-chain-ci.jsonl']:
            for role in ['exporter', 'recovery']:
                access = 'r-x' if path.is_dir() else 'r--'
                run('setfacl', '-m', f'u:broker-audit-{role}:{access},m::{access}', path)
        run('systemctl', 'start', UNITS[2])
        identity_check(UNITS[2], release, 'broker-audit-exporter')
        require(json.loads((RUN[2] / 'stats.json').read_text()) == {'signed': 1, 'published': 1}, 'initial export not completed')
        results.append('exporter-ready-after-sign-publish-readback')
        run('systemctl', 'start', UNITS[3])
        identity_check(UNITS[3], release, 'broker-audit-recovery')
        results.append('recovery-ready-after-checkpoint-and-chain-verification')
        for user in ['broker-audit-exporter', 'broker-audit-recovery']:
            denied = run('runuser', '-u', user, '--', 'test', '-r', release / 'server.js', check=False)
            require(denied.returncode != 0, 'Broker source exposed to audit identity')
        for role, other in [('exporter', 'recovery'), ('recovery', 'exporter')]:
            require(run('runuser', '-u', f'broker-audit-{role}', '--', 'test', '-r', release / f'{other}-runtime/package.json', check=False).returncode != 0, 'cross-workload runtime read allowed')
        results.append('isolated-uids-acls-capabilities-seccomp-private-network')
        run('systemctl', 'stop', UNITS[2])
        run('systemctl', 'start', UNITS[2])
        identity_check(UNITS[2], release, 'broker-audit-exporter')
        require(json.loads((RUN[2] / 'stats.json').read_text()) == {'signed': 1, 'published': 1}, 'restart repeated signing/publication')
        results.append('restart-reuses-verified-existing-anchor')
        run('systemctl', 'stop', UNITS[3])
        pin = CONFIG / 'audit/recovery-checkpoint.json'
        checkpoint = json.loads(pin.read_text())
        checkpoint.update(issued_at_ms=int(time.time()*1000)-2000, expires_at_ms=int(time.time()*1000)-1000)
        pin.write_text(json.dumps(checkpoint))
        denied = run('systemctl', 'start', UNITS[3], check=False)
        require(denied.returncode != 0 and property_of(UNITS[3], 'ActiveState') != 'active', 'expired recovery became ready')
        run('systemctl', 'stop', UNITS[3])
        results.append('expired-checkpoint-never-ready')
        run('systemctl', 'stop', UNITS[2])
        config = CONFIG / 'audit/exporter.json'
        raw = json.loads(config.read_text()); raw['revoked_key_ids'] = [raw['active_key_id']]; config.write_text(json.dumps(raw))
        denied = run('systemctl', 'start', UNITS[2], check=False)
        require(denied.returncode != 0 and property_of(UNITS[2], 'ActiveState') != 'active', 'revoked exporter became ready')
        run('systemctl', 'stop', UNITS[2])
        results.append('revoked-signing-key-never-ready')
    finally:
        for name in reversed(UNITS):
            run('systemctl', 'stop', name, check=False, timeout=15)
        for name in UNITS:
            Path('/etc/systemd/system', name).unlink(missing_ok=True)
            run('systemctl', 'reset-failed', name, check=False)
        run('systemctl', 'daemon-reload')
        for path in [BASE, CONFIG, DATA, *RUN]:
            if path.is_dir():
                shutil.rmtree(path)
        for name in reversed(created):
            run('userdel', name, check=False)
            run('groupdel', name, check=False)
    require(len(results) == 6, 'incomplete integration')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({'source_sha': sha, 'status': 'passed', 'checks': results,
                                 'backend': 'synthetic-in-memory', 'production_verified': False}, indent=2)+'\n')
    print(f'audit process integration: {len(results)} real systemd scenarios passed; synthetic backends only')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        integration(args.source.resolve(), args.node.resolve(), args.output.resolve())
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        # Do not print process stdout/stderr or environment values.
        print('audit integration failed: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
