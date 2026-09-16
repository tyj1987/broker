#!/usr/bin/env python3
"""Disposable GitHub-hosted Linux runner only; never deploy this fixture.

Uses real systemd, service UIDs, ACLs, AF_UNIX and native/Node processes, with
synthetic in-memory signing/store backends. No cloud or production evidence.
"""
import argparse
from contextlib import contextmanager
import stat
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
    result = subprocess.run([str(a) for a in args], check=False, timeout=timeout, env=ENV,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode != 0:
        # Fixed command categories only: never print dynamic paths, arguments,
        # child output, journal text or environment contents on failure.
        command = str(args[0]) if args and str(args[0]) in {
            'systemctl', 'useradd', 'userdel', 'groupdel', 'setfacl', 'runuser'} else 'command'
        verb = str(args[1]) if len(args) > 1 and str(args[1]) in {
            'show', 'start', 'stop', 'daemon-reload', 'reset-failed'} else 'operation'
        raise RuntimeError(f'{command} {verb} exited {result.returncode}')
    return result

def safe_unit_diagnostics():
    # Fixed fixture paths and public OS ownership, never config/event contents.
    sha = os.environ.get('GITHUB_SHA', '')
    if re.fullmatch('[a-f0-9]{40}', sha):
        targets = [BASE / 'runtime/node/bin/node', BASE / 'releases' / sha / 'bin/secret-broker-audit-exporter',
                   BASE / 'releases' / sha / 'exporter-runtime/bin/audit-exporter-service-check.js']
        seen = set()
        for target in targets:
            for path in [target, *target.parents]:
                if path in seen:
                    continue
                seen.add(path)
                try:
                    info = path.lstat()
                    if info.st_uid != 0 or info.st_mode & 0o022 or path.is_symlink():
                        print(f'audit fixture untrusted path={path} uid={info.st_uid} mode={info.st_mode & 0o7777:o}', file=sys.stderr)
                except OSError:
                    print(f'audit fixture unavailable path={path}', file=sys.stderr)
        for name in ACCOUNTS:
            try:
                user = pwd.getpwnam(name)
                group = grp.getgrnam(name)
                print(f'audit fixture identity={name} uid={user.pw_uid} gid={user.pw_gid} named_gid={group.gr_gid}', file=sys.stderr)
            except KeyError:
                print(f'audit fixture identity unavailable={name}', file=sys.stderr)
    for unit in UNITS:
        result = run('systemctl', 'show', unit,
                     '--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus',
                     check=False)
        lines = [line for line in result.stdout.splitlines() if re.fullmatch(
            r'(LoadState|ActiveState|SubState|Result|ExecMainCode|ExecMainStatus)=[a-z0-9-]+', line)]
        print('audit integration diagnostic ' + unit + ': ' + ' '.join(lines), file=sys.stderr)
        journal = run('journalctl', '--unit', unit, '--no-pager', '--output=cat', '-n', '20', check=False)
        codes = re.findall(r'^audit_(?:exporter|recovery)_failed=[a-z_]+$', journal.stdout, re.M)
        for value in sorted(set(codes)):
            print(value, file=sys.stderr)


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

def make_fixture_directory(path):
    # No parents/exist_ok: a pre-existing path or unexpected ancestor is never
    # repaired or overwritten. Callers enumerate new directories parent-first.
    path.mkdir()
    run('setfacl', '--remove-all', '--remove-default', path)
    path.chmod(0o755)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
            and info.st_uid == os.geteuid() and (info.st_mode & 0o777) == 0o755,
            'fixture directory permissions unavailable')

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


def duration_microseconds(value):
    # systemctl renders durations (not bare D-Bus integers). Reject unexpected
    # representations rather than accidentally interpreting an absent timeout.
    units = {'us': 1, 'ms': 1000, 's': 1000000, 'min': 60000000, 'h': 3600000000}
    parts = value.split()
    require(bool(parts), 'watchdog duration unavailable')
    total = 0
    for part in parts:
        match = re.fullmatch(r'(\d+)(us|ms|s|min|h)', part)
        require(match is not None, 'watchdog duration unavailable')
        total += int(match[1]) * units[match[2]]
    return total


def wait_for_restarted_process(unit, previous_pid, previous_restarts):
    end = time.monotonic() + 20
    while time.monotonic() < end:
        if (property_of(unit, 'ActiveState') == 'active'
                and int(property_of(unit, 'MainPID')) not in [0, previous_pid]
                and int(property_of(unit, 'NRestarts')) > previous_restarts):
            return
        time.sleep(0.1)
    raise RuntimeError('native process restart was not verified')


def wait_for_failed_verification(unit):
    end = time.monotonic() + 80
    while time.monotonic() < end:
        # A watchdog signal, startup-limit refusal or mere inactivity is NOT
        # evidence that the running verifier detected the changed audit data.
        if (property_of(unit, 'ActiveState') != 'active'
                and property_of(unit, 'ExecMainCode') == '1'
                and property_of(unit, 'ExecMainStatus') == '69'):
            return
        time.sleep(0.1)
    raise RuntimeError('running verifier did not report failure')

@contextmanager
def protected_fixture_parent(path=Path('/opt')):
    # The hosted image uses a world-writable /opt and a permissive umask.
    # Tighten that one ancestor while the fixture exists; always restore it.
    # Never change existing descendants, owners or ACL entries recursively.
    info = path.lstat()
    require(info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and not path.is_symlink(),
            'fixture parent is not root-managed')
    original_mode = stat.S_IMODE(info.st_mode)
    original_umask = os.umask(0o022)
    try:
        path.chmod(original_mode & ~0o022)
        yield
    finally:
        try:
            path.chmod(original_mode)
        finally:
            os.umask(original_umask)

def integration(source, node, output):
    guard(source, node)
    with protected_fixture_parent():
        created = []
        results = []
        sha = os.environ['GITHUB_SHA']
        release = BASE / 'releases' / sha
        try:
            for name in ACCOUNTS:
                run('useradd', '--system', '--no-create-home', '--user-group', '--shell', '/usr/sbin/nologin', name)
                created.append(name)
            # Create every new ancestor explicitly. Default ACL inheritance can
            # override umask; normalize only pristine fixture-owned directories.
            for folder in [BASE, BASE / 'releases', release, release / 'bin',
                           BASE / 'runtime', BASE / 'runtime/node', BASE / 'runtime/node/bin',
                           CONFIG, CONFIG / 'audit', DATA, DATA / 'audit', *RUN]:
                make_fixture_directory(folder)
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
            require(duration_microseconds(property_of(UNITS[2], 'WatchdogUSec')) == 135000000,
                    'verified interval did not narrow the watchdog')
            results.append('watchdog-bound-to-verified-interval-and-child-deadline')
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
            previous_pid = int(property_of(UNITS[2], 'MainPID'))
            previous_restarts = int(property_of(UNITS[2], 'NRestarts'))
            run('systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', UNITS[2])
            wait_for_restarted_process(UNITS[2], previous_pid, previous_restarts)
            identity_check(UNITS[2], release, 'broker-audit-exporter')
            require(json.loads((RUN[2] / 'stats.json').read_text()) == {'signed': 1, 'published': 1},
                    'crash recovery repeated signing/publication')
            require(duration_microseconds(property_of(UNITS[2], 'WatchdogUSec')) == 135000000,
                    'restarted process did not renegotiate its watchdog')
            results.append('native-crash-restart-reverifies-without-duplicate-publication')
            # Clear only this disposable test unit's accumulated start counter;
            # its unchanged start-limit and restart policy still apply.
            run('systemctl', 'reset-failed', UNITS[2])
            audit_file = DATA / 'audit/audit-chain-ci.jsonl'
            original_chain = audit_file.read_bytes()
            audit_file.write_bytes(b'{}\n')
            try:
                wait_for_failed_verification(UNITS[3])
                run('systemctl', 'stop', UNITS[3])
                wait_for_failed_verification(UNITS[2])
                run('systemctl', 'stop', UNITS[2])
                require(json.loads((RUN[2] / 'stats.json').read_text()) == {'signed': 1, 'published': 1},
                        'invalid chain reached signing/publication')
            finally:
                run('systemctl', 'stop', UNITS[3], check=False)
                run('systemctl', 'stop', UNITS[2], check=False)
                audit_file.write_bytes(original_chain)
            results.append('running-exporter-and-recovery-fail-after-audit-copy-corruption')
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
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError):
            safe_unit_diagnostics()
            raise
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
        require(len(results) == 9, 'incomplete integration')
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
