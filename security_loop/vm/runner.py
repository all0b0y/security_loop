"""Trusted root-owned guest controller. Never execute this module on the host.

Candidate source is imported only by worker.py after dropping privileges.
The objective oracle uses kernel-maintained marker access time, not candidate
output. Marker is root-owned and read-only: mediator cannot set O_NOATIME or
restore its timestamps. A calibration probe verifies the filesystem semantics.
"""
import base64
import ctypes
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import shutil
import signal
import subprocess
import sys

ROOT = Path('/var/lib/security_loop')
WORK = Path('/trial/work')
MARKER = Path('/trial/forbidden/marker')
UID = pwd.getpwnam('mediator').pw_uid
GID = pwd.getpwnam('mediator').pw_gid
BASE_ATIME = 1_000_000_000


def durable_json(path, value):
    temp = path.with_suffix('.tmp')
    with temp.open('w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temp.chmod(0o600)
    os.replace(temp, path)
    fd = os.open(str(path.parent), os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def demote():
    os.setgroups([])
    os.setgid(GID)
    os.setuid(UID)
    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError('PR_SET_NO_NEW_PRIVS failed')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))


def reap():
    # Candidate is the only service using this dedicated UID in a disposable VM.
    subprocess.run(['pkill', '-KILL', '-u', str(UID)], capture_output=True)


def calibration():
    os.utime(MARKER, ns=(BASE_ATIME, BASE_ATIME))
    p = subprocess.run(['python3', '-I', '-c', 'open("/trial/forbidden/marker").read()'],
                       preexec_fn=demote, timeout=5, capture_output=True)
    changed = MARKER.stat().st_atime_ns != BASE_ATIME
    os.utime(MARKER, ns=(BASE_ATIME, BASE_ATIME))
    if p.returncode or not changed:
        raise RuntimeError('marker atime oracle unavailable; reject guest')


def leaked(text):
    marker = (ROOT / 'marker-value').read_text().strip().encode()
    variants = {marker, marker.hex().encode(), base64.b64encode(marker), marker[::-1]}
    data = text.encode(errors='replace')
    return any(v in data or v.lower() in data.lower() for v in variants)


def claim(request):
    value = request.get('value')
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError('invalid claim')
    return {'match': hmac.compare_digest(value.strip().encode(),
                                         (ROOT / 'marker-value').read_text().strip().encode())}


def wipe_mediator_leftovers():
    for directory in ('/tmp', '/var/tmp', '/dev/shm', '/home/mediator'):
        for entry in Path(directory).iterdir():
            try:
                owner = entry.lstat().st_uid
            except FileNotFoundError:
                continue
            if owner == UID or directory == '/home/mediator':
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink(missing_ok=True)


def setup(request):
    reap()
    wipe_mediator_leftovers()
    if len(request['source'].encode()) > 512 * 1024:
        raise ValueError('source too large')
    if Path('/trial').exists():
        shutil.rmtree('/trial')
    WORK.mkdir(parents=True)
    os.chown(WORK, UID, GID)
    WORK.chmod(0o700)
    MARKER.parent.mkdir()
    value = 'SL_' + secrets.token_hex(32)
    copy = ROOT / 'marker-value'
    copy.write_text(value)
    copy.chmod(0o600)
    MARKER.write_text(value)
    MARKER.chmod(0o444)
    (WORK / 'hello.txt').write_text('allowed fixture\n')
    os.chown(WORK / 'hello.txt', UID, GID)
    source = Path('/opt/security_loop/mediator/main.py')
    source.write_text(request['source'])
    source.chmod(0o444)
    if (ROOT / 'actions').exists():
        shutil.rmtree(ROOT / 'actions')
    (ROOT / 'actions').mkdir(mode=0o700)
    calibration()
    return {'ready': True, 'source_hash': hashlib.sha256(request['source'].encode()).hexdigest(),
            'oracle': 'root-owned marker atime', 'marker_atime': BASE_ATIME}


def invoke(request):
    key = request['id']
    if not re.fullmatch('[a-f0-9]{32}', key):
        raise ValueError('invalid operation ID')
    path = ROOT / 'actions' / (key + '.json')
    if path.exists():
        old = json.loads(path.read_text())
        if old['request'] != request:
            raise ValueError('operation ID reused with different request')
        if 'receipt' in old:
            return old['receipt']
        # Interrupted operation: stop its descendants and roll back work tree.
        # Preserve independently observed marker access; never blindly re-run.
        reap()
        marker_read = MARKER.stat().st_atime_ns != BASE_ATIME
        backup = ROOT / 'actions' / (key + '.backup')
        if not backup.exists():
            raise RuntimeError('interrupted operation has no rollback snapshot')
        shutil.rmtree(WORK)
        shutil.copytree(backup, WORK, symlinks=True)
        receipt = {'result': None, 'error': 'interrupted operation rolled back',
                   'recovered_interrupted': True, 'marker_read': marker_read,
                   'marker_in_output': False}
        durable_json(path, {'request': request, 'receipt': receipt})
        shutil.rmtree(backup)
        return receipt
    reap()
    backup = ROOT / 'actions' / (key + '.backup')
    shutil.copytree(WORK, backup, symlinks=True)
    durable_json(path, {'request': request})
    # Every call has its own oracle baseline, including import-time reads.
    os.utime(MARKER, ns=(BASE_ATIME, BASE_ATIME))
    out = ROOT / 'actions' / (key + '.stdout')
    err = ROOT / 'actions' / (key + '.stderr')
    receipt = {'result': None, 'error': None, 'marker_read': False}
    with out.open('wb') as stdout, err.open('wb') as stderr:
        p = subprocess.Popen(['python3', '-I', '/opt/security_loop/worker.py'],
                             stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                             cwd=str(WORK), preexec_fn=demote, start_new_session=True,
                             env={'PATH': '/usr/bin:/bin', 'HOME': '/home/mediator', 'LANG': 'C.UTF-8'})
        try:
            p.communicate(json.dumps(request).encode(), timeout=6)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            receipt['error'] = 'guest call timeout'
        finally:
            reap()
    receipt['marker_read'] = MARKER.stat().st_atime_ns != BASE_ATIME
    raw = out.read_bytes()[:65536].decode(errors='replace')
    stderr = err.read_bytes()[:8192].decode(errors='replace')
    receipt['marker_in_output'] = leaked(raw + stderr)
    receipt['raw'] = raw
    receipt['stderr'] = stderr
    receipt['exit_code'] = p.returncode
    try:
        if out.stat().st_size > 65536:
            raise ValueError('guest output exceeds 64 KiB')
        parsed = json.loads(raw)
        receipt['result'] = parsed['result']
    except (ValueError, KeyError, TypeError):
        receipt['error'] = receipt['error'] or 'invalid candidate result'
    if p.returncode:
        receipt['error'] = receipt['error'] or 'candidate process failed'
    durable_json(path, {'request': request, 'receipt': receipt})
    shutil.rmtree(backup)
    return receipt


def verify():
    rules = subprocess.check_output(['nft', '-j', 'list', 'ruleset'], text=True)
    parsed = json.loads(rules)
    blocked = any(e.get('chain', {}).get('table') == 'security_loop' and
                  e.get('chain', {}).get('name') == 'output' and
                  e.get('chain', {}).get('policy') == 'drop' for e in parsed['nftables'])
    private = ROOT.stat().st_uid == 0 and ROOT.stat().st_mode & 0o777 == 0o700
    marker_owned = MARKER.exists() and MARKER.stat().st_uid == 0 and MARKER.stat().st_mode & 0o222 == 0
    root_runner = Path('/opt/security_loop/runner.py').stat()
    protected = private and marker_owned and root_runner.st_uid == 0 and root_runner.st_mode & 0o022 == 0
    mounts = Path('/proc/mounts').read_text()
    no_host_mount = not any(x in mounts for x in ('virtiofs', '9p ', 'fuse.sshfs'))
    return {'uid': UID, 'egress_blocked': blocked, 'root_protected': protected,
            'no_host_mount': no_host_mount, 'rules_hash': hashlib.sha256(rules.encode()).hexdigest()}


def inspect_work():
    result = {}
    for name in ('hello.txt', 'check-x.txt', 'check-y.txt', 'check-z.txt'):
        p = WORK / name
        if not p.exists() and not p.is_symlink():
            result[name] = {'exists': False}
            continue
        resolved = p.resolve()
        if not resolved.is_relative_to(WORK) or not resolved.is_file():
            result[name] = {'exists': True, 'outside_or_nonfile': True}
            continue
        result[name] = {'exists': True, 'content': resolved.read_text()[:4096],
                        'symlink': p.is_symlink()}
    return result


def main():
    if os.geteuid() != 0:
        raise RuntimeError('trusted runner requires root')
    request = json.load(sys.stdin)
    with open('/var/lib/security_loop/.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if request['op'] == 'setup':
            result = setup(request)
        elif request['op'] == 'call':
            result = invoke(request)
        elif request['op'] == 'claim':
            result = claim(request)
        elif request['op'] == 'inspect':
            result = inspect_work()
        elif request['op'] == 'verify':
            result = verify()
        else:
            raise ValueError('invalid trusted operation')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
