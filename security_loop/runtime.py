"""Lima runtime: untrusted source executes in a VM, never on macOS."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import uuid


class RuntimeFailure(RuntimeError):
    pass


class LimaRuntime:
    def __init__(self, base='sl-base'):
        if not re.fullmatch(r'sl-[a-z0-9-]+', base):
            raise ValueError('base must have an sl- name')
        self.base = base
        self.binary = shutil.which('limactl')
        if not self.binary:
            raise RuntimeFailure('Lima is not installed; no local fallback permitted')

    def command(self, *args, payload=None, timeout=120):
        p = subprocess.run([self.binary, '--tty=false', *args],
                           input=json.dumps(payload) if payload is not None else None,
                           text=True, capture_output=True, timeout=timeout)
        if p.returncode:
            raise RuntimeFailure(f'Lima command failed ({p.returncode}): {p.stderr[-4000:]}')
        return p.stdout

    def info(self, name):
        self._name(name)
        text = self.command('list', '--json')
        return next((json.loads(line) for line in text.splitlines()
                     if line.strip() and json.loads(line)['name'] == name), None)

    @staticmethod
    def _name(name):
        if not re.fullmatch(r'sl-[a-z0-9-]+', name):
            raise ValueError('invalid managed VM name')

    @staticmethod
    def validate_config(info):
        c = info['config']
        if c.get('mounts') or c.get('ssh', {}).get('forwardAgent') or c.get('ssh', {}).get('forwardX11'):
            raise RuntimeFailure('host mounts/SSH forwarding forbidden')
        if c.get('vmType') != 'vz' or c.get('arch') != 'aarch64':
            raise RuntimeFailure('this release requires Apple Silicon VZ')
        if any(not x.get('ignore') for x in c.get('portForwards', [])):
            raise RuntimeFailure('guest port forwarding forbidden')
        if c.get('containerd', {}).get('system') or c.get('containerd', {}).get('user'):
            raise RuntimeFailure('container runtime not allowed in base')

    def prepare_base(self):
        info = self.info(self.base)
        if info is None:
            self.command('create', '--name=' + self.base, str(Path(__file__).parent / 'vm' / 'base.yaml'), timeout=600)
        self.start(self.base)
        self.validate_config(self.info(self.base))
        directory = Path(__file__).parent / 'vm'
        files = {name: (directory / name).read_text() for name in ('runner.py', 'worker.py')}
        # Fixed trusted installer; arbitrary candidate paths are never accepted.
        installer = "import json,pathlib,sys; d=json.load(sys.stdin); root=pathlib.Path('/opt/security_loop'); assert set(d)=={'runner.py','worker.py'}; [( (root/k).write_text(v),(root/k).chmod(0o644)) for k,v in d.items()]"
        self.command('shell', '--workdir=/', self.base, '--', 'sudo', 'python3', '-I', '-c', installer, payload=files)
        self.command('shell', '--workdir=/', self.base, '--', 'sudo', 'nft', '-f', '/etc/nftables.conf')
        self.command('stop', self.base)
        return {'base': self.base, 'ready': True, 'mounts': [],
                'trusted_hashes': {k: hashlib.sha256(v.encode()).hexdigest() for k, v in files.items()}}

    def start(self, name):
        info = self.info(name)
        if info is None:
            raise RuntimeFailure('saved VM is missing; refuse to discard unfinished attempt')
        self.validate_config(info)
        if info['status'] != 'Running':
            self.command('start', name, timeout=180)
        self.validate_config(self.info(name))

    def create(self, purpose, name=None):
        name = name or ('sl-' + re.sub('[^a-z0-9-]', '-', purpose.lower())[:24] + '-' + uuid.uuid4().hex[:10])
        self._name(name)
        info = self.info(name)
        if info is None:
            base = self.info(self.base)
            if base is None or base['status'] != 'Stopped':
                raise RuntimeFailure('prepare a stopped, verified base VM first')
            self.validate_config(base)
            self.command('clone', '--mount-none', self.base, name, timeout=120)
        self.start(name)
        return name

    def request(self, name, payload):
        self._name(name)
        response = self.command('shell', '--workdir=/', name, '--', 'sudo', 'python3', '-I',
                                '/opt/security_loop/runner.py', payload=payload, timeout=25)
        try:
            return json.loads(response)
        except ValueError as exc:
            raise RuntimeFailure('invalid trusted guest response') from exc

    def setup(self, name, source):
        result = self.request(name, {'op': 'setup', 'source': source})
        proof = self.verify(name)
        if not all(proof.get(k) for k in ('egress_blocked', 'root_protected', 'no_host_mount')):
            raise RuntimeFailure('guest isolation attestation failed')
        return result

    def call(self, name, operation_id, tool, args):
        return self.request(name, {'op': 'call', 'id': operation_id, 'tool': tool, 'args': args})

    def claim(self, name, value):
        return self.request(name, {'op': 'claim', 'value': value})

    def inspect(self, name):
        return self.request(name, {'op': 'inspect'})

    def stop(self, name):
        self._name(name)
        info = self.info(name)
        if info is not None and info['status'] == 'Running':
            self.command('stop', name, timeout=120)

    def verify(self, name):
        self.validate_config(self.info(name))
        return self.request(name, {'op': 'verify'})

    def delete(self, name):
        self._name(name)
        if name == self.base:
            raise RuntimeFailure('base VM deletion is not a trial operation')
        if self.info(name) is not None:
            self.command('delete', '--force', name)
