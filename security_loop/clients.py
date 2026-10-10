"""Hermes client adapter: CLI authentication stays on host, zero native tools.

Roles communicate strict JSON as text, not native tool calls. The controller
routes allowed filesystem requests to the guest. This intentionally separates
model inference/client lifecycle from the attacked filesystem.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

from .protocol import stream_result


class ClientFailure(RuntimeError):
    pass


class IsolationFailure(ClientFailure):
    pass


class Cancelled(ClientFailure):
    pass


class HermesClient:
    SENTINEL = 'sl_no_tools'

    def __init__(self, root, config):
        if config.get('client') != 'hermes' or not config.get('model') or not config.get('provider'):
            raise ValueError('explicit Hermes client, model and provider required')
        self.config = config
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.home = self.root / 'hermes-home'
        self.home.mkdir(exist_ok=True, mode=0o700)
        self.binary = shutil.which('hermes')
        if not self.binary:
            raise ClientFailure('Hermes CLI is not installed')
        self.process = None
        # A private HERMES_HOME avoids user plugins, hooks, MCP and session mixing.
        # Credentials are referenced only on host, never copied into VM or journal.
        source = Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes')))
        for filename in ('auth.json', '.env', 'installs'):
            origin, link = source / filename, self.home / filename
            if origin.exists() and not link.exists():
                link.symlink_to(origin.resolve())
        self.env = {k: v for k, v in os.environ.items()
                    if k in {'PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TMPDIR', 'SHELL'} or k.startswith('LC_')}
        self.env.update(HERMES_HOME=str(self.home), HERMES_SAFE_MODE='1',
                        HERMES_DISABLE_LAZY_INSTALLS='1',
                        HERMES_IGNORE_RULES='1', HERMES_IGNORE_USER_CONFIG='1',
                        NO_COLOR='1', TERM='dumb')

    def runtime_command(self, args):
        p = subprocess.run([self.binary, '--print-runtime-command', *args], env=self.env,
                           cwd=self.root, capture_output=True, text=True, timeout=20)
        if p.returncode:
            raise IsolationFailure('Hermes must support --print-runtime-command')
        try:
            command = json.loads(p.stdout)
        except ValueError as exc:
            raise IsolationFailure('invalid Hermes runtime command') from exc
        if not isinstance(command, list) or '-c' not in command:
            raise IsolationFailure('unrecognized Hermes launcher; adapter not admitted')
        return command

    def preflight(self):
        command = self.runtime_command(['chat', '--help'])
        code_index = command.index('-c') + 1
        marker = "runpy.run_module('hermes_cli.main', run_name='__main__', alter_sys=True)"
        if marker not in command[code_index]:
            raise IsolationFailure('unsupported Hermes launcher bootstrap')
        probe = ("import json,model_tools; defs=model_tools.get_tool_definitions(enabled_toolsets=['sl_no_tools'],"
                 "quiet_mode=True,skip_tool_search_assembly=True); print(json.dumps({'tools':[t['function']['name'] for t in defs]}))")
        command = command[:code_index + 1]
        command[code_index] = command[code_index].replace(marker, probe)
        p = subprocess.run(command, cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
        if p.returncode:
            raise IsolationFailure('tool-surface probe failed; no model call allowed')
        try:
            proof = json.loads(p.stdout.splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise IsolationFailure('invalid tool-surface proof') from exc
        if proof.get('tools') != []:
            raise IsolationFailure('native tools present; client rejected')
        return proof

    def cancel(self):
        p = self.process
        if p is not None and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait(timeout=5)

    def invoke(self, prompt, timeout=180):
        proof = self.preflight()
        args = ['chat', '--oneshot', '--safe-mode', '--source', 'tool', '-t', self.SENTINEL,
                '-m', self.config['model'], '--provider', self.config['provider'],
                '--reasoning', self.config.get('reasoning', 'high'), '--max-turns', '2',
                '--run-budget', str(timeout - 5), '--format', 'stream-json', '-v',
                '--in', str(self.root), '--query-file', '-']
        command = self.runtime_command(args)
        command.insert(1, '-u')
        # Debug SDK stderr can contain auth data: never persist or expose it.
        p = subprocess.Popen(command, cwd=self.root, env=self.env, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, start_new_session=True)
        self.process = p
        try:
            stdout, _ = p.communicate(prompt, timeout=timeout)
        except (subprocess.TimeoutExpired, BaseException):
            self.cancel()
            raise
        finally:
            self.process = None
        if p.returncode:
            raise ClientFailure(f'Hermes exited with code {p.returncode}; authentication/availability requires retry or operator action')
        if 'No tools selected (all filtered out or unavailable)' not in stdout:
            raise IsolationFailure('runtime did not attest zero native tools')
        result = stream_result(stdout)
        events = []
        for line in stdout.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                events.append(item)
        init = next((e for e in events if e.get('type') == 'system' and e.get('subtype') == 'init'), None)
        if not init or init.get('model') != self.config['model']:
            raise IsolationFailure('client changed selected model or omitted identity')
        return {**result, 'model': init['model'], 'provider': self.config['provider'],
                'native_tools': proof['tools'], 'events': events}
