"""Strict untrusted role outputs; no executable model-generated host actions."""
import json

TOOLS = {
    'read': {'path'},
    'write': {'path', 'content'},
    'list': {'path'},
    'move': {'src', 'dst'},
    'symlink': {'target', 'path'},
}


def parse_role(role, text):
    if len(text.encode()) > 512 * 1024:
        raise ValueError('role output too large')
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError('role output must be a JSON object')
    if role == 'builder':
        if set(obj) != {'source'} or not isinstance(obj['source'], str) or not obj['source'].strip():
            raise ValueError('builder must return only source text')
    elif role == 'observer':
        if set(obj) != {'summary'} or not isinstance(obj['summary'], str):
            raise ValueError('observer must return factual summary text')
    elif role == 'attacker':
        if obj.get('type') == 'next_attempt':
            if set(obj) != {'type', 'strategy'} or not isinstance(obj['strategy'], str):
                raise ValueError('next_attempt requires strategy')
        elif obj.get('type') == 'call':
            if set(obj) != {'type', 'tool', 'args'} or obj.get('tool') not in TOOLS:
                raise ValueError('only mediator filesystem tools are allowed')
            args = obj['args']
            if not isinstance(args, dict) or set(args) != TOOLS[obj['tool']]:
                raise ValueError('invalid tool arguments')
            if any(not isinstance(v, str) for v in args.values()):
                raise ValueError('tool arguments must be strings')
            if any(len(v.encode()) > 65536 or '\x00' in v for v in args.values()):
                raise ValueError('tool argument exceeds limits or contains NUL')
        else:
            raise ValueError('attacker must call a tool or request another attempt; no safety verdict')
    else:
        raise ValueError('unknown role')
    return obj


def stream_result(text):
    result = None
    for line in text.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        if obj.get('type', '').startswith('tool'):
            raise ValueError('native client tools were used; adapter rejected')
        if obj.get('type') == 'result':
            result = obj
    if result is None or result.get('exit_code') != 0 or not isinstance(result.get('text'), str):
        raise ValueError('client did not emit a successful result')
    return result
