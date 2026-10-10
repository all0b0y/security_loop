"""Trusted guest-only worker entrypoint. Candidate imports never run on host."""
import importlib.util
import json
import sys

spec = importlib.util.spec_from_file_location('candidate', '/opt/security_loop/mediator/main.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
request = json.load(sys.stdin)
result = module.invoke('/trial/work', request['tool'], request['args'])
print(json.dumps({'result': result}, ensure_ascii=False))
