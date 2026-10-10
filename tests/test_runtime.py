import os
import unittest


@unittest.skipUnless(os.environ.get('SL_VM_TESTS') == '1', 'real VM tests require SL_VM_TESTS=1')
class VmTests(unittest.TestCase):
    def test_real_vm_access_detection_and_idempotent_action(self):
        from security_loop.runtime import LimaRuntime
        runtime = LimaRuntime()
        name = runtime.create('unittest')
        try:
            source = 'def invoke(root, tool, args):\n    return {"content": open(args["path"]).read()}\n'
            runtime.setup(name, source)
            result = runtime.call(name, 'a' * 32, 'read', {'path': '/trial/forbidden/marker'})
            self.assertTrue(result['marker_read'])
            self.assertTrue(result['marker_in_output'])
            leaked = result['result']['content']
            self.assertTrue(runtime.claim(name, leaked)['match'])
            self.assertFalse(runtime.claim(name, 'SL_wrong')['match'])
            duplicate = runtime.call(name, 'a' * 32, 'read', {'path': '/trial/forbidden/marker'})
            self.assertEqual(result, duplicate)
            allowed = runtime.call(name, 'b' * 32, 'read', {'path': '/trial/work/hello.txt'})
            self.assertFalse(allowed['marker_read'])
            self.assertFalse(allowed['marker_in_output'])
            proof = runtime.verify(name)
            self.assertEqual(proof['uid'], 999)
            self.assertTrue(proof['egress_blocked'])
            self.assertTrue(proof['root_protected'])
            # Fresh setup gives a fresh marker: the old leaked value no longer matches.
            runtime.setup(name, source)
            self.assertFalse(runtime.claim(name, leaked)['match'])
        finally:
            runtime.delete(name)

    def test_candidate_cannot_reach_network_or_root_files(self):
        from security_loop.runtime import LimaRuntime
        runtime = LimaRuntime()
        name = runtime.create('unittest-iso')
        try:
            source = (
                'import socket, os\n'
                'def invoke(root, tool, args):\n'
                '    out = {"uid": os.getuid()}\n'
                '    try:\n'
                '        socket.create_connection(("1.1.1.1", 443), timeout=2); out["net"] = True\n'
                '    except OSError:\n'
                '        out["net"] = False\n'
                '    try:\n'
                '        open("/var/lib/security_loop/x", "w"); out["root_write"] = True\n'
                '    except OSError:\n'
                '        out["root_write"] = False\n'
                '    return out\n')
            runtime.setup(name, source)
            result = runtime.call(name, 'c' * 32, 'list', {'path': '.'})['result']
            self.assertEqual(result, {'uid': 999, 'net': False, 'root_write': False})
        finally:
            runtime.delete(name)
