import unittest
from security_loop import protocol


class ProtocolTests(unittest.TestCase):
    def test_tool_call_validation(self):
        call = protocol.parse_role('attacker', '{"type":"call","tool":"read","args":{"path":"/trial/work/hello.txt"}}')
        self.assertEqual(call['tool'], 'read')
        with self.assertRaises(ValueError):
            protocol.parse_role('attacker', '{"type":"call","tool":"terminal","args":{"command":"ls"}}')

    def test_builder_output_is_data_not_imported(self):
        obj = protocol.parse_role('builder', '{"source":"raise RuntimeError(123)"}')
        self.assertEqual(obj['source'], 'raise RuntimeError(123)')

    def test_safe_verdict_does_not_terminate(self):
        with self.assertRaises(ValueError):
            protocol.parse_role('attacker', '{"type":"safe"}')

    def test_no_fence_or_trailing_comment(self):
        with self.assertRaises(ValueError):
            protocol.parse_role('builder', '```json\n{"source":"x"}\n```')
        with self.assertRaises(ValueError):
            protocol.parse_role('builder', '{"source":"x"} done')

    def test_stream_result_and_identity(self):
        text = 'Warning: Unknown toolsets: sl_no_tools\n{"type":"result","text":"PONG","exit_code":0,"session_id":"s"}\n'
        self.assertEqual(protocol.stream_result(text)['text'], 'PONG')
        with self.assertRaises(ValueError):
            protocol.stream_result('{"type":"result","text":"bad","exit_code":1}\n')

    def test_native_tool_event_rejected(self):
        with self.assertRaises(ValueError):
            protocol.stream_result('{"type":"tool_call","name":"read_file"}\n{"type":"result","exit_code":0,"text":"x"}\n')
