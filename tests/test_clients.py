import os
from pathlib import Path
import tempfile
import unittest


@unittest.skipUnless(os.environ.get('SL_MODEL_TESTS') == '1', 'actual subscription call requires SL_MODEL_TESTS=1')
class HermesTests(unittest.TestCase):
    def test_real_tool_free_client(self):
        from security_loop.clients import HermesClient
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as root:
            client = HermesClient(Path(root), {'client': 'hermes', 'provider': 'anthropic',
                                               'model': 'claude-sonnet-5-5', 'reasoning': 'high'})
            proof = client.preflight()
            self.assertEqual(proof['tools'], [])
            result = client.invoke('Reply with exactly PONG.', timeout=60)
            self.assertEqual(result['text'].strip(), 'PONG')
            self.assertEqual(result['model'], 'claude-sonnet-5-5')
            self.assertEqual(result['native_tools'], [])
