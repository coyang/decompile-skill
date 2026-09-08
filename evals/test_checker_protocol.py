"""Protocol rejection tests; synthetic responses are NOT semantic-proof evidence."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('accept_gate', Path(__file__).resolve().parents[1] / 'scripts/verify.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CheckerProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='decompile-checker-test-')
        cls.root = Path(cls.temp.name)
        source = cls.root / 'checker.c'
        source.write_text('#include <stdio.h>\nint main(void) { puts("{}"); return 0; }\n')
        cls.checker = cls.root / 'checker'
        subprocess.run(['/usr/bin/gcc', '-static', str(source), '-o', str(cls.checker)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='decompile-protocol-test-')
        self.root = Path(self.temp.name)
        self.snapshot = self.root / 'snapshots'; self.snapshot.mkdir()
        (self.snapshot / 'artifacts').mkdir()
        self.work = self.root / 'work'; self.work.mkdir()
        self.certificate = self.root / 'certificate'
        self.certificate.write_text('deliberately untrusted test certificate')
        self.config = {'path': str(self.checker), 'sha256': gate.file_hash(self.checker),
                       'obligations': ['additional-test-obligation'], 'timeout_seconds': 3,
                       'method': 'formal', 'model': 'test-model', 'certificate': str(self.certificate),
                       'certificate_sha256': gate.file_hash(self.certificate)}
        self.scope = {'id': 'test', 'assumptions': ['same runtime']}
        self.symbols = [{'name': 'function_a'}, {'name': 'function_b'}]

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self):
        return gate.run_verifier('proof', self.config, self.snapshot, self.work,
                                 {'original_sha256': 'a' * 64}, self.scope, self.symbols)

    def response(self, mutate):
        def synthetic(argv, work, mounts, timeout, runtime):
            self.assertFalse(runtime, 'checker must not see host tool/runtime tree')
            request_file = next(p for p, name in mounts if name == '/request.json')
            data = request_file.read_bytes()
            req = json.loads(data)
            self.assertTrue(set(gate.REQUIRED_OBLIGATIONS['proof']).issubset(req['obligations']))
            result = {'schema_version': 1, 'stage': 'proof', 'request_sha256': gate.digest(data),
                      'verdict': 'PASS', 'unknowns': [], 'obligations': req['obligations'],
                      'covered_exports': ['function_a', 'function_b'], 'assumptions': self.scope['assumptions'],
                      'summary': 'synthetic protocol fixture; not a proof', 'method': 'formal',
                      'model': 'test-model', 'checked_certificate_sha256': self.config['certificate_sha256']}
            mutate(result)
            return json.dumps(result).encode()
        return synthetic

    def test_invalid_bindings_and_partial_evidence_are_rejected(self):
        mutations = {
            'stale_request': lambda r: r.update(request_sha256='0' * 64),
            'wrong_stage': lambda r: r.update(stage='abi'),
            'missing_exports': lambda r: r.update(covered_exports=['function_a']),
            'unresolved': lambda r: r.update(unknowns=['unmodelled syscall']),
            'missing_obligations': lambda r: r.update(obligations=['additional-test-obligation']),
            'duplicate_obligations': lambda r: r['obligations'].append(r['obligations'][0]),
            'changed_assumptions': lambda r: r.update(assumptions=['candidate is correct']),
            'wrong_certificate': lambda r: r.update(checked_certificate_sha256='0' * 64),
            'sampled_method': lambda r: r.update(method='sampled'),
            'wrong_model': lambda r: r.update(model='different-model'),
            'unknown_status': lambda r: r.update(verdict='UNKNOWN'),
            'unknown_field': lambda r: r.update(override_approval=True),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                self.snapshot = Path(tmp) / 'snap'; self.snapshot.mkdir()
                (self.snapshot / 'artifacts').mkdir()
                self.work = Path(tmp) / 'work'; self.work.mkdir()
                with patch.object(gate, 'sandbox', self.response(mutation)):
                    with self.assertRaises(gate.Unknown):
                        self.invoke()

    def test_real_static_checker_malformed_result_cannot_pass(self):
        with self.assertRaises(gate.Unknown):
            self.invoke()

    def test_checker_hash_mismatch_prevents_execution(self):
        self.config['sha256'] = '0' * 64
        with patch.object(gate, 'sandbox') as run:
            with self.assertRaises(gate.Unknown):
                self.invoke()
            run.assert_not_called()

    def test_bad_certificate_hash_prevents_execution(self):
        self.config['certificate_sha256'] = '0' * 64
        with patch.object(gate, 'sandbox') as run:
            with self.assertRaises(gate.Unknown):
                self.invoke()
            run.assert_not_called()

    def test_sampling_is_not_an_accepted_proof_method(self):
        self.config['method'] = 'sampled'
        with self.assertRaises(gate.Unknown):
            self.invoke()

    def test_crash_timeout_and_missing_sandbox_are_unknown(self):
        for reason in ('tool exited 1', 'tool timed out', 'bubblewrap unavailable'):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as tmp:
                self.snapshot = Path(tmp) / 'snap'; self.snapshot.mkdir()
                (self.snapshot / 'artifacts').mkdir()
                self.work = Path(tmp) / 'work'; self.work.mkdir()
                with patch.object(gate, 'sandbox', side_effect=gate.Unknown(reason)):
                    with self.assertRaises(gate.Unknown):
                        self.invoke()

    def test_actual_tool_timeout_is_unknown(self):
        with self.assertRaises(gate.Unknown):
            gate.bounded(['/bin/sleep', '2'], timeout=0.1)

    def test_actual_nonzero_tool_exit_is_unknown(self):
        with self.assertRaises(gate.Unknown):
            gate.bounded(['/bin/false'])

    def test_duplicate_json_keys_are_invalid(self):
        with self.assertRaises(gate.Unknown):
            gate.load_json('{"verdict":"PASS","verdict":"UNKNOWN"}')


if __name__ == '__main__':
    unittest.main()
