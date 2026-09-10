"""Algorithm regression tests; test vectors are not benchmark/vehicle evidence."""
import csv
import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
from common import AsconAEAD128Engine, SessionManager, ROOT
from telemetry import IDS, load_recording
from event_reader import EventReader


class Regressions(unittest.TestCase):
    def test_nonce_separation_and_real_aead(self):
        key = SessionManager.generate_session_key()
        nonce = SessionManager.derive_runtime_nonce(0x20,1,1,direction=0)
        alternatives = [SessionManager.derive_runtime_nonce(0x20,1,2,direction=0),
                        SessionManager.derive_runtime_nonce(0x21,1,1,direction=0),
                        SessionManager.derive_runtime_nonce(0x20,2,1,direction=0),
                        SessionManager.derive_runtime_nonce(0x20,1,1,direction=1)]
        self.assertEqual(len(set([nonce]+alternatives)),5)
        cipher,tag = AsconAEAD128Engine.encrypt(key,nonce,b'known test plaintext',b'header')
        self.assertEqual(AsconAEAD128Engine.decrypt(key,nonce,cipher,b'header',tag),b'known test plaintext')
        for bad in alternatives:
            with self.assertRaises(ValueError):
                AsconAEAD128Engine.decrypt(key,bad,cipher,b'header',tag)

    def test_exact_14d_feature_math(self):
        # Explicit unit-test vector, never emitted as recorded telemetry.
        vector = [10,600,32768,120,8,9,11,12,100]
        features=IDS.features(vector)
        np.testing.assert_allclose(features[9:],[3,2,2,3,0])
        with self.assertRaises(ValueError):
            IDS.features([float('nan')]+vector[1:])

    def test_real_onnx_window_and_reset(self):
        model=IDS()
        # Artifact scaler minima are only numerical test input, not vehicle data.
        vector=model.minimum[:9].tolist()
        for _ in range(29):
            self.assertEqual(model.evaluate(vector,208)['tier2'],'WARMUP')
        result=model.evaluate(vector,208)
        self.assertIn(result['tier2'],('PASS','ANOMALY_DETECTED'))
        self.assertTrue(np.isfinite(result['ids_score']))
        self.assertGreater(result['inference_ns'],0)
        self.assertEqual(result['threshold'],model.threshold['locked_subsystem_tau_p995']['208'])
        model.reset()
        self.assertEqual(model.evaluate(vector,208)['window_samples'],1)

    def test_incomplete_recording_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.json'
            path.write_text(json.dumps({'schema':'unknown','samples':[]}))
            with self.assertRaises(ValueError):
                load_recording(path)

    def test_incremental_partial_line_and_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            node=Path(directory)/'node';node.mkdir();path=node/'events.jsonl'
            reader=EventReader(directory)
            path.write_bytes(b'{"monotonic_ns":1}\n{"monotonic_ns":')
            self.assertEqual(len(reader.read()),1)
            self.assertEqual(len(reader.read()),1)
            with path.open('ab') as f:f.write(b'2}\n')
            self.assertEqual([r['monotonic_ns'] for r in reader.read()],[1,2])
            path.unlink();path.write_text('{"monotonic_ns":3}\n')
            self.assertEqual(reader.read()[-1]['monotonic_ns'],3)

    def test_saved_csv_rejects_mutated_flags(self):
        import sys
        sys.path.insert(0,str(ROOT/'Phase 2/Simulation'))
        from contracts import validate
        from evidence import validate_software
        export=Path('/evidence')
        if not (export/'latest.json').exists():
            self.skipTest('Mount actual suite exports at /evidence')
        latest=json.loads((export/'latest.json').read_text())
        path=export/latest['directory']/'fault_recovery_runs.csv'
        self.assertEqual(validate_software(path,validate),[])
        with path.open() as f:
            reader=csv.DictReader(f);fields=reader.fieldnames;rows=list(reader)
        rows[0]['ftti_violation_flag']='False' if rows[0]['ftti_violation_flag']=='True' else 'True'
        with tempfile.TemporaryDirectory() as directory:
            altered=Path(directory)/'bad.csv'
            with altered.open('w',newline='') as f:
                writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();writer.writerows(rows)
            self.assertTrue(any('FTTI flag mismatch' in e for e in validate_software(altered,validate)))


if __name__=='__main__':
    unittest.main()
