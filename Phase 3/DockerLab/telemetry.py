"""Versioned recorded-input transport and artifact-backed 14D inference.

Values are in the model's original raw signal units, never guessed SI conversions.
The private laboratory payload is nine float32 signals plus original CAN ID.
"""
from collections import deque
import hashlib
import json
import math
from pathlib import Path
import struct
import time
import numpy as np
import onnxruntime as ort
from common import ROOT

WIRE = struct.Struct('>9fI')
FEATURES = ['vehicle_speed', 'engine_rpm', 'steering_angle', 'brake_pressure',
            'wheel_speed_fl', 'wheel_speed_fr', 'wheel_speed_rl', 'wheel_speed_rr', 'coolant_temp']


def load_recording(path):
    raw = Path(path).read_bytes()
    data = json.loads(raw)
    if data.get('schema') != 'pqc-recorded-raw9-v1' or data.get('feature_names') != FEATURES:
        raise ValueError('Recording must use pqc-recorded-raw9-v1 and exact model raw feature order')
    if data.get('source_kind') != 'recorded' or not data.get('source_description'):
        raise ValueError('Recording provenance required; generated fixtures are not recorded telemetry')
    samples = data['samples']
    if not 30 <= len(samples) <= 1000:
        raise ValueError('Recording must contain 30..1000 complete samples')
    for sample in samples:
        vals = sample['values']
        if len(vals) != 9 or not all(isinstance(v, (int, float)) and math.isfinite(v) for v in vals):
            raise ValueError('Nine finite raw values required; missing signals are not padded')
        if sample['source_can_id'] not in (208, 852, 1760, 1255):
            raise ValueError('Unsupported source CAN ID')
        WIRE.pack(*vals, sample['source_can_id'])
    return samples, dict(source_sha256=hashlib.sha256(raw).hexdigest(),
                         source_description=data['source_description'], samples=len(samples),
                         provenance_status='USER_DECLARED_RECORDED')


class IDS:
    def __init__(self):
        base = ROOT/'Phase 2/IDS/ONNX'
        scaler = json.loads((base/'physical_scaler_config.json').read_text())
        self.threshold = json.loads((base/'physical_anomaly_threshold.json').read_text())
        if scaler['feature_names'][:9] != FEATURES or scaler['num_features'] != 14:
            raise ValueError('Incompatible scaler feature schema')
        self.window = deque(maxlen=scaler['window_size'])
        self.minimum = np.asarray(scaler['min_vals'], dtype=np.float32)
        self.diff = np.asarray(scaler['diff_vals'], dtype=np.float32)
        if np.any(self.diff <= 0):
            raise ValueError('Scaler spans must be positive')
        options = ort.SessionOptions()
        options.intra_op_num_threads = options.inter_op_num_threads = 1
        model = base/'v30_physical_kinematics_dynamic_int8.onnx'
        self.session = ort.InferenceSession(str(model), options, providers=['CPUExecutionProvider'])
        self.input = self.session.get_inputs()[0]
        if self.input.type != 'tensor(float)' or self.input.shape[-2:] != [30,14]:
            raise ValueError(f'Incompatible ONNX input: {self.input.shape}')
        self.artifacts = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
                          (model, base/'physical_scaler_config.json', base/'physical_anomaly_threshold.json')}

    def reset(self):
        self.window.clear()

    @staticmethod
    def features(values):
        x = np.asarray(values, dtype=np.float32)
        if x.shape != (9,) or not np.isfinite(x).all():
            raise ValueError('Invalid telemetry vector')
        wheels = x[4:8]
        residual = [abs(wheels[i]-np.median(np.delete(wheels,i))) for i in range(4)]
        return np.concatenate((x, np.asarray(residual+[abs(x[0]-np.mean(wheels))], dtype=np.float32)))

    def evaluate(self, values, source_can_id):
        features = self.features(values)
        # Only unit-independent invariant: all four raw wheel speeds zero while speed positive.
        tier15 = 'VIOLATION_WHEEL_STALL' if features[0] > 0 and np.all(features[4:8] == 0) else 'PASS'
        if tier15 != 'PASS':
            self.reset()
            return dict(tier15=tier15, tier2='SKIPPED_TIER15_REJECTION', ids_score=None)
        self.window.append((features-self.minimum)/self.diff)
        if len(self.window) < self.window.maxlen:
            return dict(tier15=tier15, tier2='WARMUP', window_samples=len(self.window), ids_score=None)
        inp = np.asarray(self.window, dtype=np.float32)[None,:,:]
        started = time.monotonic_ns()
        out = self.session.run(None, {self.input.name:inp})[0]
        elapsed = time.monotonic_ns()-started
        if out.shape != inp.shape or not np.isfinite(out).all():
            raise ValueError('Invalid ONNX output')
        mse = np.mean((inp-out)**2, axis=1)[0]
        t = self.threshold
        z = (mse-np.asarray(t['channel_mean']))/(np.asarray(t['channel_std'])+np.asarray(t['epsilon_floor']))
        indices = {208:[0,13],1760:[9,10,11,12,13],1255:[8]}.get(source_can_id,list(range(14)))
        score = float(.5*np.mean(z[indices])+.5*np.max(z[indices]))
        tau = t['locked_subsystem_tau_p995'].get(str(source_can_id),t['locked_subsystem_tau_p995']['global'])
        return dict(tier15=tier15, tier2='ANOMALY_DETECTED' if score>tau else 'PASS',
                    ids_score=score, threshold=tau, inference_ns=elapsed, window_samples=len(self.window))
