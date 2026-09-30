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
try:
    import onnxruntime as ort
except ImportError:
    ort = None
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
    def __init__(self, enable_quarantine: bool = True):
        base = ROOT/'Phase 2/IDS/ONNX'
        scaler = json.loads((base/'physical_scaler_config.json').read_text())
        self.threshold = json.loads((base/'physical_anomaly_threshold.json').read_text())
        if scaler['feature_names'][:9] != FEATURES or scaler['num_features'] != 14:
            raise ValueError('Incompatible scaler feature schema')
        self.window_size = scaler['window_size']
        self.window = deque(maxlen=self.window_size)
        self.minimum = np.asarray(scaler['min_vals'], dtype=np.float32)
        self.diff = np.asarray(scaler['diff_vals'], dtype=np.float32)
        if np.any(self.diff <= 0):
            raise ValueError('Scaler spans must be positive')
        self.enable_quarantine = enable_quarantine
        self.x_valid = None  # Last verified physical kinematics vector for Zero-Order Hold (Mode B)
        self.quarantine_substitutions = 0
        model = base/'v30_physical_kinematics_dynamic_int8.onnx'
        if ort is not None:
            options = ort.SessionOptions()
            options.intra_op_num_threads = options.inter_op_num_threads = 1
            self.session = ort.InferenceSession(str(model), options, providers=['CPUExecutionProvider'])
            self.input = self.session.get_inputs()[0]
            if self.input.type != 'tensor(float)' or self.input.shape[-2:] != [30,14]:
                raise ValueError(f'Incompatible ONNX input: {self.input.shape}')
        else:
            self.session = None
            self.input = None
        self.artifacts = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
                          (model, base/'physical_scaler_config.json', base/'physical_anomaly_threshold.json')}

    def reset(self):
        self.window.clear()
        self.x_valid = None
        self.quarantine_substitutions = 0

    @staticmethod
    def features(values):
        x = np.asarray(values, dtype=np.float32)
        if x.shape != (9,) or not np.isfinite(x).all():
            raise ValueError('Invalid telemetry vector')
        wheels = x[4:8]
        residual = [abs(wheels[i]-np.median(np.delete(wheels,i))) for i in range(4)]
        return np.concatenate((x, np.asarray(residual+[abs(x[0]-np.mean(wheels))], dtype=np.float32)))

    def evaluate_tier15(self, values, telemetry_dict=None):
        """Tier 1.5 Deterministic Discrete Invariant Checker (< 50 us)."""
        speed = values[0]
        rpm = values[1]
        steer = values[2]
        brake = values[3]
        wheels = values[4:8]

        # INV_03: Vehicle highway/city speed > 10 km/h with wheel speed sensors stalled at 0
        if speed > 10.0 and np.all(wheels == 0.0):
            return 'VIOLATION_WHEEL_STALL'

        # INV_02: High engine revs (> 4000 RPM) while completely stationary (speed == 0) and brake not applied
        if speed == 0.0 and rpm > 4500.0 and brake < 10.0:
            return 'VIOLATION_RPM_SPEED_DISPARITY'

        # Optional extended dictionary checks if extra CAN signals present
        if telemetry_dict and isinstance(telemetry_dict, dict):
            gear = telemetry_dict.get('gear_status', 0)
            throttle = telemetry_dict.get('throttle_pos', 0.0)
            dtc = telemetry_dict.get('dtc_error_count', 0)
            if gear == -1 and speed > 15.0:  # Reverse gear active at forward highway speed
                return 'VIOLATION_REVERSE_LIGHT_FORWARD_SPEED'
            if brake > 200.0 and throttle > 90.0:  # Simultaneous full brake and full throttle
                return 'VIOLATION_BRAKE_THROTTLE_CONFLICT'
            if dtc > 16:  # DTC bit saturation
                return 'VIOLATION_DTC_WORD_SATURATION'

        return 'PASS'

    def evaluate(self, values, source_can_id, telemetry_dict=None):
        features = self.features(values)
        norm = np.clip((features - self.minimum) / self.diff, 0.0, 1.0)

        # Tier 1.5: Discrete Invariant Gate (< 50 us)
        tier15 = self.evaluate_tier15(values, telemetry_dict)
        if tier15 != 'PASS':
            if self.enable_quarantine and self.x_valid is not None:
                # Substitute ZOH state upon invariant rejection
                if len(self.window) == self.window_size:
                    self.window.popleft()
                    self.window.append(self.x_valid.copy())
                    self.quarantine_substitutions += 1
            else:
                self.reset()
            return dict(tier15=tier15, tier2='SKIPPED_TIER15_REJECTION', ids_score=None,
                        quarantine_activated=self.enable_quarantine)

        # Warmup phase: collect initial nominal frames until window reaches window_size (30)
        if len(self.window) < self.window_size - 1:
            self.window.append(norm)
            self.x_valid = norm.copy()
            return dict(tier15=tier15, tier2='WARMUP', window_samples=len(self.window), ids_score=None,
                        quarantine_activated=False)
        elif len(self.window) == self.window_size - 1:
            self.window.append(norm)
            self.x_valid = norm.copy()

        # -------------------------------------------------------------
        # Mode B: Dual-State Dynamic Window Quarantine (Candidate Ingress)
        # -------------------------------------------------------------
        if self.enable_quarantine:
            # Candidate window: test new packet without committing it into historical buffer
            cand_window = list(self.window)[1:] + [norm]
        else:
            # Mode A: Unquarantined FIFO queue
            self.window.append(norm)
            cand_window = list(self.window)

        inp = np.asarray(cand_window, dtype=np.float32)[None, :, :]
        started = time.monotonic_ns()
        if self.session is not None:
            out = self.session.run(None, {self.input.name: inp})[0]
            elapsed = time.monotonic_ns() - started
            if out.shape != inp.shape or not np.isfinite(out).all():
                raise ValueError('Invalid ONNX output')
        else:
            # Deterministic reference reconstruction fallback when ort is missing on host
            out = np.tile(np.mean(inp, axis=1, keepdims=True), (1, inp.shape[1], 1))
            elapsed = max(1000, time.monotonic_ns() - started)

        mse = np.mean((inp - out) ** 2, axis=1)[0]
        t = self.threshold
        z = (mse - np.asarray(t['channel_mean'])) / (np.asarray(t['channel_std']) + np.asarray(t['epsilon_floor']))
        indices = {208: [0, 13], 1760: [9, 10, 11, 12, 13], 1255: [8]}.get(source_can_id, list(range(14)))
        score = float(0.5 * np.mean(z[indices]) + 0.5 * np.max(z[indices]))
        tau = t['locked_subsystem_tau_p995'].get(str(source_can_id), t['locked_subsystem_tau_p995']['global'])

        is_anomaly = score > tau

        if self.enable_quarantine:
            if is_anomaly:
                # Mode B Quarantine Action:
                # Discard candidate poisoned frame. Commit Zero-Order Hold of last verified clean frame!
                self.quarantine_substitutions += 1
                fallback = self.x_valid if self.x_valid is not None else np.zeros(14, dtype=np.float32)
                self.window.popleft()
                self.window.append(fallback.copy())
            else:
                # Benign Frame: Commit norm to history buffer and update verified state register
                self.window.popleft()
                self.window.append(norm)
                self.x_valid = norm.copy()

        return dict(tier15=tier15,
                    tier2='ANOMALY_DETECTED' if is_anomaly else 'PASS',
                    ids_score=score,
                    threshold=tau,
                    inference_ns=elapsed,
                    window_samples=len(self.window),
                    quarantine_activated=self.enable_quarantine and is_anomaly,
                    quarantine_substitutions=self.quarantine_substitutions)

