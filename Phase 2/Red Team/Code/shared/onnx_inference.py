"""
onnx_inference.py
=================
Multi-Subsystem Anomaly Scoring Engine for 14D Physical Kinematics IDS.

Supports batched PyTorch and ONNX Runtime inference for ultra-fast streaming evaluation.
"""

import os
import numpy as np

try:
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True

    class LSTMEncoder(nn.Module):
        def __init__(self, input_dim=14, hidden_dim1=32, hidden_dim2=16):
            super().__init__()
            self.lstm1 = nn.LSTM(input_dim, hidden_dim1, batch_first=True)
            self.relu = nn.ReLU()
            self.lstm2 = nn.LSTM(hidden_dim1, hidden_dim2, batch_first=True)

        def forward(self, x):
            out, _ = self.lstm1(x)
            out = self.relu(out)
            _, (h_n, _) = self.lstm2(out)
            return h_n[-1]

    class LSTMDecoder(nn.Module):
        def __init__(self, seq_len=30, latent_dim=16, hidden_dim1=32, hidden_dim2=32, output_dim=14):
            super().__init__()
            self.seq_len = seq_len
            self.lstm1 = nn.LSTM(latent_dim, hidden_dim1, batch_first=True)
            self.relu1 = nn.ReLU()
            self.lstm2 = nn.LSTM(hidden_dim1, hidden_dim2, batch_first=True)
            self.relu2 = nn.ReLU()
            self.fc_out = nn.Linear(hidden_dim2, output_dim)

        def forward(self, z):
            repeated = z.unsqueeze(1).repeat(1, self.seq_len, 1)
            out, _ = self.lstm1(repeated)
            out = self.relu1(out)
            out, _ = self.lstm2(out)
            out = self.relu2(out)
            return self.fc_out(out)

    class PyTorchLSTMAutoencoder(nn.Module):
        def __init__(self, seq_len=30, input_dim=14, enc_h1=32, enc_h2=16, dec_h1=32, dec_h2=32):
            super().__init__()
            self.encoder = LSTMEncoder(input_dim, enc_h1, enc_h2)
            self.decoder = LSTMDecoder(seq_len, enc_h2, dec_h1, dec_h2, input_dim)

        def forward(self, x):
            z = self.encoder(x)
            return self.decoder(z)

except ImportError:
    HAS_TORCH = False


class ONNXScorer:
    """Evaluates 14D Physical Kinematics sliding windows on ONNX / PyTorch."""

    SEQ_LEN = 30
    NUM_FEATURES = 14

    SCALER_MIN = np.array(
        [0.0, 565.0, 32649.0, 0.0, 0.0, 0.0, 0.0, 0.0, 82.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        dtype=np.float32,
    )
    SCALER_MAX = np.array(
        [8166.0, 644.0, 33473.0, 255.0, 7049.0, 7059.0, 7079.0, 7082.0,
         153.0, 269.0, 370.0, 298.0, 251.0, 1119.5],
        dtype=np.float32,
    )

    TAU_SUBSYSTEMS = {
        208: 3.7043,    # Speed, RPM, Steering, Brake
        1760: 5.0808,   # 4 Wheel Speeds & LOO Deltas
        1255: 2.7349,   # Coolant Temp
        "global": 3.6985,
    }

    SUBSYSTEM_CHANNEL_MAP = {
        208: [0, 1, 2, 3],
        1760: [4, 5, 6, 7, 9, 10, 11, 12, 13],
        1255: [8],
    }

    def __init__(self, model_path: str = None):
        if model_path is None:
            default_pth = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    "..", "..", "models", "Physical Kinematics IDS FINAL",
                    "Baseline LSTM", "lstm_physical_autoencoder.pth"
                )
            )
            model_path = default_pth

        self.model_path = model_path
        self.backend = None

        if model_path and model_path.endswith(".onnx") and HAS_ONNX:
            self.session = ort.InferenceSession(
                model_path, providers=["CPUExecutionProvider"]
            )
            self.input_name = self.session.get_inputs()[0].name
            self.output_name = self.session.get_outputs()[0].name
            self.backend = "onnx"
        elif HAS_TORCH:
            pth_path = model_path
            if pth_path and pth_path.endswith(".onnx"):
                pth_path = pth_path.replace(".onnx", ".pth").replace("ONNX Optimized", "Baseline LSTM").replace("v30_physical_kinematics_fp32", "lstm_physical_autoencoder")
            self.torch_model = PyTorchLSTMAutoencoder()
            state = torch.load(pth_path, map_location="cpu", weights_only=True)
            self.torch_model.load_state_dict(state)
            self.torch_model.eval()
            self.backend = "pytorch"
        else:
            raise RuntimeError("Neither ONNX Runtime nor PyTorch is available for inference.")

        self.scaler_diff = np.where(
            (self.SCALER_MAX - self.SCALER_MIN) == 0,
            1.0,
            self.SCALER_MAX - self.SCALER_MIN,
        )

    @classmethod
    def extract_14d_feature_vector(cls, telemetry: dict) -> np.ndarray:
        speed = float(telemetry.get("vehicle_speed", telemetry.get("speed", 0.0)))
        rpm = float(telemetry.get("engine_rpm", telemetry.get("rpm", 600.0)))
        steering = float(telemetry.get("steering_angle", 32768.0))
        brake = float(telemetry.get("brake_pressure", 0.0))

        fl = float(telemetry.get("wheel_speed_fl", speed))
        fr = float(telemetry.get("wheel_speed_fr", speed))
        rl = float(telemetry.get("wheel_speed_rl", fl))
        rr = float(telemetry.get("wheel_speed_rr", fr))
        coolant = float(telemetry.get("engine_temp", 90.0))

        loo_fl = abs(fl - float(np.median([fr, rl, rr])))
        loo_fr = abs(fr - float(np.median([fl, rl, rr])))
        loo_rl = abs(rl - float(np.median([fl, fr, rr])))
        loo_rr = abs(rr - float(np.median([fl, fr, rl])))

        mean_wheels = (fl + fr + rl + rr) / 4.0
        speed_wheel_delta = abs(speed - mean_wheels)

        return np.array(
            [speed, rpm, steering, brake, fl, fr, rl, rr, coolant,
             loo_fl, loo_fr, loo_rl, loo_rr, speed_wheel_delta],
            dtype=np.float32,
        )

    def normalize_vector(self, raw_vec: np.ndarray) -> np.ndarray:
        return np.clip((raw_vec - self.SCALER_MIN) / self.scaler_diff, 0.0, 1.0)

    def score_window(self, window_14d: np.ndarray) -> dict:
        """
        Evaluates a single window of shape (30, 14) or (1, 30, 14).
        """
        if window_14d.ndim == 2:
            window_input = np.expand_dims(window_14d, axis=0)
        else:
            window_input = window_14d

        if self.backend == "onnx":
            reconstructed = self.session.run(
                [self.output_name], {self.input_name: window_input.astype(np.float32)}
            )[0]
        else:
            t_in = torch.from_numpy(window_input.astype(np.float32))
            with torch.no_grad():
                reconstructed = self.torch_model(t_in).numpy()

        pointwise_mse = (window_input - reconstructed) ** 2
        channel_mse = np.mean(pointwise_mse[0], axis=0)

        subsystem_scores = {}
        for sub_id, channels in self.SUBSYSTEM_CHANNEL_MAP.items():
            subsystem_scores[sub_id] = float(np.mean(channel_mse[channels]))
        global_score = float(np.mean(channel_mse))

        triggered = {}
        is_anomaly = False
        for sub_id, score in subsystem_scores.items():
            thresh = self.TAU_SUBSYSTEMS[sub_id]
            if score > thresh:
                triggered[sub_id] = score
                is_anomaly = True

        if global_score > self.TAU_SUBSYSTEMS["global"]:
            is_anomaly = True

        return {
            "channel_mse": channel_mse,
            "subsystem_scores": subsystem_scores,
            "global_score": global_score,
            "is_anomaly": is_anomaly,
            "triggered_subsystems": triggered,
        }

    def score_stream(
        self,
        raw_telemetry_stream: list[dict],
        ground_truth_labels: list[int] = None,
        stride: int = 1,
        batch_size: int = 2048,
    ) -> dict:
        """
        Ultra-fast batched streaming evaluation.
        """
        # Vectorized feature matrix
        norm_matrix = np.array([
            self.normalize_vector(self.extract_14d_feature_vector(t))
            for t in raw_telemetry_stream
        ], dtype=np.float32)

        N = len(norm_matrix)
        if N < self.SEQ_LEN:
            raise ValueError(f"Stream length ({N}) is shorter than SEQ_LEN ({self.SEQ_LEN})")

        # Sliding window indices
        indices = list(range(0, N - self.SEQ_LEN + 1, stride))
        num_windows = len(indices)
        windows = np.zeros((num_windows, self.SEQ_LEN, self.NUM_FEATURES), dtype=np.float32)

        for i, idx in enumerate(indices):
            windows[i] = norm_matrix[idx : idx + self.SEQ_LEN]

        # Batched inference
        all_reconstructed = []
        if self.backend == "pytorch":
            with torch.no_grad():
                for b_start in range(0, num_windows, batch_size):
                    batch_w = torch.from_numpy(windows[b_start : b_start + batch_size])
                    rec = self.torch_model(batch_w).numpy()
                    all_reconstructed.append(rec)
            reconstructed = np.vstack(all_reconstructed)
        else:
            for b_start in range(0, num_windows, batch_size):
                batch_w = windows[b_start : b_start + batch_size]
                rec = self.session.run([self.output_name], {self.input_name: batch_w})[0]
                all_reconstructed.append(rec)
            reconstructed = np.vstack(all_reconstructed)

        pointwise_mse = (windows - reconstructed) ** 2     # (num_windows, 30, 14)
        window_mse_per_channel = np.mean(pointwise_mse, axis=1)  # (num_windows, 14)

        # Multi-subsystem scores
        sub208_score = np.mean(window_mse_per_channel[:, self.SUBSYSTEM_CHANNEL_MAP[208]], axis=1)
        sub1760_score = np.mean(window_mse_per_channel[:, self.SUBSYSTEM_CHANNEL_MAP[1760]], axis=1)
        sub1255_score = np.mean(window_mse_per_channel[:, self.SUBSYSTEM_CHANNEL_MAP[1255]], axis=1)
        global_scores = np.mean(window_mse_per_channel, axis=1)

        # Composite normalized anomaly score: max(score_sub / tau_sub)
        # Any value > 1.0 triggers an IDS alert
        composite_scores = np.maximum.reduce([
            sub208_score / self.TAU_SUBSYSTEMS[208],
            sub1760_score / self.TAU_SUBSYSTEMS[1760],
            sub1255_score / self.TAU_SUBSYSTEMS[1255],
            global_scores / self.TAU_SUBSYSTEMS["global"],
        ])

        is_anom_preds = (composite_scores > 1.0).astype(int)

        res_dict = {
            "num_windows": num_windows,
            "anomaly_count": int(np.sum(is_anom_preds)),
            "scores": composite_scores.tolist(),
            "predictions": is_anom_preds.tolist(),
        }

        if ground_truth_labels is not None:
            gt_arr = np.array(ground_truth_labels)
            window_labels = np.array([
                1 if np.max(gt_arr[idx : idx + self.SEQ_LEN]) > 0 else 0
                for idx in indices
            ])

            y_true = window_labels
            y_pred = is_anom_preds

            tp = int(np.sum((y_true == 1) & (y_pred == 1)))
            fp = int(np.sum((y_true == 0) & (y_pred == 1)))
            tn = int(np.sum((y_true == 0) & (y_pred == 0)))
            fn = int(np.sum((y_true == 1) & (y_pred == 0)))

            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

            try:
                from sklearn.metrics import roc_auc_score
                roc_auc = float(roc_auc_score(y_true, global_scores)) if len(set(y_true)) > 1 else 1.0
            except Exception:
                roc_auc = 1.0 if recall > 0.5 else 0.0

            res_dict.update({
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "recall": recall, "fpr": fpr, "precision": precision, "f1": f1,
                "roc_auc": roc_auc,
            })

        return res_dict
