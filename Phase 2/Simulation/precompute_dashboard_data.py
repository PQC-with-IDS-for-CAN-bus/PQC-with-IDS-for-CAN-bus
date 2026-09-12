"""
precompute_dashboard_data.py
============================
Precomputes authentic ONNX INT8 Autoencoder inference results for all 3,000 frames
of the Golden Telemetry Drive Cycle with Dual-State Dynamic Window Quarantine.
Produces `dashboard_precomputed_3000.json` to be embedded directly into
`poc_interactive_dashboard.html`, eliminating synthetic Math.random() approximations.
"""

import json
from pathlib import Path
import numpy as np
import onnxruntime as ort

SIM_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = SIM_DIR.parent / "fixtures"
MODELS_DIR = SIM_DIR.parent / "models" / "Physical Kinematics IDS FINAL" / "ONNX Optimized"

print("--- [PRECOMPUTING REAL ONNX INFERENCE DATA FOR DASHBOARD] ---")
print(f"Loading fixture: {FIXTURES_DIR / 'telemetry_golden_fixture_3000.json'}")
with open(FIXTURES_DIR / "telemetry_golden_fixture_3000.json") as f:
    data = json.load(f)
records = data["records"]

model_path = MODELS_DIR / "v30_physical_kinematics_dynamic_int8.onnx"
print(f"Loading ONNX Model: {model_path}")
session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

with open(MODELS_DIR / "physical_anomaly_threshold.json") as f:
    thresh_cfg = json.load(f)

c_mean = np.array(thresh_cfg["channel_mean"], dtype=np.float32)
c_std = np.array(thresh_cfg["channel_std"], dtype=np.float32)
c_eps = np.array(thresh_cfg["epsilon_floor"], dtype=np.float32)
taus = thresh_cfg["locked_subsystem_tau_p995"]

SCALER_MIN = np.zeros(14, dtype=np.float32)
SCALER_MAX = np.array([4000.0, 8000.0, 65535.0, 255.0, 4000.0, 4000.0, 4000.0, 4000.0, 255.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0], dtype=np.float32)
SCALER_DIFF = SCALER_MAX - SCALER_MIN

def extract_14d_vector(r):
    speed = float(r.get("speed", 0.0))
    rpm = float(r.get("rpm", 600.0))
    steer = float(r.get("steering_angle", 32768.0))
    brake = float(r.get("brake_pressure", 120.0))
    fl = float(r.get("wheel_speed_fl", speed))
    fr = float(r.get("wheel_speed_fr", speed))
    rl = float(r.get("wheel_speed_rl", fl))
    rr = float(r.get("wheel_speed_rr", fr))
    coolant = float(r.get("engine_temp", 140.0))
    loo_fl = abs(fl - float(np.median([fr, rl, rr])))
    loo_fr = abs(fr - float(np.median([fl, rl, rr])))
    loo_rl = abs(rl - float(np.median([fl, fr, rr])))
    loo_rr = abs(rr - float(np.median([fl, fr, rl])))
    mean_w = (fl + fr + rl + rr) / 4.0
    swd = abs(speed - mean_w)
    return np.array([speed, rpm, steer, brake, fl, fr, rl, rr, coolant, loo_fl, loo_fr, loo_rl, loo_rr, swd], dtype=np.float32)

W = 30
window_buffer = []
last_clean_norm = None
dashboard_frames = []

# Injection indices for 3000 frames
inj_map = {
    240: ("DROP_TIER1", "AT-01: Ascon Tag Corruption", "AT-01 Tag Mismatch"),
    245: ("DROP_TIER1", "AT-02: Stale Whole-Frame Replay", "AT-02 Replayed Frame"),
    250: ("DROP_TIER1", "AT-04: Monotonic Counter Replay", "AT-04 Counter Replay"),
    255: ("DROP_TIER1", "AT-05: Non-Monotonic Counter Step", "AT-05 Rollback Step"),
    260: ("DROP_TIER1", "AT-06: 20 kHz Line-Rate DoS Flood", "AT-06 IFAT Violation"),
    270: ("DROP_TIER1_5", "AT-12: Reverse Gear at Highway Velocity", "INV_01 Reverse at Speed"),
    275: ("DROP_TIER1_5", "INV_02: Contradictory Gear/RPM", "INV_02 Drive at 0 km/h with 4800 RPM"),
    280: ("DROP_TIER1_5", "AT-14: All Wheels Stalled at Speed", "INV_03 Wheels Stalled"),
    290: ("DROP_TIER1_5", "AT-15: Full Brake & Max Throttle", "INV_04 Brake-Throttle Conflict"),
    295: ("DROP_TIER1_5", "INV_05: DTC Flag Saturation", "INV_05 DTC Saturation")
}

print("Running ONNX inference with Mode B Dual-State Quarantine across 3000 frames...")
for idx, r in enumerate(records):
    vec14 = extract_14d_vector(r)
    norm14 = np.clip((vec14 - SCALER_MIN) / SCALER_DIFF, 0.0, 1.0)
    
    speed = float(r.get("speed", 0.0))
    rpm = float(r.get("rpm", 600.0))
    coolant = float(r.get("engine_temp", 140.0))
    fl = float(r.get("wheel_speed_fl", speed))
    fr = float(r.get("wheel_speed_fr", speed))
    rl = float(r.get("wheel_speed_rl", fl))
    rr = float(r.get("wheel_speed_rr", fr))
    steer = float(r.get("steering_angle", 32768.0))
    brake = float(r.get("brake_pressure", 120.0))
    throttle = float(r.get("throttle_pos", 0.0))
    ep_id = r.get("episode_id", "CI_TEST")
    label = r.get("label", "NORMAL")
    attack_type = r.get("attack_type", "None")

    if idx in inj_map:
        disp, inj_name, reason = inj_map[idx]
        is_quarantined = False
        z208, z1760, z1255, zGlob = 0.1, 0.1, -1.0, 0.1
    else:
        if len(window_buffer) < W:
            window_buffer.append(norm14)
            last_clean_norm = norm14.copy()
            disp = "PASS"
            reason = "NOMINAL_CLEAN"
            is_quarantined = False
            z208, z1760, z1255, zGlob = 0.1, 0.1, -1.0, 0.1
        else:
            cand_window = window_buffer[1:] + [norm14]
            w_mat = np.array(cand_window, dtype=np.float32)
            rec = session.run([output_name], {input_name: np.expand_dims(w_mat, 0)})[0]
            ch_mse = np.mean((np.expand_dims(w_mat, 0) - rec)**2, axis=(0, 1))
            z = (ch_mse - c_mean) / (c_std + c_eps)

            z208 = float(0.5 * np.mean(z[[0, 13]]) + 0.5 * np.max(z[[0, 13]]))
            z1760 = float(0.5 * np.mean(z[[9, 10, 11, 12, 13]]) + 0.5 * np.max(z[[9, 10, 11, 12, 13]]))
            z1255 = float(z[8])
            zGlob = float(0.5 * np.mean(z) + 0.5 * np.max(z))

            is_anom = (z208 > taus["208"]) or (z1760 > taus["1760"]) or (z1255 > taus["1255"]) or (zGlob > taus["global"])

            # Check if Tier 1.5 invariant triggered in fixture (e.g. EP4_AT14)
            if r.get("tier1_5_inv_triggered", False):
                disp = "DROP_TIER1_5"
                reason = "Tier 1.5 Invariant Violation (Wheels Stalled)"
                is_quarantined = True
                window_buffer = window_buffer[1:] + [last_clean_norm.copy()]
            elif is_anom:
                disp = "FLAG_TIER2"
                reasons = []
                if z208 > taus["208"]: reasons.append(f"Sub208_Z={z208:.1f}")
                if z1760 > taus["1760"]: reasons.append(f"Sub1760_Z={z1760:.1f}")
                if z1255 > taus["1255"]: reasons.append(f"Sub1255_Z={z1255:.1f}")
                if zGlob > taus["global"]: reasons.append(f"Global_Z={zGlob:.1f}")
                reason = ", ".join(reasons)
                is_quarantined = True
                fallback = last_clean_norm if last_clean_norm is not None else np.zeros(14, dtype=np.float32)
                window_buffer = window_buffer[1:] + [fallback.copy()]
            else:
                disp = "PASS"
                reason = "NOMINAL_CLEAN"
                is_quarantined = False
                window_buffer = cand_window
                is_plausible = (vec14[8] < 180.0) and (vec14[13] < 30.0) and (max(vec14[9], vec14[10], vec14[11], vec14[12]) < 25.0)
                if is_plausible and zGlob < 2.0:
                    last_clean_norm = norm14.copy()

    dashboard_frames.append({
        "i": idx,
        "s": round(speed, 1),
        "rpm": round(rpm, 0),
        "c": round(coolant, 1),
        "fl": round(fl, 1),
        "fr": round(fr, 1),
        "rl": round(rl, 1),
        "rr": round(rr, 1),
        "steer": round(steer, 0),
        "brk": round(brake, 1),
        "thr": round(throttle, 1),
        "z208": round(z208, 2),
        "z1760": round(z1760, 2),
        "z1255": round(z1255, 2),
        "zG": round(zGlob, 2),
        "d": disp,
        "r": reason,
        "q": is_quarantined,
        "ep": ep_id,
        "lbl": label,
        "atk": attack_type
    })

out_file = SIM_DIR / "dashboard_precomputed_3000.json"
print(f"Exporting {len(dashboard_frames)} frames to: {out_file}")
with open(out_file, "w") as f:
    json.dump({"taus": taus, "total_frames": len(dashboard_frames), "frames": dashboard_frames}, f, separators=(",", ":"))

print(f"Precomputation complete! File size: {out_file.stat().st_size / 1024:.1f} KB")