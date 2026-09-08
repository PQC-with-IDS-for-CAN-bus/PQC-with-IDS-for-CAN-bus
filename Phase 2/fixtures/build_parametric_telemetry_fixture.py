# build_parametric_telemetry_fixture.py
import os
import sys
import json
import math
import argparse
import numpy as np
import pandas as pd
import onnxruntime as ort

BASE_DIR = r"c:\Users\tapan\Downloads\7th sem Capstone"
RED_TEAM_DIR = os.path.join(BASE_DIR, r"Anti Gravity\Phase 2\Red Team")
if RED_TEAM_DIR not in sys.path:
    sys.path.insert(0, RED_TEAM_DIR)

from module_4_masquerade_streamer.road_attack_streamer import ROADAttackStreamer

MODEL_PATH = os.path.join(BASE_DIR, r"Anti Gravity\Phase 2\models\Physical Kinematics IDS FINAL\ONNX Optimized\v30_physical_kinematics_dynamic_int8.onnx")
THRESH_PATH = os.path.join(BASE_DIR, r"Anti Gravity\Phase 2\models\Physical Kinematics IDS FINAL\ONNX Optimized\physical_anomaly_threshold.json")
OUTPUT_DIR = os.path.join(BASE_DIR, r"Anti Gravity\Phase 2\fixtures")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# DBC Physical Engineering Bounds (Hardware Scaler - 100% Leak-Free)
SCALER_MIN = np.zeros(14, dtype=np.float32)
SCALER_MAX = np.array([4000.0, 8000.0, 65535.0, 255.0, 4000.0, 4000.0, 4000.0, 4000.0, 255.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0], dtype=np.float32)
SCALER_DIFF = SCALER_MAX - SCALER_MIN

FEATURE_NAMES = [
    "vehicle_speed", "engine_rpm", "steering_angle", "brake_pressure",
    "wheel_speed_fl", "wheel_speed_fr", "wheel_speed_rl", "wheel_speed_rr",
    "coolant_temp", "loo_wheel_fl", "loo_wheel_fr", "loo_wheel_rl", "loo_wheel_rr",
    "speed_wheel_delta"
]

ATTACK_CONFIGS = [
    {"id": "EP1_AT17", "name": "AT-17_Speedometer_Masquerade", "source": "ORNL_ROAD_CSV", "file": "max_speedometer_attack_1_masquerade.csv"},
    {"id": "EP2_AT18", "name": "AT-18_Single_Wheel_LOO_Anomaly", "source": "ORNL_ROAD_CSV", "file": "correlated_signal_attack_1_masquerade.csv"},
    {"id": "EP3_AT19", "name": "AT-19_Coolant_Temp_Spike", "source": "ORNL_ROAD_CSV", "file": "max_engine_coolant_temp_attack_masquerade.csv"},
    {"id": "EP4_AT14", "name": "AT-14_All_Wheels_Stalled", "source": "SYNTHETIC"},
    {"id": "EP5_AT22", "name": "AT-22_Boiling_Frog_Drift", "source": "SYNTHETIC"},
    {"id": "EP6_AT23", "name": "AT-23_4Wheel_Symmetric_LOO_Evasion", "source": "SYNTHETIC"},
    {"id": "EP7_AT24", "name": "AT-24_Window_Boundary_Poisoning", "source": "SYNTHETIC"},
    {"id": "EP8_AT27", "name": "AT-27_Stateful_Preconditioning", "source": "SYNTHETIC"}
]

def extract_14d(telemetry: dict) -> np.ndarray:
    speed = float(telemetry.get("vehicle_speed", telemetry.get("speed", 0.0)))
    rpm = float(telemetry.get("engine_rpm", telemetry.get("rpm", 600.0)))
    steer = float(telemetry.get("steering_angle", 32768.0))
    brake = float(telemetry.get("brake_pressure", 120.0))

    fl = float(telemetry.get("wheel_speed_fl", speed))
    fr = float(telemetry.get("wheel_speed_fr", speed))
    rl = float(telemetry.get("wheel_speed_rl", fl))
    rr = float(telemetry.get("wheel_speed_rr", fr))
    coolant = float(telemetry.get("engine_temp", telemetry.get("coolant_temp", 140.0)))

    loo_fl = abs(fl - float(np.median([fr, rl, rr])))
    loo_fr = abs(fr - float(np.median([fl, rl, rr])))
    loo_rl = abs(rl - float(np.median([fl, fr, rr])))
    loo_rr = abs(rr - float(np.median([fl, fr, rl])))

    mean_wheels = (fl + fr + rl + rr) / 4.0
    speed_wheel_delta = abs(speed - mean_wheels)

    return np.array(
        [speed, rpm, steer, brake, fl, fr, rl, rr, coolant,
         loo_fl, loo_fr, loo_rl, loo_rr, speed_wheel_delta],
        dtype=np.float32
    )

def to_record(t: dict, label: str, attack_type: str, episode_id: str) -> dict:
    return {
        "label": label,
        "attack_type": attack_type,
        "episode_id": episode_id,
        "speed": float(t.get("speed", 100.0)),
        "rpm": float(t.get("rpm", 609.0)),
        "steering_angle": float(t.get("steering_angle", 32768.0)),
        "brake_pressure": float(t.get("brake_pressure", 120.0)),
        "wheel_speed_fl": float(t.get("wheel_speed_fl", 100.0)),
        "wheel_speed_fr": float(t.get("wheel_speed_fr", 100.0)),
        "wheel_speed_rl": float(t.get("wheel_speed_rl", 100.0)),
        "wheel_speed_rr": float(t.get("wheel_speed_rr", 100.0)),
        "engine_temp": float(t.get("engine_temp", 140.0)),
        "gear_status": 1,
        "dtc_flags": 0
    }

def synthesize_attack_episode(atk_cfg: dict, count: int, anchor: dict, streamer: ROADAttackStreamer) -> list:
    atk_id = atk_cfg["id"]
    atk_name = atk_cfg["name"]
    source = atk_cfg["source"]
    records = []

    if source == "ORNL_ROAD_CSV":
        csv_path = os.path.join(streamer.attacks_dir, atk_cfg["file"])
        s_atk, l_atk = streamer.parse_road_csv_to_telemetry(csv_path, max_context=20000)
        attack_frames = [s_atk[i] for i in range(len(l_atk)) if l_atk[i] == 1]
        
        # If count exceeds available frames, sustain the attack state
        if len(attack_frames) < count:
            while len(attack_frames) < count:
                base = dict(attack_frames[-1]) if attack_frames else dict(anchor)
                if "1255" in atk_cfg["file"] or "coolant" in atk_cfg["file"]:
                    base["engine_temp"] = 152.0
                attack_frames.append(base)
        else:
            attack_frames = attack_frames[:count]

        for t in attack_frames:
            records.append(to_record(t, "ATTACK", atk_name, atk_id))

    elif atk_name == "AT-14_All_Wheels_Stalled":
        for _ in range(count):
            r = dict(anchor)
            r.update({
                "label": "ATTACK", "attack_type": atk_name, "episode_id": atk_id,
                "wheel_speed_fl": 0.0, "wheel_speed_fr": 0.0, "wheel_speed_rl": 0.0, "wheel_speed_rr": 0.0
            })
            records.append(r)

    elif atk_name == "AT-22_Boiling_Frog_Drift":
        # Gradual ramp across the attack episode
        for i in range(count):
            # Scale drift so it ramps realistically across count frames
            drift = 15.0 + (i * (75.0 / count))
            r = dict(anchor)
            r.update({
                "label": "ATTACK", "attack_type": atk_name, "episode_id": atk_id,
                "speed": anchor["speed"] + drift
            })
            records.append(r)

    elif atk_name == "AT-23_4Wheel_Symmetric_LOO_Evasion":
        for _ in range(count):
            r = dict(anchor)
            r.update({
                "label": "ATTACK", "attack_type": atk_name, "episode_id": atk_id,
                "wheel_speed_fl": 350.0, "wheel_speed_fr": 350.0, "wheel_speed_rl": 350.0, "wheel_speed_rr": 350.0
            })
            records.append(r)

    elif atk_name == "AT-24_Window_Boundary_Poisoning":
        for i in range(count):
            pulse = 600.0 if (i % 10 < 3) else 0.0
            r = dict(anchor)
            r.update({
                "label": "ATTACK", "attack_type": atk_name, "episode_id": atk_id,
                "speed": anchor["speed"] + pulse, "rpm": anchor["rpm"] + (pulse * 2)
            })
            records.append(r)

    elif atk_name == "AT-27_Stateful_Preconditioning":
        for i in range(count):
            osc = (math.sin(i * 0.4) + 1.2) * 1500.0
            r = dict(anchor)
            r.update({
                "label": "ATTACK", "attack_type": atk_name, "episode_id": atk_id,
                "rpm": anchor["rpm"] + osc, "steering_angle": anchor["steering_angle"] + (osc * 0.5),
                "wheel_speed_fl": anchor["wheel_speed_fl"] + 40.0, "wheel_speed_fr": anchor["wheel_speed_fr"] - 40.0
            })
            records.append(r)

    return records

def generate_fixture(mode: str = "upper_bound", seed: int = 42, W: int = 30):
    print("=" * 80)
    print(f"GENERATING GOLDEN TELEMETRY FIXTURE: MODE={mode.upper()} | SEED={seed} | W={W}")
    print("=" * 80)

    streamer = ROADAttackStreamer()
    session = ort.InferenceSession(MODEL_PATH, providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    output_name = session.get_outputs()[0].name

    with open(THRESH_PATH) as f:
        thresh_cfg = json.load(f)

    c_mean = np.array(thresh_cfg["channel_mean"], dtype=np.float32)
    c_std = np.array(thresh_cfg["channel_std"], dtype=np.float32)
    c_eps = np.array(thresh_cfg["epsilon_floor"], dtype=np.float32)
    taus = thresh_cfg["locked_subsystem_tau_p995"]

    # 1. Determine Episode Sizes
    rng = np.random.default_rng(seed)
    if mode == "upper_bound":
        # Strict upper bound of all recommendations:
        # Burn-in: 10W (300 frames)
        # All 8 attacks: 5W (150 frames each)
        # All 8 recoveries: 5W (150 frames each)
        burn_in_frames = 10 * W
        attack_frames = [5 * W] * 8
        recovery_frames = [5 * W] * 8
        fixture_name = "telemetry_golden_fixture_upper_bound"
    elif mode == "dynamic":
        # Dynamic sampling across literature recommended ranges:
        # Burn-in: Uniform(3W, 10W) -> 90 to 300 frames
        # Each attack i: Uniform(1W, 5W) -> 30 to 150 frames (all different!)
        # Each recovery i: Uniform(2.5W, 5W) -> 75 to 150 frames
        burn_in_w = rng.uniform(3.0, 10.0)
        burn_in_frames = int(round(burn_in_w * W))
        
        attack_w = rng.uniform(1.0, 5.0, size=8)
        attack_frames = [int(round(m * W)) for m in attack_w]

        rec_w = rng.uniform(2.5, 5.0, size=8)
        recovery_frames = [int(round(m * W)) for m in rec_w]
        fixture_name = f"telemetry_golden_fixture_dynamic_seed{seed}"
    else:
        raise ValueError(f"Unknown mode: {mode}")

    total_clean_needed = burn_in_frames + sum(recovery_frames)
    total_attack_needed = sum(attack_frames)
    total_stream_length = total_clean_needed + total_attack_needed

    print(f"Stream Plan:")
    print(f"  • Burn-in:       {burn_in_frames} frames ({burn_in_frames/W:.1f}W, {burn_in_frames*0.01:.2f}s)")
    print(f"  • Attack Frames: {total_attack_needed} frames across 8 episodes: {attack_frames}")
    print(f"  • Recovery:      {sum(recovery_frames)} frames across 8 buffers: {recovery_frames}")
    print(f"  • Total Stream:  {total_stream_length} frames ({total_stream_length*0.01:.2f}s) | Clean: {total_clean_needed} ({total_clean_needed/total_stream_length*100:.1f}%), Attack: {total_attack_needed} ({total_attack_needed/total_stream_length*100:.1f}%)")

    # 2. Load Clean Highway Driving Frames
    ambient_path = os.path.join(streamer.ambient_dir, "ambient_highway_street_driving_long.csv")
    s_amb, _ = streamer.parse_road_csv_to_telemetry(ambient_path, max_context=25000)
    clean_moving = [t for t in s_amb if t.get("speed", 0.0) > 30.0 and t.get("wheel_speed_fl", 0.0) > 30.0]
    
    if len(clean_moving) < total_clean_needed:
        print(f"Warning: Clean moving frames ({len(clean_moving)}) < needed ({total_clean_needed}). Cycling ambient.")
        clean_moving = clean_moving * (int(math.ceil(total_clean_needed / len(clean_moving))) + 1)
    
    clean_pool = clean_moving[:total_clean_needed]

    # 3. Assemble Interleaved Stream
    all_records = []
    clean_ptr = 0

    def add_clean_buffer(count: int, ep_id: str):
        nonlocal clean_ptr
        chunk = clean_pool[clean_ptr : clean_ptr + count]
        clean_ptr += count
        for t in chunk:
            all_records.append(to_record(t, "NORMAL", "NONE", ep_id))

    # Add initial burn-in
    add_clean_buffer(burn_in_frames, "WARMUP")

    # Add 8 cycles
    for ep_idx, atk_cfg in enumerate(ATTACK_CONFIGS):
        ep_num = ep_idx + 1
        atk_count = attack_frames[ep_idx]
        rec_count = recovery_frames[ep_idx]

        # Anchor from preceding normal driving frame
        last = all_records[-1]
        anchor = {
            "speed": last["speed"], "rpm": last["rpm"], "steering_angle": last["steering_angle"],
            "brake_pressure": 120.0, "wheel_speed_fl": last["wheel_speed_fl"],
            "wheel_speed_fr": last["wheel_speed_fr"], "wheel_speed_rl": last["wheel_speed_rl"],
            "wheel_speed_rr": last["wheel_speed_rr"], "engine_temp": last["engine_temp"],
            "gear_status": 1, "dtc_flags": 0
        }

        # Attack episode
        atk_recs = synthesize_attack_episode(atk_cfg, atk_count, anchor, streamer)
        all_records.extend(atk_recs)

        # Recovery interval
        rec_id = f"RECOVERY_{ep_num}"
        add_clean_buffer(rec_count, rec_id)

    for idx, r in enumerate(all_records):
        r["frame_idx"] = idx

    # 4. Score Entire Stream using ONNX INT8 Autoencoder
    print("\nScoring stream with ONNX Dynamic INT8 Engine...")
    feature_matrix = np.array([extract_14d(r) for r in all_records], dtype=np.float32)
    norm_matrix = np.clip((feature_matrix - SCALER_MIN) / SCALER_DIFF, 0.0, 1.0)

    eval_results = []
    for i in range(len(norm_matrix)):
        if i < W:
            pad = W - (i + 1)
            w = np.vstack([np.tile(norm_matrix[0], (pad, 1)), norm_matrix[:i+1]])
        else:
            w = norm_matrix[i-W+1:i+1]
        
        rec = session.run([output_name], {input_name: np.expand_dims(w, 0)})[0]
        ch_mse = np.mean((np.expand_dims(w, 0) - rec)**2, axis=(0, 1))
        z = (ch_mse - c_mean) / (c_std + c_eps)

        s_208 = float(0.5 * np.mean(z[[0, 13]]) + 0.5 * np.max(z[[0, 13]]))
        s_1760 = float(0.5 * np.mean(z[[9, 10, 11, 12, 13]]) + 0.5 * np.max(z[[9, 10, 11, 12, 13]]))
        s_1255 = float(z[8])
        s_glob = float(0.5 * np.mean(z) + 0.5 * np.max(z))

        inv_triggered = False
        row_spd = feature_matrix[i, 0]
        row_fl = feature_matrix[i, 4]
        row_fr = feature_matrix[i, 5]
        row_rl = feature_matrix[i, 6]
        row_rr = feature_matrix[i, 7]
        if row_spd > 60.0 and (row_fl == 0.0 and row_fr == 0.0 and row_rl == 0.0 and row_rr == 0.0):
            inv_triggered = True

        is_anomaly = (
            (s_208 > taus["208"]) or
            (s_1760 > taus["1760"]) or
            (s_1255 > taus["1255"]) or
            (s_glob > taus["global"]) or
            inv_triggered
        )

        eval_results.append({
            "tier2_sub_208_z": s_208,
            "tier2_sub_1760_z": s_1760,
            "tier2_sub_1255_z": s_1255,
            "tier2_global_z": s_glob,
            "tier1_5_inv_triggered": inv_triggered,
            "tier2_is_anomaly": bool(is_anomaly)
        })

    df_fixture = pd.DataFrame(all_records)
    for idx, col in enumerate(FEATURE_NAMES):
        df_fixture[col] = feature_matrix[:, idx]
        df_fixture[f"{col}_norm"] = norm_matrix[:, idx]

    for k in eval_results[0].keys():
        df_fixture[k] = [res[k] for res in eval_results]

    # 5. Evaluate Metrics
    clean_mask = (df_fixture["label"] == "NORMAL")
    attack_mask = (df_fixture["label"] == "ATTACK")
    tp_total = int(df_fixture.loc[attack_mask, "tier2_is_anomaly"].sum())

    # Flush buffer mask (W frames immediately following each attack episode)
    flush_mask = pd.Series(False, index=df_fixture.index)
    for ep in range(1, 9):
        rec_indices = df_fixture[df_fixture["episode_id"] == f"RECOVERY_{ep}"].index
        if len(rec_indices) >= W:
            flush_mask.loc[rec_indices[:W]] = True

    steady_clean_mask = clean_mask & (~flush_mask)
    fp_steady = int(df_fixture.loc[steady_clean_mask, "tier2_is_anomaly"].sum())
    fp_flush = int(df_fixture.loc[flush_mask, "tier2_is_anomaly"].sum())

    print("\n" + "=" * 80)
    print(f"BENCHMARK RESULTS: {fixture_name}")
    print("=" * 80)
    print(f"Total Stream Frames:           {len(df_fixture)} ({len(df_fixture)*0.01:.2f}s)")
    print(f"Attack Injections:             {total_attack_needed} frames | Detected: {tp_total} (TPR: {tp_total/total_attack_needed*100:.2f}%)")
    print(f"Steady-State Clean Frames:     {steady_clean_mask.sum()} frames | False Positives: {fp_steady} (FPR: {fp_steady/steady_clean_mask.sum()*100:.2f}%)")
    print(f"Flush Buffer Transitions (W):  {flush_mask.sum()} frames | Transients: {fp_flush}")
    print("-" * 80)
    print("Per-Episode Detection Breakdown:")
    for ep_idx, atk_cfg in enumerate(ATTACK_CONFIGS):
        ep_num = ep_idx + 1
        atk_id = atk_cfg["id"]
        sub_at = df_fixture[df_fixture["episode_id"] == atk_id]
        det = int(sub_at["tier2_is_anomaly"].sum())
        
        rec_sub = df_fixture[df_fixture["episode_id"] == f"RECOVERY_{ep_num}"]
        steady_rec = rec_sub.iloc[W:] if len(rec_sub) > W else rec_sub.iloc[:0]
        rec_alarms = int(steady_rec["tier2_is_anomaly"].sum())
        
        print(f"  • Episode {ep_num} [{atk_cfg['name']:35s}]: {det:3d}/{len(sub_at):3d} detected ({det/len(sub_at)*100:5.1f}%) | Duration: {len(sub_at)*0.01:.2f}s ({len(sub_at)/W:.1f}W) | Post-Flush Alarms: {rec_alarms:d}/{len(steady_rec):d}")
    print("=" * 80)

    # 6. Export CSV & JSON
    csv_path = os.path.join(OUTPUT_DIR, f"{fixture_name}.csv")
    json_path = os.path.join(OUTPUT_DIR, f"{fixture_name}.json")

    df_fixture.to_csv(csv_path, index=False)
    print(f"Saved CSV:  {csv_path} ({os.path.getsize(csv_path):,} bytes)")

    json_payload = {
        "metadata": {
            "fixture_name": fixture_name,
            "mode": mode,
            "seed": seed if mode == "dynamic" else None,
            "total_records": len(df_fixture),
            "clean_records": int(clean_mask.sum()),
            "attack_records": int(attack_mask.sum()),
            "steady_clean_records": int(steady_clean_mask.sum()),
            "duration_seconds": round(len(df_fixture) * 0.01, 2),
            "sampling_rate_hz": 100.0,
            "window_size_W": W,
            "burn_in_frames": burn_in_frames,
            "attack_frames_per_episode": attack_frames,
            "recovery_frames_per_episode": recovery_frames,
            "feature_names": FEATURE_NAMES,
            "scaler_bounds": {"min_vals": SCALER_MIN.tolist(), "max_vals": SCALER_MAX.tolist()},
            "thresholds": taus,
            "attack_classes": [cfg["name"] for cfg in ATTACK_CONFIGS]
        },
        "records": df_fixture.to_dict(orient="records")
    }

    with open(json_path, "w") as f:
        json.dump(json_payload, f, indent=2)

    print(f"Saved JSON: {json_path} ({os.path.getsize(json_path):,} bytes)")
    return df_fixture

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", type=str, choices=["upper_bound", "dynamic"], default="upper_bound")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--window", type=int, default=30)
    args = parser.parse_args()

    generate_fixture(mode=args.mode, seed=args.seed, W=args.window)
