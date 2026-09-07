#!/usr/bin/env python3
"""
compare_transport_protocols.py
==============================
Phase 3 M3.1: 3-Way Transport Protocol Trade-Off & Benchmarking Engine

Evaluates and compares three in-vehicle large-payload transport strategies:
  1. Base Paper Custom Slicing (Castiglione & Elia 2025: Unindexed slicing, ID 0x047 full restart)
  2. Automotive Industry Standard ISO-TP (ISO 15765-2:2016: Rolling SN, full-sequence abort)
  3. Proposed 60/4 Indexed Block Transfer (41 frames, 4B header, 64-bit selective NACK bitmap on ID 0x201)

Methodology:
  - Pillar 1: Exact Closed-Form Bounded-Retry Math (Initial send + at most 3 retries, total 4 attempts)
  - Pillar 2: Gilbert-Elliott 2-State Markov Burst Noise Monte Carlo Validation
  - Pillar 3: 5 Project-Defined Deterministic Fault-Injection Canonical Case Studies
  - Multi-Bitrate Regimes: 1.0 Mbps flat, 500k/2.0 Mbps, and 500k/5.0 Mbps

Outputs:
  - 3 Publication-Quality Figures (300 DPI) in Anti Gravity/Phase 3/figures/
  - Raw Benchmark Dataset in Anti Gravity/Phase 3/data/transport_protocol_benchmark_data.csv
  - Provenance & Environment Metadata in Anti Gravity/Phase 3/data/provenance_metadata.json
"""

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone

import matplotlib.pyplot as plt
import numpy as np

# Set publication style
plt.rcParams.update({
    "font.size": 11,
    "font.family": "serif",
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.titlesize": 14,
    "lines.linewidth": 2.0,
    "grid.alpha": 0.35,
    "grid.linestyle": "--"
})


# ==============================================================================
# 1. PILLAR 1: EXACT CLOSED-FORM BOUNDED-RETRY MATHEMATICAL FORMULATION
# ==============================================================================

def analytical_eval_castiglione(n_frames: int, p: float, max_retries: int = 3) -> dict:
    """
    Castiglione et al. (2025) Unindexed Slicing.
    Frames have 0B headers. Receiver counts arrivals.
    Any single frame loss causes an unindexed retransmission request (ID 0x047)
    which forces the Gateway to retransmit all n_frames from scratch.
    """
    total_attempts = max_retries + 1
    p_attempt_succ = (1.0 - p) ** n_frames
    p_attempt_fail = 1.0 - p_attempt_succ

    # Overall success probability within max_retries
    p_overall_succ = 1.0 - (p_attempt_fail ** total_attempts)

    # Expected frames transmitted under bounded retries
    if p_attempt_succ > 1e-12:
        # Sum of geometric series for 4 attempts
        attempts_expected = (1.0 - (p_attempt_fail ** total_attempts)) / p_attempt_succ
    else:
        attempts_expected = float(total_attempts)

    # Each attempt transmits n_frames + 1 null NACK frame on ID 0x047 (for failed attempts)
    expected_data_frames = attempts_expected * n_frames
    expected_nack_frames = (attempts_expected - p_overall_succ)  # NACK sent on each failed attempt

    return {
        "p_success": float(p_overall_succ),
        "expected_data_frames": float(expected_data_frames),
        "expected_ctrl_frames": float(max(0.0, expected_nack_frames)),
        "expected_total_frames": float(expected_data_frames + max(0.0, expected_nack_frames))
    }


def analytical_eval_isotp(p: float, max_retries: int = 3) -> dict:
    """
    Standard ISO-TP (ISO 15765-2:2016).
    1 First Frame (62B payload per ISO 15765-2:2016 for DL <= 4095) + 38 Consecutive Frames (63B payload) = 39 frames.
    Plus 1 Flow Control (FC) frame per attempt.
    Under normative Linux kernel net/can/isotp.c rules, any CF sequence jump (N_WRONG_SN)
    or timeout (N_TIMEOUT_Cr) immediately resets to IDLE and aborts.
    Application must retransmit all 39 frames from First Frame.
    """
    n_frames = 39
    total_attempts = max_retries + 1
    p_attempt_succ = (1.0 - p) ** n_frames
    p_attempt_fail = 1.0 - p_attempt_succ

    p_overall_succ = 1.0 - (p_attempt_fail ** total_attempts)

    if p_attempt_succ > 1e-12:
        attempts_expected = (1.0 - (p_attempt_fail ** total_attempts)) / p_attempt_succ
    else:
        attempts_expected = float(total_attempts)

    expected_data_frames = attempts_expected * n_frames
    expected_fc_frames = attempts_expected * 1.0  # 1 Flow Control frame per attempt

    return {
        "p_success": float(p_overall_succ),
        "expected_data_frames": float(expected_data_frames),
        "expected_ctrl_frames": float(expected_fc_frames),
        "expected_total_frames": float(expected_data_frames + expected_fc_frames)
    }


def analytical_eval_sixty_four(p: float, max_retries: int = 3) -> dict:
    """
    Proposed 60/4 Indexed Block Transfer.
    41 frames (60B payload + 4B header).
    Frame 40 carries 36B data + 24B zero padding.
    Gateway evaluates 64-bit NACK bitmap.
    Only missing frame indices are selectively retransmitted.
    """
    total_attempts = max_retries + 1
    # Single frame fails only if dropped across all 4 attempts
    p_frame_drop_all = p ** total_attempts
    p_frame_succ = 1.0 - p_frame_drop_all

    # All 41 frames must succeed for complete session reconstruction
    p_overall_succ = p_frame_succ ** 41

    # Expected data frames transmitted: Initial burst (41) + retransmission attempts
    # E[N_data] = 41 * (1 + p + p^2 + p^3) = 41 * (1 - p^4) / (1 - p)
    if abs(1.0 - p) > 1e-9:
        expected_data_frames = 41.0 * (1.0 - p ** total_attempts) / (1.0 - p)
    else:
        expected_data_frames = 41.0 * total_attempts

    # Expected NACK frames (16B on CAN ID 0x201):
    # A NACK is issued in retry round r (r in 1..3) if at least 1 frame was missing in round r-1
    expected_nack_frames = 0.0
    for r in range(1, total_attempts):
        # Probability that at least 1 frame needed retransmission in round r
        p_need_retransmit_r = 1.0 - ((1.0 - (p ** r)) ** 41)
        expected_nack_frames += p_need_retransmit_r

    return {
        "p_success": float(p_overall_succ),
        "expected_data_frames": float(expected_data_frames),
        "expected_ctrl_frames": float(expected_nack_frames),
        "expected_total_frames": float(expected_data_frames + expected_nack_frames)
    }


# ==============================================================================
# 2. PILLAR 2: GILBERT-ELLIOTT BURST NOISE MONTE CARLO SIMULATION
# ==============================================================================

class GilbertElliottChannel:
    """
    2-State Discrete-Time Markov Chain Channel:
      State 0 (GOOD): Quiet bus, error probability e_good = 1e-4
      State 1 (BAD):  High-noise inductive burst, error probability e_bad = 0.50
      P(Good -> Bad) = p_gb = 0.01
      P(Bad -> Good) = p_bg = 0.20 => Mean burst length = 1/p_bg = 5 frames
    """
    def __init__(self, p_gb: float = 0.01, p_bg: float = 0.20, e_good: float = 0.0001, e_bad: float = 0.50, rng: np.random.Generator = None):
        self.p_gb = p_gb
        self.p_bg = p_bg
        self.e_good = e_good
        self.e_bad = e_bad
        self.state = 0  # Start in GOOD state
        self.rng = rng if rng is not None else np.random.default_rng()

    def transmit_frame(self) -> bool:
        """Returns True if frame successfully delivered, False if dropped."""
        # State transition
        if self.state == 0:
            if self.rng.random() < self.p_gb:
                self.state = 1
        else:
            if self.rng.random() < self.p_bg:
                self.state = 0

        # Frame error determination
        err_prob = self.e_bad if self.state == 1 else self.e_good
        return bool(self.rng.random() >= err_prob)


def simulate_mc_trial_sixty_four(channel: GilbertElliottChannel, max_retries: int = 3) -> tuple[bool, int, int]:
    """Simulates 1 trial of 60/4 Indexed Transfer over burst channel."""
    total_frames = 41
    received_bitmap = np.zeros(total_frames, dtype=bool)
    data_frames_sent = 0
    ctrl_frames_sent = 0

    # Initial burst
    for i in range(total_frames):
        data_frames_sent += 1
        if channel.transmit_frame():
            received_bitmap[i] = True

    # Selective NACK retries
    for retry in range(max_retries):
        missing_indices = np.where(~received_bitmap)[0]
        if len(missing_indices) == 0:
            break  # All frames assembled!

        # Gateway sends NACK frame
        ctrl_frames_sent += 1
        channel.transmit_frame()  # NACK frame on wire

        # Sender selectively re-blasts only missing indices
        for idx in missing_indices:
            data_frames_sent += 1
            if channel.transmit_frame():
                received_bitmap[idx] = True

    is_success = bool(np.all(received_bitmap))
    return is_success, data_frames_sent, ctrl_frames_sent


def simulate_mc_trial_isotp(channel: GilbertElliottChannel, max_retries: int = 3) -> tuple[bool, int, int]:
    """Simulates 1 trial of ISO-TP over burst channel (abort on drop)."""
    n_frames = 39
    total_attempts = max_retries + 1
    data_frames_sent = 0
    ctrl_frames_sent = 0

    for attempt in range(total_attempts):
        ctrl_frames_sent += 1  # Flow Control frame
        attempt_success = True

        for f in range(n_frames):
            data_frames_sent += 1
            if not channel.transmit_frame():
                attempt_success = False
                # Under ISO-TP normative rule: sequence jump resets RX state.
                # In pessimistic model, sender finishes current burst or aborts immediately.
                # We model standard sender burst attempt:
                pass

        if attempt_success:
            return True, data_frames_sent, ctrl_frames_sent

    return False, data_frames_sent, ctrl_frames_sent


def simulate_mc_trial_castiglione(channel: GilbertElliottChannel, n_frames: int = 39, max_retries: int = 3) -> tuple[bool, int, int]:
    """Simulates 1 trial of Castiglione unindexed slicing (full restart on ID 0x047)."""
    total_attempts = max_retries + 1
    data_frames_sent = 0
    ctrl_frames_sent = 0

    for attempt in range(total_attempts):
        received_count = 0
        for f in range(n_frames):
            data_frames_sent += 1
            if channel.transmit_frame():
                received_count += 1

        if received_count == n_frames:
            return True, data_frames_sent, ctrl_frames_sent

        # Missing frames: ECU sends 64 null bytes on ID 0x047 requesting full restart
        ctrl_frames_sent += 1

    return False, data_frames_sent, ctrl_frames_sent


# ==============================================================================
# 3. PHYSICAL WIRE & LATENCY CALCULATIONS ACROSS BITRATE REGIMES
# ==============================================================================

def calculate_frame_duration_us(payload_bytes: int, tau_nom_us: float, tau_dat_us: float, worst_case_stuffing: bool = False) -> float:
    """
    Computes CAN-FD physical frame transmission duration C_i per ISO 11898-1:2015.
    Header Phase: 17 nominal bits (BRS sample point split)
    Trailer Phase: 12 nominal bits (CRC Delimiter, ACK, EOF, IFS)
    Data Phase: 4-bit DLC + Data Bits + CRC Field
    """
    nom_bits = 32 if worst_case_stuffing else 29

    if payload_bytes == 64:
        # Canonical Bordoloi & Samii (RTSS 2014) / Joshi et al. (ECRTS 2017) Eq. (1) WCTT bound:
        # WCTT(64) = 32 * tau_nom + (28 + 5*ceil((64-16)/64) + 10*64) * tau_dat = 32 nom + 673 dat bits = 400.5 us (0.4005 ms).
        # Unstuffed nominal data phase yields 548 bits = 332.0 us at 500k nom / 2M dat.
        data_bits = 673 if worst_case_stuffing else 548
    elif payload_bytes == 16:
        # Canonical Bordoloi & Samii Eq. (1) for 16B: 32 nom + 188 dat bits = 158.0 us (0.1580 ms)
        data_bits = 188 if worst_case_stuffing else 164
    else:
        # Linear interpolation for intermediate control sizes
        data_bits = int(payload_bytes * 8 + 35)

    return (nom_bits * tau_nom_us) + (data_bits * tau_dat_us)


# ==============================================================================
# 4. MAIN BENCHMARKING ENGINE
# ==============================================================================

def run_transport_benchmark(config_path: str, out_dir: str, n_mc_trials: int = 10000, seed: int = 42, skip_mc: bool = False):
    print("=" * 80)
    print("PHASE 3 M3.1: 3-WAY CAN-FD TRANSPORT PROTOCOL EVALUATION ENGINE")
    print("=" * 80)
    print(f"Loading Configuration from: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    # Output directory setup
    figs_dir = os.path.join(out_dir, "figures")
    data_dir = os.path.join(out_dir, "data")
    os.makedirs(figs_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)

    rng = np.random.default_rng(seed)
    loss_rates = np.arange(
        cfg["simulation_params"]["loss_range_start"],
        cfg["simulation_params"]["loss_range_end"] + 1e-5,
        cfg["simulation_params"]["loss_step"]
    )

    # Physical frame timing constants
    regimes = cfg["bitrate_regimes"]
    timing = {}
    for r_key, r_val in regimes.items():
        timing[r_key] = {
            "name": r_val["name"],
            "c_64b_us": calculate_frame_duration_us(64, r_val["tau_nom_us"], r_val["tau_dat_us"]),
            "c_16b_us": calculate_frame_duration_us(16, r_val["tau_nom_us"], r_val["tau_dat_us"]),
            "c_64b_wc_us": calculate_frame_duration_us(64, r_val["tau_nom_us"], r_val["tau_dat_us"], worst_case_stuffing=True),
        }
        print(f"  [{r_val['name']}] C_64B = {timing[r_key]['c_64b_us']:.1f} us (WC: {timing[r_key]['c_64b_wc_us']:.1f} us)")

    # --------------------------------------------------------------------------
    # A. Execute Analytical Sweeps (Pillar 1)
    # --------------------------------------------------------------------------
    print("\n[PILLAR 1] Computing Exact Closed-Form Bounded-Retry Formulations...")
    records = []

    res_sixty_four = [analytical_eval_sixty_four(p, max_retries=3) for p in loss_rates]
    res_isotp = [analytical_eval_isotp(p, max_retries=3) for p in loss_rates]
    res_cast_scaled = [analytical_eval_castiglione(39, p, max_retries=3) for p in loss_rates]
    res_cast_native = [analytical_eval_castiglione(12, p, max_retries=3) for p in loss_rates]

    # --------------------------------------------------------------------------
    # B. Execute Monte Carlo Gilbert-Elliott Simulation (Pillar 2)
    # --------------------------------------------------------------------------
    mc_sixty_four_frames = []
    mc_sixty_four_succ = []
    mc_isotp_frames = []
    mc_isotp_succ = []
    mc_cast_scaled_frames = []

    if not skip_mc:
        print(f"\n[PILLAR 2] Running Gilbert-Elliott Monte Carlo Burst Simulation ({n_mc_trials} trials/point)...")
        ge_cfg = cfg["gilbert_elliott_burst"]

        for idx, p in enumerate(loss_rates):
            # Scale bad state drop rate proportionally to sweep loss p
            eff_e_bad = min(1.0, max(0.01, p * 4.0)) if p > 0 else 0.0
            eff_e_good = min(1.0, p * 0.1) if p > 0 else 0.0

            trial_sf_frames = []
            trial_sf_succ = 0
            trial_iso_frames = []
            trial_iso_succ = 0
            trial_cast_frames = []

            for _ in range(n_mc_trials):
                # Channel instance
                ch = GilbertElliottChannel(
                    p_gb=ge_cfg["p_gb"],
                    p_bg=ge_cfg["p_bg"],
                    e_good=eff_e_good,
                    e_bad=eff_e_bad,
                    rng=rng
                )
                # 60/4
                s_sf, d_sf, c_sf = simulate_mc_trial_sixty_four(ch, max_retries=3)
                trial_sf_frames.append(d_sf + c_sf)
                if s_sf: trial_sf_succ += 1

                # ISO-TP
                s_iso, d_iso, c_iso = simulate_mc_trial_isotp(ch, max_retries=3)
                trial_iso_frames.append(d_iso + c_iso)
                if s_iso: trial_iso_succ += 1

                # Castiglione Scaled
                s_c, d_c, c_c = simulate_mc_trial_castiglione(ch, n_frames=39, max_retries=3)
                trial_cast_frames.append(d_c + c_c)

            mc_sixty_four_frames.append(float(np.mean(trial_sf_frames)))
            mc_sixty_four_succ.append(float(trial_sf_succ / n_mc_trials))
            mc_isotp_frames.append(float(np.mean(trial_iso_frames)))
            mc_isotp_succ.append(float(trial_iso_succ / n_mc_trials))
            mc_cast_scaled_frames.append(float(np.mean(trial_cast_frames)))

            if idx % 2 == 0 or idx == len(loss_rates) - 1:
                print(f"  Loss p = {p*100:4.1f}% | 60/4: {mc_sixty_four_frames[-1]:5.1f} frames ({mc_sixty_four_succ[-1]*100:5.1f}% succ) | ISO-TP: {mc_isotp_frames[-1]:5.1f} frames ({mc_isotp_succ[-1]*100:5.1f}% succ)")

    # --------------------------------------------------------------------------
    # C. Compile Full Dataset
    # --------------------------------------------------------------------------
    csv_rows = []
    pao_app_bytes = 2420.0  # Application signature payload bytes

    for idx, p in enumerate(loss_rates):
        sf_d = res_sixty_four[idx]
        iso_d = res_isotp[idx]
        cs_d = res_cast_scaled[idx]
        cn_d = res_cast_native[idx]

        # Total wire bytes
        sf_bytes = sf_d["expected_data_frames"] * 64 + sf_d["expected_ctrl_frames"] * 16
        iso_bytes = iso_d["expected_data_frames"] * 64 + iso_d["expected_ctrl_frames"] * 64
        cs_bytes = cs_d["expected_data_frames"] * 64 + cs_d["expected_ctrl_frames"] * 64
        cn_bytes = cn_d["expected_data_frames"] * 64 + cn_d["expected_ctrl_frames"] * 64

        # Goodput efficiencies (%)
        sf_goodput = (pao_app_bytes / sf_bytes) * 100.0 if sf_bytes > 0 else 0.0
        iso_goodput = (pao_app_bytes / iso_bytes) * 100.0 if iso_bytes > 0 else 0.0
        cs_goodput = (pao_app_bytes / cs_bytes) * 100.0 if cs_bytes > 0 else 0.0
        cn_goodput = (768.0 / cn_bytes) * 100.0 if cn_bytes > 0 else 0.0

        # Latencies at 2 Mbps production (ms)
        prod_timing = timing["production_canfd_2mbps"]
        sf_lat_ms = (sf_d["expected_data_frames"] * prod_timing["c_64b_us"] + sf_d["expected_ctrl_frames"] * prod_timing["c_16b_us"]) / 1000.0
        iso_lat_ms = (iso_d["expected_data_frames"] * prod_timing["c_64b_us"] + iso_d["expected_ctrl_frames"] * prod_timing["c_64b_us"]) / 1000.0
        cs_lat_ms = (cs_d["expected_data_frames"] * prod_timing["c_64b_us"] + cs_d["expected_ctrl_frames"] * prod_timing["c_64b_us"]) / 1000.0

        row = {
            "loss_rate": round(p, 3),
            "loss_percent": round(p * 100, 1),
            "sixty_four_expected_frames": round(sf_d["expected_total_frames"], 2),
            "sixty_four_success_prob": round(sf_d["p_success"], 4),
            "sixty_four_wire_bytes": round(sf_bytes, 1),
            "sixty_four_goodput_pct": round(sf_goodput, 2),
            "sixty_four_latency_2mbps_ms": round(sf_lat_ms, 3),
            "isotp_expected_frames": round(iso_d["expected_total_frames"], 2),
            "isotp_success_prob": round(iso_d["p_success"], 4),
            "isotp_wire_bytes": round(iso_bytes, 1),
            "isotp_goodput_pct": round(iso_goodput, 2),
            "isotp_latency_2mbps_ms": round(iso_lat_ms, 3),
            "castiglione_scaled_frames": round(cs_d["expected_total_frames"], 2),
            "castiglione_scaled_success_prob": round(cs_d["p_success"], 4),
            "castiglione_scaled_goodput_pct": round(cs_goodput, 2),
            "castiglione_native_frames": round(cn_d["expected_total_frames"], 2),
            "castiglione_native_success_prob": round(cn_d["p_success"], 4),
        }
        if not skip_mc:
            row["mc_sixty_four_frames"] = round(mc_sixty_four_frames[idx], 2)
            row["mc_sixty_four_success"] = round(mc_sixty_four_succ[idx], 4)
            row["mc_isotp_frames"] = round(mc_isotp_frames[idx], 2)
            row["mc_isotp_success"] = round(mc_isotp_succ[idx], 4)

        csv_rows.append(row)

    # Save CSV
    csv_path = os.path.join(data_dir, "transport_protocol_benchmark_data.csv")
    import pandas as pd
    df = pd.DataFrame(csv_rows)
    df.to_csv(csv_path, index=False)
    print(f"\n[DATA] Wrote full benchmark dataset -> {csv_path}")

    # --------------------------------------------------------------------------
    # D. Deterministic Canonical Fault Case Studies (Pillar 3)
    # --------------------------------------------------------------------------
    print("\n[PILLAR 3] Evaluating Project-Defined Deterministic Fault Scenarios...")
    scenarios = cfg["deterministic_scenarios"]
    scen_results = []
    prod_c64 = timing["production_canfd_2mbps"]["c_64b_us"] / 1000.0
    prod_c16 = timing["production_canfd_2mbps"]["c_16b_us"] / 1000.0

    print(f"{'Scenario Name':<45} | {'60/4 Frames':<12} | {'ISO-TP Frames':<13} | {'Castiglione 39F':<15} | {'60/4 Latency':<12}")
    print("-" * 105)

    for sc in scenarios:
        drops = sc["drop_indices"]
        k_drop = len(drops)

        # 60/4 selective recovery: sends 41 initial + k_drop retransmitted + 1 NACK (if k_drop > 0)
        sf_f = 41 + k_drop + (1 if k_drop > 0 else 0)
        sf_time = (41 + k_drop) * prod_c64 + (1 if k_drop > 0 else 0) * prod_c16

        # ISO-TP: single frame drop forces full 39 frame restart (39 + 1 FC initial + 39 + 1 FC retry)
        iso_f = 40 if k_drop == 0 else 80
        iso_time = iso_f * prod_c64

        # Castiglione Scaled: 39 initial + 39 retry + 1 ID 0x047 null request
        cast_f = 39 if k_drop == 0 else (39 + 39 + 1)
        cast_time = cast_f * prod_c64

        print(f"{sc['name']:<45} | {sf_f:<12} | {iso_f:<13} | {cast_f:<15} | {sf_time:6.2f} ms")
        scen_results.append({
            "scenario_id": sc["id"],
            "name": sc["name"],
            "dropped_count": k_drop,
            "sixty_four_frames": sf_f,
            "sixty_four_latency_ms": round(sf_time, 3),
            "isotp_frames": iso_f,
            "isotp_latency_ms": round(iso_time, 3),
            "castiglione_scaled_frames": cast_f,
            "castiglione_scaled_latency_ms": round(cast_time, 3)
        })

    # Save scenario results
    scen_json_path = os.path.join(data_dir, "deterministic_scenarios_results.json")
    with open(scen_json_path, "w") as f:
        json.dump(scen_results, f, indent=2)
    print(f"[DATA] Wrote deterministic scenario results -> {scen_json_path}")

    # --------------------------------------------------------------------------
    # E. Generate 300 DPI Publication-Quality Figures
    # --------------------------------------------------------------------------
    print("\n[VISUALIZATION] Rendering 300 DPI Publication Figures...")

    loss_pct = loss_rates * 100

    # ----------------------------------------------------
    # Figure 1: Transmitted Wire Bytes & Frames vs. Loss Rate
    # ----------------------------------------------------
    fig1, (ax1a, ax1b) = plt.subplots(1, 2, figsize=(14, 5.5), dpi=300)

    # 1a: Total Transmitted Frames
    sf_tot_frames = [r["expected_total_frames"] for r in res_sixty_four]
    iso_tot_frames = [r["expected_total_frames"] for r in res_isotp]
    cast_tot_frames = [r["expected_total_frames"] for r in res_cast_scaled]

    ax1a.plot(loss_pct, sf_tot_frames, "b-", label="Proposed 60/4 Selective NACK (41F)", zorder=4)
    ax1a.plot(loss_pct, iso_tot_frames, "r--", label="Standard ISO-TP (39F Full Abort)", zorder=3)
    ax1a.plot(loss_pct, cast_tot_frames, "g-.", label="Castiglione Scaled (39F Slicing)", zorder=2)

    if not skip_mc:
        ax1a.scatter(loss_pct, mc_sixty_four_frames, color="blue", marker="o", s=30, label="60/4 MC Burst Validation", zorder=5)
        ax1a.scatter(loss_pct, mc_isotp_frames, color="red", marker="x", s=30, label="ISO-TP MC Burst Validation", zorder=5)

    ax1a.set_xlabel("CAN-FD Post-MAC Frame Loss Rate (%)")
    ax1a.set_ylabel("Total Frames Transmitted on Wire")
    ax1a.set_title("Total Wire Frames vs. Loss Rate (K_retry = 3)")
    ax1a.set_xlim(0, 20)
    ax1a.set_ylim(35, 175)
    ax1a.grid(True)
    ax1a.legend(loc="upper left", frameon=True)

    # 1b: Total Transmitted Wire Kilobytes
    sf_kb = [df["sixty_four_wire_bytes"].iloc[i] / 1024.0 for i in range(len(loss_rates))]
    iso_kb = [df["isotp_wire_bytes"].iloc[i] / 1024.0 for i in range(len(loss_rates))]
    cast_kb = [df["castiglione_scaled_frames"].iloc[i] * 64.0 / 1024.0 for i in range(len(loss_rates))]

    ax1b.plot(loss_pct, sf_kb, "b-", label="Proposed 60/4 Protocol")
    ax1b.plot(loss_pct, iso_kb, "r--", label="Standard ISO-TP")
    ax1b.plot(loss_pct, cast_kb, "g-.", label="Castiglione Scaled")

    ax1b.set_xlabel("CAN-FD Post-MAC Frame Loss Rate (%)")
    ax1b.set_ylabel("Total Wire Traffic (Kilobytes)")
    ax1b.set_title("Physical Bus Traffic Consumption vs. Loss Rate")
    ax1b.set_xlim(0, 20)
    ax1b.grid(True)
    ax1b.legend(loc="upper left", frameon=True)

    fig1.tight_layout()
    fig1_path = os.path.join(figs_dir, "transport_wire_bytes_vs_loss.png")
    fig1.savefig(fig1_path, dpi=300)
    plt.close(fig1)
    print(f"  [FIGURE 1] Saved -> {fig1_path}")

    # ----------------------------------------------------
    # Figure 2: Completion Latency Across 3 Bitrate Regimes
    # ----------------------------------------------------
    fig2, ax2 = plt.subplots(figsize=(10, 6), dpi=300)

    colors = {"castiglione_baseline_1mbps": "darkorange", "production_canfd_2mbps": "blue", "high_perf_canfd_5mbps": "forestgreen"}

    for r_key, r_info in timing.items():
        c_name = r_info["name"]
        c_64 = r_info["c_64b_us"] / 1000.0
        c_16 = r_info["c_16b_us"] / 1000.0

        # 60/4 latency
        sf_lat = [(res_sixty_four[i]["expected_data_frames"] * c_64 + res_sixty_four[i]["expected_ctrl_frames"] * c_16) for i in range(len(loss_rates))]
        # ISO-TP latency
        iso_lat = [(res_isotp[i]["expected_data_frames"] * c_64 + res_isotp[i]["expected_ctrl_frames"] * c_64) for i in range(len(loss_rates))]

        ax2.plot(loss_pct, sf_lat, linestyle="-", color=colors[r_key], label=f"60/4 @ {c_name}")
        ax2.plot(loss_pct, iso_lat, linestyle=":", color=colors[r_key], alpha=0.75, label=f"ISO-TP @ {c_name}")

    ax2.set_xlabel("CAN-FD Post-MAC Frame Loss Rate (%)")
    ax2.set_ylabel("Expected Attestation Completion Latency (ms)")
    ax2.set_title("Attestation Transfer Latency across 3 CAN-FD Bitrate Regimes")
    ax2.set_xlim(0, 20)
    ax2.grid(True)
    ax2.legend(loc="upper left", frameon=True, ncol=2)

    fig2.tight_layout()
    fig2_path = os.path.join(figs_dir, "transport_completion_latency_vs_loss.png")
    fig2.savefig(fig2_path, dpi=300)
    plt.close(fig2)
    print(f"  [FIGURE 2] Saved -> {fig2_path}")

    # ----------------------------------------------------
    # Figure 3: Goodput Efficiency & Session Success Probability
    # ----------------------------------------------------
    fig3, (ax3a, ax3b) = plt.subplots(1, 2, figsize=(14, 5.5), dpi=300)

    # 3a: Goodput Efficiency
    ax3a.plot(loss_pct, df["sixty_four_goodput_pct"], "b-", label="Proposed 60/4 Protocol")
    ax3a.plot(loss_pct, df["isotp_goodput_pct"], "r--", label="Standard ISO-TP")
    ax3a.plot(loss_pct, df["castiglione_scaled_goodput_pct"], "g-.", label="Castiglione Scaled")

    ax3a.set_xlabel("CAN-FD Post-MAC Frame Loss Rate (%)")
    ax3a.set_ylabel("Goodput Efficiency (% = 2420B / Wire Bytes)")
    ax3a.set_title("Effective Protocol Goodput vs. Channel Loss")
    ax3a.set_xlim(0, 20)
    ax3a.set_ylim(0, 100)
    ax3a.grid(True)
    ax3a.legend(loc="upper right", frameon=True)

    # 3b: Session Success Probability (Reliability)
    sf_succ_pct = [r["p_success"] * 100.0 for r in res_sixty_four]
    iso_succ_pct = [r["p_success"] * 100.0 for r in res_isotp]
    cast_succ_pct = [r["p_success"] * 100.0 for r in res_cast_scaled]

    ax3b.plot(loss_pct, sf_succ_pct, "b-", label="Proposed 60/4 Protocol (99.59% at p=10%)", zorder=4)
    ax3b.plot(loss_pct, iso_succ_pct, "r--", label="Standard ISO-TP (6.41% at p=10%)", zorder=3)
    ax3b.plot(loss_pct, cast_succ_pct, "g-.", label="Castiglione Scaled (6.41% at p=10%)", zorder=2)

    if not skip_mc:
        ax3b.scatter(loss_pct, np.array(mc_sixty_four_succ) * 100.0, color="blue", marker="o", s=30, label="60/4 MC Validation", zorder=5)
        ax3b.scatter(loss_pct, np.array(mc_isotp_succ) * 100.0, color="red", marker="x", s=30, label="ISO-TP MC Validation", zorder=5)

    ax3b.set_xlabel("CAN-FD Post-MAC Frame Loss Rate (%)")
    ax3b.set_ylabel("Attestation Session Success Rate (%)")
    ax3b.set_title("Attestation Completion Success Rate (K_retry = 3)")
    ax3b.set_xlim(0, 20)
    ax3b.set_ylim(-5, 105)
    ax3b.grid(True)
    ax3b.legend(loc="lower left", frameon=True)

    fig3.tight_layout()
    fig3_path = os.path.join(figs_dir, "transport_goodput_efficiency_vs_loss.png")
    fig3.savefig(fig3_path, dpi=300)
    plt.close(fig3)
    print(f"  [FIGURE 3] Saved -> {fig3_path}")

    # --------------------------------------------------------------------------
    # F. Provenance & Environment Metadata
    # --------------------------------------------------------------------------
    with open(config_path, "rb") as f:
        cfg_hash = hashlib.sha256(f.read()).hexdigest()

    provenance = {
        "milestone": "M3.1",
        "description": "3-Way Transport Protocol Evaluation (Castiglione vs ISO-TP vs 60/4)",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "runtime_environment": {
            "python_version": sys.version.split()[0],
            "numpy_version": np.__version__,
            "matplotlib_version": plt.matplotlib.__version__,
            "os_platform": platform.platform(),
            "cpu_architecture": platform.machine()
        },
        "config_provenance": {
            "config_file": config_path,
            "config_sha256": cfg_hash
        },
        "execution_parameters": {
            "random_seed": seed,
            "mc_trials_per_point": n_mc_trials if not skip_mc else 0,
            "loss_sweep_points": len(loss_rates),
            "bitrate_regimes_evaluated": list(regimes.keys())
        },
        "output_artifacts": {
            "figures": [
                "transport_wire_bytes_vs_loss.png",
                "transport_completion_latency_vs_loss.png",
                "transport_goodput_efficiency_vs_loss.png"
            ],
            "data": [
                "transport_protocol_benchmark_data.csv",
                "deterministic_scenarios_results.json"
            ]
        }
    }

    prov_path = os.path.join(data_dir, "provenance_metadata.json")
    with open(prov_path, "w") as f:
        json.dump(provenance, f, indent=2)
    print(f"\n[PROVENANCE] Recorded execution provenance -> {prov_path}")
    print("\n" + "=" * 80)
    print("M3.1 TRANSPORT PROTOCOL EVALUATION EXECUTION COMPLETE!")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 3 M3.1: 3-Way Transport Protocol Evaluation Engine")
    parser.add_argument("--config", type=str, default="Anti Gravity/Phase 3/config/transport_simulation_config.json", help="Path to config JSON")
    parser.add_argument("--out-dir", type=str, default="Anti Gravity/Phase 3", help="Output directory")
    parser.add_argument("--trials", type=int, default=10000, help="Number of Monte Carlo trials per loss point")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--skip-mc", action="store_true", help="Skip Monte Carlo simulation and run analytical math only")

    args = parser.parse_args()
    run_transport_benchmark(
        config_path=args.config,
        out_dir=args.out_dir,
        n_mc_trials=args.trials,
        seed=args.seed,
        skip_mc=args.skip_mc
    )
