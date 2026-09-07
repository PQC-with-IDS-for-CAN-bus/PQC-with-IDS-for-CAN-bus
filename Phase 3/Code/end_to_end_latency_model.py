"""
end_to_end_latency_model.py
===========================
Milestone M3.4: Complete Cross-Domain End-to-End Latency & Ascon Cryptographic Simulation Engine.

Mathematical Formulation:
T_E2E = T_Host_TX + T_Wire1 + T_Gateway_Compute + T_Wire2 + T_Host_RX

Ascon-AEAD128 Round Models:
1. Official NIST SP 800-232 Standard:
   Rate r = 128 bits (16 bytes), a = 12, b = 8
   N_rounds = 12 (init) + 8 * ceil(L_AD / 16) + 8 * ceil(L_data / 16) + 12 (final)
   For 8B AD + 40B data: 12 + 8(1) + 8(3) + 12 = 56 rounds (2,128 ops -> 0.3554 ms @ 1.5 GHz)
2. Conservative Baseline (Competition Ascon-128 / Dobraunig et al. 2021):
   Rate r = 64 bits (8 bytes), a = 12, b = 6
   N_rounds = 12 (init) + 6 * ceil(L_AD / 8) + 6 * ceil(L_data / 8) + 12 (final)
   For 8B AD + 40B data: 12 + 6(1) + 6(5) + 12 = 60 rounds (2,280 ops -> 0.3736 ms @ 1.5 GHz)

Evaluates:
1. Cat 1 Inter-Domain Telemetry (Powertrain -> Chassis)
2. Cat 1 Intra-Domain Telemetry (Powertrain -> Powertrain peer)
3. Cat 2 PQC Boot Attestation (ECU -> Gateway)
4. Cat 3.1 Attestation Challenge (Gateway -> ECU)
5. Cat 3.3 Session Key Delivery (Gateway -> ECU)
6. Comparative Benchmark against Castiglione & Elia (2025) Base Paper

Outputs:
- data/end_to_end_latency_breakdown.csv
- figures/end_to_end_latency_budget_breakdown.png (300 DPI)
- figures/end_to_end_latency_vs_deadlines.png (300 DPI)
- figures/end_to_end_platform_comparison.png (300 DPI)
"""

import os
import sys
import math
import csv
import json
import matplotlib.pyplot as plt
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
FIGURES_DIR = os.path.join(BASE_DIR, 'figures')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(FIGURES_DIR, exist_ok=True)

def calculate_ascon_latency_ms(payload_bytes: int, ad_bytes: int, freq_ghz: float = 1.5, mode: str = 'python', standard: str = 'conservative'):
    """
    Computes Ascon-AEAD128 execution latency from first principles.
    
    Supports two standard configurations:
    1. 'conservative' (Default baseline from competition Ascon-128 submission):
       - Rate r = 64 bits (8 bytes), a = 12 rounds, b = 6 rounds per 8B block.
       - For 8B AD + 40B Data: 12 + 6*ceil(8/8) + 6*ceil(40/8) + 12 = 12 + 6(1) + 6(5) + 12 = 60 rounds.
       - Execution latency = 0.3736 ms @ 1.5 GHz ARM Cortex-A72.
    2. 'nist_sp800_232' (Official Final NIST Standard Ascon-AEAD128):
       - Rate r = 128 bits (16 bytes), a = 12 rounds, b = 8 rounds per 16B block.
       - For 8B AD + 40B Data: 12 + 8*ceil(8/16) + 8*ceil(40/16) + 12 = 12 + 8(1) + 8(3) + 12 = 56 rounds.
       - Execution latency = 0.3554 ms @ 1.5 GHz ARM Cortex-A72 (4.88% faster than conservative model).
       (NOTE: A common misconception is to assume b=8 with an 8-byte rate, producing 12+8(1)+8(5)+12 = 72 rounds.
       That is mathematically incorrect because NIST standardized the 128-bit rate variant, reducing block count from 5 to 3).
    
    Primitive Bitwise Ops per Round:
      - Constant addition (p_C): 1 op
      - Non-linear S-box (p_S): 15 bitwise logic ops (AND, XOR, NOT)
      - Linear diffusion (p_L): 20 ops (10 circular rotations + 10 XORs)
      Total = 36 to 40 ops (~38 average)
    """
    if standard == 'nist_sp800_232':
        rate_bytes = 16.0
        rounds_b = 8
    else:  # 'conservative'
        rate_bytes = 8.0
        rounds_b = 6

    ad_blocks = math.ceil(ad_bytes / rate_bytes) if ad_bytes > 0 else 0
    data_blocks = math.ceil(payload_bytes / rate_bytes) if payload_bytes > 0 else 0
    
    # Total permutation rounds
    total_rounds = 12 + (rounds_b * ad_blocks) + (rounds_b * data_blocks) + 12
    
    ops_per_round = 38
    total_ops = total_rounds * ops_per_round
    
    if mode == 'python':
        # Python interpreter overhead: dynamic typing, 64-bit int objects, bytecode dispatch
        cycles_per_op = 180
        total_cycles = total_ops * cycles_per_op  # ~410,400 to 675,000 cycles with memory slicing
        # Add byte slicing, nonce formatting, and tag assembly overhead (~150,000 cycles)
        total_cycles += 150000
    else:
        # Bare-metal optimized C / Assembly (e.g. ARMv8 NEON crypto extensions: ~10.5 CPB)
        total_cycles = max(400, int(payload_bytes * 10.5 + ad_bytes * 10.5 + 200))
        
    latency_seconds = total_cycles / (freq_ghz * 1e9)
    return latency_seconds * 1000.0  # Return milliseconds

# -------------------------------------------------------------
# Microarchitectural Profiles across Hardware Platforms
# -------------------------------------------------------------
PLATFORMS = {
    'ARM_Cortex_A72_RPi4': {
        'name': 'ARM Cortex-A72 @ 1.5GHz (RPi4 Gateway Reference)',
        'freq_ghz': 1.5,
        'mode': 'python',
        'monotonic_check_ms': 0.002,
        'discrete_invariant_ms': 0.008,
        'onnx_int8_lstm_ms': 0.820,
        'routing_lookup_ms': 0.001,
        'puf_reconstruct_ms': 0.090,
        'hkdf_derive_ms': 0.050,
        'mldsa_sign_ms': 6.420,
        'mldsa_verify_ms': 2.856
    },
    'x86_64_Host': {
        'name': 'Intel Core i7-1185G7 @ 3.0GHz (High-End Vehicle Server)',
        'freq_ghz': 3.0,
        'mode': 'python',
        'monotonic_check_ms': 0.0005,
        'discrete_invariant_ms': 0.002,
        'onnx_int8_lstm_ms': 0.190,
        'routing_lookup_ms': 0.0002,
        'puf_reconstruct_ms': 0.015,
        'hkdf_derive_ms': 0.010,
        'mldsa_sign_ms': 1.150,
        'mldsa_verify_ms': 0.520
    },
    'TriCore_AURIX_TC397': {
        'name': 'Infineon AURIX TC397 @ 300MHz (Automotive ASIL-D MCU)',
        'freq_ghz': 0.3,
        'mode': 'python',
        'monotonic_check_ms': 0.005,
        'discrete_invariant_ms': 0.015,
        'onnx_int8_lstm_ms': 1.850,
        'routing_lookup_ms': 0.002,
        'puf_reconstruct_ms': 0.220,
        'hkdf_derive_ms': 0.110,
        'mldsa_sign_ms': 14.800,
        'mldsa_verify_ms': 6.900
    }
}

# -------------------------------------------------------------
# Wire Response Times (Worst-Case R_i from Milestone M3.2 RTA Engine)
# -------------------------------------------------------------
WIRE_RTA_2M_MS = {
    'powertrain_cat1_wire_ms': 0.8630,  # 0x0D0 Powertrain Engine ECM (Bordoloi & Samii RTA WCRT)
    'chassis_cat1_wire_ms': 0.8630,      # 0x354 Chassis Steering / Brake (Bordoloi & Samii RTA WCRT segmented)
    'body_cat1_wire_ms': 0.7030,         # 0x4E7 Thermal / 0x5A0 BCM (Bordoloi & Samii RTA WCRT segmented)
    'infotainment_cat1_wire_ms': 0.4625, # 0x7E0 OBD Telemetry (Bordoloi & Samii RTA WCRT segmented)
    'pqc_burst_41f_wire_ms': 16.4205,    # Pure wire transit: 41 frames * 0.4005 ms (unpaced dedicated cold-boot per Bordoloi & Samii Eq 1).
                                         # Under cross-traffic, M3.2 RTA yields WCRT = 23.587 ms; even with full WCRT,
                                         # Flow 3 E2E is 33.38 ms <= 50.0 ms deadline (+16.62 ms slack, 33.2% margin).
    'nack_control_wire_ms': 0.1580,      # 16B selective NACK frame (Bordoloi & Samii Eq 1)
    'key_delivery_wire_ms': 0.4005       # 64B key delivery frame (Bordoloi & Samii Eq 1)
}

def simulate_end_to_end_pipeline(platform_key='ARM_Cortex_A72_RPi4', standard='conservative'):
    """
    Simulates end-to-end timing budget using first-principles Ascon math.
    Supports:
      - standard='conservative': 60 rounds (r=8B, b=6) - Upper-bound baseline
      - standard='nist_sp800_232': 56 rounds (r=16B, b=8) - Official NIST SP 800-232
    """
    p = PLATFORMS[platform_key]
    w = WIRE_RTA_2M_MS

    # Dynamically compute Ascon latency per specified standard
    t_ascon_40b = calculate_ascon_latency_ms(payload_bytes=40, ad_bytes=8, freq_ghz=p['freq_ghz'], mode=p['mode'], standard=standard)
    t_ascon_wrap_16b = calculate_ascon_latency_ms(payload_bytes=16, ad_bytes=8, freq_ghz=p['freq_ghz'], mode=p['mode'], standard=standard)

    flows = []

    # -------------------------------------------------------------------------
    # Flow 1: Category 1 Inter-Domain Runtime Telemetry (Powertrain -> Chassis)
    # -------------------------------------------------------------------------
    t_tx = t_ascon_40b
    t_wire1 = w['powertrain_cat1_wire_ms']
    t_gw_mono = p['monotonic_check_ms']
    t_gw_dec = t_ascon_40b
    t_gw_inv = p['discrete_invariant_ms']
    t_gw_ids = p['onnx_int8_lstm_ms']
    t_gw_route = p['routing_lookup_ms']
    t_gw_enc = t_ascon_40b
    t_gw_total = t_gw_mono + t_gw_dec + t_gw_inv + t_gw_ids + t_gw_route + t_gw_enc
    t_wire2 = w['chassis_cat1_wire_ms']
    t_rx = t_ascon_40b
    t_total = t_tx + t_wire1 + t_gw_total + t_wire2 + t_rx
    deadline = 10.0

    flows.append({
        'flow_id': 'FLOW_CAT1_INTER_DOMAIN',
        'name': 'Cat 1: Inter-Domain Telemetry (Powertrain -> Chassis)',
        'category': 'Cat 1 Telemetry',
        'description': 'Speed/Torque encrypted by Engine, routed through CISG with 3-tier IDS, delivered to Brakes',
        't_host_tx_ms': round(t_tx, 4),
        't_wire_1_ms': round(t_wire1, 4),
        't_gw_ingress_decrypt_ms': round(t_gw_mono + t_gw_dec, 4),
        't_gw_ids_inference_ms': round(t_gw_inv + t_gw_ids, 4),
        't_gw_egress_encrypt_ms': round(t_gw_route + t_gw_enc, 4),
        't_gw_total_ms': round(t_gw_total, 4),
        't_wire_2_ms': round(t_wire2, 4),
        't_host_rx_ms': round(t_rx, 4),
        't_end_to_end_ms': round(t_total, 4),
        'deadline_ms': deadline,
        'slack_margin_ms': round(deadline - t_total, 4),
        'schedulable': (t_total <= deadline),
        'asil_class': 'ASIL-D'
    })

    # -------------------------------------------------------------------------
    # Flow 2: Category 1 Intra-Domain Runtime Telemetry (Powertrain -> Powertrain)
    # -------------------------------------------------------------------------
    t_tx = t_ascon_40b
    t_wire1 = w['powertrain_cat1_wire_ms']
    t_gw_total = 0.0
    t_wire2 = 0.0
    t_rx = t_ascon_40b
    t_total = t_tx + t_wire1 + t_rx
    deadline = 10.0

    flows.append({
        'flow_id': 'FLOW_CAT1_INTRA_DOMAIN',
        'name': 'Cat 1: Intra-Domain Direct Telemetry (Engine -> TCM)',
        'category': 'Cat 1 Telemetry',
        'description': 'Powertrain peer broadcast encrypted with K_i, passive CISG monitoring',
        't_host_tx_ms': round(t_tx, 4),
        't_wire_1_ms': round(t_wire1, 4),
        't_gw_ingress_decrypt_ms': 0.0,
        't_gw_ids_inference_ms': 0.0,
        't_gw_egress_encrypt_ms': 0.0,
        't_gw_total_ms': 0.0,
        't_wire_2_ms': 0.0,
        't_host_rx_ms': round(t_rx, 4),
        't_end_to_end_ms': round(t_total, 4),
        'deadline_ms': deadline,
        'slack_margin_ms': round(deadline - t_total, 4),
        'schedulable': (t_total <= deadline),
        'asil_class': 'ASIL-D'
    })

    # -------------------------------------------------------------------------
    # Flow 3: Category 2 PQC Boot Attestation (ECU -> Gateway)
    # -------------------------------------------------------------------------
    t_tx = p['puf_reconstruct_ms'] + p['hkdf_derive_ms'] + p['mldsa_sign_ms']
    t_wire1 = w['pqc_burst_41f_wire_ms']
    t_gw_total = t_ascon_40b + p['mldsa_verify_ms']
    t_wire2 = 0.0
    t_rx = 0.0
    t_total = t_tx + t_wire1 + t_gw_total
    deadline = 50.0

    flows.append({
        'flow_id': 'FLOW_CAT2_BOOT_ATTESTATION',
        'name': 'Cat 2: PQC Boot Attestation (41-Frame Block Transfer)',
        'category': 'Cat 2 Block Transfer',
        'description': 'SRAM-PUF reconstruction, ML-DSA-44 signing, 41-frame bus transit, Gateway verification',
        't_host_tx_ms': round(t_tx, 4),
        't_wire_1_ms': round(t_wire1, 4),
        't_gw_ingress_decrypt_ms': round(t_ascon_40b, 4),
        't_gw_ids_inference_ms': round(p['mldsa_verify_ms'], 4),
        't_gw_egress_encrypt_ms': 0.0,
        't_gw_total_ms': round(t_gw_total, 4),
        't_wire_2_ms': 0.0,
        't_host_rx_ms': 0.0,
        't_end_to_end_ms': round(t_total, 4),
        'deadline_ms': deadline,
        'slack_margin_ms': round(deadline - t_total, 4),
        'schedulable': (t_total <= deadline),
        'asil_class': 'ASIL-D'
    })

    # -------------------------------------------------------------------------
    # Flow 4: Category 3.1 Attestation Challenge (Gateway -> ECU)
    # -------------------------------------------------------------------------
    t_tx = 0.010
    t_wire1 = w['key_delivery_wire_ms']
    t_gw_total = 0.0
    t_wire2 = 0.0
    t_rx = 0.005
    t_total = t_tx + t_wire1 + t_rx
    deadline = 10.0

    flows.append({
        'flow_id': 'FLOW_CAT3_1_CHALLENGE',
        'name': 'Cat 3.1: Attestation Challenge Dispatch',
        'category': 'Cat 3 Control Frame',
        'description': 'CISG generates 16B challenge nonce, transmits single 64B frame to ECU',
        't_host_tx_ms': round(t_tx, 4),
        't_wire_1_ms': round(t_wire1, 4),
        't_gw_ingress_decrypt_ms': 0.0,
        't_gw_ids_inference_ms': 0.0,
        't_gw_egress_encrypt_ms': 0.0,
        't_gw_total_ms': 0.0,
        't_wire_2_ms': 0.0,
        't_host_rx_ms': round(t_rx, 4),
        't_end_to_end_ms': round(t_total, 4),
        'deadline_ms': deadline,
        'slack_margin_ms': round(deadline - t_total, 4),
        'schedulable': (t_total <= deadline),
        'asil_class': 'ASIL-D'
    })

    # -------------------------------------------------------------------------
    # Flow 5: Category 3.3 Session Key Delivery (Gateway -> ECU)
    # -------------------------------------------------------------------------
    t_tx = p['hkdf_derive_ms'] + t_ascon_wrap_16b
    t_wire1 = w['key_delivery_wire_ms']
    t_gw_total = 0.0
    t_wire2 = 0.0
    t_rx = t_ascon_wrap_16b
    t_total = t_tx + t_wire1 + t_rx
    deadline = 10.0

    flows.append({
        'flow_id': 'FLOW_CAT3_3_KEY_DELIVERY',
        'name': 'Cat 3.3: Session Key Wrapping & Activation',
        'category': 'Cat 3 Control Frame',
        'description': 'CISG wraps fresh session key K_i with Ascon-128, transmits to ECU, ECU unwraps key',
        't_host_tx_ms': round(t_tx, 4),
        't_wire_1_ms': round(t_wire1, 4),
        't_gw_ingress_decrypt_ms': 0.0,
        't_gw_ids_inference_ms': 0.0,
        't_gw_egress_encrypt_ms': 0.0,
        't_gw_total_ms': 0.0,
        't_wire_2_ms': 0.0,
        't_host_rx_ms': round(t_rx, 4),
        't_end_to_end_ms': round(t_total, 4),
        'deadline_ms': deadline,
        'slack_margin_ms': round(deadline - t_total, 4),
        'schedulable': (t_total <= deadline),
        'asil_class': 'ASIL-D'
    })

    return flows

def generate_publication_plots(flows, platform_key='ARM_Cortex_A72_RPi4'):
    """
    Generates 3 publication-grade figures (300 DPI) for Milestone M3.4.
    """
    plt.rcParams.update({
        'font.family': 'serif',
        'font.size': 11,
        'axes.labelsize': 12,
        'axes.titlesize': 13,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 10,
        'figure.titlesize': 14
    })

    # -------------------------------------------------------------
    # Figure 1: Stacked Breakdown of End-to-End Latency Budget
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(11, 5.5))

    flow_labels = [
        "Cat 1 Inter-Domain\n(Powertrain->Chassis)",
        "Cat 1 Intra-Domain\n(Powertrain Direct)",
        "Cat 3.1 Challenge\n(Gateway->ECU)",
        "Cat 3.3 Key Delivery\n(Gateway->ECU)"
    ]
    selected_flows = [flows[0], flows[1], flows[3], flows[4]]

    tx_times = [f['t_host_tx_ms'] for f in selected_flows]
    w1_times = [f['t_wire_1_ms'] for f in selected_flows]
    gw_times = [f['t_gw_total_ms'] for f in selected_flows]
    w2_times = [f['t_wire_2_ms'] for f in selected_flows]
    rx_times = [f['t_host_rx_ms'] for f in selected_flows]

    x = np.arange(len(flow_labels))
    width = 0.48

    p1 = ax.bar(x, tx_times, width, label='Host TX Encrypt (Ascon-128)', color='#1f77b4', edgecolor='black')
    p2 = ax.bar(x, w1_times, width, bottom=tx_times, label='Wire 1 Transit (CAN-FD 2 Mbps)', color='#aec7e8', edgecolor='black')
    bottom_gw = np.array(tx_times) + np.array(w1_times)
    p3 = ax.bar(x, gw_times, width, bottom=bottom_gw, label='Gateway Ingress + IDS + Re-Encrypt', color='#ff7f0e', edgecolor='black')
    bottom_w2 = bottom_gw + np.array(gw_times)
    p4 = ax.bar(x, w2_times, width, bottom=bottom_w2, label='Wire 2 Transit (Destination Bus)', color='#c5b0d5', edgecolor='black')
    bottom_rx = bottom_w2 + np.array(w2_times)
    p5 = ax.bar(x, rx_times, width, bottom=bottom_rx, label='Host RX Decrypt (Ascon-128)', color='#2ca02c', edgecolor='black')

    for idx, f in enumerate(selected_flows):
        tot = f['t_end_to_end_ms']
        slack = f['slack_margin_ms']
        ax.text(idx, tot + 0.25, f"{tot:.3f} ms\n(+{slack:.1f}ms slack)", ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax.axhline(y=10.0, color='red', linestyle='--', linewidth=2.0, label='10.0 ms Hard Real-Time ASIL-D Deadline')

    ax.set_ylabel('Execution & Transit Time (Milliseconds)')
    ax.set_title('Milestone M3.4: Complete End-to-End Latency Budget Breakdown\n(NIST SP 800-232 Ascon-128 Math + ONNX INT8 IDS + CAN-FD Dual-Hop Wire RTA)')
    ax.set_xticks(x)
    ax.set_xticklabels(flow_labels)
    ax.set_ylim(0, 12.5)
    ax.grid(True, linestyle='--', alpha=0.5, axis='y')
    ax.legend(loc='upper right', framealpha=0.95)

    fig.tight_layout()
    fig1_path = os.path.join(FIGURES_DIR, 'end_to_end_latency_budget_breakdown.png')
    fig.savefig(fig1_path, dpi=300)
    plt.close(fig)
    print(f"[+] Saved Figure 1: {fig1_path}")

    # -------------------------------------------------------------
    # Figure 2: End-to-End Latency vs Hard Deadlines (Log Scale)
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(10, 5.5))

    all_labels = [f['name'][:28] for f in flows]
    all_totals = [f['t_end_to_end_ms'] for f in flows]
    all_deadlines = [f['deadline_ms'] for f in flows]
    all_slacks = [f['slack_margin_ms'] for f in flows]

    x = np.arange(len(all_labels))
    width = 0.35

    rects1 = ax.bar(x - width/2, all_totals, width, label='Total End-to-End Latency ($T_{\\mathrm{E2E}}$)', color='#1f77b4', edgecolor='black')
    rects2 = ax.bar(x + width/2, all_deadlines, width, label='Safety Deadline ($D_i$)', color='#d62728', edgecolor='black', alpha=0.7, hatch='//')

    for idx, (tot, dl, slk) in enumerate(zip(all_totals, all_deadlines, all_slacks)):
        pct = (slk / dl) * 100.0
        ax.text(idx, max(tot, dl) + 1.2, f"+{slk:.1f}ms\n({pct:.0f}% slack)", ha='center', va='bottom', fontsize=8, fontweight='bold', color='#2ca02c')

    ax.set_yscale('log')
    ax.set_ylabel('Latency (ms, Log Scale)')
    ax.set_title('End-to-End Latency vs Hard Real-Time Deadlines Across All Protocol Categories\n(Proving 100% Schedulability with Full Cryptographic & IDS Overhead)')
    ax.set_xticks(x)
    ax.set_xticklabels(all_labels, rotation=20, ha='right')
    ax.set_ylim(0.1, 150)
    ax.grid(True, which="both", ls="--", alpha=0.4)
    ax.legend(loc='upper right', framealpha=0.95)

    fig.tight_layout()
    fig2_path = os.path.join(FIGURES_DIR, 'end_to_end_latency_vs_deadlines.png')
    fig.savefig(fig2_path, dpi=300)
    plt.close(fig)
    print(f"[+] Saved Figure 2: {fig2_path}")

    # -------------------------------------------------------------
    # Figure 3: Hardware Platform Benchmark & Castiglione Comparison
    # -------------------------------------------------------------
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    # Subplot A: Hardware Platforms
    platforms = list(PLATFORMS.keys())
    platform_names = [PLATFORMS[k]['name'].split('(')[0].strip() for k in platforms]
    
    cat1_latencies = []
    cat2_latencies = []

    for pk in platforms:
        f_res = simulate_end_to_end_pipeline(pk)
        cat1_latencies.append(f_res[0]['t_end_to_end_ms'])
        cat2_latencies.append(f_res[2]['t_end_to_end_ms'])

    x = np.arange(len(platforms))
    width = 0.35

    ax1.bar(x - width/2, cat1_latencies, width, label='Cat 1 Inter-Domain (D: 10.0 ms)', color='#1f77b4', edgecolor='black')
    ax1.bar(x + width/2, cat2_latencies, width, label='Cat 2 Boot Attest (D: 50.0 ms)', color='#ff7f0e', edgecolor='black')

    for idx, (c1, c2) in enumerate(zip(cat1_latencies, cat2_latencies)):
        ax1.text(idx - width/2, c1 + 0.4, f"{c1:.2f} ms", ha='center', va='bottom', fontsize=9, fontweight='bold')
        ax1.text(idx + width/2, c2 + 0.6, f"{c2:.2f} ms", ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax1.axhline(y=10.0, color='red', linestyle='--', linewidth=1.5, label='10.0 ms Real-Time Threshold')
    ax1.axhline(y=50.0, color='purple', linestyle=':', linewidth=1.5, label='50.0 ms Boot FTTI Threshold')

    ax1.set_ylabel('End-to-End Latency (ms)')
    ax1.set_title('A. Cross-Platform Hardware Scaling\n(MCU vs Gateway vs Server)')
    ax1.set_xticks(x)
    ax1.set_xticklabels(platform_names)
    ax1.set_ylim(0, 60)
    ax1.grid(True, linestyle='--', alpha=0.5, axis='y')
    ax1.legend(loc='upper right', framealpha=0.95)

    # Subplot B: Architectural Comparison with Castiglione et al. 2025
    # Castiglione theoretical inter-domain: RC6 Encrypt (0.12) + Wire1 (0.863) + Gateway RC6 Dec/Twofish Enc (0.30) + Wire2 (0.863) + Receiver Dec (0.18) = 2.33 ms
    # BUT Castiglione has: NO MAC tag (0B), NO Monotonic Counter (0B), NO IDS (0 ms)
    # Proposed: Ascon Encrypt (0.37) + Wire1 (0.863) + Gateway Ingress/Monotonic/Ascon Dec/Tier1.5/ONNX INT8/Re-encrypt (1.58) + Wire2 (0.863) + Receiver Dec (0.37) = 4.05 ms
    comp_labels = ['Castiglione et al. 2025\n(Base Paper)\n[No MAC, No IDS, No Replay]', 'Proposed Architecture\n(Our Work)\n[Full AEAD, 14D IDS, Replay Gate]']
    wire_times = [1.726, 1.726]  # Two CAN-FD wire hops (0.863 + 0.863 per Bordoloi & Samii RTA)
    crypto_times = [0.600, 1.494] # Castiglione symmetric vs Our 4x Ascon-128
    ids_times = [0.000, 0.830]    # Castiglione has NO IDS vs Our Tier 1.5 + Tier 2 ONNX

    x_comp = np.arange(len(comp_labels))
    width_c = 0.45

    ax2.bar(x_comp, wire_times, width_c, label='CAN-FD Bus Wire Hops (Dual-Hop)', color='#aec7e8', edgecolor='black')
    ax2.bar(x_comp, crypto_times, width_c, bottom=wire_times, label='Cryptographic Ops (Encrypt/Decrypt)', color='#1f77b4', edgecolor='black')
    bottom_ids = np.array(wire_times) + np.array(crypto_times)
    ax2.bar(x_comp, ids_times, width_c, bottom=bottom_ids, label='Gateway 3-Tier IDS & Monotonic Gate', color='#ff7f0e', edgecolor='black')

    totals_c = bottom_ids + np.array(ids_times)
    for idx, tot in enumerate(totals_c):
        ax2.text(idx, tot + 0.15, f"{tot:.2f} ms\n({10.0-tot:.2f}ms slack)", ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax2.axhline(y=10.0, color='red', linestyle='--', linewidth=1.5, label='10.0 ms ASIL-D Deadline')
    ax2.set_ylabel('Total Turnaround Latency (ms)')
    ax2.set_title('B. Architecture Comparison: Base Paper vs Proposed\n(Adding Full Zero-Trust & IDS Adds Only 1.7ms)')
    ax2.set_xticks(x_comp)
    ax2.set_xticklabels(comp_labels)
    ax2.set_ylim(0, 11)
    ax2.grid(True, linestyle='--', alpha=0.5, axis='y')
    ax2.legend(loc='upper right', framealpha=0.95)

    fig.tight_layout()
    fig3_path = os.path.join(FIGURES_DIR, 'end_to_end_platform_comparison.png')
    fig.savefig(fig3_path, dpi=300)
    plt.close(fig)
    print(f"[+] Saved Figure 3: {fig3_path}")

def main():
    print("=" * 80)
    print(" MILESTONE M3.4: COMPLETE CROSS-DOMAIN END-TO-END LATENCY & ASCON SIMULATION")
    print("=" * 80)

    print("[+] Simulating end-to-end timing budget under BOTH Ascon round models...")
    # 1. Conservative Baseline (Upper bound: r=8B, b=6, 60 rounds)
    flows_conservative = simulate_end_to_end_pipeline('ARM_Cortex_A72_RPi4', standard='conservative')
    
    # 2. Official NIST SP 800-232 Standard (r=16B, b=8, 56 rounds)
    flows_nist = simulate_end_to_end_pipeline('ARM_Cortex_A72_RPi4', standard='nist_sp800_232')

    # Export primary conservative baseline CSV
    csv_path = os.path.join(DATA_DIR, 'end_to_end_latency_breakdown.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = list(flows_conservative[0].keys())
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flows_conservative)
    print(f"[+] Exported conservative breakdown dataset (60 rounds) to: {csv_path}")

    # Export official NIST SP 800-232 CSV for exact reproducibility
    csv_nist_path = os.path.join(DATA_DIR, 'end_to_end_latency_nist_standard.csv')
    with open(csv_nist_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = list(flows_nist[0].keys())
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flows_nist)
    print(f"[+] Exported official NIST SP 800-232 dataset (56 rounds) to: {csv_nist_path}")

    print("\n" + "=" * 130)
    print(f"{'Flow ID':<26} | {'Host TX':<9} | {'Wire 1':<8} | {'Gateway':<9} | {'Wire 2':<8} | {'Host RX':<9} | {'T_E2E (ms)':<10} | {'Deadline':<9} | {'Slack (ms)':<10} | {'Status':<6}")
    print("-" * 130)
    for f in flows_conservative:
        status_str = "PASS" if f['schedulable'] else "FAIL"
        print(f"{f['flow_id']:<26} | {f['t_host_tx_ms']:<9.4f} | {f['t_wire_1_ms']:<8.4f} | {f['t_gw_total_ms']:<9.4f} | {f['t_wire_2_ms']:<8.4f} | {f['t_host_rx_ms']:<9.4f} | {f['t_end_to_end_ms']:<10.4f} | {f['deadline_ms']:<9.1f} | {f['slack_margin_ms']:<10.4f} | {status_str:<6}")
    print("=" * 130)

    f1_cons = flows_conservative[0]
    f1_nist = flows_nist[0]
    print("\n[+] First-Principles Mathematical Verification for Category 1 Inter-Domain Telemetry:")
    print("    1. Official NIST SP 800-232 Standard (128-bit Rate r=16B, b=8):")
    print(f"       - Permutation Rounds:               56 Rounds (12 init + 8 AD + 24 data + 12 final = 2,128 ops)")
    print(f"       - Ascon-AEAD128 Execution Latency:  {f1_nist['t_host_tx_ms']:.4f} ms per encrypt/decrypt")
    print(f"       - Total 4x Ascon Pipeline Overhead: {f1_nist['t_host_tx_ms']*4:.4f} ms (Tx + GwDec + GwEnc + Rx)")
    print(f"       - Dual CAN-FD Wire Hops (M3.2 RTA): {f1_nist['t_wire_1_ms']*2:.4f} ms (Wire 1 + Wire 2)")
    print(f"       - Gateway 3-Tier IDS & Monotonic:   {f1_nist['t_gw_ids_inference_ms']:.4f} ms")
    print(f"       ------------------------------------------------")
    print(f"       Total End-to-End Latency (T_E2E):   {f1_nist['t_end_to_end_ms']:.4f} ms (Deadline: 10.0 ms)")
    print(f"       Safety Headroom (Slack Margin):     +{f1_nist['slack_margin_ms']:.4f} ms (60.2% spare slack!)")
    print("\n    2. Conservative Baseline (Competition Ascon-128, 64-bit Rate r=8B, b=6):")
    print(f"       - Permutation Rounds:               60 Rounds (12 init + 6 AD + 30 data + 12 final = 2,280 ops)")
    print(f"       - Ascon-AEAD128 Execution Latency:  {f1_cons['t_host_tx_ms']:.4f} ms per encrypt/decrypt")
    print(f"       - Total 4x Ascon Pipeline Overhead: {f1_cons['t_host_tx_ms']*4:.4f} ms (Tx + GwDec + GwEnc + Rx)")
    print(f"       - Dual CAN-FD Wire Hops (M3.2 RTA): {f1_cons['t_wire_1_ms']*2:.4f} ms (Wire 1 + Wire 2)")
    print(f"       - Gateway 3-Tier IDS & Monotonic:   {f1_cons['t_gw_ids_inference_ms']:.4f} ms")
    print(f"       ------------------------------------------------")
    print(f"       Total End-to-End Latency (T_E2E):   {f1_cons['t_end_to_end_ms']:.4f} ms (Upper bound)")
    print(f"       Safety Headroom (Slack Margin):     +{f1_cons['slack_margin_ms']:.4f} ms (59.5% spare slack!)")

    print("\n[+] Generating high-resolution 300 DPI publication plots...")
    generate_publication_plots(flows_conservative)
    print("\n[+] Milestone M3.4 Execution Completed Successfully!")

if __name__ == '__main__':
    main()
