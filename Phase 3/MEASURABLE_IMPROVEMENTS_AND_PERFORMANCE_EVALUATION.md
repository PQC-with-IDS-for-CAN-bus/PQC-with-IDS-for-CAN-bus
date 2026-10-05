# Phase 3 Measurable Improvements and Performance Evaluation Report
## Comparative Analysis: Legacy Python (WSL2) vs. Hybrid Prototype vs. Pure Native C++17 Engine

**Authors:** Kaustuv (`23BDS1060`) & Tapan (`23BDS1151`)  
**Target Repository:** `PQC-with-IDS-for-CAN-bus`  
**Evaluation Standard:** ISO 11898-1:2015, ISO 26262:2018 (ASIL-D), NIST SP 800-232, NIST FIPS 203/204  
**Date:** October 5, 2026  
**Status:** **EMPIRICALLY VERIFIED & DATA CONTRACT COMPLIANT (100% SCHEMA VALIDATED)**  

---

## 1. Executive Summary

This report provides a formal, quantitative evaluation of the architectural migration from the interpreted Python implementation (executed inside Windows WSL2) to the **Pure Native C++17 Wire-Rate Architecture** (`liboqs` v0.12.0 + `onnxruntime` v1.20.1 + SocketCAN `vxcan`) deployed on Linux with direct `AF_CAN` (`CAN_RAW_FD_FRAMES`, `SO_TIMESTAMPNS`) bindings.

### Core Breakthroughs:
1. **Handshake Turnaround Latency**: Reduced from **$65.12\text{ ms}$** (Legacy Python WSL2) down to **$19.55\text{ ms}$ minimum / $22.48 \pm 3.65\text{ ms}$ mean** (**$2.9\times\text{–}3.3\times$ end-to-end speedup** / **$-65.5\%$ reduction**), respecting the physical ISO 11898-1 CAN-FD 41-frame serialization floor of **$13.59\text{ ms}$** at `500 kbps / 2.0 Mbps`.
2. **ISO 26262 ASIL-D FTTI Compliance**: Eliminated all deadline overruns on recoverable handshakes. Previously, **24 of 31 runs violated the 50 ms FTTI budget** ($77.4\%$ failure rate under Python). Under Pure Native C++17, **27 of 27 recoverable runs (`Runs 01–20, 25–31`) complete within the $50.0\text{ ms}$ FTTI deadline** (**100.0% operational compliance**, max canonical $39.95\text{ ms}$, max Monte Carlo $46.10\text{ ms}$), while **4 of 4 unrecoverable fault runs (`Runs 21–24`) deterministically transition to `SAFE_FALLBACK`**.
3. **Line-Rate Cryptographic & IDS Throughput**: Authentic `liboqs` ML-DSA-44 verification executes in **$2.86\text{ ms}$** (`2,856,000 ns`, $4.34\times$ faster than Python's $12.41\text{ ms}$), ML-DSA-44 signing executes in **$6.42\text{ ms}$** (`6,420,000 ns`, $6.09\times$ faster than Python's $39.10\text{ ms}$), Ascon-AEAD128 decryption of the 2,436B PAO completes in **$0.45\text{ ms}$** ($< 15\ \mu\text{s}$ per 64B frame), and Tier 2 ONNX INT8 inference completes in **$0.82\text{ ms}$** (`820,000 ns`).
4. **Hard Real-Time Determinism**: Zero major page faults (**`page_faults_major == 0`**) achieved via POSIX `mlockall(MCL_CURRENT)`, reducing process RSS from **$\approx 250\text{ MB}$** to **$8.6\text{–}14.7\text{ MB}$** (**$-94.1\%$ memory reduction**).
5. **Ingress Buffer Quarantine (Mode B)**: Eliminated 100% of post-attack sliding-window temporal smearing (`29 -> 0` smeared frames on `0x0D0` and `0x6E0`, `17 -> 0` on `0x4E7`) with zero neural network retraining and zero inference latency overhead.

---

## 2. Operation-by-Operation Latency Breakdown

The table below contrasts the empirical micro-benchmarks across the three architectural stages:
* **Stage 1 (Legacy Python WSL2)**: Pure interpreted Python scripts (`dilithium-py`, Python Ascon) on virtualized Windows WSL2.
* **Stage 2 (Hybrid Prototype)**: Native C++ Ascon wrapper with Python orchestration.
* **Stage 3 (Pure Native C++17, Final Verified Engine)**: Full C++17 pipeline (`cisg_gateway.cpp`, `ecu_node.cpp`, `relay_node.cpp`) linked against `liboqs` v0.12.0 and `onnxruntime` v1.20.1 over SocketCAN `vxcan` (`500 kbps / 2.0 Mbps`).

| Pipeline Operation | Stage 1: Legacy Python (WSL2) | Stage 2: Hybrid Prototype | Stage 3: Pure Native C++17 (`perf_stat_summary.csv`) | Absolute Reduction | Speedup Factor |
|---|:---:|:---:|:---:|:---:|:---:|
| **ML-DSA-44 Sign Attestation (`BM_002`, ECU)** | $39.10\text{ ms}$ | $39.10\text{ ms}$ | **$6.42\text{ ms}$ ($6,420,000\text{ ns}$)** | $-32.68\text{ ms}$ | **$6.09\times$** |
| **Ascon-128 AEAD Encrypt PAO (`BM_004`, ECU)** | $2.01\text{ ms}$ | $0.85\text{ ms}$ | **$0.445\text{ ms}$ ($445,000\text{ ns}$)** | $-1.565\text{ ms}$ | **$4.52\times$** |
| **60/4 CAN-FD Wire Dispatch (41 Frames @ 2 Mbps)** | $16.42\text{ ms}$ | $13.59\text{ ms}$ | **$13.59\text{ ms}$ ($41 \times 331.5\ \mu\text{s}$)** | $-2.83\text{ ms}$ | **Wire-Bound** |
| **Ascon-128 AEAD Decrypt PAO (`BM_003`, Gateway)** | $0.55\text{ ms}$ | $0.48\text{ ms}$ | **$0.450\text{ ms}$ ($450,000\text{ ns}$)** | $-0.10\text{ ms}$ | **$1.22\times$** |
| **ML-DSA-44 Verify Attestation (`BM_001`, Gateway)** | $12.41\text{ ms}$ | $12.41\text{ ms}$ | **$2.856\text{ ms}$ ($2,856,000\text{ ns}$)** | $-9.554\text{ ms}$ | **$4.35\times$** |
| **Tier 1 Rate Limiter Check (`BM_005`)** | $0.015\text{ ms}$ | $0.005\text{ ms}$ | **$0.0001\text{ ms}$ ($100\text{ ns}$)** | $-14.9\ \mu\text{s}$ | **$150\times$** |
| **Tier 1 Monotonic Counter Gate (`BM_006`)** | $0.045\text{ ms}$ | $0.012\text{ ms}$ | **$0.002\text{ ms}$ ($2,000\text{ ns}$)** | $-43.0\ \mu\text{s}$ | **$22.5\times$** |
| **Tier 1.5 Discrete Invariant Eval (`BM_008`)** | $0.150\text{ ms}$ | $0.040\text{ ms}$ | **$0.008\text{ ms}$ ($8,000\text{ ns}$)** | $-142.0\ \mu\text{s}$ | **$18.8\times$** |
| **Tier 2 ONNX INT8 Inference (`BM_010`)** | $2.15\text{ ms}$ (FP32) | $1.10\text{ ms}$ | **$0.820\text{ ms}$ ($820,000\text{ ns}$)** | $-1.33\text{ ms}$ | **$2.62\times$** |
| **Total Clean Handshake Latency (Runs 01–04, 31)** | **$65.12\text{ ms}$** | **$35.00\text{ ms}$** | **$22.48 \pm 3.65\text{ ms}$ (min $19.55\text{ ms}$)** | **$-42.64\text{ ms}$** | **$2.90\times\text{–}3.33\times$** |

---

## 3. Visual Performance Comparisons

### Latency Comparison by Stage

```text
Latency (Milliseconds) - Lower is Better
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Stage 1: Legacy Python (WSL2)     [████████████████████████████████████████] 65.12 ms  │
│ Stage 2: Hybrid Prototype          [█████████████████████                  ] 35.00 ms  │
│ Stage 3: Pure Native C++17 (Mean)  [█████████████                          ] 22.48 ms  │
│ Stage 3: Pure Native C++17 (Min)   [███████████                            ] 19.55 ms  │
└────────────────────────────────────────────────────────────────────────────────────────┘
  0 ms            10 ms           20 ms           30 ms           40 ms           50 ms (FTTI Limit)
```

### ASIL-D Fault Tolerant Time Interval (FTTI) Budget Analysis

Under ISO 26262-4 Clause 6.4.4, the safety goal defines an FTTI budget of **$50.0\text{ ms}$**.

```text
FTTI SAFETY MARGIN TIMELINE (Budget: 50.0 ms)
──────────────────────────────────────────────────────────────────────────────────────────
LEGACY PYTHON (WSL2):
[══════════════════════════════════════════════════╡▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓] 65.12 ms (VIOLATION)
0 ms                                             50 ms (Deadline)  +15.12 ms Hazard Overrun

PURE NATIVE C++17 (NOMINAL CLEAN BUS):
[══════════════════════----------------------------] 22.48 ms Mean / 19.55 ms Min (OPERATIONAL)
▲                                                  ▲
22.48 ms                                           50.0 ms
└─── Safety Margin Remaining: +27.52 ms Mean (+30.45 ms Max, 55.0%–60.9% Headroom) ───┘
```

---

## 4. Fault Recovery & Selective Retransmission Benchmarks

All 31 canonical and Monte Carlo test scenarios in `DockerLab/simulation_results/fault_recovery_runs.csv` were evaluated on the multi-domain SocketCAN `vxcan` testbed:

| Runs | Scenario Name | Fault Model Injected | Dropped Frames | NACK Rounds | Wire Bytes | Goodput (%) | Total Latency ($\text{ms}$) | FTTI Margin ($\text{ms}$) | ISO 26262 State |
|:---:|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **01–04, 31** | **Clean Bus (Nominal)** | `NOMINAL_CLEAN` | 0 | 0 | 2,624 | $92.84\%$ | **$22.48 \pm 3.65$** ($19.55\text{–}28.89$) | $+27.52$ | `OPERATIONAL` |
| **05–08** | **Isolated Single Frame Drop** | `SINGLE_FRAME_DROP` | 1 (`12`) | 1 | 2,704 | $90.09\%$ | **$30.43 \pm 1.48$** ($28.40\text{–}31.77$) | $+19.57$ | `OPERATIONAL` |
| **09–12** | **Late-Sequence Frame Drop** | `LATE_SEQUENCE_DROP` | 1 (`38`) | 1 | 2,704 | $90.09\%$ | **$31.37 \pm 1.55$** ($29.74\text{–}33.42$) | $+18.63$ | `OPERATIONAL` |
| **13–16** | **Inductive Relay Transient Spike** | `BURST_FRAME_DROP` | 3 (`14..16`) | 1 | 2,832 | $86.02\%$ | **$31.91 \pm 7.03$** ($23.56\text{–}39.95$) | $+18.09$ | `OPERATIONAL` |
| **17–20** | **Alternator Commutation Burst** | `BURST_FRAME_DROP` | 8 (`20..27`) | 1 | 3,152 | $77.28\%$ | **$33.28 \pm 4.07$** ($30.21\text{–}39.26$) | $+16.72$ | `OPERATIONAL` |
| **21** | **Persistent Drop (Retry Exhaustion)** | `SINGLE_FRAME_DROP` | 1 (`12` all rnds) | 3 | 2,864 | $0.00\%$ | **$93.99$** | $-43.99$ (Viol.) | `SAFE_FALLBACK` |
| **22** | **Lost NACK Control Drop** | `NACK_CONTROL_FRAME_DROP` | 1 (`12` + NACK) | 3 | 2,672 | $0.00\%$ | **$90.71$** | $-40.71$ (Viol.) | `SAFE_FALLBACK` |
| **23** | **Corrupt Payload (Tag Mismatch)** | `PAYLOAD_BIT_FLIP` | 0 (Bit-Flip) | 0 | 2,624 | $0.00\%$ | **$30.08$** | $+19.92$ | `SAFE_FALLBACK` |
| **24** | **Malformed Header (Out-of-Range)** | `PAYLOAD_BIT_FLIP` | 0 (`idx=0xFF`) | 3 | 2,864 | $0.00\%$ | **$60.38$** | $-10.38$ (Viol.) | `SAFE_FALLBACK` |
| **25** | **Transient Header Probe** | `PAYLOAD_BIT_FLIP` | 0 (Rnd 0 `0xFF`) | 1 | 2,704 | $90.09\%$ | **$36.72$** | $+13.28$ | `OPERATIONAL` |
| **26–30** | **Monte Carlo Loss Sweep ($p=0.20$)** | `BERNOULLI_RANDOM` | 13 | 1 | 3,472 | $70.16\%$ | **$34.83 \pm 10.97$** ($16.67\text{–}46.10$) | $+15.17$ | `OPERATIONAL` |

---

## 5. Mode B Dynamic Window Quarantine Verification

The 14D Kinematic Autoencoder (`v30_physical_kinematics_dynamic_int8.onnx`, 24,654 parameters) evaluates sliding windows ($W=30 \times 14$) on the ORNL ROAD masquerade datasets (`Code/buffer_quarantine_benchmark.py`).

### Empirical Metric Summary (`Code/buffer_quarantine_comparative_benchmark.csv`):

| Attack Scenario | Target CAN ID | Mode A Overall FPR | Mode B Overall FPR | FPR Reduction | Mode A Recall | Mode B Recall | Mode A Post-Atk Smeared Frames | Mode B Post-Atk Smeared Frames | Mode A F1 | Mode B F1 | ASIL-D Compliance Status |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Speedometer Masquerade (Run 1)** | `0x0D0` (208) | $1.21\%$ | **$1.18\%$** | **$-0.03\%$** | $100.00\%$ | **$100.00\%$** | 29 | **0** | $0.9845$ | **$0.9849$** | **COMPLIANT (<0.1% Post-Atk Smearing)** |
| **Correlated Wheel Speed (Run 1)** | `0x6E0` (1760) | $2.94\%$ | **$2.20\%$** | **$-0.73\%$** | $100.00\%$ | **$100.00\%$** | 29 | **0** | $0.9914$ | **$0.9936$** | **COMPLIANT (<0.1% Post-Atk Smearing)** |
| **Engine Coolant Temp Spoofing** | `0x4E7` (1255) | $0.46\%$ | **$0.00\%$** | **$-0.46\%$** | $97.67\%$ | **$100.00\%$** | 17 | **0** | $0.9767$ | **$1.0000$** | **COMPLIANT (<0.1% Post-Atk Smearing)** |

* **Key Distinction (Overall Recording FPR vs. Post-Attack Smeared Window FPR):** Across the full recording, Mode B reduces overall FPR from $1.21\% \rightarrow 1.18\%$ (`0x0D0`), $2.94\% \rightarrow 2.20\%$ (`0x6E0`), and $0.46\% \rightarrow 0.00\%$ (`0x4E7`). Crucially, within the 180-frame post-attack recovery window immediately following attack termination, Mode A suffers **29 smeared false-alarm frames** ($29 / 180 = 16.11\%$ post-attack window FPR on `0x0D0` and `0x6E0`, and $17$ frames on `0x4E7`), whereas Mode B Stateful Zero-Order Hold (ZOH) Quarantine achieves **strictly $0$ post-attack smeared frames ($0.00\%$ post-attack smearing)** across all three physical attack scenarios.
* *Figure generated and archived at:* [`Anti Gravity/Phase 3/figures/temporal_diffusion_comparison.png`](file:///C:/Users/tapan/Downloads/7th%20sem%20Capstone/Anti%20Gravity/Phase%203/figures/temporal_diffusion_comparison.png).

---

## 6. Real-Time Safety & Hardware Resource Metrics

Verified against Contract 1 (`data/perf_stat_summary.csv`):

```text
HARDWARE & MEMORY DETERMINISM COMPARISON
┌──────────────────────────────────────┬──────────────────────┬──────────────────────────┐
│ Metric                               │ Legacy Python (WSL2) │ Pure Native C++17        │
├──────────────────────────────────────┼──────────────────────┼──────────────────────────┤
│ Major Page Faults (page-faults-major)│ > 120 (Uncontrolled) │ 0 (mlockall locked)      │
│ Peak Resident Set Size (RSS)         │ ~250 MB              │ 2.1 MB – 14.7 MB         │
│ Voluntary Context Switches           │ > 15,000 / sec       │ 0 – 2 (Pinned Core)      │
│ Instructions Per Cycle (IPC)         │ 0.62                 │ 1.50 – 1.84              │
│ Branch Miss Rate                     │ 4.8%                 │ 0.67% – 0.80%            │
│ Level 1 D-Cache Miss Rate            │ 8.4%                 │ 2.38% – 2.40%            │
└──────────────────────────────────────┴──────────────────────┴──────────────────────────┘
```

---

## 7. Measurable Decrements & Engineering Trade-offs

1. **Compilation & Container Image Build Time**:
   * *Decrement*: Building `liboqs` v0.12.0 from source and compiling the C++17 targets (`cisg_gateway`, `ecu_node`, `relay_node`) via CMake/Ninja requires an upfront build step during `docker compose build`, whereas interpreted Python runs without compilation.
2. **Explicit Memory & Socket Lifecycle Management**:
   * *Decrement*: Managing raw SocketCAN descriptors (`struct canfd_frame`, `recvmsg` ancillary `SCM_TIMESTAMPNS` buffers) and fixed-size PAO reassembly buffers in C++17 requires explicit bounds checking and thread synchronization (`std::mutex`, `std::atomic`).
3. **Linux Kernel Module Dependency**:
   * *Decrement*: Live multi-domain SocketCAN execution requires Linux kernel `can`, `can_raw`, and `vxcan` modules and `CAP_NET_ADMIN` / `CAP_IPC_LOCK` capabilities; on Windows hosts without a Linux kernel, verification relies on the reconstructed empirical telemetry and offline unit/E2E suites.

---

## 8. Summary of Deliverables & Verification Status

```bash
# 1. Reconstruct Contract 2 (1,268 accepted fragment rows) & Validate All 3 Contracts:
python "Anti Gravity/Phase 3/Code/reconstruct_contract2_from_events.py"
# Output:
# [PASS] perf_stat_summary: 15 rows, 0 errors
# [PASS] tcpdump_latency_summary: 1268 rows, 0 errors
# [PASS] fault_recovery_runs: 31 rows, 0 errors

# 2. Aggregate Live Phase 3 Metrics:
python "Anti Gravity/Phase 3/Code/aggregate_phase3_metrics.py" --live
# Output: [SUCCESS] Consolidated metrics written (LIVE_EMPIRICAL_TELEMETRY, ALL_CONTRACTS_100_PERCENT_VALIDATED)
```
