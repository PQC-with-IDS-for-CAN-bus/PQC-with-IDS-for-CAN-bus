# IEEE Performance Figures & Empirical Evaluation Suite
## Post-Quantum Cryptographic (PQC) & Multi-Domain IDS Architecture for CAN-FD Bus

**Authors / Candidates:** Kaustuv (`23BDS1060`) & Tapan (`23BDS1151`)  
**Investigation:** Phase 3 Multi-Domain Central In-Vehicle Security Gateway (CISG)  
**Target Publication Venues:** *IEEE Transactions on Vehicular Technology* / *IEEE Transactions on Information Forensics and Security*  
**Standards Grounding:**
* **ISO 11898-1:2015:** Controller Area Network with Flexible Data-Rate (CAN-FD) (`500 kbps` nominal arbitration / `2.0 Mbps` data phase, `331.5 µs` nominal 64B frame duration)
* **ISO 26262 ASIL-D:** Automotive Functional Safety ($T_{\mathrm{FTTI}} = 50.0\,\mathrm{ms}$ Fault Tolerant Time Interval)
* **NIST FIPS 204:** Module-Lattice-Based Digital Signature Standard (ML-DSA-44)
* **NIST SP 800-232:** Ascon-AEAD128 Authenticated Encryption with Associated Data (AEAD)
* **Execution Environment:** Pure C++17 DockerLab (`liboqs` v0.12.0, `onnxruntime` v1.20.1), Linux Kernel `vxcan` with `SCM_TIMESTAMPNS` Hardware Emulation, Zero-Bypass Audit Contracts

---

## 1. Directory Structure & File Manifest

The `Performance Figures` directory contains the complete reproduction engine, publication-grade vector graphics, high-resolution raster images, LaTeX manuscript tables, and comprehensive performance analysis reports.

```text
Phase 3/Performance Figures/
├── README.md                                        <-- [This Document] Academic guide & documentation
├── code/
│   └── generate_ieee_visualizations.py              <-- Complete IEEE-compliant plotting & analysis engine
└── visualizations/
    ├── fig1_latency_vs_ftti_budget.pdf              <-- Figure 1 (Vector PDF, 600 DPI, IEEE Double Column)
    ├── fig1_latency_vs_ftti_budget.png              <-- Figure 1 (Lossless Raster PNG, 600 DPI)
    ├── fig2_goodput_and_wire_overhead.pdf           <-- Figure 2 (Vector PDF, 600 DPI)
    ├── fig2_goodput_and_wire_overhead.png           <-- Figure 2 (Lossless Raster PNG, 600 DPI)
    ├── fig3_nack_turnaround_distribution.pdf        <-- Figure 3 (Vector PDF, 600 DPI)
    ├── fig3_nack_turnaround_distribution.png        <-- Figure 3 (Lossless Raster PNG, 600 DPI)
    ├── fig4_pqc_ids_security_radar_and_attacks.pdf  <-- Figure 4 (Vector PDF, 600 DPI)
    ├── fig4_pqc_ids_security_radar_and_attacks.png  <-- Figure 4 (Lossless Raster PNG, 600 DPI)
    ├── fig5_schedulability_waterfall_breakdown.pdf  <-- Figure 5 (Vector PDF, 600 DPI)
    ├── fig5_schedulability_waterfall_breakdown.png  <-- Figure 5 (Lossless Raster PNG, 600 DPI)
    ├── figure1_latency.pdf / .png                   <-- Canonical alias for Figure 1
    ├── figure2_goodput.pdf / .png                   <-- Canonical alias for Figure 2
    ├── figure3_turnaround.pdf / .png                <-- Canonical alias for Figure 3
    ├── figure4_attacks.pdf / .png                   <-- Canonical alias for Figure 4
    ├── figure5_waterfall.pdf / .png                 <-- Canonical alias for Figure 5
    ├── ieee_table_fault_recovery.tex                <-- LaTeX Table 1: Complete 31-run empirical benchmark
    ├── ieee_table_attack_mitigation.tex             <-- LaTeX Table 2: Multi-tier adversarial defense table
    └── performance_analysis_report.md               <-- Exhaustive empirical analysis report
```

### Underlying Empirical Datasets
The visualizations and LaTeX tables are strictly derived from empirical data recorded during SocketCAN execution in DockerLab:
1. `Phase 3/DockerLab/simulation_results/fault_recovery_runs.csv`: 31 empirical test runs under diverse fault injection models (Contract 3).
2. `Phase 3/data/tcpdump_latency_summary.csv`: 1,268 accepted CAN-FD fragment arrivals across all 31 sessions (`SESS_DOCKER_000001..000031`, Contract 2).
3. `Phase 3/DockerLab/simulation_results/perf_stat_summary.csv`: 15 hardware/software microarchitectural benchmarks (`page_faults_major == 0`, Contract 1).
4. `Phase 3/data/consolidated_phase3_metrics.json`: Consolidated cryptographic and gateway latency metrics (`LIVE_EMPIRICAL_TELEMETRY`, `ALL_CONTRACTS_100_PERCENT_VALIDATED`).

---

## 2. Quickstart & Reproduction Guide

### Prerequisites
* Python 3.10+
* Required packages: `matplotlib`, `seaborn`, `numpy`, `pandas`
* Fonts: Standard serif system fonts (`Times New Roman`, `DejaVu Serif`, or `Liberation Serif`). Matplotlib's `stix` engine is used for mathematical typography.

### Executing the Generation Pipeline
To regenerate all 5 figures (both vector PDF and lossless 600 DPI PNG under descriptive and canonical names), LaTeX tables, and markdown report, run the generation script from the project root:

```bash
python "Anti Gravity/Phase 3/Performance Figures/code/generate_ieee_visualizations.py"
```

---

## 3. Comprehensive Breakdown of IEEE Visualizations

Each figure was designed in strict accordance with the IEEE Computer Society and IEEE Vehicular Technology Society formatting rules:
- **Typography:** Times New Roman serif typography, bold axis titles, math expressions rendered via STIX math fonts.
- **Color Palette:** High-contrast, colorblind-safe academic palette (Navy `#1B365D`, Deep Teal `#007788`, Forest Green `#2E7D32`, Amber `#D97706`, Crimson `#C0392B`, Purple `#4A148C`).
- **Zero Data Occlusion:** All callout text, data points, error bars, and legend boxes include dedicated vertical and horizontal headroom so zero text-to-box or text-to-line collisions occur.

---

### Figure 1: End-to-End Latency vs. ISO 26262 ASIL-D $50.0\,\mathrm{ms}$ FTTI Budget
* **Files:** `visualizations/fig1_latency_vs_ftti_budget.pdf` & `.png` (`figure1_latency.pdf` & `.png`)
* **Layout:** Double-column width ($7.50\,\text{in} \times 4.20\,\text{in}$), 600 DPI.
* **Format:** Box-and-whisker distribution plot with empirical scatter jitter overlay across all 10 distinct fault injection regimes ($N=31$), including Run 25 (`Transient Header Probe`, $36.72\,\mathrm{ms}$).

#### Detailed Academic Observations:
1. **Nominal Clean Bus (Runs 01–04, 31):**
   - Mean handshake latency is **$22.48\,\mathrm{ms} \pm 3.65\,\mathrm{ms}$** (fastest: **$19.55\,\mathrm{ms}$**).
   - Demonstrates that post-quantum digital signature verification (ML-DSA-44) and 41-frame CAN-FD transport complete in less than half the available ASIL-D budget under non-fault conditions.
2. **Recoverable Physical Bus Dropouts (Runs 05–20, 25–30):**
   - **Isolated Single Drop (Seq 12):** Completes in **$30.43\,\mathrm{ms} \pm 1.48\,\mathrm{ms}$** ($+7.95\,\mathrm{ms}$ retransmission cost).
   - **Late Sequence Drop (Seq 38):** Completes in **$31.37\,\mathrm{ms} \pm 1.55\,\mathrm{ms}$**. Proves that late-arriving drops do not stall reassembly.
   - **Relay Transient Spike (3 Frames):** Completes in **$31.91\,\mathrm{ms} \pm 7.03\,\mathrm{ms}$** (peak: **$39.95\,\mathrm{ms}$**).
   - **Alternator Commutation Burst (8 Frames):** Completes in **$33.28\,\mathrm{ms} \pm 4.07\,\mathrm{ms}$** (peak: **$39.26\,\mathrm{ms}$**).
   - **Transient Header Probe (Run 25, 1 Frame):** Completes in **$36.72\,\mathrm{ms}$** (`OPERATIONAL`), recovering cleanly via 1 selective NACK round after rejecting a single round-0 corrupted header.
   - **Monte Carlo Bernoulli Sweep (Runs 26–30):** Completes in **$34.83\,\mathrm{ms} \pm 10.97\,\mathrm{ms}$** (max: **$46.10\,\mathrm{ms}$**).
   - **Deterministic Safety Margin:** All 20 canonical recoverable handshakes (Runs 01–20) finish at or below **$39.95\,\mathrm{ms}$** ($\ge 10.05\,\mathrm{ms}$ / $20.1\%$ headroom), and all 27 successful handshakes across the entire 31-run suite (including Run 25 and Monte Carlo Runs 26–30) complete at or below **$46.10\,\mathrm{ms}$** ($\ge 3.90\,\mathrm{ms}$ / $7.8\%$ headroom) below the $50.0\,\mathrm{ms}$ FTTI boundary.
3. **Fail-Safe Quarantine Regimes (Runs 21–24):**
   - **Run 23 (Corrupt Payload / Tag Mismatch):** Terminated in **$30.08\,\mathrm{ms}$** upon Ascon authentication tag mismatch (`SAFE_FALLBACK`).
   - **Run 24 (Malformed Header / Out-of-Range):** Terminated in **$60.38\,\mathrm{ms}$** (`ftti_violation_flag = True`, `SAFE_FALLBACK`) after out-of-range sequence ID rejection.
   - **Run 22 (Lost NACK Control Drop):** Quarantined cleanly at **$90.71\,\mathrm{ms}$** (`ftti_violation_flag = True`, `SAFE_FALLBACK`) after timer expiration.
   - **Run 21 (Persistent Drop / Retry Exhaustion):** Quarantined cleanly at **$93.99\,\mathrm{ms}$** (`ftti_violation_flag = True`, `SAFE_FALLBACK`) upon 3-retry exhaustion without bus lockup.

---

### Figure 2: Goodput Efficiency & Physical Wire Serialization Overhead Breakdown
* **Files:** `visualizations/fig2_goodput_and_wire_overhead.pdf` & `.png` (`figure2_goodput.pdf` & `.png`)
* **Layout:** Double-column width ($7.50\,\text{in} \times 3.55\,\text{in}$), two-panel layout.

#### Detailed Academic Observations:
1. **Goodput Efficiency ($\eta_{\mathrm{wire}}$) [Panel (a)]:**
   - **Nominal Clean Bus:** **$92.84\%$** ($92.8\%$ rounded) usable payload efficiency ($2,436\,\text{bytes}$ Protected Attestation Object over $41 \times 64 = 2,624\,\text{wire bytes}$).
   - **Single / Late Drop / Header Probe:** **$90.09\%$** ($90.1\%$) efficiency ($2,704\,\text{wire bytes}$: $+64\,\text{B}$ retransmitted data frame and $+16\,\text{B}$ selective NACK control frame).
   - **Relay Spike (3 Frames):** **$86.02\%$** ($86.0\%$) efficiency ($2,832\,\text{wire bytes}$).
   - **Alternator Burst (8 Frames):** **$77.28\%$** ($77.3\%$) efficiency ($3,152\,\text{wire bytes}$).
   - **Monte Carlo Sweep (13 Frames):** **$70.16\%$** ($70.2\%$) efficiency ($3,472\,\text{wire bytes}$).
2. **Selective Bitmap Retransmission Advantage [Panel (b)]:**
   - Classical Go-Back-N would require retransmitting from the first dropped frame to frame 40 (up to $2,000+\,\text{bytes}$ wasted overhead).
   - Our 64-bit selective NACK protocol transmits a single $16\,\text{byte}$ control frame (`0x201`) and requests **only** the missing indices on `0x200`, achieving an **$85.4\%$ reduction in retransmission wire overhead**.

---

### Figure 3: Dynamic NACK Turnaround Latency Distribution & Retransmission Burden
* **Files:** `visualizations/fig3_nack_turnaround_distribution.pdf` & `.png` (`figure3_nack.pdf` & `.png`)
* **Layout:** Double-column width ($7.16\,\text{in} \times 3.30\,\text{in}$), two-panel layout.
* **Grounding:** Kernel-level `SCM_TIMESTAMPNS` timestamps captured directly between Gateway NACK transmission (`0x201`) and ECU first-retransmitted frame arrival (`0x200`).

#### Detailed Academic Observations:
1. **Dynamic Turnaround Distribution [Panel (a)]:**
   - Range: **$822.17\,\mu\mathrm{s}$ to $2,972.12\,\mu\mathrm{s}$** ($N=22$ recovered runs).
   - Mean Turnaround: **$1,229.3\,\mu\mathrm{s}$**; Median Turnaround: **$956.3\,\mu\mathrm{s}$**.
   - Non-Overlap Typography: Dedicated vertical headroom (`ylim 0 to 16.5`) ensures the `Mean: 1229.3 µs` and `Median: 956.3 µs` reference lines and legend sit strictly above the 14-run first histogram bin with zero overlap.
2. **Retransmission Burden Scaling [Panel (b)]:**
   - **1 Frame Drop ($n=9$):** Turnaround spans **$822.2\,\mu\mathrm{s} - 2,265.2\,\mu\mathrm{s}$** (mean $1,294.7\,\mu\mathrm{s}$).
   - **3 Frame Burst ($n=4$):** Turnaround spans **$899.7\,\mu\mathrm{s} - 954.7\,\mu\mathrm{s}$** (mean $927.8\,\mu\mathrm{s}$).
   - **8 Frame Burst ($n=4$):** Turnaround spans **$844.2\,\mu\mathrm{s} - 2,180.5\,\mu\mathrm{s}$** (mean $1,272.8\,\mu\mathrm{s}$).
   - **13 Frame Loss ($n=5$):** Turnaround spans **$842.1\,\mu\mathrm{s} - 2,972.1\,\mu\mathrm{s}$** (mean $1,290.1\,\mu\mathrm{s}$).

---

### Figure 4: Multi-Domain Adversarial Stress-Test Verification & Multi-Tier Mitigation Accuracy
* **Files:** `visualizations/fig4_pqc_ids_security_radar_and_attacks.pdf` & `.png` (`figure4_security.pdf` & `.png`)
* **Layout:** Double-column width ($7.50\,\text{in} \times 3.45\,\text{in}$), two-panel layout.

#### Detailed Academic Observations:
1. **Adversarial Injection Evaluation [Panel (a)]:**
   - **Replay Injection:** 1 frame injected, **1 frame blocked (100%)** (`replay_rejected`, $0$ cross-domain leakage).
   - **Forged Ascon Tag:** 1 frame injected, **1 frame blocked (100%)** (`runtime_tag_rejected`, $0$ cross-domain leakage).
   - **Domain Spoofing:** 1 frame injected, **1 frame blocked (100%)** (`header_rejected`, $0$ cross-domain leakage).
   - **DoS / Bus Flood:** 300 frames injected (`counter > 100` rate-limit threshold); **100 benign frames admitted within quota and all 200+ excess flood frames (`202` observed rejections) blocked at line rate**, with **$0$ frames leaked** to Domains 2–4.
2. **Defensive Mechanism Latency Matrix [Panel (b)]:**
   - **Replay Protection (`BM_006` Monotonic Counter Gate):** Verified in **$2.00\,\mu\mathrm{s}$** (`2,000 ns`).
   - **Cryptographic Gate (`BM_007` Ascon-128 AEAD Tag Verification):** Verified in **$450.0\,\mu\mathrm{s}$** (`450,000 ns` for full 2,436B PAO; $< 15\,\mu\mathrm{s}$ for 64B frame).
   - **Domain Isolation (`BM_008` Discrete Invariant / Header ACL):** Verified in **$8.00\,\mu\mathrm{s}$** (`8,000 ns`).
   - **Rate Limiting (`BM_005` Token-Bucket Rate Limiter):** Evaluated in **$0.10\,\mu\mathrm{s}$** (`100 ns`).
   - **Tier 2 Anomaly Detection (`BM_010` Quantized INT8 ONNX Engine):** Full 14D sliding-window ($30 \times 14$) inference completed in **$820.0\,\mu\mathrm{s}$ ($0.82\,\mathrm{ms}$)** with **$99.4\%$** accuracy.

---

### Figure 5: Real-Time Schedulability Waterfall: Host Compute & Physical Bus Serialization
* **Files:** `visualizations/fig5_schedulability_waterfall_breakdown.pdf` & `.png` (`figure5_waterfall.pdf` & `.png`)
* **Layout:** Double-column width ($7.50\,\text{in} \times 3.90\,\text{in}$), stacked horizontal Gantt waterfall breakdown.
* **Grounding:** Component-wise breakdown of a 3-frame burst recovery handshake under ISO 26262 ASIL-D ($500\,\mathrm{kbps}$ arbitration / $2.0\,\mathrm{Mbps}$ data phase).

#### Detailed Academic Observations:
1. **Computational Workload (Host Nodes):**
   - ECU ML-DSA-44 Signing (`BM_002`): **$6.42\,\mathrm{ms}$**
   - Ascon Decryption & Tag Verification (`BM_003`): **$0.45\,\mathrm{ms}$**
   - Gateway ML-DSA-44 Signature Verification (`BM_001`): **$2.86\,\mathrm{ms}$**
   - Tier 2 ONNX INT8 Anomaly Inference (`BM_010`): **$0.82\,\mathrm{ms}$**
   - Key Delivery (`0x203`) & Diagnostic Verification (`0x300`): **$0.45\,\mathrm{ms}$**
   - **Total Host Computation:** **$11.00\,\mathrm{ms}$** ($34.8\%$ of total handshake time).
2. **CAN-FD Physical Bus Serialization ($500\,\mathrm{kbps} / 2.0\,\mathrm{Mbps}$):**
   - 41-Frame Initial PQC Burst ($41 \times 331.5\,\mu\mathrm{s}$): **$13.59\,\mathrm{ms}$**
   - Gateway Reception & Socket Buffer Idle Gap: **$5.00\,\mathrm{ms}$**
   - 64-bit Selective NACK Frame Transmission + Turnaround: **$1.04\,\mathrm{ms}$**
   - 3 Retransmitted CAN-FD Frames ($3 \times 331.5\,\mu\mathrm{s}$): **$0.99\,\mathrm{ms}$**
   - **Total Bus Serialization:** **$20.62\,\mathrm{ms}$** ($65.2\%$ of total handshake time).
3. **Schedulability & Functional Safety Margin:**
   - **Total End-to-End Latency ($T_{\mathrm{E2E}}$):** **$31.62\,\mathrm{ms}$** (closely matching the empirical 3-frame burst mean of **$31.91\,\mathrm{ms}$** across Runs 13–16).
   - **Admissible Safety Slack ($\Delta_{\mathrm{slack}}$):** **$+18.38\,\mathrm{ms}$ ($36.8\%$ safety margin)** below the $50.0\,\mathrm{ms}$ ASIL-D FTTI deadline.

---

## 4. Academic LaTeX Tables & Integration Guide

The generation pipeline outputs ready-to-paste LaTeX tables formatted according to the `IEEEtran` document class (with all `&` characters properly escaped as `\&` and Runs 21–25 explicitly disambiguated).

### Table 1: Complete 31-Run Empirical Fault Recovery Benchmark
* **File:** `visualizations/ieee_table_fault_recovery.tex`
* **Summary Table:**

| Run | Scenario Description | Injected Fault Model | Retx | Recovered | Wire Bytes | Goodput (%) | Latency (ms) | ISO 26262 State |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **01–04** | Clean Bus (Nominal) | `NOMINAL_CLEAN` | 0 | 0 | 2,624 | 92.8% | 19.55–21.54 | OPERATIONAL |
| **05–08** | Single Frame Drop (Seq 12) | `SINGLE_FRAME_DROP` | 1 | 1 | 2,704 | 90.1% | 28.40–31.77 | OPERATIONAL |
| **09–12** | Late-Sequence Drop (Seq 38) | `LATE_SEQUENCE_DROP` | 1 | 1 | 2,704 | 90.1% | 29.74–33.42 | OPERATIONAL |
| **13–16** | Relay Transient Spike | `BURST_FRAME_DROP` | 3 | 3 | 2,832 | 86.0% | 23.56–39.95 | OPERATIONAL |
| **17–20** | Alternator Commutation Burst | `BURST_FRAME_DROP` | 8 | 8 | 3,152 | 77.3% | 30.21–39.26 | OPERATIONAL |
| **21** | Persistent Drop (Retry Exhaustion) | `SINGLE_FRAME_DROP` | 3 | 0 | 2,864 | 0.0% | 93.99 | SAFE_FALLBACK |
| **22** | Lost NACK Control Drop | `NACK_CONTROL_FRAME_DROP` | 0 | 0 | 2,672 | 0.0% | 90.71 | SAFE_FALLBACK |
| **23** | Corrupt Payload (Tag Mismatch) | `PAYLOAD_BIT_FLIP` | 0 | 0 | 2,624 | 0.0% | 30.08 | SAFE_FALLBACK |
| **24** | Malformed Header (Out-of-Range) | `PAYLOAD_BIT_FLIP` | 3 | 0 | 2,864 | 0.0% | 60.38 | SAFE_FALLBACK |
| **25** | Transient Header Probe | `PAYLOAD_BIT_FLIP` | 1 | 1 | 2,704 | 90.1% | 36.72 | OPERATIONAL |
| **26–30** | Monte Carlo Bernoulli Sweep | `BERNOULLI_RANDOM` | 13 | 13 | 3,472 | 70.2% | 16.67–46.10 | OPERATIONAL |
| **31** | Final Clean Bus Validation | `NOMINAL_CLEAN` | 0 | 0 | 2,624 | 92.8% | 28.89 | OPERATIONAL |

### Table 2: Multi-Tier Adversarial Attack Mitigation
* **File:** `visualizations/ieee_table_attack_mitigation.tex`

| Attack Vector | Adversarial Frames | Observed Count | Mitigation Policy | Defense Rate |
| :--- | :---: | :---: | :--- | :---: |
| **Replay Injection** | 1 | 1 | Category 3.1 Monotonic Nonce Tracker | 100.0% |
| **Forged Tag** | 1 | 1 | Ascon-128 AEAD Authentication Gate | 100.0% |
| **Domain Spoofing** | 1 | 1 | Ingress Routing Interface ACL Table | 100.0% |
| **DoS / Bus Flood** | 300 | 202 | Gateway Token-Bucket Rate Limiter | 100.0% |

---

## 5. Mathematical Formulations & Analytical Models

### 5.1 End-to-End Real-Time Schedulability Bound
The total end-to-end handshake latency $T_{\mathrm{E2E}}$ must satisfy:

$$T_{\mathrm{E2E}} = T_{\mathrm{sign}} + T_{\mathrm{burst}} + T_{\mathrm{gap}} + T_{\mathrm{NACK}} + T_{\mathrm{retx}} + T_{\mathrm{decrypt}} + T_{\mathrm{verify}} + T_{\mathrm{IDS}} + T_{\mathrm{key\_dist}} \le T_{\mathrm{FTTI}}$$

Where:
* $T_{\mathrm{FTTI}} = 50.0\,\mathrm{ms}$ (Mandatory ISO 26262 ASIL-D Fault Tolerant Time Interval).
* Under nominal clean conditions: $T_{\mathrm{E2E}} = 22.48 \pm 3.65\,\mathrm{ms}$ (min $19.55\,\mathrm{ms}$).
* Under 3-frame burst recovery: $T_{\mathrm{E2E}} = 31.91 \pm 7.03\,\mathrm{ms}$ (analytical waterfall $31.62\,\mathrm{ms}$).
* Under 8-frame alternator burst recovery: $T_{\mathrm{E2E}} = 33.28 \pm 4.07\,\mathrm{ms}$.
* Available Safety Slack: $\Delta_{\mathrm{slack}} = T_{\mathrm{FTTI}} - T_{\mathrm{E2E}} \ge 10.05\,\mathrm{ms}$ ($20.1\%$ headroom across canonical runs; $\ge 3.90\,\mathrm{ms}$ across Monte Carlo sweeps).

### 5.2 Physical CAN-FD Frame Transmission Latency (ISO 11898-1:2015)
For a 64-byte CAN-FD frame (`DLC = 15`, `BRS = 1`) operating with an arbitration bit rate $R_{\mathrm{nom}} = 500\,\mathrm{kbps}$ ($\tau_{\mathrm{nom}} = 2.0\,\mu\mathrm{s}$) and a data bit rate $R_{\mathrm{data}} = 2.0\,\mathrm{Mbps}$ ($\tau_{\mathrm{data}} = 0.5\,\mu\mathrm{s}$):

$$T_{\mathrm{frame}} = N_{\mathrm{nom}} \cdot \tau_{\mathrm{nom}} + N_{\mathrm{data}} \cdot \tau_{\mathrm{data}}$$

* Nominal arbitration & framing bits ($N_{\mathrm{nom}} = 29\,\text{bits}$): $29 \times 2.0\,\mu\mathrm{s} = 58.0\,\mu\mathrm{s}$
* Data phase bits ($N_{\mathrm{data}} = 6 + 8 \times 64 + 29 = 547\,\text{bits}$, including 21-bit CRC + stuff bits): $547 \times 0.5\,\mu\mathrm{s} = 273.5\,\mu\mathrm{s}$
* Nominal 64B frame wire duration: $T_{\mathrm{frame,nom}} = 58.0 + 273.5 = \mathbf{331.5\,\mu\mathrm{s}}$ (worst-case bit-stuffed duration per Bordoloi & Samii: $400.5\,\mu\mathrm{s}$).
* 41-frame attestation burst wire serialization: $41 \times 331.5\,\mu\mathrm{s} = \mathbf{13.59\,\mathrm{ms}}$ ($16.42\,\mathrm{ms}$ worst-case).

### 5.3 Wire Goodput Efficiency ($\eta_{\mathrm{wire}}$)
The ratio of usable post-quantum cryptographic payload $S_{\mathrm{payload}} = 2,436\,\text{B}$ to total serialized bytes on the physical medium $S_{\mathrm{total\_wire}}$:

$$\eta_{\mathrm{wire}} = \frac{S_{\mathrm{payload}}}{S_{\mathrm{total\_wire}}} \times 100\% = \frac{2436}{2624 + (N_{\mathrm{retx}} \times 64) + (N_{\mathrm{NACK}} \times 16)} \times 100\%$$

Under 64-bit selective NACK, wire goodput remains bounded between **$70.16\%$ ($70.2\%$) and $92.84\%$ ($92.8\%$)**, preventing bus saturation.

---

## 6. Verification & Audit Trail Summary

1. **Deterministic Functional Safety:** All 27 recoverable handshakes (`Runs 01–20, 25–31`) completed well below the $50.0\,\mathrm{ms}$ FTTI limit (`ftti_violation_flag = False`, `safety_state_achieved = OPERATIONAL`).
2. **Safe Fallback Isolation:** In the 4 unrecoverable fault scenarios (`Runs 21–24`), the gateway deterministically severed the session and transitioned into `SAFE_FALLBACK` quarantine (with `ftti_violation_flag = True` on timeout/exhaustion Runs 21, 22, and 24 where $T_{\mathrm{E2E}} > 50\,\mathrm{ms}$, and `ftti_violation_flag = False` on immediate cryptographic tag rejection Run 23 at $30.08\,\mathrm{ms}$).
3. **Adversarial Resilience:** 100% of injected adversarial vectors (replays, forged tags, domain spoofing, and high-frequency flood) were detected and quarantined at line rate with zero cross-domain leakage.
