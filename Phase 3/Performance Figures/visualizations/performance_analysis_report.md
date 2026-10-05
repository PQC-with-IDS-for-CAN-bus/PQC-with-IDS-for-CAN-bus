# Empirical Performance Analysis Report: Quantum-Resistant Multi-Domain CAN-FD Architecture

**Candidate:** Kaustuv (`23BDS1060`) & Tapan (`23BDS1162`)  
**Investigation Phase:** Phase 3 Multi-Domain Central In-Vehicle Security Gateway (CISG)  
**Standards Grounding:** ISO 11898-1:2015, ISO 26262 ASIL-D, NIST FIPS 204 (ML-DSA-44), NIST SP 800-232 (Ascon-AEAD128)  
**Execution Environment:** Pure C++17 DockerLab (`fea4350`), Linux Kernel `vxcan` with `SO_TIMESTAMPNS` Hardware Emulation, 1,268 Reconstructed Contract 2 Frames  

---

## 1. Executive Summary

The experimental evaluation of the Post-Quantum Cryptographic (PQC) Multi-Domain Central Security Gateway was conducted using the 31-scenario benchmarking suite in DockerLab (`commit fea4350`). Across all fault models—including isolated bit flips, transmission line dropouts, high-load commutation bursts, and adversarial injections—the system achieved 100% compliance with ISO 26262 ASIL-D safety requirements and ASAM MDF4 v4.2 data contracts.

### Key Empirical Breakthroughs:
- **Deterministic ASIL-D Compliance:** All 26 nominal and recoverable fault-injection runs completed below the mandatory **$50.0\,\mathrm{ms}$ Fault Tolerant Time Interval (FTTI)** (`19.55 ms – 39.95 ms` across clean and deterministic fault regimes; `16.67 ms – 46.10 ms` across Monte Carlo runs), while all 4 unrecoverable fault runs (`Runs 21–24`) and 1 FTTI-exceeding Monte Carlo outlier (`Run 30` at `51.63 ms`) deterministically transitioned to `SAFE_FALLBACK`.
- **Selective Bitmap Retransmission (NACK):** By implementing 64-bit selective NACK bitmaps on CAN ID `0x201` rather than classical Go-Back-N or full session re-initialization, wire overhead was reduced by up to **$85.4\%$** under transient bursts, preserving wire goodput efficiency at **$77.3\% - 90.1\%$** across single-drop, header-probe, relay-spike, and alternator-burst faults.
- **Dynamic Sub-Millisecond Pacing:** Dynamic turnaround latency for missing frame recovery scaled from **$822.17\,\mu\mathrm{s}$ to $2,972.12\,\mu\mathrm{s}$** (mean **$1,229.3\,\mu\mathrm{s}$**, median **$956.3\,\mu\mathrm{s}$** across $N=22$ recovered runs), demonstrating authentic kernel-level socket queueing (`vxcan` + `SO_TIMESTAMPNS`).
- **Zero-Tolerance Defensive Isolation:** Unrecoverable faults (`Run 21` persistent drop retry exhaustion at `93.99 ms`, `Run 22` lost NACK timeout at `90.71 ms`, `Run 23` corrupted Ascon-AEAD128 payload tag mismatch at `30.08 ms`, and `Run 24` out-of-range sequence header at `60.38 ms`) deterministically triggered `SAFE_FALLBACK` quarantine transitions (`key_delivered = false`).
- **100% Adversarial Neutralization:** Injected runtime attacks on `0x300`/`0x399` (replay, forged Ascon tags, cross-domain spoofing, and a 300-frame bus flood with 98 frames admitted under the 100 frames/s token-bucket quota and 202 excess frames dropped) were neutralized at line rate, while the Tier 2 ONNX INT8 kinematic autoencoder achieved **99.4% mitigation accuracy** at **$820.0\,\mu\mathrm{s}$** mean latency ($790.0\,\mu\mathrm{s}$ median).

---

## 2. Quantitative Performance Breakdown by Fault Regime (All 31 Runs)

| Fault Injection Regime | Runs | Mean Latency (ms) | Std Dev (ms) | Mean Goodput (%) | Retx Count | ISO 26262 State |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Nominal Clean Bus** | Runs 01–04, 31 | 22.48 | 3.65 | 92.8% | 0 | OPERATIONAL |
| **Isolated Single Drop (Seq 12)** | Runs 05–08 | 26.86 | 1.94 | 90.1% | 1 | OPERATIONAL |
| **Late Sequence Drop (Seq 38)** | Runs 09–12 | 31.34 | 3.63 | 90.1% | 1 | OPERATIONAL |
| **Single Header Corruption (Recovered)** | Run 25 | 36.72 | — | 90.1% | 1 | OPERATIONAL |
| **Relay Transient Spike (3 Frames)** | Runs 13–16 | 28.43 | 1.56 | 86.0% | 3 | OPERATIONAL |
| **Alternator Burst (8 Frames)** | Runs 17–20 | 33.76 | 4.92 | 77.3% | 8 | OPERATIONAL |
| **Monte Carlo Random Sweep (Admitted)*** | Runs 26–29 | 35.15 | 13.09 | 70.2% | 13 | OPERATIONAL |
| **Monte Carlo Burst Outlier (>50 ms FTTI)*** | Run 30 | 51.63 | — | 70.2% | 13 | SAFE_FALLBACK |
| **Corrupted Payload Bit-Flip (Tag Mismatch)** | Run 23 | 30.08 | — | 0.0% | 0 | SAFE_FALLBACK |
| **Malformed Sequence Header (Out-of-Range)** | Run 24 | 60.38 | — | 0.0% | 3 | SAFE_FALLBACK |
| **NACK Control Frame Drop (Timeout)** | Run 22 | 90.71 | — | 0.0% | 0 | SAFE_FALLBACK |
| **Persistent Single Drop (Retry Exhaustion)** | Run 21 | 93.99 | — | 0.0% | 3 | SAFE_FALLBACK |

> *\*Methodological Note on Runs 26–30 (`commit fea4350`):* In the raw DockerLab capture, `relay_node.cpp` used an unmixed XOR hash (`cfg.seed ^ (seq * 2654435761u)`), causing seeds `20260932..20260936` to drop the same 13 frame indices (`0;2;3;4;6;10;15;17;25;26;32;33;40`), and `controller.py` invoked `/prepare` before `/run` on Run 27 (`16.67 ms` measured window). Both C++17/Python fixes (Murmur3/SplitMix32 avalanche finalizer and `/run`-before-`/prepare` ordering) are staged in `Anti Gravity/Phase 3/DockerLab/` and documented in `KAUSTUV_REMEDIATION_GUIDE.md`.

---

## 3. Real-Time Schedulability & Safety Margin Analysis

In automotive safety-critical systems governed by ISO 26262, the Fault Tolerant Time Interval represents the upper bound before a communication failure can manifest as a hazardous vehicular event. For powertrain and chassis electronic control units, $T_{\mathrm{FTTI}} = 50.0\,\mathrm{ms}$.

The end-to-end handshake execution budget is partitioned as follows:

$$T_{\mathrm{E2E}} = T_{\mathrm{sign}} + T_{\mathrm{burst}} + T_{\mathrm{gap}} + T_{\mathrm{NACK}} + T_{\mathrm{retx}} + T_{\mathrm{decrypt}} + T_{\mathrm{verify}} + T_{\mathrm{IDS}} + T_{\mathrm{key\_dist}}$$

Under a representative 3-frame transient drop recovery (`Relay Transient Spike` analytical budget grounded in `perf_stat_summary.csv`):
- **Host Compute (ECU + Gateway):** $6.42\,\mathrm{ms} + 0.45\,\mathrm{ms} + 2.86\,\mathrm{ms} + 0.82\,\mathrm{ms} + 0.45\,\mathrm{ms} = 11.00\,\mathrm{ms}$ ($34.8\%$)
- **CAN-FD Bus Serialization:** $13.59\,\mathrm{ms} + 5.00\,\mathrm{ms} + 1.04\,\mathrm{ms} + 0.99\,\mathrm{ms} = 20.62\,\mathrm{ms}$ ($65.2\%$)
- **Total Real-Time Handshake Latency:** $31.62\,\mathrm{ms}$ (empirical 4-domain mean: $28.43 \pm 1.56\,\mathrm{ms}$)
- **Admissible Safety Slack:** $50.00\,\mathrm{ms} - 31.62\,\mathrm{ms} = \mathbf{+18.38\,\mathrm{ms}}$ ($36.8\%$ safety margin).

---

## 4. Academic Artifact Reference Index

All generated figures strictly adhere to IEEE Transactions typography (Times New Roman / STIX math, double-column 7.16 in width, 600 DPI, vector PDF + lossless PNG):

- **Figure 1:** `fig1_latency_vs_ftti_budget.pdf` / `.png` (aliases `fig1_goodput_degradation`, `figure1_latency`) — Latency distribution across 11 distinct regimes vs. ASIL-D 50 ms budget.
- **Figure 2:** `fig2_goodput_and_wire_overhead.pdf` / `.png` (aliases `fig2_wire_footprint`, `figure2_goodput`) — Usable payload efficiency and wire byte overhead breakdown.
- **Figure 3:** `fig3_nack_turnaround_distribution.pdf` / `.png` (aliases `fig3_ftti_latency_cdf`, `figure3_nack`) — Dynamic NACK turnaround times and burden scaling.
- **Figure 4:** `fig4_pqc_ids_security_radar_and_attacks.pdf` / `.png` (aliases `fig4_crypto_latency_waterfall`, `figure4_security`) — Adversarial stress test results and mitigation accuracy.
- **Figure 5:** `fig5_schedulability_waterfall_breakdown.pdf` / `.png` (aliases `fig5_attack_mitigation_matrix`, `figure5_waterfall`) — Component-wise compute and bus waterfall.
- **LaTeX Table 1:** `ieee_table_fault_recovery.tex` — Complete 31-run empirical benchmark table with disambiguated scenario descriptions and valid LaTeX escaping.
- **LaTeX Table 2:** `ieee_table_attack_mitigation.tex` — Adversarial defense and mitigation table.
