# Phase 2 Deliverable: CAN-FD Cryptographic Fault Recovery Simulation Suite

This suite is the **official Phase 2 algorithmic proof-of-concept (PoC)** for the Post-Quantum Cryptography (PQC) and 3-Tier Intrusion Detection System (IDS) framework over CAN-FD.

---

## 1. Architectural Scope & Purpose (Phase 2 Deliverable)

- **Pure Python Algorithmic Proof-of-Concept:** Demonstrates the mathematical correctness and state-machine transitions of our 3-tier automotive security framework and selective bitmap NACK transport protocol (60/4 block segmentation for 2,420-byte ML-DSA-44 signatures and 1,024-byte Kyber-768 capsules).
- **Cross-Platform Native Execution:** Implements dual-stack UDP socketpairs on `127.0.0.1` allowing developers and auditors to verify protocol logic natively on Windows, macOS, and Linux without requiring root privileges, virtual machines, or Linux kernel CAN drivers.
- **Standardized Data Contracts:** Emits strictly validated 40-column empirical records (`fault_recovery_runs.csv`) and cryptographic hash audits (`manifest.json`) across 5 automotive physical fault profiles.

### Relationship to Phase 3 & DockerLab
- **Phase 2 Simulation (`run_simulation.py`):** Algorithmic verification, protocol state logic assertion, discrete fault handling, and cryptographic KAT validation.
- **Phase 3 DockerLab (`DockerLab/`):** Barebones containerized ECU/CISG software simulation running over Linux SocketCAN (`vxcan`) to calculate empirical OS scheduling jitter, wire latencies, and microarchitectural overhead (`perf stat`) for direct comparison against the Phase 3 mathematical worst-case response time (WCRT / Davis-Burns RTA).

---

## 2. Key Upgrades & Bug Fixes Applied

1. **Native Cross-Platform Execution:** Replaced Linux-only `AF_UNIX` datagram socketpairs with dual-stack localhost UDP socketpairs, allowing native execution on Windows, macOS, and Linux.
2. **True Cold-Boot Attestation Measurement:** Included ML-DSA-44 signing and Ascon-AEAD128 wrapping latency in `end_to_end_latency_us` rather than truncating timing to the socket flush.
3. **Physical CAN-FD Bus Timing:** Replaced the arbitrary 5.0 ms OS sleep with physical CAN-FD frame transmission and timeout calculation (~840 µs).
4. **Complete Physical CAN-FD Data Contracts:** Populated all 6 previously omitted columns (`bitrate_regime`, `nominal_baud`, `data_baud`, `total_frames_on_wire`, `total_wire_bytes`, `goodput_efficiency_pct`), achieving **100% strict schema validation with 0 errors**.
5. **Non-Negative Recovery Overhead:** Eliminated the inverted negative overhead (`-3703 µs`) in early-abort scenarios by using phase-accurate baselines and enforcing `recovery_overhead_latency_us >= 0.0`.
6. **Zero-Bitmap Empty NACK Resilience:** Gracefully completes transmission immediately upon receiving an empty bitmap NACK rather than stalling.
7. **Elimination of Redundant Socket Timeouts:** Removed the extra 4th socket wait on retry exhaustion.
8. **Dynamic Cryptographic Provenance:** Generated cryptographic hashes dynamically in `manifest.json` to ensure 100% data integrity auditing.

---

## 3. Running the Repaired Simulation

From the repository root or PowerShell on Windows:

```powershell
python "Anti Gravity/Phase 2/Simulation/run_simulation.py" --output "Anti Gravity/Phase 2/Simulation/results/verified_demo" --trials 3 --monte-carlo 20
```

## Running Strict Validation & Audit

```powershell
python "Anti Gravity/Phase 2/Simulation/validate_results.py" "Anti Gravity/Phase 2/Simulation/results/verified_demo"
```

## Running Automated Integration Tests

```powershell
python -m unittest "Anti Gravity/Phase 2/Simulation/test_integration.py"
```

---

## 4. Running the Unified End-to-End System PoC

To run the complete, unified end-to-end Python proof-of-concept integrating both **Phase A (Post-Quantum ML-DSA-44 Cold-Boot Attestation & 60/4 NACK Recovery)** and **Phase B (Operational Telemetry Streaming & 3-Tier IDS Gateway Defense)** against all Red Team attack vectors:

```powershell
# Canonical 30s benchmark run (3,000 frames, max batch throughput):
python "Anti Gravity/Phase 2/Simulation/run_full_system_poc.py"

# Fast 10s smoke test (1,000 frames):
python "Anti Gravity/Phase 2/Simulation/run_full_system_poc.py" --frames 1000

# Physical 100.0 Hz bus clock pacing (10 ms frame sleep demonstrating 3.4% Gateway load):
python "Anti Gravity/Phase 2/Simulation/run_full_system_poc.py" --realtime
```

- **Phase A (Category 2 CAN-FD Cold-Boot Attestation):**
  - **Hardware SRAM-PUF Simulation:** On-chip Fuzzy Extractor error-correction reconstruction (`PUFEmulator`) via PBKDF2-HMAC-SHA256 (100,000 iterations, ~79 ms), deriving ephemeral bootstrap key $K_{\text{boot}, i}$ without non-volatile key storage.
  - **Post-Quantum Attestation:** Real NIST FIPS 204 ML-DSA-44 signing (2,420 bytes, ~26 ms) and NIST SP 800-232 Ascon-128 AEAD 60/4 fragmentation into 41 frames (~9 ms).
  - **Resilient Transport & NACK:** Physical burst fault injection (frames 14, 15, 16 dropped), 64-bit Selective Bitmap NACK recovery, ML-DSA-44 cryptographic verification (~22 ms), and operational session key derivation ($K_{\text{session}}$).
- **Phase B (Category 1 CAN-FD Operational Telemetry):** Streaming all 3,000 frames of the canonical Golden Telemetry Drive Cycle at 100 Hz encrypted with Ascon-128 under $K_{\text{session}}$:
  - **Tier 1 (Deterministic Wire Firewall, <15 µs):** Rejection of tag tampering (AT-01), monotonic counter replay (AT-04), and 20 kHz line-rate bus flood (AT-06).
  - **Tier 1.5 (Discrete Physical Invariant Gate, <50 µs):** Sub-line-rate blocking of reverse gear at highway speed (AT-12), all wheels stalled at velocity (AT-14), and contradictory pedal depression (AT-15).
  - **Tier 2 (Continuous Kinematic Autoencoder, ~270 µs):** Real-time ONNX INT8 quantized LSTM inference detecting subtle kinematic manifold divergences across all 8 attack episodes with **0.00% False Positive Rate (FPR)** on steady-state clean driving.

---

## 5. Launching the Interactive Presentation Dashboard

For live committee presentations and capstone demonstrations, open the self-contained Mission Control Dashboard:

```powershell
# Open in default browser (Chrome / Edge / Firefox):
Start-Process "Anti Gravity\Phase 2\Simulation\poc_interactive_dashboard.html"
```

### Dashboard Features for Presentation:
- **Dual "Run All" Master Action Deck:**
  * **`🎓 Run All (Slowed-Down Mode)` (Cyan):** Runs Phase A with ~3-second explanatory pauses per stage, then auto-cascades into Phase B slow-mo streaming (0.25x / 2.5 FPS) with `Auto-Freeze on Attack` active for relaxed oral defense explanation.
  * **`⚡ Run All (Real-Time 100 Hz Mode)` (Emerald):** Executes Phase A at benchmark latency (~180 ms), then auto-cascades into Phase B at true 100.0 Hz physical bus timing (10 ms / frame) demonstrating line-rate throughput and 3.4% Gateway CPU utilization.
- **Phase A Full Graphical Animation Canvas:** Visual bus wire transit animation with active packet flow, 41-frame segmentation matrix (#00 to #40), physical noise burst drop injection (frames 14, 15, 16), and 64-bit selective bitmap NACK recovery (`0x0001c000`).
- **Phase B Stream Controller (inside 3-Tier IDS Section):** Relocated directly into the 3-Tier IDS section with Play/Pause, Step (+10ms), Reset, and instant Attack Episode Jumper.
- **Dynamic Z-Score Oscilloscope with Custom Speed Controls:** Presets (0.1x Slow-Mo, 0.25x, 0.5x, 1x, 3x, Max), live 1–120 FPS slider, and `Auto-Freeze on Attack Detection` modal callout.


