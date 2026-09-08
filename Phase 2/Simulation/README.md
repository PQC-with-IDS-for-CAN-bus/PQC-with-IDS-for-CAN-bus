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
