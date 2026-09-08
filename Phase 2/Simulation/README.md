# Phase 2 CAN-FD Fault Recovery Simulation Suite (Repaired & Validated)

This suite is the **cross-platform, fully audited and repaired** CAN-FD Post-Quantum Cryptography (PQC) fault recovery simulation.

## Key Upgrades & Bug Fixes Applied

1. **Native Cross-Platform Execution:** Replaced Linux-only `AF_UNIX` datagram socketpairs with dual-stack localhost UDP socketpairs, allowing native execution on Windows, macOS, and Linux without virtual machines or WSL.
2. **True Cold-Boot Attestation Measurement:** Included ML-DSA-44 signing and Ascon-AEAD128 wrapping latency in `end_to_end_latency_us` rather than truncating timing to the socket flush.
3. **Physical CAN-FD Bus Timing:** Replaced the arbitrary 5.0 ms OS sleep with physical CAN-FD frame transmission and timeout calculation (~840 µs).
4. **Complete Physical CAN-FD Data Contracts:** Populated all 6 previously omitted columns (`bitrate_regime`, `nominal_baud`, `data_baud`, `total_frames_on_wire`, `total_wire_bytes`, `goodput_efficiency_pct`), achieving **100% strict schema validation with 0 errors**.
5. **Non-Negative Recovery Overhead:** Eliminated the inverted negative overhead (`-3703 µs`) in early-abort scenarios by using phase-accurate baselines and enforcing `recovery_overhead_latency_us >= 0.0`.
6. **Zero-Bitmap Empty NACK Resilience:** Gracefully completes transmission immediately upon receiving an empty bitmap NACK rather than stalling.
7. **Elimination of Redundant Socket Timeouts:** Removed the extra 4th socket wait on retry exhaustion.
8. **Dynamic Cryptographic Provenance:** Generated cryptographic hashes dynamically in `manifest.json` to ensure 100% data integrity auditing.

## Running the Repaired Simulation

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
