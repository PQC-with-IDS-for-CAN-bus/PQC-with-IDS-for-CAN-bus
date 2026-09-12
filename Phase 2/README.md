# Phase 2: Gateway-Side Federated Learning IDS & 3-Tier CISG Security Suite

This directory contains the **official Phase 2 deliverables** for the B.Tech Capstone Project: *Secure Internet of Vehicles (IoV) via Post-Quantum Cryptography and Multi-Tier Intrusion Detection Systems*.

---

## 1. Architectural Scope & Directory Structure

Phase 2 establishes the algorithmic proof-of-concept for the **Central In-Vehicle Security Gateway (CISG)** 3-tier defense-in-depth framework and the cross-silo Federated Learning anomaly detection model:

```
Phase 2/
├── IDS/
│   ├── Baseline LSTM/          # PyTorch Dual-Bias LSTM Autoencoder (24,654 params, W=30, D=14)
│   ├── FL IDS/                 # 10-Round Flower (flwr) FedAvg simulation & cross-silo generalization matrix
│   ├── ONNX/                   # FP32 Golden Reference & Dynamic INT8 quantized ONNX models (<108 KB)
│   └── Phase_2_IDS_Project_Report.md  # Comprehensive Phase 2 engineering & theoretical report
├── Red Team/
│   ├── Code/
│   │   ├── module_1_wire_attacks/        # Wire corruption, replay, and 20 kHz flooding (AT-01 to AT-06)
│   │   ├── module_2_protocol_fuzzer/     # 60/4 block segmentation & NACK abuse (AT-07 to AT-11)
│   │   ├── module_3_invariant_injector/  # Discrete state invariant checks (AT-12 to AT-16)
│   │   ├── module_4_masquerade_streamer/ # ORNL ROAD masquerade replays (AT-17 to AT-20)
│   │   ├── module_5_novel_attacks/       # Novel vectors: boiling frog, 4-wheel symmetry, covert DTC (AT-21 to AT-28)
│   │   └── run_red_team_suite.py         # Master test harness executing all 28 attack scenarios
│   └── red_team_attack_benchmark.csv     # Complete 28-scenario evaluation results
├── Simulation/
│   ├── run_full_system_poc.py  # Unified end-to-end Python PoC (Cold-boot PQC attestation + 3-tier streaming IDS)
│   ├── run_simulation.py       # Selective NACK cryptographic recovery simulation engine
│   ├── validate_results.py     # Formal 40-column contract & schema validator
│   ├── test_integration.py     # Automated state-machine and protocol integration tests
│   └── results/demo/           # Authoritative, 100% contract-compliant 40-column benchmark dataset
└── fixtures/                   # Golden reference CAN telemetry fixtures (1,000 frames)
```

---

## 2. Quick Start: Executing Phase 2 Deliverables

### A. Run the Unified End-to-End System PoC
Executes cold-boot ML-DSA-44 post-quantum attestation, 60/4 block transfer, and live 3-tier gateway filtering on 3,000 continuous CAN telemetry frames:
```bash
python 'Phase 2/Simulation/run_full_system_poc.py'
```

### B. Execute the 28-Scenario Red Team Threat Emulation Suite
Runs all 28 adversarial attack scenarios across Tier 1, Tier 1.5, and Tier 2 defenses:
```bash
python 'Phase 2/Red Team/Code/run_red_team_suite.py'
```

### C. Validate Simulation Results Against Schema Contracts
Validates the authoritative 40-column empirical dataset for strict ISO 26262 and ASIL-D timing compliance:
```bash
python 'Phase 2/Simulation/validate_results.py' 'Phase 2/Simulation/results/demo'
```

### D. Run Automated Protocol Integration Tests
```bash
python -m unittest 'Phase 2/Simulation/test_integration.py'
```

---

## 3. Relationship to Phase 3 & DockerLab

- **Phase 2 (This Directory):** Focuses on algorithmic correctness, mathematical formulation (14D Leave-One-Out kinematics), ONNX edge model validation, Federated Learning convergence, and software threat emulation.
- **Phase 3 (`Phase 3/`):** Focuses on integrated system evaluation, Davis-Burns Worst-Case Response Time (WCRT) schedulability analysis, streaming FIFO buffer quarantine benchmarking, and physical/containerized evaluation.
- **Containerized DockerLab:** The multi-container ECU/Gateway virtual CAN simulation environment (`DockerLab/`) is part of **Phase 3**. For live multi-container network tests, dashboards, and SocketCAN experiments, please refer to [`Phase 3/DockerLab/README.md`](../Phase%203/DockerLab/README.md).
