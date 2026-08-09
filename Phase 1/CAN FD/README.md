# CAN-FD Frame Schematics & Gateway Feature Extraction

Secure Segmented CAN-FD Architecture with Post-Quantum Attestation & Gateway-Hosted ML IDS (Phase 1).

## Overview

This repository contains the reference Python implementation, unit test suite, and architectural specifications for:
1. **Protected Runtime Telemetry Frame (64 Bytes)**: 8-byte unencrypted header (AD), 40-byte Ascon-AEAD128 encrypted telemetry payload, and 16-byte authentication tag.
2. **60/4 Indexed Block-Transfer Attestation Frame (64 Bytes)**: 4-byte transport header and 60-byte payload data per fragment for ML-DSA key/signature transfer across 41 frames.
3. **Gateway IDS Feature Extraction Pipeline**: Converts incoming decrypted CAN-FD frames into 12-dimensional feature vectors $\mathbf{X}_t$ for ONNX LSTM anomaly detection.

## Directory Structure

```text
.
├── canfd_schema.py                # Reference implementation of frame packing/unpacking & feature extraction
├── test_canfd_schema.py           # Unit tests (unittest framework)
├── canfd_bytewise_schematics.md   # Byte-level frame layout specifications & signal mappings
├── scratch_canfd_arch.txt         # Physical CAN-FD topology & domain isolation rules
├── scratch_trust_boundary.txt     # Security architecture brief & adversary model
└── .gitignore                     # Git ignore file for Python & OS artifacts
```

## Running the Code & Tests

### Self-Test Run
Execute `canfd_schema.py` directly:
```bash
python canfd_schema.py
```

### Unit Tests
Run the unit test suite:
```bash
python -m unittest test_canfd_schema.py
```

## Feature Vector Schema $\mathbf{X}_t$ (12D)

| Index | Feature | Description |
| :---: | :--- | :--- |
| $f_1$ | `Delta_Time` | Inter-arrival time between consecutive frames (ms) |
| $f_2$ | `Counter_Gap` | Monotonic counter gap ($C_k - C_{k-1} - 1$) |
| $f_3$ | `Sender_ECU_ID` | ECU ID normalized ($0.0 - 1.0$) |
| $f_4$ | `Domain_ID` | Origin domain (1: Powertrain, 2: Chassis, 3: Body, 4: Infotainment) |
| $f_5$ | `Msg_Type` | Message type (1: Telemetry, 2: Challenge, 3: NACK, 4: Key) |
| $f_6$ | `Auth_Tag_Status` | `0.0` = Valid Tag, `1.0` = Invalid/Failed Tag |
| $f_7$ | `Vehicle_Speed` | Decrypted speed (km/h) |
| $f_8$ | `Engine_RPM` | Decrypted RPM |
| $f_9$ | `Steering_Angle` | Decrypted steering angle (deg) |
| $f_{10}$ | `Brake_Pressure` | Decrypted brake pressure (kPa) |
| $f_{11}$ | `Long_Accel` | Decrypted longitudinal acceleration ($m/s^2$) |
| $f_{12}$ | `DTC_Error_Count` | Active diagnostic error bit count |
