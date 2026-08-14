# Phase 1: Cryptographic Engine & CAN-FD Protocol Layer

This directory contains the production-ready reference implementation of the cryptographic primitives, CAN-FD byte-wise frame schemas, and the end-to-end boot handshake state machine for the **Post-Quantum In-Vehicle CAN-FD Security Architecture**.

---

## 📂 Directory Structure

```text
Crypto/Code/
├── ascon_official.py          # Official reference NIST SP 800-232 Ascon-AEAD128 implementation
├── crypto_engine.py           # Core cryptographic primitives (PUF, HKDF, ML-DSA-44, Ascon, RNG)
├── canfd_schema.py            # CAN-FD frame encoders/decoders & fragmentation managers
├── handshake_simulation.py    # Master end-to-end boot handshake simulation (Steps 1–9)
├── verify_phase1_smoke.py     # Automated technical checklist & smoke-test verifier
└── README.md                  # Module documentation (this file)
```

---

## 🔐 Architecture Overview

The system establishes a **Logical Pure-Star Security Architecture** over 4 physically segmented CAN-FD domains (Powertrain, Chassis, Body & Comfort, Infotainment) managed by a central **Central Intelligent Security Gateway (CISG)**.

```text
                  Phase 1 Cryptographic Stack
                               │
            ┌──────────────────┴──────────────────┐
            │                                     │
    crypto_engine.py                       canfd_schema.py
  (Mathematical Layer)                    (Protocol Layer)
            │                                     │
   ├── PUFEmulator (SRAM-PUF)            ├── ChallengeFrame (Cat 3.1)
   ├── KeyDerivation (HKDF-SHA256)       ├── AttestationDeliveryManager (Cat 2)
   ├── PostQuantumAttestation (ML-DSA-44)├── KeyDeliveryFrame (Cat 3.3)
   ├── AsconAEAD128Engine (NIST SP 800)  ├── ProtectedRuntimeFrame (Cat 1)
   └── SessionManager (CSPRNG)           └── GatewayIDSExtractor (12D Vector)
            │                                     │
            └──────────────────┬──────────────────┘
                               │
                    handshake_simulation.py
                   (End-to-End Boot Pipeline)
```

---

## 🛠️ Module Inventory & Responsibilities

### 1. `crypto_engine.py` (Core Primitives)
- **`PUFEmulator`**: Simulates deterministic SRAM-PUF response generation per ECU and outputs 32-byte SHA-256 Input Keying Material (`IKM`).
- **`KeyDerivation`**: Implements HKDF-SHA256 (RFC 5869) to derive per-boot $K_{boot\_i}$ bound to session context (`"CAPSTONE-V1/BOOTSTRAP-KEY" || ECU_ID || SESSION_ID`).
- **`PostQuantumAttestation`**: Pure-Python FIPS 204 ML-DSA-44 key generation (1312B public key / 2560B secret key) and transcript signing (2420B signature).
- **`AsconAEAD128Engine`**: Standard NIST SP 800-232 Ascon-AEAD128 authenticated encryption with 16-byte keys, 16-byte nonces, and 16-byte tags. Validated against official NIST Known Answer Tests (KAT #1 & #67).
- **`SessionManager`**: CSPRNG generation of 16-byte challenges, operational session keys ($K_i$), and nonces.

### 2. `canfd_schema.py` (CAN-FD Frame Layer)
- **`ChallengeFrame` (Cat 3.1)**: 64-byte plaintext challenge frame (`ver_type = 0x12`, 16B random challenge, 4B session ID).
- **`AttestationDeliveryManager` (Cat 2)**: Encrypts the 2420B ML-DSA-44 signature into a **2436B Protected Attestation Object (PAO)** using $K_{boot\_i}$ and fragments it into **41 $\times$ 64B CAN-FD frames** (`IndexedAttestationFrame`). Handles complete reassembly and Ascon verification on the CISG side.
- **`KeyDeliveryFrame` (Cat 3.3)**: Wraps fresh 16B session key $K_i$ under $K_{boot\_i}$ into a 64B frame (`ver_type = 0x14`, `flags = 0x40`) with 8-byte authenticated Associated Data (AD).
- **`ProtectedRuntimeFrame` (Cat 1)**: Encapsulates 40 bytes of telemetry payload (12 vehicle signals) + 16-byte Ascon tag into 64-byte runtime frames.
- **`GatewayIDSExtractor`**: Implements Step 7b Monotonic Counter Gate (hard-reject against replays) and extracts a **12D feature vector** for the gateway LSTM Autoencoder.

### 3. `ascon_official.py`
- Reference Ascon-AEAD128 implementation from the official Ascon design team (Maria Eichlseder et al., Graz University of Technology).

---

## ⚡ 9-Step Handshake Flow (`handshake_simulation.py`)

1. **Offline Enrollment**: CISG stores ECU public key ($1312\text{B}$) and PUF hash ($32\text{B}$).
2. **Step 1 (Cat 3.1)**: CISG issues plaintext `RANDOM_CHALLENGE` ($16\text{B}$) and `SESSION_ID`.
3. **Step 2**: ECU parses challenge and session context.
4. **Step 3 (HKDF)**: Both sides independently derive per-boot $K_{boot\_i}$ from the PUF hash and challenge.
5. **Step 4 (Cat 2)**: ECU signs boot state with ML-DSA-44 ($2420\text{B}$), encrypts to $2436\text{B}$ PAO, and transmits across 41 CAN-FD frames.
6. **Step 5**: CISG reassembles 41 frames, verifies Ascon tag, and validates ML-DSA-44 signature (FIPS 204).
7. **Step 6 (Cat 3.3)**: CISG generates fresh random $K_i$ and transmits it wrapped under $K_{boot\_i}$.
8. **Step 7**: ECU decrypts Cat 3.3 and activates $K_i$ (retires $K_{boot\_i}$).
9. **Step 8 (Cat 1)**: ECU transmits first runtime telemetry frame encrypted under $K_i$.
10. **Step 9 (CISG IDS)**: Monotonic counter check $\rightarrow$ Payload decryption $\rightarrow$ 12D IDS vector extraction.

---

## 🚀 Installation & Running

### Prerequisites
Python 3.10+ with the following packages:
```bash
pip install cryptography dilithium-py
```

### 1. Run Cryptographic Primitives Self-Test
```bash
python crypto_engine.py
```
*Validates PUF, HKDF derivation, ML-DSA-44 signature/tamper checks, and NIST Ascon KAT vectors.*

### 2. Run CAN-FD Frame Schematics & Security Tests
```bash
python canfd_schema.py
```
*Tests Cat 3.1, Cat 3.3, Cat 2 wrapping/unwrapping, AD header tampering, and session mismatch rejections.*

### 3. Run the Complete Handshake Simulation
```bash
python handshake_simulation.py
```
*Executes the full 9-step vehicle boot lifecycle in sequence with detailed console tracing.*

### 4. Run Pre-Commit Smoke Tests
```bash
python verify_phase1_smoke.py
```
*Runs automated technical checklist validation across DLC compliance, fragmentation math, and attack rejections.*

---

## 🛡️ Security Invariants Enforced

| Property | Enforcement Mechanism | Failure Result |
| :--- | :--- | :--- |
| **Ciphertext Tampering** | Ascon-AEAD128 128-bit authentication tag | Tag mismatch $\rightarrow$ Frame dropped |
| **Header / Routing Spoofing** | 8-byte Associated Data (AD) binding in Ascon | Tag mismatch $\rightarrow$ Frame dropped |
| **Replay / Stale Counter Attack** | Gateway 32-bit strict monotonic counter gate | Hard rejection before IDS extraction |
| **Out-of-Order Burst Fragments** | 4-byte `IndexedAttestationFrame` header validation | Sequence error $\rightarrow$ Reassembly abort |
| **Session Incoherence** | `session_id` binding across all frame headers & HKDF | Session mismatch exception $\rightarrow$ Drop |

