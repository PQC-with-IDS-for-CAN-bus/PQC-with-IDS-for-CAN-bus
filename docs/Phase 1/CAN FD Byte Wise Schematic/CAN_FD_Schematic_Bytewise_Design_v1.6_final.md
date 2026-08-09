# Custom Byte-Wise CAN-FD Frame Schematics & Specification v1.6 Final

**Project**: Secure Segmented CAN-FD Architecture with Post-Quantum Attestation & Gateway-Hosted ML IDS  
**Document Version**: 1.6 Final (Frozen Specification)  

---

## 1. Architectural Context & System Constraints

This specification defines the complete, byte-level payload layouts for all CAN-FD frames operating across the 4-domain in-vehicle network (Powertrain, Chassis, Body & Comfort, Infotainment) connected via the **Central Intelligent Security Gateway (CISG)**.

```text
 ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
 │ Powertrain Domain │  │ Chassis Domain  │  │  Body Domain   │  │ Infotainment   │
 └───────┬────────┘  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘
         │                   │                   │                   │
         └───────────┬───────┴───────────┬───────┴───────────────────┘
                     │                   │
             ┌───────▼───────────────────▼───────┐
             │ Central Intelligent Security      │
             │ Gateway (CISG) [Root of Trust]    │
             │  ├── Ascon-AEAD128 Engine         │
             │  ├── ML-DSA Remote Attestation    │
             │  ├── 60/4 Reassembly Engine       │
             │  └── Gateway LSTM/ONNX IDS        │
             └───────────────────────────────────┘
```

### Protocol & Security Parameters
* **CAN-FD Max Payload Size**: DLC 15 = **64 Bytes**.
* **Nominal / Data Bitrate**: 500 kbps / 2 Mbps.
* **Cryptographic Engine**: NIST SP 800-232 **Ascon-AEAD128**.
  * Key Size: 128 bits (16 bytes).
  * Nonce Size: 128 bits (16 bytes).
  * Authentication Tag: **16 Bytes (128-bit full tag, no truncation)**.
* **Remote Attestation Algorithm**: **ML-DSA-44 (FIPS 204 / Dilithium2)** (~2420B signature $\rightarrow$ 2436B protected attestation object).
* **Large Payload Transport**: **60/4 Indexed Block-Transfer Protocol** (4-byte transport header + 60-byte payload data per frame $\rightarrow$ **41 frames**).
* **IDS Gateway Hook**: Decrypted telemetry + Unencrypted Associated Data (AD) mapped directly into a 12-dimensional feature vector $\mathbf{X}_t$ for local ONNX LSTM inference.

---

## 2. Category 1: Protected Runtime Telemetry Frame (64 Bytes)

This frame is used during normal vehicle operation. It carries encrypted telemetry data protected by Ascon-AEAD128 with replay prevention and message authentication.

### Byte-Wise Allocation Overview

```text
 0      1      2      3      4    5    6    7      8                         47 48                        63
┌──────┬──────┬──────┬──────┬──────────────────┬────────────────────────────┬────────────────────────────┐
│VER/  │SENDER│DOMAIN│FLAGS │MONOTONIC COUNTER │ ENCRYPTED TELEMETRY DATA   │   ASCON-AEAD128 AUTH TAG   │
│TYPE  │ECU ID│  ID  │      │   (32-bit BE)    │        (40 Bytes)          │         (16 Bytes)         │
└──────┴──────┴──────┴──────┴──────────────────┴────────────────────────────┴────────────────────────────┘
│◄───────── UNENCRYPTED HEADER / AD (8 Bytes) ────►│◄── ENCRYPTED PAYLOAD ─────►│◄──── AUTHENTICATION ──────►│
```

### Detailed Field Definitions

| Byte Range | Field Name | Type / Size | AD Field? | Description & Value Constraints |
| :--- | :--- | :--- | :--- | :--- |
| **Byte 0** | `PROTOCOL_VER_TYPE` | `uint8_t` (8 bit) | **Yes** | **Bits 7..4**: Protocol Version (`0x1` for v1.0).<br>**Bits 3..0**: Message Type (`0x1` = Runtime Telemetry). |
| **Byte 1** | `SENDER_ECU_ID` | `uint8_t` (8 bit) | **Yes** | Unique ECU ID (`0x10`=Engine, `0x11`=Transmission, `0x20`=Brake, `0x21`=Steering, `0x30`=BCM, `0x40`=Telematics). |
| **Byte 2** | `DOMAIN_ID` | `uint8_t` (8 bit) | **Yes** | Origin Domain (`0x01`=Powertrain, `0x02`=Chassis, `0x03`=Body, `0x04`=Infotainment). |
| **Byte 3** | `FLAGS_RESERVED` | `uint8_t` (8 bit) | **Yes** | **Bit 7**: Emergency Msg Flag.<br>**Bit 6**: Encrypted Flag (`1`=Ascon-128).<br>**Bits 5..0**: Reserved (`000000`). |
| **Bytes 4-7** | `MONOTONIC_COUNTER`| `uint32_t` (32 bit) | **Yes** | Big-Endian incremental counter per ECU session. Prevents replay attacks. |
| **Bytes 8-47**| `ENCRYPTED_PAYLOAD`| `uint8_t[40]` | **No** | **Ascon-128 Encrypted Ciphertext**. Contains the 40-byte plaintext sensor signals detailed below. |
| **Bytes 48-63**|`ASCON_AUTH_TAG` | `uint8_t[16]` | **N/A** | **128-bit Ascon Authentication Tag** computed over AD (Bytes 0–7 + CAN ID) + Plaintext Telemetry. |

### Plaintext Telemetry Signal Layout (Inside Encrypted Bytes 8–47)

| Offset inside Payload | Signal Name | Data Type | Engineering Units & Scale |
| :--- | :--- | :--- | :--- |
| `+00 .. +03` (4B) | `Vehicle_Speed` | `float32` | Speed in km/h ($0.0$ to $300.0$) |
| `+04 .. +07` (4B) | `Engine_RPM` | `float32` | Engine speed in RPM ($0.0$ to $8000.0$) |
| `+08 .. +11` (4B) | `Steering_Angle` | `float32` | Angle in degrees ($-720.0$ to $+720.0$) |
| `+12 .. +15` (4B) | `Brake_Pressure` | `float32` | Hydraulic pressure in kPa ($0.0$ to $20000.0$) |
| `+16 .. +19` (4B) | `Throttle_Pos` | `float32` | Throttle opening percentage ($0.0\%$ to $100.0\%$) |
| `+20 .. +23` (4B) | `Longitudinal_Accel` | `float32` | Acceleration $a_x$ in $m/s^2$ ($-15.0$ to $+15.0$) |
| `+24 .. +27` (4B) | `Lateral_Accel` | `float32` | Acceleration $a_y$ in $m/s^2$ ($-15.0$ to $+15.0$) |
| `+28 .. +29` (2B) | `Wheel_Speed_FL` | `uint16_t` | Front-Left wheel speed ($0.1$ km/h per LSB) |
| `+30 .. +31` (2B) | `Wheel_Speed_FR` | `uint16_t` | Front-Right wheel speed ($0.1$ km/h per LSB) |
| `+32 .. +33` (2B) | `Engine_Temp` | `int16_t` | Coolant temp in $^\circ\text{C}$ (Offset $-40^\circ\text{C}$) |
| `+34 .. +35` (2B) | `Gear_Status` | `uint16_t` | Active gear bitmask / position |
| `+36 .. +39` (4B) | `Diagnostic_Flags` | `uint32_t` | Error DTC bitmask & ECU health status |

---

## 3. Category 2: 60/4 Indexed Block-Transfer Attestation Frame (64 Bytes)

Used during Boot-Time Remote Attestation to transfer the 2436B ML-DSA protected attestation object across **41 sequential frames**.

### Byte-Wise Allocation Overview (Kaustuv's Protocol)

```text
 0      1      2      3      4                                                                           63
┌──────┬──────┬──────┬──────┬───────────────────────────────────────────────────────────────────────────┐
│SESS  │FRAME │TOTAL │CTRL  │ FRAGMENT PAYLOAD DATA                                                     │
│ ID   │INDEX │FRAMES│FLAGS │ (60 Bytes of ML-DSA Signature / Public Key Fragment)                      │
└──────┴──────┴──────┴──────┴───────────────────────────────────────────────────────────────────────────┘
│◄── 4-BYTE TRANSPORT HEADER ──►│◄──────────────────────── 60-BYTE PAYLOAD DATA ───────────────────────────►│
```

### Detailed Field Definitions

| Byte Range | Field Name | Type / Size | Description & Value Constraints |
| :--- | :--- | :--- | :--- |
| **Byte 0** | `SESSION_ID` | `uint8_t` (8 bit) | Attestation Session Identifier (randomized per boot). |
| **Byte 1** | `FRAME_INDEX` | `uint8_t` (8 bit) | Fragment index (`0` to `40` for 41 total frames). |
| **Byte 2** | `TOTAL_FRAMES` | `uint8_t` (8 bit) | Total fragments in current transfer (`41` = `0x29`). |
| **Byte 3** | `CONTROL_FLAGS` | `uint8_t` (8 bit) | **Bits 7..4**: Message Subtype (`0x2` = Block Data, `0x3` = Transfer Complete).<br>**Bits 3..0**: Re-transmission Sequence / Retry Counter. |
| **Bytes 4-63** | `FRAGMENT_PAYLOAD`| `uint8_t[60]` | **60-Byte Block Data Fragment**. Fragment $i$ contains bytes $i \times 60$ to $(i \times 60) + 59$ of the attestation payload. |

---

## 4. Category 3: Control & Session Management Frames

### 3.1 Gateway Attestation Challenge Frame (Gateway $\rightarrow$ ECU) — 64 Bytes
Initiates startup attestation for an ECU.

| Byte Range | Field Name | Type / Size | Description |
| :--- | :--- | :--- | :--- |
| **Byte 0** | `PROTOCOL_VER_TYPE` | `uint8_t` | Version `0x1` + Msg Type `0x2` (Attestation Challenge). |
| **Byte 1** | `TARGET_ECU_ID` | `uint8_t` | Target ECU ID receiving challenge. |
| **Byte 2** | `SESSION_ID` | `uint8_t` | Newly generated session ID. |
| **Byte 3** | `ALGO_SELECTION` | `uint8_t` | Crypto suite ID (`0x01` = Ascon-AEAD128 + ML-DSA-44). |
| **Bytes 4-19**| `RANDOM_CHALLENGE` | `uint8_t[16]` | 128-bit fresh cryptographic nonce/challenge. |
| **Bytes 20-27**|`TIMESTAMP_EPOCH` | `uint64_t` | 64-bit UTC microsecond timestamp. |
| **Bytes 28-63**|`RESERVED_PADDING` | `uint8_t[36]` | Zero padding / extended parameters. |

---

### 3.2 Selective NACK / Recovery Request Frame (ECU $\leftrightarrow$ Gateway) — 16 Bytes (CAN-FD DLC 10)
Used when fragments are dropped during 60/4 block transfer.

| Byte Range | Field Name | Type / Size | Description |
| :--- | :--- | :--- | :--- |
| **Byte 0** | `PROTOCOL_VER_TYPE` | `uint8_t` | Version `0x1` + Msg Type `0x3` (NACK Recovery). |
| **Byte 1** | `SESSION_ID` | `uint8_t` | Active attestation session ID. |
| **Byte 2** | `SENDER_ID` | `uint8_t` | ECU or Gateway ID requesting retransmission. |
| **Byte 3** | `RETRY_COUNT` | `uint8_t` | Attempt number (Max 3 retries allowed). |
| **Bytes 4-7**| `MISSING_BITMAP_0` | `uint32_t` | Bitmask for missing frames 0 to 31 (`1` = Missing). |
| **Bytes 8-11**| `MISSING_BITMAP_1` | `uint32_t` | Bitmask for missing frames 32 to 40 (`1` = Missing). |
| **Bytes 12-15`|`RESERVED` | `uint32_t` | Padding to 16 bytes. |

---

### 3.3 Session Key Transport Frame (Gateway $\rightarrow$ ECU) — 64 Bytes
Delivers the fresh operational session key after attestation passes.

| Byte Range | Field Name | Type / Size | Description |
| :--- | :--- | :--- | :--- |
| **Byte 0** | `PROTOCOL_VER_TYPE` | `uint8_t` | Version `0x1` + Msg Type `0x4` (Key Delivery). |
| **Byte 1** | `TARGET_ECU_ID` | `uint8_t` | Target ECU ID. |
| **Byte 2** | `SESSION_ID` | `uint8_t` | Confirmed session ID. |
| **Byte 3** | `KEY_DERIVATION_ID`| `uint8_t` | HKDF parameter selection (`0x01`). |
| **Bytes 4-19**| `RESERVED_PADDING` | `uint8_t[16]` | 128-bit zero padding reserved. |
| **Bytes 20-35`|`WRAPPED_KEY` | `uint8_t[16]` | Ascon-encrypted 128-bit Operational Session Key ($K_i$). |
| **Bytes 36-47`|`EXPLICIT_NONCE` | `uint8_t[12]` | 12-byte explicit nonce material for key wrapping. |
| **Bytes 48-63`|`KEY_AUTH_TAG` | `uint8_t[16]` | 128-bit Ascon tag for key delivery frame. |

---

## 5. Category 4: Gateway IDS Feature Vector Extraction Pipeline (Tapan's Role)

When a 64-byte protected runtime frame arrives at the Central Gateway (CISG), the gateway executes decryption and format checks, then extracts a 12-dimensional feature vector $\mathbf{X}_t$ for the local ONNX LSTM Autoencoder.

```text
       CAN-FD Frame (64 Bytes)
                 │
                 ▼
     ┌───────────────────────┐
     │ CISG Header & Ascon   │
     │ Tag Verification      │
     └───────────┬───────────┘
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
[Valid Tag]           [Invalid Tag]
       │                   │
       ▼                   ▼
Decrypt Payload     Log Security Event
       │           (Auth Failure Stream)
       ▼
Extract Telemetry Signals + Protocol Metadata
       │
       ▼
 12-Dimensional Feature Vector X_t
       │
       ▼
 Gateway ONNX LSTM Model Inference --> Anomaly Score
```

### Feature Vector $\mathbf{X}_t$ Schema (12 Features)

| Feature Index | Name | Formula / Source | Description & Unit |
| :---: | :--- | :--- | :--- |
| $f_1$ | `Delta_Time` | $t_k - t_{k-1}$ | Inter-arrival time between consecutive frames (ms). |
| $f_2$ | `Counter_Gap` | $C_k - C_{k-1} - 1$ | Gap in 32-bit monotonic counter (0 = normal, >0 = lost/replayed). |
| $f_3$ | `Sender_ECU_ID` | Byte 1 | Sender ECU identifier (normalized $0.0 - 1.0$). |
| $f_4$ | `Domain_ID` | Byte 2 | Origin domain identifier ($1$ to $4$). |
| $f_5$ | `Msg_Type` | Byte 0 (Bits 3..0) | Message type code. |
| $f_6$ | `Auth_Tag_Status` | Tag Verification | `0.0` = Valid Tag, `1.0` = Tag Failure / Corruption. |
| $f_7$ | `Vehicle_Speed` | Payload `+00..+03` | Decrypted vehicle speed (km/h). |
| $f_8$ | `Engine_RPM` | Payload `+04..+07` | Decrypted engine RPM. |
| $f_9$ | `Steering_Angle` | Payload `+08..+11` | Decrypted steering angle (degrees). |
| $f_{10}$ | `Brake_Pressure` | Payload `+12..+15` | Decrypted brake pressure (kPa). |
| $f_{11}$ | `Long_Accel` | Payload `+20..+23` | Decrypted acceleration $a_x$ ($m/s^2$). |
| $f_{12}$ | `DTC_Error_Count` | Payload `+36..+39` | Count of active bitwise diagnostic error flags. |

---

## 6. Summary Comparison Matrix

| Frame Category | Total Size | Header Size | Payload Size | Crypto / Auth Overhead | Frequency / Trigger |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **1. Protected Runtime Telemetry** | 64 Bytes | 8 Bytes | 40 Bytes | 16 Bytes (Ascon Tag) | Periodic (10ms – 100ms) |
| **2. 60/4 Indexed Attestation** | 64 Bytes | 4 Bytes | 60 Bytes | Transport Indexing | Boot-time burst (~41 frames) |
| **3.1 Attestation Challenge** | 64 Bytes | 4 Bytes | 60 Bytes | 128-bit Nonce | Startup / Re-attestation |
| **3.2 Selective NACK Recovery** | 16 Bytes | 4 Bytes | 12 Bytes | Bitmap Checksum | On dropped fragment detection |
| **3.3 Session Key Delivery** | 64 Bytes | 4 Bytes | 44 Bytes | 16 Bytes (Ascon Tag) | Post-Attestation Success |
