# Phase 1: CISG Gateway Node & Network Reliability Layer

This directory contains the C++ native implementation of the **Central Intelligent Security Gateway (CISG)** for the Post-Quantum In-Vehicle CAN-FD Security Architecture. It handles low-latency network routing, indexed block-transfers, fault-tolerant frame reassembly, and IPC bridging to the Python cryptographic engine.

---

## Directory Structure

```text
Gateway_Node/
├── CMakeLists.txt                 # C++ build configuration
├── include/
│   ├── block_transfer.hpp         # 41-frame PAO reassembly & NACK headers
│   ├── ids_extractor.hpp          # 12D LSTM feature extraction headers
│   └── routing_engine.hpp         # ECU registration & policy headers
├── src/
│   ├── block_transfer.cpp         # Bitmap state machine and selective retransmission
│   ├── ids_extractor.cpp          # Monotonic counter parsing & vector generation
│   ├── main.cpp                   # Event loop, vcan0 socket, and IPC bridge
│   └── routing_engine.cpp         # Domain routing logic
├── crypto_bridge_server.py        # IPC TCP Server for ML-DSA-44 verification
├── send_test_attestation1.py       # Simulated ECU injector without NACK recovery
└── send_test_attestation2.py       # Simulated ECU injector with NACK recovery
```

## Architecture Overview

The Gateway Node acts as the central traffic director and security enforcer. Because computationally heavy Post-Quantum Cryptography (ML-DSA-44) is executed in Python, the C++ Gateway acts as a high-speed network frontend. It ingests fragmented CAN-FD frames directly from the Linux kernel (vcan0), reassembles them using a strict bitmap state machine, and passes completed 2436-byte Protected Attestation Objects (PAO) across a local IPC socket to the Python backend.
```text
C++ Gateway Node (Network Layer)
                              │
          ┌───────────────────┴───────────────────┐
          │                                       │
     Network I/O                             State Machines
  (vcan0 raw sockets)                     (block_transfer.cpp)
          │                                       │
 ├── Non-Blocking Reads (500ms TO)       ├── 41-Bit Array Tracking
 ├── Selective NACK (0x201)              ├── Duplicate Rejection
 └── IPC Bridge Client (Port 5000)       └── Missing Index Resolution
          │
          └─────────────► Python Bridge Server (Port 5000)
                          (crypto_bridge_server.py)
```
## Module Inventory & Responsibilities

### 1. `block_transfer.cpp` (Reliability & Reassembly)
* Indexed Reassembly: Ingests up to 41 sequence indices, placing 60-byte payload chunks at precise offsets within the 2436-byte PAO buffer.
* Bitmap Tracking: Maintains a strict std::array<bool, 41> to track frame arrivals and reject duplicate replays.
* Selective Retransmission: Exposes get_missing_blocks() to dynamically compute dropped sequence indices for NACK generation.

### 2. `main.cpp` (The Core Event Loop)
+ Raw Socket Management: Binds directly to `vcan0` with CAN-FD extensions enabled.
+ Timeout & NACK Generation: Implements a 500ms SO_RCVTIMEO socket timeout. If a block transfer stalls, it broadcasts a `0x201` NACK frame containing the missing indices. Enforces a strict 3-retry limit before aborting a dead session.
+ IPC Handshake: Initiates a TCP connection to `127.0.0.1:5000` to offload the reassembled 2436-byte buffer and awaits a 1-byte (`0x01` or `0x00`) validation response from Python.

### 3. `ids_extractor.cpp` (Machine Learning Hooks)
* Feature Vector Generation: Intercepts Category 1 Runtime Frames (after decryption/authentication) and translates raw CAN identifiers, DLCs, and timing gaps into standardized 12D vectors[cite: 7].
* Zero-Fill Enforcement: If the Ascon-AEAD128 tag is invalid, enforces the Integration Contract by replacing the payload features with zeroes to prevent tampered data from poisoning the LSTM Autoencoder.

### 4. `crypto_bridge_server.py`
* A lightweight TCP listener that ingests the 2436B PAO from the C++ Gateway, slices out the 2420-byte ML-DSA-44 signature, and invokes the FIPS 204 verifier.

### 5. `send_test_attestation.py`
* An ECU network simulator that fragments a real ML-DSA-44 signature into 41 CAN-FD frames, injects them onto `vcan0`, and actively listens for gateway NACKs to seamlessly retransmit intentionally dropped packets.

## Installation & Running

### Prerequisites
* CMake 3.10
* GCC / G++ with C++17 support
* Linux `can-utils` (for `vcan0` virtual interface)

### 1. Build the C++ Gateway
```bash
mkdir build
cd build
cmake ..
make
```
### 2. Start the Network Simulation

Open three separate terminal windows
Terminal 1: Start the Python IPC Bridge
```bash
python crypto_bridge_server.py
# Listens on 127.0.0.1:5000
```
Terminal 2: Start the C++ Gateway
```bash
./build/cisg_router
# Binds to vcan0 and awaits Category 2 and Category 1 frames
```
Terminal 3: Inject the Test Traffic
```bash
python send_test_attestation.py
# Fires the 41-frame burst, intentionally drops a frame, and tests NACK recovery
```

## Network Invariants Enforced

| Property | Enforcement Mechanism | Failure Result |
| :---: | :---: | :---: |
| Packet Loss | 500ms Socket Timeout + NACK Request | Missing frames are dynamically re-requested. |
| ECU Disconnection | Hard NACK limit | After 3 retries, buffer is cleared & session resets. |
| Buffer Overflow | Payload math constrained to TOTAL_PAO_SIZE | Out-of-bounds indices are hard-rejected. |
| Duplicate Frames | Array Bitmap State Machine | Replayed sequence indices are silently dropped.  
