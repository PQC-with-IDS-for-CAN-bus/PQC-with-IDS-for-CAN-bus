# Kaustuv Remediation Guide: Technical Rectifications for DockerLab C++17 Suite

**Target Engineer:** Kaustuv (`23BDS1060`)  
**Environment:** Linux (EndeavourOS / Arch / Ubuntu, Kernel 6.x+, Docker, SocketCAN)  
**Deliverable Path:** `Anti Gravity/Phase 3/KAUSTUV_REMEDIATION_GUIDE.md`  
**Date:** October 4, 2026  

---

## Overview

Great job resolving the Docker ulimits (`memlock: -1`), `MCL_FUTURE` memory allocation crash, and HTTP chunking in `8cba70e`! The C++ binaries now build and run reliably on EndeavourOS.

Acceptance target thresholds (e.g. 21 ms vs 24 ms) are empirical engineering observations and do not block progress. However, there are **four core technical and architectural issues** in the simulation pipeline that need rectification to ensure our simulation represents a genuine, publishable hardware-in-the-loop (HIL) benchmark rather than in-memory emulation:

1. **Issue 1:** Gateway SocketCAN Decoupling (Gateway running an in-memory loop instead of ingesting SocketCAN wire frames).
2. **Issue 2:** Fault Recovery & Retransmission Omission (All 31 runs logging `NONE` drops, `0` retransmissions, and hardcoded NACK turnaround times).
3. **Issue 3:** Cryptographic Transcript Mismatch (Python audit bypassed with `try...except: pass` due to 68-byte vs 58-byte transcript mismatch).
4. **Issue 4:** Synthetic PMU Metrics in Docker (Hardware counters failing with permission error 255).

---

## Issue 1: Gateway SocketCAN Decoupling

### The Problem
In `cisg_gateway.cpp` (`lines 357–404`), when `/run` is triggered:
- The gateway signs its own challenge, encrypts the 2,436B PAO in a local C++ array, and loops over 41 frames in-memory while calling `clock_nanosleep()`:
  ```cpp
  // cisg_gateway.cpp
  for (int i = 0; i < 41; ++i) {
      if (dropped_set.count(i)) continue;
      st_ptr->reassembler.ingest_frame(frames[i].data());
      cisg::timing::CANFDWireModel::inject_wire_delay(single_frame_us);
  }
  ```
- Meanwhile, `ecu_node.cpp` broadcasts frames onto SocketCAN, but `cisg_gateway.cpp` **never opens a SocketCAN socket or calls `recvmsg()`**.
- **Result:** The 21.17 ms measurement reflects single-threaded in-memory processing with synthetic sleep pauses, not a true inter-container network exchange.

### How to Rectify
Update `cisg_gateway.cpp` to receive incoming frames directly from the SocketCAN virtual interface:

1. **Open and bind a raw CAN-FD socket in `cisg_gateway.cpp`:**
   ```cpp
   int can_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
   int enable_canfd = 1;
   setsockopt(can_fd, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable_canfd, sizeof(enable_canfd));

   // Enable nanosecond kernel timestamps for Contract 2
   int enable_timestamp = 1;
   setsockopt(can_fd, SOL_SOCKET, SO_TIMESTAMPNS, &enable_timestamp, sizeof(enable_timestamp));

   struct ifreq ifr{};
   std::string iface = "domain" + std::to_string(domain); // or "g" + std::to_string(domain)
   std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
   ioctl(can_fd, SIOCGIFINDEX, &ifr);

   struct sockaddr_can addr{};
   addr.can_family = AF_CAN;
   addr.can_ifindex = ifr.ifr_ifindex;
   bind(can_fd, (struct sockaddr*)&addr, sizeof(addr));
   ```

2. **In the `/run` handler, ingest frames from the socket:**
   * Set a socket receive timeout (`SO_RCVTIMEO`) matching the ASIL-D burst timeout (e.g. 50 ms).
   * Loop `recvmsg()` / `read()` on `can_fd`.
   * For each frame with `can_id == 0x200`, ingest into `st_ptr->reassembler.ingest_frame(frame.data)` and extract `kernel_epoch_ns` from `SCM_TIMESTAMPNS`.
   * When all 41 frames are received (or timeout expires), proceed to reassembly and cryptographic verification.

---

## Issue 2: Fault Recovery & Retransmission Execution

### The Problem
In `fault_recovery_runs.csv`:
- All 16 fault injection runs report `injected_dropped_frame_indices: NONE` and `retransmitted_frames_count: 0`.
- The ECU blasts 41 frames with `round: 0` and immediately terminates. It never listens for CAN ID `0x201` (Selective NACK).
- When a frame is missing, the gateway self-recovers the frame internally from its local in-memory array rather than issuing a NACK and receiving a retransmission over the bus.
- `nack_turnaround_time_us` is hardcoded to `+400000` ns (400.0 µs) in `cisg_gateway.cpp:476`.

### How to Rectify

1. **Emit Drop Events in `relay_node.cpp`:**
   When `relay_node.cpp` drops a frame (e.g. frame index 12), write an explicit event to `/logs/relay/events.jsonl`:
   ```cpp
   // When should_drop == true:
   log_event("injected_drop", domain, frame.data[1] /* seq */, round);
   ```
   This ensures `controller.py` can parse which frames were dropped on the wire.

2. **Add NACK Listening and Retransmission to `ecu_node.cpp`:**
   After sending the initial 41 frames, `ecu_node` should:
   * Listen on its CAN socket for CAN ID `0x201` (NACK frame) with a 10 ms timeout.
   * If a NACK frame is received:
     ```cpp
     // Extract 64-bit missing frame bitmap from NACK payload
     uint64_t missing_bitmap;
     std::memcpy(&missing_bitmap, nack_payload + 8, sizeof(uint64_t));

     // Retransmit only frames where the bit is set
     for (int i = 0; i < 41; ++i) {
         if (missing_bitmap & (1ULL << i)) {
             write(can_fd, &frames[i], sizeof(frames[i]));
             log_tx_event(run_id, domain, ..., i, 41, round = 1, ...);
             cisg::timing::CANFDWireModel::inject_wire_delay(single_frame_us);
         }
     }
     ```
   * Set `ecu_result["nack_rounds"]` to the actual number of recovery rounds executed.

3. **Measure Dynamic NACK Turnaround in `cisg_gateway.cpp`:**
   * When frames are missing after the initial burst, transmit CAN ID `0x201` onto the CAN bus with the selective bitmap.
   * Record `t_nack_tx = get_monotonic_ns()`.
   * When the first retransmitted frame arrives on the CAN socket, record `t_first_rx = get_monotonic_ns()`.
   * Set `nack_turnaround_time_us = (t_first_rx - t_nack_tx) / 1000.0` instead of adding `+400000` ns.

---

## Issue 3: Cryptographic Transcript Mismatch (PQC Audit)

### The Problem
In `controller.py:200-212`, the independent ML-DSA verification was modified:
```python
# controller.py
try:
    ...
    if not PostQuantumAttestation.verify_attestation_signature(...):
        errors.append("ML-DSA verification failed")
except Exception:
    pass  # Bypassed silently!
```

This occurred because the C++ gateway and Python verification expect **different transcript formats**:
- **Python (`crypto_engine.py:227`):** Enforces a **16-byte challenge** and a canonical **58-byte transcript**:
  $$\text{Transcript}_{58\text{B}} = \text{version}_{2\text{B}} \parallel \text{ecu\_id}_{4\text{B}} \parallel \text{session\_id}_{4\text{B}} \parallel \text{challenge}_{16\text{B}} \parallel \text{measurement}_{32\text{B}}$$
- **C++ Gateway (`cisg_gateway.cpp:368`):** Uses a **32-byte challenge** and signs a non-standard **68-byte payload**:
  $$\text{Payload}_{68\text{B}} = \text{challenge}_{32\text{B}} \parallel \text{measurement}_{32\text{B}} \parallel \text{session\_id}_{4\text{B}}$$

Because the bytes being signed differ, Python verification returns `False` or raises an exception.

### How to Rectify

1. **Standardize the C++ transcript in `cisg_gateway.cpp` and `ecu_node.cpp` to the canonical 58-byte layout:**
   ```cpp
   // Canonical 58-Byte Transcript Construction
   std::array<uint8_t, 16> challenge_16B{}; // 16-byte challenge
   std::memcpy(challenge_16B.data(), challenge_hex_bytes, 16);

   std::vector<uint8_t> canonical_transcript(58);
   // Bytes 0-1: Protocol version (0x0001)
   canonical_transcript[0] = 0x00;
   canonical_transcript[1] = 0x01;
   // Bytes 2-5: ECU ID (big-endian 32-bit: 0x1F + domain)
   uint32_t ecu_id = 0x1F + domain;
   canonical_transcript[2] = (ecu_id >> 24) & 0xFF;
   canonical_transcript[3] = (ecu_id >> 16) & 0xFF;
   canonical_transcript[4] = (ecu_id >> 8)  & 0xFF;
   canonical_transcript[5] = ecu_id & 0xFF;
   // Bytes 6-9: Session ID (big-endian 32-bit)
   canonical_transcript[6] = (session_id >> 24) & 0xFF;
   canonical_transcript[7] = (session_id >> 16) & 0xFF;
   canonical_transcript[8] = (session_id >> 8)  & 0xFF;
   canonical_transcript[9] = session_id & 0xFF;
   // Bytes 10-25: 16-byte challenge
   std::memcpy(&canonical_transcript[10], challenge_16B.data(), 16);
   // Bytes 26-57: 32-byte measurement hash
   std::memcpy(&canonical_transcript[26], measurement_32B.data(), 32);

   // Pass canonical_transcript to ML-DSA sign and verify:
   mldsa_engine.sign(canonical_transcript.data(), 58, sk, sig, sig_len);
   ```

2. **Restore strict audit verification in `controller.py`:**
   Revert `controller.py:200-212` back to strict verification without `try...except: pass`:
   ```python
   proof = record['gateway'].get('verification_evidence')
   if not proof or not PostQuantumAttestation.verify_attestation_signature(
       bytes.fromhex(proof['public_key_hex']),
       bytes.fromhex(proof['signature_hex']),
       1,  # Version
       0x1F + record['domain'],  # ECU ID
       record['gateway']['session_id'],
       bytes.fromhex(proof['challenge_hex']),
       bytes.fromhex(proof['measurement_hex'])
   ):
       errors.append(f"{row['run_id']}: independent ML-DSA verification failed")
   ```

---

## Issue 4: Hardware PMU Performance Counters in Docker

### The Problem
In `simulation_results/perf_probe.txt`:
```text
Error: No permission to enable cycles event.
```
Linux blocks hardware PMU counters inside unprivileged containers (`perf_event_paranoid` kernel security barrier). As a result, `evidence.py` fell back to synthetic formulas (`cycles = wall_ns * 1.5`).

### How to Rectify
To capture genuine PMU counters on EndeavourOS:

1. **Lower kernel paranoid level on the host:**
   ```bash
   sudo sysctl -w kernel.perf_event_paranoid=1
   ```
   *(Allows unprivileged users to read CPU cycles, instructions, and cache references).*

2. **Grant profiling permissions in `DockerLab/compose.yaml`:**
   Add `PERFMON` and `SYS_PTRACE` capabilities to the `controller` and `app` definitions:
   ```yaml
   cap_add:
     - NET_RAW
     - NET_ADMIN
     - IPC_LOCK
     - PERFMON         # Kernel 5.8+ PMU monitoring capability
     - SYS_PTRACE      # Required for perf_event_open inspection
   ```

3. **Verify PMU access inside the container:**
   ```bash
   docker compose exec controller perf stat -e cycles,instructions -- true
   ```
   When this returns exit code `0`, `controller.py` will automatically record authentic hardware cycles and instructions instead of using formula fallbacks.

---

## Verification Checklist for Kaustuv

Once these 4 rectifications are applied, verify the following before committing:

- [ ] `cisg_gateway` binds to `domain{d}` SocketCAN and ingests frames via `recvmsg()`.
- [ ] In `fault_recovery_runs.csv`, dropped runs (e.g. `single`, `burst`) show actual dropped indices (`12`, `14;15;16`) and `retransmitted_frames_count > 0`.
- [ ] `nack_turnaround_time_us` reflects dynamically measured timestamps (not a flat 400.0 µs).
- [ ] `controller.py:audit()` runs cleanly with **zero exceptions** and **zero schema errors** without `try...except: pass`.
- [ ] `perf_probe.txt` outputs return code `0` with genuine hardware event counts.
