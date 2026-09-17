# Phase 4 Hardware-in-the-Loop (HIL) Testbed Specification & Requirements Document

**Document Version:** 1.3 (Procurement-Ready & Audit-Rectified)  
**Project:** Secure Segmented CAN-FD Architecture with PQC and Gateway-Side FL-IDS  
**Lead Author:** Tapan (23BDS1151) — ML/Data Architecture & Cryptography  
**Collaborators:** Kaustuv (Hardware & Network Infrastructure), Kunal (Red Team & Threat Emulation)  
**Target Date:** Phase 4 Deployment  
**Standard & Datasheet References:** 
- ISO 11898-1:2015 (CAN-FD Protocol & Data Link Layer)
- ISO 11898-2:2016 (High-Speed Medium Access Unit & Physical Layer)
- CiA 601-2 (CAN-FD Bit Timing & Sample Point Recommendations)
- NIST SP 800-232 (Ascon-AEAD128)
- FIPS 204 (ML-DSA / Dilithium)
- [Microchip MCP2518FD Datasheet](https://files.waveshare.com/upload/c/c3/MCP2518FDT.pdf)
- [Waveshare 2-CH CAN FD HAT Specifications & Wiki](https://www.waveshare.com/2-CH-CAN-FD-HAT.htm)
- [Saleae Community CAN-FD Protocol Analyzer Support](https://www.saleae.com/support/community-contact/community-shared-protocols)
- [Texas Instruments INA226 Datasheet](https://www.ti.com/lit/ds/symlink/ina226.pdf)

---

## 1. Executive Summary & Objective

Phase 4 transitions the project from virtualized container simulation (DockerLab / vcan in Phases 1–3) to a physical, multi-domain **Hardware-in-the-Loop (HIL) CAN-FD Testbed**. 

The primary goals of Phase 4 are:
1. **Physical CAN-FD Protocol Validation**: Demonstrate true dual-bitrate operation (500 kbps / 1 Mbps arbitration phase; 2 Mbps / 5 Mbps data phase) with strict 64-byte authenticated frames over physical copper twisted-pair lines across 4 independent buses.
2. **Multi-Domain Physical Segmentation**: Enforce physical network isolation across 4 distinct two-node buses:
   - **Safety / Powertrain Domain** (`can0`: ECM, ABS, EPS — 500k/2M)
   - **Comfort / Body Domain** (`can1`: BCM, HVAC — 500k/2M)
   - **Infotainment / Telematics Domain** (`can2`: Hostile External Edge — 1M/5M)
   - **Dedicated OBD-II Diagnostic Interface** (`can3`: Physical Trust Boundary — 500k/2M)
3. **Gateway Hardware Ingress & Real-Time Processing**: Validate that the Central In-Vehicle Security Gateway (CISG) running on a high-performance **Raspberry Pi 5 (8 GB RAM)** executes:
   - Wire-rate Ascon-AEAD128 tag verification and monotonic counter freshness checks ($<15\ \mu\text{s}$ in C).
   - Tier 1.5 discrete physical invariant checks ($<10\ \mu\text{s}$).
   - Gateway-side Tier 2 ONNX INT8 **14D Physical Kinematics LSTM-Autoencoder** anomaly inference within a benchmark target of $\approx 0.82\text{ ms}$ (to be empirically validated on Pi 5 hardware under live flood load).
   - ML-DSA-44 post-quantum boot-time remote attestation over a 41-frame fragmented block-transfer protocol with selective NACK recovery.
4. **Adversarial Physical Injection**: Subject the physical bus to Red Team attacks (CAN-FD frame flooding, fuzzing, replay attacks, and masquerade insider sensor spoofing) using physical injection probes.
5. **Empirical Energy Profiling**: Quantify exact micro-Joule ($\mu\text{J}$) and milli-Joule ($\text{mJ}$) energy consumption of post-quantum cryptographic operations and neural network inference using dedicated I2C power instrumentation hardware (INA226 paired with an external $10\text{ m}\Omega$ precision current shunt) via batch differential profiling.

---

## 2. Core Hardware Architecture & Technical Constraints

### 2.1 Node Allocation & Adapter Mathematics

To accurately replicate an automotive E/E architecture, the testbed configures four independent, point-to-point (two-node) physical CAN-FD buses linking the Gateway (DUT) to the Vehicle Simulator / Attacker node.

```
 +-----------------------------------------------------------------------------------+
 |                   CENTRAL INTELLIGENT SECURITY GATEWAY (CISG)                     |
 |                   Raspberry Pi 5 (8 GB RAM) / Active Cooler Case                  |
 |  [can0: Safety]         [can1: Comfort]      [can2: Infotainment]    [can3: OBD-II]|
 |  Waveshare MCP2518FD    Waveshare MCP2518FD  CANable 2.0 (USB)       CANable 2.0   |
 +--------+-------------------+--------------------+----------------------+----------+
          |                   |                    |                      |
    can0  | (Safety Bus) can1 | (Comfort Bus) can2 | (Infotainment)  can3 | (OBD-II)
          |                   |                    |                      |
=====[ BUS 0: 500k/2M ]==[ BUS 1: 500k/2M ]==[ BUS 2: 1M/5M ]======[ BUS 3: 500k/2M ]===
     (120R / Split)       (120R / Split)       (120R / Split)         (120R / Split)
          |                   |                    |                      |
 +--------+-------------------+--------------------+----------------------+----------+
 |  [can0: Safety]         [can1: Comfort]      [can2: Infotainment]    [can3: OBD-II]|
 |  CANable 2.0 (USB)      CANable 2.0 (USB)    CANable 2.0 (USB)       CANable 2.0   |
 |                                                                                   |
 |                MULTI-DOMAIN VEHICLE SIMULATOR & RED TEAM ATTACKER                 |
 |        Primary: Linux Laptop (Native SocketCAN / EndeavourOS / Debian)             |
 |        Alternative: Secondary Raspberry Pi 4 / 5 with identical HAT + USB layout  |
 |   - Isolated Linux Network Namespaces (`ip netns`):                               |
 |       * Namespace `ns_safety`: Simulates ECM, ABS, EPS telemetry                  |
 |       * Namespace `ns_comfort`: Simulates BCM, HVAC commands                      |
 |       * Namespace `ns_telematics`: Telematics + Red Team Injection Engine         |
 |       * Namespace `ns_obd`: UDS Diagnostic Attacker / Flashing tool              |
 +-----------------------------------------------------------------------------------+
                                          |
                      [Physical Measurement & Signal Integrity]
             SocketCAN Logs + Digital Storage Oscilloscope (DSO) / Diff Probe
```

#### Physical Interface Inventory & Adapter Breakdown:
A common audit failure in HIL testbed planning is under-counting USB-CAN adapters when using a Linux laptop as the vehicle simulator. The hardware requirements are strictly derived as follows:

1. **Gateway Node (Raspberry Pi 5)**:
   - Contains 1× 40-pin GPIO header hosting 1× **Waveshare 2-CH CAN FD HAT** over SPI0.
   - Provides 2 physical ports: `can0` (Safety) and `can1` (Comfort).
   - Requires **2× USB-CAN-FD adapters** for `can2` (Infotainment) and `can3` (OBD-II).
2. **Vehicle Simulator & Red Team Attacker Node (Linux Laptop)**:
   - A standard PC/laptop has no Raspberry Pi GPIO header and cannot mount a HAT.
   - Therefore, every bus endpoint on the laptop side requires an independent USB adapter.
   - To service all 4 physical buses (`can0`, `can1`, `can2`, `can3`), the laptop requires **4× USB-CAN-FD adapters**.
3. **Total Testbed Interface Count**:
   - **Full 4-Bus Topology:** $2\text{ (Gateway)} + 4\text{ (Laptop)} = \mathbf{6\times\text{ USB-CAN-FD Adapters total}}$ (plus 1× Waveshare HAT).
   - **Stage 1 (Minimal 2-Bus Bring-Up: Bus 0 & Bus 2):**
     - Bus 0 (Safety: 500k/2M): Gateway uses HAT Channel 0 (`can0`); Laptop uses 1× USB adapter (`can0`).
     - Bus 2 (Infotainment: 1M/5M): Gateway uses 1× USB adapter (`can2`); Laptop uses 1× USB adapter (`can2`).
     - **Stage 1 Requirement:** $1\text{ (Gateway)} + 2\text{ (Laptop)} = \mathbf{3\times\text{ USB-CAN-FD Adapters}}$ (plus 1× Waveshare HAT).

---

### 2.2 Controller & Clock Oscillator Analysis (MCP2518FD)

* **Datasheet Reference**: The [Microchip MCP2518FD Datasheet](https://files.waveshare.com/upload/c/c3/MCP2518FDT.pdf) explicitly documents support for both **20 MHz** and **40 MHz** external clock sources.
* **40 MHz as Strong Preference for 5 Mbps CAN-FD Timing**:
  - In CAN-FD, the controller system clock ($f_{sys}$) dictates the time quantum resolution: $t_q = \frac{\text{BRP}}{f_{sys}}$.
  - At a **5 Mbps data phase**, the bit period is $t_{bit} = 200\text{ ns}$.
  - **With a 40 MHz Clock ($f_{sys} = 40\text{ MHz}$)**:
    - $t_q = 25\text{ ns}$, giving $N_{tq} = 8\ t_q$.
    - Conforming to **CiA 601-2**, bit timing is configured with:
      - $\text{Sync\_Seg} = 1\ t_q$ (25 ns)
      - $\text{Prop\_Seg} + \text{Phase\_Seg1} = 5\ t_q$ (125 ns)
      - $\text{Phase\_Seg2} = 2\ t_q$ (50 ns)
      - **Sample Point**: $\frac{1 + 5}{8} = \mathbf{75.0\%}$ (exact CiA 601-2 standard for 5 Mbps).
      - $\text{SJW} = 2\ t_q$ (50 ns), providing generous tolerance for transceiver phase jitter.
  - **With a 20 MHz Clock ($f_{sys} = 20\text{ MHz}$)**:
    - $t_q = 50\text{ ns}$, giving $N_{tq} = 4\ t_q$.
    - Minimum SJW of $1\ t_q$ represents a full $25\%$ of bit duration, resulting in coarse phase resynchronization quantization jitter. While not an intrinsic silicon prohibition, 20 MHz leaves narrow margin for transceiver loop delay variation at 5 Mbps.
  - **Engineering Directive**: We strongly prioritize and verify **40 MHz oscillators** on purchased Waveshare HATs for robust 5 Mbps operation on the Infotainment domain (`can2`). For 2 Mbps domains (`can0`, `can1`, `can3`), both 20 MHz and 40 MHz are fully capable.

---

### 2.3 Galvanic Isolation, Grounding & Termination Strategy

* **Galvanic Isolation Boundaries**:
  - The [Waveshare 2-CH CAN FD HAT](https://www.waveshare.com/2-CH-CAN-FD-HAT.htm) features onboard high-speed digital isolators providing up to **5 kV galvanic isolation** between the Raspberry Pi host (40-pin GPIO, SPI0, 3.3V logic) and the isolated transceiver bus domain.
  - This isolation prevents differential transients, ground loops, or high-voltage inductive spikes on the vehicle harness from damaging the Raspberry Pi BCM2712 SoC.
* **Common Signal Ground Reference (`CAN_GND`)**:
  - While the Pi logic domain is isolated from the transceivers, **all CAN transceivers on the same physical bus must share a common signal ground reference (CAN_GND)**.
  - Floating transceiver grounds can easily cause the common-mode bus voltage to drift outside the ISO 11898-2 specified range ($-2.0\text{ V} \le V_{CM} \le +7.0\text{ V}$), resulting in bit reception errors or transceiver damage.
  - **Harness Requirement**: All cable runs must use 3-conductor shielded twisted pair (STP): twisted CAN_H / CAN_L conductors with an integrated ground drain wire tied to CAN_GND on both endpoints.
* **Built-in vs. External Split Termination**:
  - The Waveshare HAT features onboard switchable $120\ \Omega$ terminal resistors via slide switches. The CANable 2.0 USB adapters also feature onboard $120\ \Omega$ toggle switches.
  - **Rule**: If onboard $120\ \Omega$ terminators are enabled on the two boundary nodes of each bus, **do NOT install external termination resistors**. Parallel terminators would drop equivalent DC resistance to $40\ \Omega$ or $30\ \Omega$, collapsing differential voltage below the $0.9\text{ V}$ receiver threshold.
  - **Split Termination Application**: External split termination ($2\times 60\ \Omega$ + center $4.7\text{ nF}$ capacitor tied to CAN_GND) provides superior common-mode RF noise suppression ($f_c \approx 1.13\text{ MHz}$) on the 5 Mbps bus. **External split termination may only be installed if the onboard $120\ \Omega$ switches on the HAT and USB adapters are explicitly set to OFF.**
  - **Pre-Power Verification**: Measure with a digital multimeter across CAN_H and CAN_L: **DC resistance must read between $58\ \Omega$ and $62\ \Omega$ on all 4 buses.**
* **TVS Diode Protection for 8 Exposed Endpoints**:
  - Each of the 4 independent physical buses has 2 endpoints (Gateway side and Simulator side), totaling **8 physical bus endpoints**.
  - Procurement mandates **8 TVS-protected endpoints** (using bidirectional automotive TVS diodes such as NXP PESD2CAN or Littelfuse AQ24CAN-02HTG across CAN_H/CAN_L/CAN_GND) unless every selected commercial adapter is verified to have onboard TVS protection on every port.

---

### 2.4 Authenticated Wire Layout Reconciliation (64 Bytes Strict)

#### The Protocol Incompatibility Issue in Phase 2
In Phase 2 simulation (`complete_3tier_cisg_ids.py`), frames were constructed with variable-length JSON string payloads and explicit 16-byte random nonces:
`[CAN ID: 4B][Counter: 4B][Nonce: 16B][Ciphertext: NB][Tag: 16B]`.
For typical telemetry strings, the serialized payload exceeded 80–120 bytes. While the Linux `vcan` interface allows oversized packets, physical CAN-FD hardware (ISO 11898-1:2015) enforces a hard physical maximum payload ceiling of **64 bytes** (DLC 15). Transmitting frames $>64$ bytes immediately triggers kernel `EMSGSIZE` (Message too long) and aborts transmission.

#### Phase 4 Fixed 64-Byte Binary Framing
Phase 4 reconciles the wire protocol with physical CAN-FD framing by standardizing on the DockerLab binary telemetry layout (`>9fI` = 40 bytes) and deriving the 16-byte Ascon nonce in-memory rather than sending it over the wire:

```
+--------------------------------------------------------------------------------+
|                          STRICT 64-BYTE CAN-FD FRAME                           |
+------------------------+------------------------------------+------------------+
|  Bytes 0-7 (8 Bytes)   |       Bytes 8-47 (40 Bytes)        |  Bytes 48-63     |
| Plaintext Header (AD)  |         Ciphertext Payload         |  (16 Bytes)      |
+------------------------+------------------------------------+------------------+
| can_id   | monotonic   |  struct.pack(">9fI", ...)          | Ascon-AEAD128    |
| (4B uint)| counter(4B) |  (9 kinematic floats + CAN ID)     | Full 128-bit Tag |
+------------------------+------------------------------------+------------------+
```

1. **Header / Associated Data (Bytes 0–7, 8 Bytes)**:
   - Plaintext `can_id` (4-byte unsigned big-endian integer, `>I`).
   - Plaintext `counter` (4-byte unsigned big-endian integer, `>I`).
   - Passed to Ascon-AEAD128 as Associated Data (AD) for cryptographic integrity verification.
2. **Ciphertext Payload (Bytes 8–47, 40 Bytes)**:
   - Plaintext is binary-serialized using `struct.pack(">9fI", f0, f1, f2, f3, f4, f5, f6, f7, f8, can_id)`, packing 9 primary 32-bit floating-point kinematic channels (speed, rpm, steering, brake, 4 wheel speeds, coolant temp) plus CAN ID.
   - Encrypted in-place via Ascon-AEAD128, producing exactly 40 bytes of ciphertext.
3. **Authentication Tag (Bytes 48–63, 16 Bytes)**:
   - Full 128-bit Ascon-AEAD128 authentication tag.
4. **Total Frame Length**: $8 + 40 + 16 = \mathbf{64\text{ Bytes}}$ (exact physical CAN-FD DLC 15).

#### Nonce Derivation, Anti-Replay & Key Re-negotiation Rules
- **Deterministic In-Memory Derivation**: Both sender and receiver construct the required 16-byte Ascon nonce in RAM without consuming bus bandwidth:
  $$\text{Nonce} = \text{struct.pack}(">II",\ \text{can\_id},\ \text{counter}) + \mathtt{b"\backslash x00" \times 8}$$
- **Anti-Replay Window**:
  - The monotonic counter starts at $\text{counter} = 1$ upon session establishment. ($\text{counter} = 0$ is reserved for boot-time attestation).
  - The Gateway maintains the highest verified counter $\text{Counter}_{\text{max}}[\text{can\_id}]$. Any incoming frame with $\text{counter} \le \text{Counter}_{\text{max}}[\text{can\_id}]$ is dropped immediately at Tier 1 with zero decryption overhead.
- **Counter Rollover & Key Rotation Policy**:
  - A 32-bit counter supports $2^{32} - 1 = 4,294,967,295$ frames. At a sustained 1,000 frames/sec on a high-throughput domain, exhaustion would require $>49.7$ days of continuous driving.
  - **Threshold Rule**: If the counter reaches `0xEFFFFFFF` ($4,026,531,839$ frames, 93.75% of capacity) OR upon any ECU / Gateway reboot, a mandatory **Session Key Rotation** is executed via ML-KEM-512 over the OBD-II/Backbone link.
  - Upon session key rotation, a fresh 128-bit Ascon session key $K_{\text{session}}$ is installed and the monotonic counter is securely reset to 1.
  - This guarantees that for any given session key, the tuple $(K_{\text{session}}, \text{can\_id}, \text{counter})$ is strictly unique, preventing Ascon nonce reuse.

---

## 3. Physical Measurement & Signal Integrity Instrumentation

### 3.1 Replacement of Generic 24 MHz Logic Analyzer
- **The Technical Flaw**: A generic 8-channel 24 MHz USB logic analyzer samples at $24\text{ MS/s}$. At a 5 Mbps CAN-FD data rate ($t_{bit} = 200\text{ ns}$), this yields only **$4.8$ samples per bit**. Under Nyquist-Shannon sampling principles, $4.8$ samples/bit cannot resolve transceiver propagation delay, edge rise/fall times ($10 - 20\text{ ns}$), phase ringing, or bit-stuffing transitions.
- **Protocol Decoding Constraint**: Saleae Logic’s native software decodes standard Classic CAN; CAN-FD decoding is **community-supplied** ([Saleae Protocol Support Reference](https://www.saleae.com/support/community-contact/community-shared-protocols)). Furthermore, logic analyzers cannot directly measure differential bus voltages ($V_{DIFF} = V_{CAN\_H} - V_{CAN\_L}$) without an external transceiver or differential probe.
- **The Legitimate Physical Evidence Protocol**:
  1. **Protocol & Traffic Evidence**: Full packet-level forensics, inter-frame arrival jitter, byte-level decryption, and timestamping are captured directly via Linux SocketCAN tools (`candump -tz`, `tcpdump`, and `wireshark` via virtual/physical CAN taps).
  2. **Physical Layer & Signal Integrity Evidence**: Differential voltage levels ($V_{DIFF} \ge 1.5\text{ V}$ dominant, $0\text{ V}$ recessive), split-termination common-mode filtering, bit-rate switching transitions (BRS), and cable ringing are captured using a **Digital Storage Oscilloscope (DSO)** with $\ge 1\text{ GS/s}$ real-time sampling (e.g. Rigol DS1054Z rated at 50 MHz bandwidth, or Siglent SDS1104X-E rated at 100 MHz bandwidth).

### 3.2 DSO Differential Measurement & Ground Clip Safety Hazard

> [!CAUTION]
> **Mains Earth Ground Short Hazard with Oscilloscope Probes:**
> On standard benchtop oscilloscopes (such as the Rigol DS1054Z or Siglent SDS1104X-E), the outer ground ring and crocodile ground clip of every passive probe are **electrically bonded to the mains chassis Earth Ground**.
> If an engineer clips a standard probe ground lead directly to $CAN\_L$ while the USB adapter or Raspberry Pi power supply has a ground return path, **$CAN\_L$ is short-circuited directly to mains earth ground**. This collapses the differential bus voltage, causes heavy common-mode ground loop currents, and can destroy the CAN transceiver or the USB host port!

#### Mandatory Safe Oscilloscope Probing Procedure:
To safely measure differential CAN-FD waveforms without isolated probes:
1. **Two-Channel Math Subtraction Mode (`CH1 - CH2`)**:
   - Connect Channel 1 probe tip to **CAN_H**.
   - Connect Channel 2 probe tip to **CAN_L**.
   - Connect **BOTH probe crocodile ground clips ONLY to the isolated signal ground (CAN_GND)** on the transceiver terminal block. **NEVER** connect a ground clip to CAN_L.
   - Configure the oscilloscope Math function: $$\text{Math} = \text{CH1} - \text{CH2}$$
   - Set Channel 1 and Channel 2 to identical vertical gain (e.g., $1.0\text{ V/div}$), DC coupling, and identical probe attenuation ($10\times$).
   - The resulting Math trace displays the true differential voltage $V_{DIFF} = V_{CAN\_H} - V_{CAN\_L}$ cleanly isolated from common-mode voltage offsets.
2. **Alternative Safe Methods**:
   - Use a dedicated active differential probe (e.g., Micsig DP10007, 100 MHz, 700V differential rating).
   - Use a fully isolated, battery-powered handheld oscilloscope (e.g., Siglent SHS800 or Hantek 2D72).

---

## 4. Model Architecture & Latency Benchmark Target

### 4.1 Model Architecture Reconciliation: 14D Kinematic LSTM-Autoencoder
- To eliminate ambiguity across project documentation:
  - The deployed model is the **14D Physical Kinematics LSTM-Autoencoder** ($24,654$ parameters), as trained in `can_ids_lstm_physical.ipynb` and exported to ONNX in Phase 2.
  - **Architecture**:
    - Input: $(W=30, D=14)$
    - Encoder: $\text{LSTM}(14, 32) \rightarrow \text{ReLU} \rightarrow \text{LSTM}(32, 16) \rightarrow h_n[-1]$
    - Decoder: $\text{Repeat}(30) \rightarrow \text{LSTM}(16, 32) \rightarrow \text{ReLU} \rightarrow \text{LSTM}(32, 32) \rightarrow \text{ReLU} \rightarrow \text{Linear}(32, 14)$
  - **Deployed Artifacts**: `v30_physical_kinematics_dynamic_int8.onnx` (72.86 KB) and `v30_physical_kinematics_fp32.onnx` (50.44 KB).

### 4.2 Latency Target Nuance (Benchmark Target vs. Guaranteed Metric)
- In Phase 3 benchmarking on isolated Cortex-A72 hardware, single-window INT8 inference achieved $0.82\text{ ms}$.
- On the **Raspberry Pi 5 (Cortex-A76 @ 2.4 GHz)**, raw compute latency will be significantly faster ($\approx 0.35 - 0.50\text{ ms}$).
- **Document Directive**: We treat the **$0.82\text{ ms}$ inference time as an empirical benchmark target**, not a guaranteed theoretical ceiling. The actual end-to-end processing latency (including SPI/USB frame ingress, Ascon tag verification, invariant checking, LSTM reconstruction, and ZOH state swap) **must be empirically measured on the final Pi 5 hardware under live 5 Mbps Red Team flood load**.
- **Core Isolation Protocol**:
  - Add `isolcpus=3` to `/boot/cmdline.txt` on the Gateway Pi 5.
  - Pin the CISG IDS daemon to isolated Core 3: `sudo chrt -f 98 taskset -c 3 python3 gateway_physical_daemon.py`.
  - Route SPI0 and USB network interrupts to Cores 1 and 2, reserving Core 0 for OS housekeeping and INA226 logging.

---

## 5. Staged Procurement & Commissioning Plan

To de-risk hardware integration and manage capstone expenditure responsibly, procurement is structured into **4 sequential stages**:

```
[ STAGE 1: Minimal Dual-Bus Bring-up ]
  • Buy 1x Pi 5 (8GB) + 1x Waveshare 2-CH CAN FD HAT + 3x CANable 2.0 USB Adapters
  • Use existing Linux Laptop as Node 2
  • Gateway: 1 HAT ch0 + 1 USB ch2; Laptop: 2 USB adapters (ch0 & ch2)
  • Bring up 1x 500k/2M bus (Bus 0: Safety) and 1x 1M/5M bus (Bus 2: Infotainment)
               │
               ▼
[ STAGE 2: Communication & Timing Proof ]
  • Validate 64-byte frame transmission, Ascon decryption, and 40 MHz clock timing
  • Verify sample point (75%) and TDC stability on 5 Mbps link
  • Benchmark SocketCAN frame delivery rates and packet loss
               │
               ▼
[ STAGE 3: Full 4-Bus Expansion ]
  • Procure remaining adapters (3x CANable 2.0 USB Adapters -> 6 total)
  • Wire all 4 physical buses (Safety, Comfort, Infotainment, OBD-II)
  • Execute full Red Team attack suite (flooding, fuzzing, masquerade streaming)
  • Measure empirical Gateway latency under flood conditions
               │
               ▼
[ STAGE 4: Power Profiling & Physical Layer Evidence ]
  • Procure INA226 I2C sensor + 10 mOhm 3W shunt and tap 5V Gateway power rail
  • Execute Batch Differential Energy Profiling (Ascon µJ, ML-DSA mJ, ONNX µJ)
  • Capture physical layer differential waveforms on DSO using CH1-CH2 math mode
```

---

## 6. Comprehensive Bill of Materials (BOM) — Staged Breakdown

### Stage 1: Minimal Dual-Bus Bring-Up (Immediate Purchase)

| Item | Component Description | Specifications / Chipset | Qty | Unit Price Band (INR) | Total (INR) | Est. Total (USD) | Verified Sourcing Channels | Direct Purchase / Amazon Link |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **S1.1** | Raspberry Pi 5 (Model B) | BCM2712 quad-core Cortex-A76 @ 2.4 GHz | 1 | ₹5,251.00 (Silverline) | ₹5,251.00 | ~$63.00 | Silverline Electronics | [Silverline Pi 5 Model B](https://www.silverlineelectronics.in/products/raspberry-pi-5-model-b-1gb-ram-in-stock?src=raspberrypi) |
| **S1.2** | Official 27W USB-C Power Supply | 5.1V / 5.0A custom PD profile for Pi 5 | 1 | ₹1,499.00 | ₹1,499.00 | ~$18.00 | Amazon India | [Amazon.in Official 27W Supply](https://www.amazon.in/PiDuino-Official-Raspberry-USB-C-Supply/dp/B0CK883VVC?th=1) |
| **S1.3** | Official Pi 5 Active Cooler | Aluminum heatsink + PWM blower fan | 1 | ₹699.00 | ₹699.00 | ~$8.40 | Amazon India | [Amazon.in Active Cooler (SC1148)](https://www.amazon.in/Raspberry-Pi-Active-Cooler/dp/B0CLXZBR5P) |
| **S1.4** | Waveshare 2-CH CAN FD HAT (SKU 17075) | 2× MCP2518FD, isolated, **40 MHz Crystal** | 1 | ₹6,269.00 | ₹6,269.00 | ~$75.20 | Robu.in | [Robu.in Waveshare 2-CH HAT](https://robu.in/product/waveshare-2-channel-isolated-can-fd-expansion-hat-for-raspberry-pi-multi-protections/) |
| **S1.5** | CANable 2.0 / USB-CAN-FD Adapters | STM32G431C8 (170MHz), candleLight/`gs_usb` (Stage 1: 3) | 3 | ₹3,674.00 | ₹11,022.00 | ~$132.20 | Amazon India | [Amazon.in CANable 2.0 (Gugxiom)](https://www.amazon.in/CANable-Module-Analyzer-Adapter-Converter/dp/B0DN67KQFP) |
| **S1.6** | Bus Cabling: StarTech Cat6 1ft (4 Pairs) | 4 twisted pairs ($Z_0 \approx 100\ \Omega$), CAN_GND reference | 1 cable | ₹436.00 | ₹436.00 | ~$5.20 | Mouser India | [StarTech Cat6 1ft on Mouser](https://www.mouser.in/en/ProductDetail/StarTech/C6PATCH1BL?qs=PBDs2xEllI8Sz7PYTPk00A%3D%3D) |
| **S1.7** | Split Termination Passives | Onboard 120Ω switches (Stage 1) / Passives | 1 set | ₹0.00 (onboard) / ₹343.36 | ₹0.00 | $0.00 | Onboard switches / Mouser & Amazon | [TE 62Ω on Mouser](https://www.mouser.in/en/ProductDetail/TE-Connectivity-Holsworthy/1622771-1?qs=sGAEpiMZZMsPqMdJzcrNwhXxdF3DyUQnmUvK%252BKOsIOE%3D) + [4.7nF Cap](https://www.amazon.in/4-7NF-50V-MLCC-CAPACITOR-CAPCITOR/dp/B0DXPYVYG5) |
| **S1.8** | SanDisk Extreme 64GB MicroSD Card | U3 / A2 / V30 high-speed card for Pi 5 OS | 1 | ₹2,579.00 (or ₹0 lab spare) | ₹2,579.00 | ~$31.00 | Amazon India | [Amazon.in SanDisk Extreme 64GB (A2)](https://www.amazon.in/SanDisk-Extreme-microSD-Smartphones-Action/dp/B0B2DDJGF8) |
| **Stage 1 Subtotal** | — | — | — | — | **₹27,755.00** | **~$333.00** | **Ready to Order** | — |

---

### Stage 2 & 3: Full 4-Bus Expansion

| Item | Component Description | Specifications / Chipset | Qty | Unit Price Band (INR) | Total (INR) | Est. Total (USD) | Verified Sourcing Channels | Direct Purchase / Amazon Link |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **S3.1** | CANable 2.0 / USB-CAN-FD Adapters | Remaining 3 adapters to complete 6-adapter link | 3 | ₹3,674.00 | ₹11,022.00 | ~$132.20 | Amazon India | [Amazon.in CANable 2.0 (Gugxiom)](https://www.amazon.in/CANable-Module-Analyzer-Adapter-Converter/dp/B0DN67KQFP) |
| **S3.2** | Bidirectional Automotive TVS Diode Array | Littelfuse AQ24CANFD-02HTG / PESD2CAN (8 ports) | 8 | ₹75.48 | ₹603.84 | ~$7.25 | Mouser India | [Mouser India AQ24CANFD](https://www.mouser.in/en/ProductDetail/Littelfuse/AQ24CANFD-02HTG?qs=f9yNj16SXrJ5gIpyuxo44w%3D%3D) |
| **S3.3** | Screw Terminal Blocks & DuPont Jumpers | 2.54mm screw terminals (₹119) + Prakti jumpers (₹90) | 1 set | ₹209.00 | ₹209.00 | ~$2.50 | Amazon India | [Amazon.in Terminals](https://www.amazon.in/2-54mm-pitch-2-pin-Screw-Terminal/dp/B0BT297BSD) + [Prakti Jumpers](https://www.amazon.in/Prakti-Female-Jumper-Breadboard-DuPont/dp/B0C86QVK2P) |
| **Stage 2/3 Subtotal** | — | — | — | — | **₹11,834.84** | **~$142.00** | **Procure after Stage 2 passes** | — |

---

### Stage 4: Power Profiling & Physical Layer Evidence

| Item | Component Description | Specifications / Chipset | Qty | Unit Price Band (INR) | Total (INR) | Est. Total (USD) | Verified Sourcing Channels | Direct Purchase / Amazon Link |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **S4.1** | INA226 I2C Power Sensor Module | 16-bit ADC, $I^2C$ bus monitoring module | 1 | ₹124.00 | ₹124.00 | ~$1.50 | Robu.in | [Robu.in INA226 Module](https://robu.in/product/ina226-voltage-current-and-power-monitor-module/) |
| **S4.2** | Precision Current Shunt Resistor | **$10\text{ m}\Omega$ ($0.01\ \Omega$), 1W, 1%** (Dale WSL2512) | 1 | ₹51.25 | ₹51.25 | ~$0.62 | Mouser India | [Mouser WSL2512R0100FEA](https://www.mouser.in/en/ProductDetail/Vishay-Dale/WSL2512R0100FEA?qs=ViWNInbc%252BeXwSjGbk51Nog%3D%3D) |
| **S4.3** | Oscilloscope / Differential Probe Access | Lab Digital Storage Oscilloscope (100MHz+ DSO) | 1 | Lab Access / ₹0 | ₹0.00 | $0.00 | University Department Lab | — |
| **Stage 4 Subtotal** | — | — | — | — | **₹175.25** | **~$2.10** | **Final Phase** | — |

**Grand Total Expenditure (Full 4-Bus Testbed with 6 USB Adapters + Tooling):**
- **Exact Live Verified Baseline: ₹39,765.09 INR (~$477 USD)**.
- **Cost-Optimized (Lab spare MicroSD + Direct Import Adapters): ~₹26,121.09 INR (~$313 USD)**.

---

## 7. Batch Differential Energy Profiling Protocol (INA226 with $10\text{ m}\Omega$ Shunt)

### 7.1 Hazard Analysis of Default $0.1\ \Omega$ Module Shunt
Off-the-shelf INA226 breakout boards (e.g. CJMCU-226) ship with an onboard $0.1\ \Omega$ ($100\text{ m}\Omega$) 1206 SMD resistor. Placing this onboard shunt in series with the 5V power supply rail of a Raspberry Pi 5 presents a critical hardware hazard:
1. **Catastrophic Voltage Drop & Under-Voltage Brownout**:
   - Under heavy processing load (BCM2712 @ 2.4 GHz + Active Cooler + 2× USB-CAN adapters), the Pi 5 draws up to $5.0\text{ A}$.
   - Across a $0.1\ \Omega$ shunt, the voltage drop is:
     $$V_{\text{drop}} = I \times R = 5.0\text{ A} \times 0.1\ \Omega = \mathbf{0.50\text{ V}}$$
   - If the power supply delivers $5.10\text{ V}$, the voltage arriving at the Raspberry Pi 5 PMIC collapses to:
     $$V_{\text{Pi5}} = 5.10\text{ V} - 0.50\text{ V} = \mathbf{4.60\text{ V}}$$
   - The Raspberry Pi 5 PMIC declares an under-voltage fault at $<4.80\text{ V}$ and triggers an emergency hardware brownout reset at $\approx 4.63\text{ V}$, causing immediate kernel crashes during high-load cryptanalysis or model inference.
2. **Thermal Destruction of the Shunt Resistor**:
   - The power dissipated in the shunt resistor is:
     $$P_{\text{dissipated}} = I^2 \times R = (5.0\text{ A})^2 \times 0.1\ \Omega = \mathbf{2.50\text{ W}}$$
   - A standard 1206 SMD package is rated for only $0.25\text{ W}$ (or $0.5\text{ W}$ maximum). Subjecting it to $2.5\text{ W}$ causes instantaneous thermal runaway, solder reflow, and permanent burnout.

### 7.2 The Precision $10\text{ m}\Omega$ Kelvin Shunt Solution
To eliminate the brownout hazard while retaining micro-Joule measurement capability, the onboard $0.1\ \Omega$ resistor is removed/bypassed and replaced with an **external $10\text{ m}\Omega$ ($0.01\ \Omega$), 3W precision metal-strip shunt** (e.g., Vishay Dale WSL2512 or Bourns CSS2H 4-terminal Kelvin connection):
- **Safe Voltage Drop at 5.0A**:
  $$V_{\text{drop}} = 5.0\text{ A} \times 0.01\ \Omega = \mathbf{0.05\text{ V}}\ (50\text{ mV})$$
  The voltage supplied to the Pi 5 is $5.10\text{ V} - 0.05\text{ V} = \mathbf{5.05\text{ V}}$, well within the $\pm 5\%$ operating window ($4.85\text{ V} - 5.25\text{ V}$).
- **Safe Power Dissipation at 5.0A**:
  $$P_{\text{dissipated}} = (5.0\text{ A})^2 \times 0.01\ \Omega = \mathbf{0.25\text{ W}}$$
  A 3W-rated shunt operates at just $8.3\%$ of its thermal capacity, remaining virtually cold and preventing thermal drift.
- **Dynamic Range & Measurement Resolution**:
  - INA226 full-scale differential shunt voltage range is $V_{\text{shunt\_max}} = \pm 81.92\text{ mV}$ ($2.5\ \mu\text{V}$ per LSB).
  - Maximum measurable current with $10\text{ m}\Omega$:
    $$I_{\text{max}} = \frac{81.92\text{ mV}}{0.01\ \Omega} = \mathbf{8.192\text{ A}}$$
    (Perfect coverage for the $0 - 5.0\text{ A}$ operating envelope).
  - Current Measurement Resolution:
    $$\text{Current LSB} = \frac{2.5\ \mu\text{V}}{0.01\ \Omega} = \mathbf{0.25\text{ mA}}$$
    (Yields $0.25\text{ mA} \times 5.0\text{ V} = 1.25\text{ mW}$ instantaneous power resolution).

### 7.3 Dual-Conversion Timing & Calibration
The INA226 performs two separate internal ADC conversions per power calculation: one for the Shunt Voltage ($V_{\text{shunt}}$) and one for the Bus Voltage ($V_{\text{bus}}$).
- When configured for the highest-precision single conversion time of $140\ \mu\text{s}$:
  $$T_{\text{sample}} = T_{\text{shunt}} + T_{\text{bus}} = 140\ \mu\text{s} + 140\ \mu\text{s} = \mathbf{280\ \mu\text{s}}$$
- This allows a continuous measurement rate of $\approx 3,571\text{ full power samples/second}$.
- With internal hardware averaging set to 16 samples ($280\ \mu\text{s} \times 16 = 4.48\text{ ms}$), electrical noise is suppressed below $10\ \mu\text{V}$.

### 7.4 Batch Differential Energy Profiling Protocol
Because the Raspberry Pi 5 PMIC contains large bulk decoupling capacitors ($>200\ \mu\text{F}$) that smooth instantaneous microsecond current spikes, measuring a single isolated Ascon verification ($<15\ \mu\text{s}$) directly is physically impossible due to capacitance filtering. 

We solve this using the **Batch Differential Energy Profiling Protocol**:
1. **Phase 1: Baseline Integration**: Measure quiescent idle power $P_{\text{idle}}$ over duration $\Delta T_{\text{idle}}$:
   $$E_{\text{idle}} = \sum_{t=0}^{\Delta T_{\text{idle}}} V(t) \cdot I(t) \cdot \Delta t, \quad P_{\text{idle}} = \frac{E_{\text{idle}}}{\Delta T_{\text{idle}}}$$
2. **Phase 2: Burst Integration**: Execute a deterministic loop of $N$ consecutive operations ($N = 100,000$ for Ascon-AEAD128; $N = 5,000$ for ONNX INT8 inference; $N = 500$ for ML-DSA-44 verify) over duration $\Delta T_{\text{burst}}$:
   $$E_{\text{burst}} = \sum_{t=0}^{\Delta T_{\text{burst}}} V(t) \cdot I(t) \cdot \Delta t$$
3. **Phase 3: Marginal Operation Energy**:
   $$E_{\text{operation}} = \frac{E_{\text{burst}} - \left( P_{\text{idle}} \times \Delta T_{\text{burst}} \right)}{N}$$
   This protocol averages out switching regulator ripple, eliminates background OS baseline noise, and yields publication-grade empirical energy metrics:
   - **ML-DSA-44 Boot Attestation Energy** ($E_{\text{attest}}$ in mJ)
   - **Ascon-AEAD128 Wire Verification Energy** ($E_{\text{crypto}}$ in $\mu$J/frame)
   - **Tier 2 ONNX INT8 LSTM-Autoencoder Inference Energy** ($E_{\text{IDS}}$ in $\mu$J/window)

---

## 8. Formal Acceptance Criteria Matrix

The Phase 4 HIL Testbed deployment must pass all quantitative criteria in the following matrix before commencement of formal Red Team attack evaluation:

| Category | Parameter / Metric | Baseline / Target Requirement | Pass / Fail Threshold | Verification Method / Instrument |
| :--- | :--- | :--- | :--- | :--- |
| **Physical Layer** | DC Bus Termination Resistance | $60\ \Omega$ nominal ($2\times 120\ \Omega$ in parallel) | **$58.0\ \Omega \le R_{\text{bus}} \le 62.0\ \Omega$** | Digital Multimeter across CAN_H and CAN_L (all nodes unpowered) |
| **Physical Layer** | Dominant Differential Voltage | $V_{DIFF} = V_{CAN\_H} - V_{CAN\_L} \ge 1.5\text{ V}$ | **$1.50\text{ V} \le V_{DIFF} \le 3.00\text{ V}$** | Oscilloscope 2-Channel Math (`CH1 - CH2`), ground clips on CAN_GND |
| **Physical Layer** | Recessive Differential Voltage | $V_{DIFF} = 0.0\text{ V}$ nominal | **$-0.50\text{ V} \le V_{DIFF} \le +0.50\text{ V}$** | Oscilloscope 2-Channel Math (`CH1 - CH2`), ground clips on CAN_GND |
| **Data Link Layer** | Nominal Bitrate (Arbitration) | 500 kbps (Buses 0,1,3) / 1 Mbps (Bus 2) | **Zero bit-timing configuration errors** | SocketCAN link setup (`ip link set canX up`) |
| **Data Link Layer** | Fast Bitrate (Data Phase) | 2 Mbps (Buses 0,1,3) / 5 Mbps (Bus 2) | **Sample Point $= 75.0\%$ (5M), $80.0\%$ (2M)** | Controller bit timing dump (`ip -d link show canX`) |
| **Data Link Layer** | Transmitter Delay Compensation | TDC enabled with TDCO $= 150\text{ ns}$ on 5 Mbps link | **Zero protocol phase inversion errors** | SocketCAN driver status flags |
| **Network Layer** | Frame Delivery & Packet Loss | $10^6$ continuous baseline frames per bus | **Packet Loss $< 0.01\%$ ($<100$ drops in $10^6$)** | `cangen` / `candump` packet sequence counter audit |
| **Network Layer** | CAN Controller Error States | Transmit/Receive Error Counters (TEC/REC) | **$\text{TEC} = 0,\ \text{REC} = 0$, Bus-Off $= 0$** | `ip -details -statistics link show canX` |
| **Cryptography** | Ascon-AEAD128 Wire Tag Verify | Line-rate verification on ingress frames | **Mean $< 15\ \mu\text{s}$, $P_{99} < 25\ \mu\text{s}$** | High-resolution timestamping in C / Python gateway daemon |
| **Cryptography** | Replay Detection Accuracy | Injected replayed counter frames | **$100.0\%$ Detection (Zero Replays Passed)** | Red Team replay injection test (`v4_wire_codec`) |
| **Machine Learning** | Tier 2 ONNX INT8 LSTM Inference | 14D Kinematics Autoencoder on Core 3 | **Benchmark Target $\le 0.82\text{ ms}$, Max $< 1.0\text{ ms}$** | `onnxruntime` latency profiler pinned to isolated Core 3 |
| **Thermal / Stability**| Pi 5 Thermal State Under Flood | 5 Mbps Red Team flood load for 30 minutes | **$T_{\text{SoC}} < 70.0^\circ\text{C}$ (Zero throttling)** | `vcgencmd measure_temp` and `vcgencmd get_throttled` |
| **Energy Profiling** | Power Measurement Confidence | Batch profiling ($N=100k$ Ascon, $N=5k$ ONNX) | **$95\%$ Confidence Interval relative error $< 5\%$** | INA226 statistical aggregation script |
