# Phase 4 Hardware-in-the-Loop (HIL) Testbed — Component Procurement & Sourcing Guide

**Document Version:** 1.1 (Audit-Rectified & Procurement-Ready)  
**Project:** Secure Segmented CAN-FD Architecture with PQC and Gateway-Side FL-IDS  
**Target Phase:** Phase 4 Hardware-in-the-Loop Deployment  
**Lead Author:** Tapan (23BDS1151) — ML/Data Architecture & Cryptography  
**Infrastructure Collaborators:** Kaustuv (Hardware Infrastructure), Kunal (Red Team Threat Emulation)  
**Last Updated:** September 2026  

---

## 1. Executive Summary & Testbed Overview

Phase 4 validates our post-quantum in-vehicle network security architecture on physical hardware across four electrically independent, two-node CAN-FD buses:
1. **Safety / Powertrain Bus** (`can0`: 500 kbps nominal / 2 Mbps data)
2. **Comfort / Body Bus** (`can1`: 500 kbps nominal / 2 Mbps data)
3. **Infotainment / Telematics Bus** (`can2`: 1 Mbps nominal / 5 Mbps data — high-throughput hostile interface)
4. **Diagnostic OBD-II Bus** (`can3`: 500 kbps nominal / 2 Mbps data — isolated trust boundary)

### System Nodes & Interface Topology:
- **Node 1 (CISG Gateway / Device Under Test):** Raspberry Pi 5 (8 GB RAM) hosting Ascon-AEAD128 decryption (<15 µs in C), monotonic replay checking, and Tier 2 ONNX INT8 LSTM-Autoencoder anomaly inference (~0.5–0.82 ms target on isolated Core 3).
  - Interfaces: 1× Waveshare 2-CH CAN FD HAT (`can0`, `can1`) + 2× CANable 2.0 USB Adapters (`can2`, `can3`).
- **Node 2 (Vehicle Simulator & Red Team Attacker):** Existing Linux Laptop (EndeavourOS / Debian / Ubuntu) running 4 isolated Linux Network Namespaces (`ns_safety`, `ns_comfort`, `ns_telematics`, `ns_obd`) streaming synchronized vehicle kinematics and injecting attacks.
  - Interfaces: **4× CANable 2.0 USB Adapters** (one dedicated adapter for each physical bus endpoint `can0`, `can1`, `can2`, `can3`).
- **Total USB-CAN-FD Adapters Required:**
  - **Stage 1 (Dual-Bus: Bus 0 & Bus 2):** **3 Adapters** (Gateway: 1 USB adapter; Laptop: 2 USB adapters).
  - **Stage 3 (Full 4-Bus Expansion):** **6 Adapters Total** (Gateway: 2 USB adapters; Laptop: 4 USB adapters).

---

## 2. Master Bill of Materials (BOM) & Sourcing Directory

| # | Item Description | Primary Function / Need | Unit Cost (INR) | Testbed Qty | Total Cost (INR) | Approx. (USD) | Verified Sourcing Channels | Primary Sourcing Link | Direct Purchase / Amazon Link |
| :-: | :--- | :--- | :---: | :---: | :---: | :---: | :--- | :--- | :--- |
| **1** | **Raspberry Pi 5 (2 GB / 8 GB)** | Central Security Gateway (CISG / DUT) | ₹7,616 (2GB) – ₹8,499 (8GB) | 1 | ₹7,616 – ₹8,250 | ~$91.00 – $99.00 | Silverline, Robu.in | [Silverline 2GB](https://silverlineelectronics.in), [Robu.in Pi 5](https://robu.in) | [Amazon.in Pi 5 Search](https://www.amazon.in/s?k=Raspberry+Pi+5) *(Caution: scalpers)* |
| **2** | **Official 27W USB-C Power Supply** | 5.1V / 5.0A PD power delivery for Pi 5 under heavy I/O | ₹1,199 – ₹1,350 | 1 | ₹1,199 | ~$14.50 | Amazon India, Robu.in, Element14 | [Robu.in 27W Supply](https://robu.in) | [Amazon.in Official 27W Supply (White)](https://www.amazon.in/PiDuino-Official-Raspberry-USB-C-Supply/dp/B0CK883VVC?th=1) |
| **3** | **Official Pi 5 Active Cooler** | Heatsink + PWM fan to prevent thermal throttling | ₹499 – ₹599 | 1 | ₹499 | ~$6.00 | Amazon India, Robu.in, Silverline | [Robu.in Active Cooler](https://robu.in) | [Amazon.in Active Cooler (SC1148)](https://www.amazon.in/Raspberry-Pi-Active-Cooler/dp/B0CLXZBR5P) |
| **4** | **Waveshare 2-CH CAN FD HAT** (SKU 17075) | Safety & Comfort SPI0 buses (`can0`, `can1`), **40 MHz OSC** | ₹3,926 – ₹6,269 | 1 | ₹4,673 | ~$56.00 | Robu.in, Fab.to.Lab, Hubtronics | [Waveshare Wiki](https://www.waveshare.com/2-CH-CAN-FD-HAT.htm), [Fab.to.Lab](https://fabtolab.com) | [Robu.in Waveshare 2-CH HAT](https://robu.in/product/waveshare-2-channel-isolated-can-fd-expansion-hat-for-raspberry-pi-multi-protections/) |
| **5** | **CANable 2.0 / USB-CAN-FD (candleLight)** | Infotainment/OBD-II on Gateway (2) + All 4 buses on Laptop (4) | ₹3,899 (local) / ~$26 (import) | **6 Total** *(3 in S1, 3 in S3)* | ₹23,394 *(local)* / ~₹13,000 *(import)* | ~$280 (local) / ~$156 (import) | Amazon India, Probots India, Makerfabs | [Probots India](https://probots.co.in), [Makerfabs](https://www.makerfabs.com) | [Amazon.in CANable 2.0 (Gugxiom)](https://www.amazon.in/CANable-Module-Analyzer-Adapter-Converter/dp/B0DN67KQFP) |
| **6** | **Bus Cabling: Cat6 Twisted Pair (or Automotive STP)** | $100\text{–}120\ \Omega$ differential pairs for 5 Mbps CAN-FD + CAN_GND | ₹180 – ₹350 | 1 cable (4 pairs / 10m) | ₹180 – ₹350 | ~$2.20 – $4.20 | Amazon India, Robu.in, Local Retail | [Robu.in Automotive Cable](https://robu.in) | [Amazon.in Cat6 Patch Cable (4 Pairs)](https://www.amazon.in/s?k=Cat6+Ethernet+Patch+Cable+2m) *(Recommended)* |
| **7** | **SanDisk Extreme 64GB MicroSD** | High random 4K read/write speed (A2/V30) for OS & ONNX models | ₹650 – ₹750 | 1 | ₹650 | ~$8.00 | Amazon India, Local Retail | [Amazon.in SanDisk](https://amazon.in) | [Amazon.in SanDisk Extreme 64GB (A2/V30)](https://www.amazon.in/SanDisk-Extreme-microSD-Smartphones-Action/dp/B0B2DDJGF8) |
| **8** | **Passive Split Termination Pack** | $60\ \Omega$ / $62\ \Omega$ 1% resistors + $4.7\text{ nF}$ 50V ceramic caps | ₹150 / pack | 1 pack | ₹150 | ~$1.80 | Local Electronics Market, Amazon, Robu.in | Local market / Robu.in | [Amazon.in 4.7nF 50V Capacitor](https://www.amazon.in/4-7NF-50V-MLCC-CAPACITOR-CAPCITOR/dp/B0DXPYVYG5) |
| **9** | **Automotive TVS Diode Arrays (8 pcs)** | Littelfuse AQ24CANFD-02HTG (12pF, 24V, SOT-23) for 8 endpoints | ₹45 – ₹65 / piece | 8 | ₹520 | ~$6.20 | Mouser India, Element14 India | [Element14 India](https://in.element14.com) | [Mouser India AQ24CANFD-02HTG](https://www.mouser.in/en/ProductDetail/Littelfuse/AQ24CANFD-02HTG?qs=f9yNj16SXrJ5gIpyuxo44w%3D%3D) |
| **10**| **Screw Terminal Blocks & DuPont Jumpers** | Pluggable 2.54mm / 3.81mm terminal taps + 40-pin M-M/M-F jumper wires | ₹250 – ₹360 / set | 1 set | ₹315 | ~$3.80 | Amazon India, Local Electronics Market | [Amazon.in 2.54mm Terminals](https://www.amazon.in/2-54mm-pitch-2-pin-Screw-Terminal/dp/B0BT297BSD) | [Amazon.in 2.54mm Terminals (B0BT297BSD)](https://www.amazon.in/2-54mm-pitch-2-pin-Screw-Terminal/dp/B0BT297BSD) + [Prakti DuPont Jumpers (B0C86QVK2P)](https://www.amazon.in/Prakti-Female-Jumper-Breadboard-DuPont/dp/B0C86QVK2P) |
| **11**| **INA226 I2C Module + $10\text{ m}\Omega$ Shunt** | 16-bit power sensor + external **$10\text{ m}\Omega$ 3W** Kelvin shunt | ₹124 (mod) + ₹150 (shunt) | 1 set | ₹274 – ₹430 | ~$3.30 – $5.20 | Robu.in, Mouser India, Element14 | [Robu.in INA226 Module](https://robu.in/product/ina226-i2c-voltage-current-and-power-monitor-module/) | [Robu.in INA226 (₹124)](https://robu.in/product/ina226-i2c-voltage-current-and-power-monitor-module/) + [Mouser WSL2512 10mR Shunt](https://mouser.in) |
| **12**| **Oscilloscope Access (100MHz+ DSO)** | Differential voltage ($V_{DIFF}$) via **2-Channel Math (`CH1-CH2`)** | ₹0 (Lab Access) | 1 | ₹0 | $0.00 | University Engineering Department | College Hardware Lab | — |

---

## 3. Detailed Component Breakdown & Technical Justification

### 3.1 Compute & Power Infrastructure

#### 1. Raspberry Pi 5 (8 GB RAM)
* **Exact Role:** Central In-Vehicle Security Gateway (CISG / DUT).
* **Technical Need:** 
  * Running line-rate Ascon-AEAD128 verification, 4-bus packet routing, and real-time Tier 2 ONNX INT8 LSTM inference requires significant single-thread and memory throughput.
  * Broadcom BCM2712 quad-core Cortex-A76 @ 2.4 GHz delivers ~2.5× to 3× the integer and vector SIMD (NEON) performance of the Pi 4.
  * Dedicated Core 3 isolation (`isolcpus=3`) guarantees our ~0.5–0.82 ms inference target is never delayed by Linux OS housekeeping.
* **Price:** **₹7,999 – ₹8,499 INR (~$99.00 USD)** for bare board.
* **Where to Get:** **Silverline Electronics** or **Robu.in** (authorized distributors).
* **Critical Warning:** **Do NOT buy bare Pi 5 boards from third-party Amazon India sellers**, where marketplace scalpers inflate prices up to ₹18,000–₹23,889.

#### 2. Official Raspberry Pi 27W USB-C Power Supply (5.1V / 5.0A PD)
* **Exact Role:** Clean, low-ripple DC power supply for the Gateway.
* **Technical Need:** 
  * The Raspberry Pi 5 requires a custom USB-PD profile (5.1V @ 5A). Standard 15W USB-C chargers limit downstream USB power delivery to 600 mA, which causes under-voltage brownouts when two USB-CAN-FD adapters and an active cooler are connected simultaneously. The 27W supply unlocks the full 1.6A downstream USB current budget.
* **Price:** **₹1,199 – ₹1,350 INR (~$14.50 USD)**.
* **Where to Get:**
  * **Direct Amazon India Link:** [Raspberry Pi 5 Official 27W USB-C PD Power Supply - White (Amazon.in)](https://www.amazon.in/PiDuino-Official-Raspberry-USB-C-Supply/dp/B0CK883VVC?th=1)
  * **Authorized Distributors:** Robu.in, Silverline Electronics, Element14 India.

#### 3. Official Raspberry Pi 5 Active Cooler
* **Exact Role:** Thermal regulation and frequency stability under flood conditions.
* **Technical Need:** 
  * Under 5 Mbps Red Team flooding, all 4 cores and the PCIe/USB subsystem operate under heavy interrupt load. 
  * Without active cooling, BCM2712 hits $80^\circ\text{C}$ within 3 minutes, triggering hardware throttling down to 1.5 GHz or 1.0 GHz—doubling neural network inference latency and causing safety-critical FTTI violations. Active cooler keeps SoC $<65^\circ\text{C}$ indefinitely.
* **Price:** **₹499 – ₹599 INR (~$6.00 USD)**.
* **Where to Get:**
  * **Direct Amazon India Link:** [Raspberry Pi Active Cooler for Raspberry Pi 5 (SC1148) (Amazon.in)](https://www.amazon.in/Raspberry-Pi-Active-Cooler/dp/B0CLXZBR5P)
  * **Authorized Distributors:** Robu.in, Silverline, Fab.to.Lab.

#### 3b (Item 7). SanDisk Extreme 64GB MicroSD Card (A2 / V30 / U3)
* **Exact Role:** Primary Operating System & Runtime Boot Drive for the Gateway Raspberry Pi 5.
* **Technical Need & Why Local Storage is Mandatory (vs. Storing Data on Laptop):**
  * **No Onboard eMMC/Flash:** Unlike a laptop or PC, the Raspberry Pi 5 has *zero* internal flash storage. Without a local boot media, the Pi cannot boot the Linux kernel, initialize SocketCAN drivers, or run Python.
  * **OS Boot Drive vs. Telemetry Logging:** The MicroSD card acts as the **OS root drive** (hosting Raspberry Pi OS 64-bit, SocketCAN kernel modules, ONNX Runtime, Ascon cryptography routines, and the Gateway daemon). 
  * **Storing Experimental Data Directly on the Laptop:** **YES, this is fully supported and recommended!** All vehicle telemetry streams, attack traffic generation, and ground-truth timestamps on the Simulator side are stored directly on the laptop's internal NVMe SSD. The Pi 5 can also stream its detection alerts and latency metrics over Ethernet/SSH directly to the laptop in real-time, eliminating heavy write cycles to the card.
  * **Why A2 Performance Rating:** Cheap Class 10 / A1 cards experience random 4K write stalls of hundreds of milliseconds. The **A2 Application Performance Class** guarantees $\ge 4000\text{ Read IOPS}$ and $\ge 2000\text{ Write IOPS}$, preventing IO wait states during real-time IDS inference and cold-boot attestation.
* **Zero-Cost Alternatives:**
  * If the lab has any existing MicroSD card ($\ge 16\text{ GB}$) from an old phone/camera, or an unused **USB 3.0 flash drive** (the Pi 5 natively boots from USB 3.0), you can flash it with Raspberry Pi Imager and **skip purchasing a new card**.
* **Price:** **₹650 – ₹750 INR (~$8.00 USD)**.
* **Where to Get:**
  * **Direct Amazon India Link:** [SanDisk Extreme 64GB microSDXC UHS-I Memory Card (Amazon.in)](https://www.amazon.in/SanDisk-Extreme-microSD-Smartphones-Action/dp/B0B2DDJGF8)
  * **Local Retail:** Any authorized electronics / computer accessories store.

---

### 3.2 CAN-FD Physical Interfaces

#### 4. Waveshare 2-CH CAN FD HAT (SKU: 17075)
* **Exact Role:** Hardware interfaces for **Bus 0 (Safety / Powertrain)** and **Bus 1 (Comfort / Body)** on the Gateway.
* **Technical Need:** 
  * Features 2× Microchip MCP2518FD controllers and 2× MCP2562FD transceivers communicating over Pi SPI0 (CS0 & CS1).
  * Direct GPIO hard-interrupts (`irq/25-mcp2518f` and `irq/24-mcp2518f`) provide sub-80 µs latency for cyclic kinematic messages (ECM, ABS, Steering).
  * Onboard galvanic digital isolation (up to 5 kV) and built-in switchable $120\ \Omega$ termination resistors.
* **Price:** **₹3,926 – ₹6,269 INR (~$47.00 – $75.00 USD)**. (Fab.to.Lab: ₹3,926–₹4,673; Robu.in: ₹6,269 incl. GST).
* **Where to Get:**
  * **Direct Store Link (Robu.in):** [Waveshare 2-Channel Isolated CAN-FD Expansion HAT for Raspberry Pi (Robu.in)](https://robu.in/product/waveshare-2-channel-isolated-can-fd-expansion-hat-for-raspberry-pi-multi-protections/)
  * **Alternative Distributors:** Fab.to.Lab, Tanna TechBiz, Hubtronics, Evelta.
* **Procurement Rule:** Ensure order specifies **SKU 17075** (Isolated CAN-FD version). Upon receipt, visually inspect the metal crystal can next to the MCP2518FD chips to verify the **40 MHz** marking (`40.000` or `40M`).

#### 5. CANable 2.0 / candleLight USB-CAN-FD Adapters (6 Units Total)
* **Exact Role & Allocation**:
  - **Gateway (2 Units):** Provides `can2` (Infotainment — 5 Mbps) and `can3` (OBD-II — 2 Mbps). Completely offloads the SPI0 bus.
  - **Vehicle Simulator / Laptop (4 Units):** Provides all 4 bus endpoints (`can0`, `can1`, `can2`, `can3`) since laptops cannot mount HATs.
  - **Stage 1 (Dual-Bus) Requirement:** Exactly **3 units** (Gateway uses 1 for `can2`; Laptop uses 2 for `can0` and `can2`).
  - **Stage 3 (Full 4-Bus) Requirement:** **3 additional units** (Total = 6 units).
* **Technical Need:** 
  * Powered by STM32G431C8 (ARM Cortex-M4F @ 170 MHz) with native on-chip hardware FDCAN peripherals and SIT1044FD transceivers.
  * Flashed with open-source **candleLight firmware**, it connects as a native `gs_usb` network device in Linux (zero Device Tree overlays required).
  * Routes high-throughput 5 Mbps frames and 41-frame ML-DSA attestation bursts directly through independent USB endpoints with over 128 frames of hardware SRAM buffering.
* **Price:** **₹3,899 INR (~$47.00 USD)** per unit locally on Probots India, or **~$23–$28 USD (~₹2,200–₹2,500 INR)** via Makerfabs / AliExpress direct import. Amazon India listing (Gugxiom) provides domestic fulfillment.
* **Where to Get:**
  * **Direct Store Link (Amazon India):** [Amazon.in Gugxiom CANable 2.0 USB to CAN Analyzer Bus Converter Module (ASIN: B0DN67KQFP)](https://www.amazon.in/CANable-Module-Analyzer-Adapter-Converter/dp/B0DN67KQFP)
  * **Domestic Embedded Vendor:** [Probots India CANable 2.0 USB-CAN-FD](https://probots.co.in) (fastest local domestic dispatch)
  * **Direct Import Channel:** [Makerfabs CANable 2.0](https://www.makerfabs.com) / OpenLightLabs (~$23–$28 USD)
* **Critical Verification Rule:** Verify the unit received features the **170 MHz ARM Cortex-M4 (STM32G431)** microcontroller and native **CAN-FD** transceiver (as confirmed on ASIN: B0DN67KQFP). Standard legacy CANable 1.0 (STM32F042) supports only Classic CAN 2.0B (8-byte max) and will reject CAN-FD traffic! Upon connection, verify via `lsusb` (vendor ID `1d50:606f` candleLight or `0483:df11` DFU bootloader).

---

### 3.3 Cabling, Termination & Electrical Protection

#### 6. Bus Cabling: Cat6 Twisted Pair or Automotive STP Wire
* **Exact Role:** Physical Layer 1 transmission media linking Gateway and Simulator nodes across all 4 buses.
* **Technical Need:** 
  * Differential CAN signaling requires tightly twisted pair conductors (22–24 AWG) with a controlled differential characteristic impedance ($Z_0 \approx 100\text{--}120\ \Omega$).
  * High-speed twisting (~30–50 twists/meter) ensures that external electromagnetic noise couples equally into CAN_H and CAN_L, allowing the differential transceiver to reject common-mode noise completely.
  * An integrated ground wire / drain wire connects transceivers to a common **CAN_GND** across both endpoints, preventing floating power supplies from violating the ISO 11898-2 common-mode voltage range ($-2.0\text{ V} \le V_{CM} \le +7.0\text{ V}$).
* **Price:** **₹180 – ₹350 INR (~$2.20 – $4.20 USD)**.
* **Where to Get (User Link Validated):**
  * **Verified Mouser Option (StarTech C6PATCH1BL):** [StarTech 1ft Blue Cat6 Molded Patch Cable on Mouser](https://www.mouser.in/en/ProductDetail/StarTech/C6PATCH1BL?qs=PBDs2xEllI8Sz7PYTPk00A%3D%3D) (~$4.68 / ~₹390 INR). 24 AWG 100% stranded copper, rated to 650 MHz. Slicing open provides 4 twisted pairs for all 4 buses. Compact 1-foot length is ideal for adjacent Pi 5 and Laptop bench setup. Can be bundled with Mouser TVS diodes & shunt resistor.
  * **Domestic Express Option (Amazon India):** [Amazon.in Cat6 Ethernet Patch Cable (1m–3m)](https://www.amazon.in/s?k=Cat6+Ethernet+Patch+Cable+2m) (~₹180–₹220 INR).
  * **Automotive Dedicated Wire:** [Robu.in Automotive Wire](https://robu.in) or local electrical cable supplier.
* **Critical Physical-Layer Trap (Avoid Loose Hookup Wire):**
  * Generic DC primary hookup wire (such as parallel untwisted red/black wires for school science kits, e.g. ASIN B07MD617FF) **MUST NOT be used for 5 Mbps CAN-FD**.
  * Untwisted parallel wire exhibits uncontrolled impedance ($Z_0 \approx 250\ \Omega$) and zero common-mode noise immunity. At 5 Mbps ($t_{bit} = 200\text{ ns}$), impedance mismatch reflections corrupt the signal at the 75% sample point, causing immediate CRC errors, Bit-Stuffing errors, and controller **Bus-Off**. Furthermore, loose 2-conductor wires lack the required common `CAN_GND` return conductor.

#### 7. Split Termination Network Pack ($60\ \Omega$ / $62\ \Omega$ 1% Resistors + $4.7\text{ nF}$ 50V Ceramic Capacitors)
* **Exact Role:** High-speed RF common-mode noise suppression on 5 Mbps CAN-FD bus.
* **Technical Need & Circuit Topology:** 
  * At 5 Mbps (bit time = 200 ns, edge rise time 10–20 ns), standard single-resistor termination allows high-frequency common-mode ringing to corrupt sample points.
  * Split termination connects two matched resistors in series across CAN_H and CAN_L, with a center-tap $4.7\text{ nF}$ capacitor tied to **CAN_GND**:
    $$\text{CAN\_H} \longleftrightarrow [R_1] \longleftrightarrow \text{Center Tap} \longleftrightarrow [R_2] \longleftrightarrow \text{CAN\_L}$$
    $$\text{Center Tap} \longleftrightarrow [C = 4.7\text{ nF}] \longleftrightarrow \text{CAN\_GND}$$
  * This creates a low-pass filter ($f_c = \frac{1}{2\pi (R/2) C} \approx \frac{1}{2\pi \times 30\ \Omega \times 4.7\text{ nF}} \approx \mathbf{1.13\text{ MHz}}$) that shunts RF common-mode noise directly to ground while preserving the $120\ \Omega$ differential DC termination.
* **Component Selection & Availability Rule:**
  * **$62\ \Omega$ vs $60\ \Omega$ Standard Value:** $60\ \Omega$ is an uncommon E96/E192 resistor value. Standard practice is to use two **$62\ \Omega$ 1% metal film resistors** (standard E24 series). Two $62\ \Omega$ resistors give $R_L = 124\ \Omega$, which is well within the ISO 11898-2 requirement ($110\ \Omega \le R_L \le 130\ \Omega$).
  * **Through-Hole vs SMD Package:** For screw terminals or breadboard taps, select **radial through-hole (leaded)** ceramic/MLCC capacitors (often marked `472` for $47 \times 10^2\text{ pF} = 4.7\text{ nF}$). Bare SMD chip capacitors (0805/0603) lack wire leads and cannot be clamped directly into screw terminal blocks.
* **Price:** **₹150 INR (~$1.80 USD)** for a multipack.
* **Where to Get (User Links Validated):**
  * **Verified $62\ \Omega$ 1% Resistors (Mouser):** [TE Connectivity 1622771-1 62Ω 1% 750mW Through-Hole Resistors on Mouser](https://www.mouser.in/en/ProductDetail/TE-Connectivity-Holsworthy/1622771-1?qs=sGAEpiMZZMsPqMdJzcrNwhXxdF3DyUQnmUvK%252BKOsIOE%3D) (~₹35.41 each). Metal film, axial through-hole with long wire leads. Bundle with Mouser TVS diodes & current shunt.
  * **Direct Amazon India Link (Capacitors):** [4.7nF 50V Ceramic / MLCC Capacitor (Amazon.in)](https://www.amazon.in/4-7NF-50V-MLCC-CAPACITOR-CAPCITOR/dp/B0DXPYVYG5) (~₹120–₹150 / pack).
  * **Alternative Local Sourcing:** Local electronics component shop, Robu.in, or Element14 India.
* **Stage 1 Zero-Cost Alternative (Onboard Switches):**
  * Both the **Waveshare 2-CH HAT** (Channel 0/1 DIP switches) and the **CANable 2.0 adapters** (onboard $120\ \Omega$ jumper) feature built-in $120\ \Omega$ termination resistors. For initial bring-up, you can simply enable the onboard $120\ \Omega$ jumpers at both ends of the bus without purchasing external passive components. External split termination is primarily deployed for Stage 2/3 DSO differential waveform and noise filtering analysis.
* **Mandatory Rule:** When deploying external split termination, ensure onboard $120\ \Omega$ switches on the HAT and CANable adapters are set to **OFF**. Total DC resistance measured across CAN_H and CAN_L must read **58–62 $\Omega$**.

#### 8. Bidirectional Automotive TVS Diode Arrays (8 endpoints)
* **Exact Role:** Electrostatic discharge (ESD) and inductive surge clamping on exposed terminal blocks across all 4 buses.
* **Technical Need & Electrical Specifications:** 
  * Manual benchtop probe tapping and wire handling can discharge thousands of volts of static electricity ($\pm 15\text{ kV}$ to $\pm 21\text{ kV}$ air discharge).
  * Automotive TVS diodes (Littelfuse **AQ24CANFD-02HTG** or NXP **PESD2CAN**) clamp voltage spikes in $<1\text{ ns}$ ($V_R = 24\text{ V}$, $V_{\text{clamp}} \approx 33\text{ V}$).
  * **Ultra-Low Capacitance:** Features an ultra-low typical diode capacitance of **$C_{I/O} \approx 12\text{ pF}$**, preventing capacitive low-pass attenuation of the 5 Mbps CAN-FD edge transitions ($10\text{--}20\text{ ns}$ rise/fall times).
* **Price:** **₹45 – ₹65 INR (~$0.60 – $0.80 USD)** per unit (~₹520 INR for 8 pieces).
* **Where to Get:**
  * **Direct Sourcing Link (Mouser India):** [Littelfuse AQ24CANFD-02HTG TVS Diode Array (Mouser India)](https://www.mouser.in/en/ProductDetail/Littelfuse/AQ24CANFD-02HTG?qs=f9yNj16SXrJ5gIpyuxo44w%3D%3D)
  * **Alternative Distributors:** Element14 India, DigiKey India.
* **Mounting Rule & SOT-23-3L Packaging:**
  * The AQ24CANFD-02HTG is packaged in a miniature 3-pin **SOT-23-3L** format (Pin 1: CAN_H, Pin 2: CAN_L, Pin 3: CAN_GND).
  * For benchtop screw terminal blocks, solder the SOT-23 component onto a standard **SOT-23 to DIP breakout PCB** with 2.54mm pin headers, or solder short (<5 mm) lead extensions to clamp directly across the screw terminal block pins.
* **Stage 1 Note:** The Waveshare 2-CH CAN FD HAT already integrates onboard ESD clamping on Channel 0 and 1. External TVS arrays are primarily required when expanding to Stage 3 (protecting the 4 laptop USB adapters and wiring harness).

#### 9 (Item 10). Screw Terminal Breakouts & 2.54mm DuPont Jumpers
* **Exact Role:** Modular bus wiring, logic analyzer/oscilloscope test taps, and breadboard interconnects.
* **Technical Need & Component Selection:**
  * **Screw Terminal Blocks:** 2-pin / 3-pin screw terminals with 2.54mm or 3.81mm pin pitch to clamp stripped Cat6 twisted pairs, split termination passives, and TVS breakout boards securely without intermittent contact.
  * **Electronics Jumper Wires:** Standard 2.54mm **DuPont jumper wires** (40-pin Male-to-Male and Male-to-Female ribbon wires) for breadboard taps and connecting logic analyzer probes / INA226 I2C pins.
* **Price:** **₹250 – ₹360 INR (~$3.00 – $4.30 USD)**.
* **Where to Get:**
  * **Direct Store Link (2.54mm Terminals):** [2.54mm Pitch 2-Pin Screw Terminal Blocks (Amazon.in)](https://www.amazon.in/2-54mm-pitch-2-pin-Screw-Terminal/dp/B0BT297BSD)
  * **Alternative (3.81mm Terminals):** [3.81mm Pluggable Screw Terminal Connector (Amazon.in)](https://www.amazon.in/Terminal-Connector-Interface-Industrial-Electronics/dp/B0H3LB75NQ)
  * **DuPont Jumper Wires (40 pcs):** [Prakti 2.54mm DuPont Jumper Ribbon Wires (Amazon.in B0C86QVK2P)](https://www.amazon.in/Prakti-Female-Jumper-Breadboard-DuPont/dp/B0C86QVK2P) (~₹135 INR)
* **Keyword Hazard Alert (Avoid Car Battery Jumper Cables):**
  * Do **NOT** buy heavy-duty roadside battery booster cables (e.g. 700A Paghadi car battery clamps, ASIN B0CNRMGH56). When searching Amazon for "bus jumpers", the algorithm surfaces 700 Amp lead-acid battery jump-starters intended for stalled vehicles, rather than delicate 2.54mm electronics jumpers! Use the verified Prakti link above.

---

### 3.4 Power Instrumentation & Verification Tools

#### 10 (Item 11). INA226 Module + External $10\text{ m}\Omega$ Precision Current Shunt
* **Exact Role:** Measuring exact micro-Joule ($\mu\text{J}$) and milli-Joule ($\text{mJ}$) energy consumption of cryptographic operations and neural network inference.
* **Technical Need & Hazard Mitigation**:
  * **$0.1\ \Omega$ Default Hazard:** Standard INA226 modules ship with an onboard $0.1\ \Omega$ 1206 resistor. At 5A load, this drops 0.5V (collapsing the 5.1V rail to 4.6V and crashing the Pi 5) and dissipates 2.5W (instantly burning the SMD shunt).
  * **$10\text{ m}\Omega$ 3W Solution:** Solder an external **$10\text{ m}\Omega$ ($0.01\ \Omega$), 3W, 1% precision metal-strip shunt** (Vishay Dale WSL2512 / Bourns CSS2H). At 5A, voltage drop is only 50 mV ($5.10\text{ V} \rightarrow 5.05\text{ V}$, completely safe) and heat dissipation is only 0.25W.
  * **Dynamic Range:** Full-scale current is $8.192\text{ A}$ ($0.25\text{ mA}$ resolution per LSB).
  * **Dual-Conversion Timing:** Each power measurement requires two conversions ($140\ \mu\text{s}$ shunt + $140\ \mu\text{s}$ bus = **$280\ \mu\text{s}$ per power sample**).
* **Price:** **₹176 – ₹185 INR (~$2.10 – $2.25 USD)** (₹124 for INA226 board on Robu + ~₹52–₹61 for shunt on Mouser/DigiKey).
* **Where to Get (User-Checked Links Validated):**
  * **Direct Verified INA226 Module Link (Robu.in):** [INA226 Voltage, Current, and Power Monitor Module (₹124 on Robu.in)](https://robu.in/product/ina226-voltage-current-and-power-monitor-module/)
  * **Precision $10\text{ m}\Omega$ Shunt:** [Vishay Dale WSL2512R0100FEA (DigiKey India, ~₹61)](https://www.digikey.in/en/products/detail/vishay-dale/WSL2512R0100FEA/712561) or [Mouser India (~₹52)](https://www.mouser.in/ProductDetail/Vishay-Dale/WSL2512R0100FEA). Bundle with Mouser TVS diodes for free combined shipping.
* **Amazon Search Traps (Crucial Warnings):**
  * **Trap 1 (ADS1115 Mismatch):** Amazon listings matching "16-bit I2C sensor" (such as Robocraze ASIN B077QXWCW1) are **ADS1115 4-channel voltage ADCs**, NOT INA226 power monitors. An ADS1115 lacks the dedicated high-side shunt sense amplifier and hardware power multiplier ($P = V \times I$).
  * **Trap 2 (Through-Hole Resistors):** Amazon searches for "$10\text{ m}\Omega$ precision shunt" match ordinary 1/4W carbon film resistors (10 ohm or 10k ohm, such as Electronic Spices ASIN B0BD7HBSQP). Placing a 1/4W 10-ohm resistor in series with the 5A power rail will drop 50V (Pi receives 0V) and dissipate 250 Watts, instantly bursting into flames. Precision current sense shunts must be sourced from component distributors like Mouser or Element14.

#### 11. Digital Storage Oscilloscope (DSO) / Differential Probe
* **Exact Role:** Physical Layer 1 signal integrity evidence for the Capstone dissertation (differential voltage $V_{DIFF}$, bit-rate switching transitions, eye diagrams).
* **Technical Need & Safe Probing**:
  * Rigol DS1054Z is rated at 50 MHz bandwidth (1 GSa/s); Siglent SDS1104X-E is rated at 100 MHz bandwidth (1 GSa/s).
  * **Ground Clip Warning:** Standard passive probe ground crocodile clips are bonded to mains Earth. Directly clipping a probe ground to CAN_L will short CAN_L to Earth and blow the transceiver.
  * **Mandatory Probing Mode:** Use **Two-Channel Math (`CH1 - CH2`)**. CH1 tip on CAN_H, CH2 tip on CAN_L. Both ground clips tied strictly to isolated **CAN_GND**.
* **Price:** **₹0 (University Laboratory Equipment Access)**.
* **Where to Get:** University Electrical / Electronics Engineering Lab.

---

## 4. Staged Procurement & Cash Outlay Schedule

```
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 1: Minimal Dual-Bus Bring-Up (Immediate Order)                                   │
 │ ---------------------------------------------------                                    │
 │ • 1× Raspberry Pi 5 Model B (Silverline Electronics)    : ₹5,251.00                    │
 │ • 1× Official 27W USB-C Power Supply                    : ₹1,499.00                    │
 │ • 1× Official Pi 5 Active Cooler                        : ₹699.00                      │
 │ • 1× Waveshare 2-CH CAN FD HAT (SKU 17075, 40MHz, Robu) : ₹6,269.00                    │
 │ • 3× Gugxiom CANable 2.0 USB Adapters (3x ₹3,674, Amazon): ₹11,022.00                  │
 │ • 1× StarTech 1ft Cat6 Cable (Mouser C6PATCH1BL)        : ₹436.00                      │
 │ • 1× SanDisk Extreme 64GB MicroSD (Amazon)              : ₹2,579.00 (or ₹0 lab spare)  │
 │ • Passive Termination (Onboard 120Ω switches enabled)   : ₹0.00                        │
 │ ────────────────────────────────────────────────────────────────────────────────────── │
 │ STAGE 1 OUTLAY:                                           ₹27,755.00 INR (~$333 USD)   │
 └───────────────────────────────────────────┬────────────────────────────────────────────┘
                                             │
                                             ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 2: Communication & Bit-Timing Proof                                              │
 │ -----------------------------------------                                              │
 │ • Bring up Bus 0 (Safety: 500k/2M) and Bus 2 (Infotainment: 1M/5M).                     │
 │ • Validate 64-byte frame transmission, Ascon decryption, 40 MHz clock timing, and TDC.  │
 │ • Financial Outlay: ₹0.00 (Software & Bench Testing).                                  │
 └───────────────────────────────────────────┬────────────────────────────────────────────┘
                                             │
                                             ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 3: Full 4-Bus Expansion (Procure after Stage 2 passes)                           │
 │ ------------------------------------------------------------                           │
 │ • 3× Additional Gugxiom CANable 2.0 USB Adapters        : ₹11,022.00                   │
 │ • 8× Littelfuse TVS Diodes (8x ₹75.48 on Mouser)        : ₹603.84                      │
 │ • 2.54mm Screw Terminal Blocks (Amazon)                 : ₹119.00                      │
 │ • 40-pin Prakti DuPont Ribbon Wires (Amazon)            : ₹90.00                       │
 │ ────────────────────────────────────────────────────────────────────────────────────── │
 │ STAGE 3 OUTLAY:                                           ₹11,834.84 INR (~$142 USD)   │
 └───────────────────────────────────────────┬────────────────────────────────────────────┘
                                             │
                                             ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ STAGE 4: Power Profiling & Physical Waveform Capture                                   │
 │ ----------------------------------------------------                                   │
 │ • 1× INA226 Power Sensor Module (Robu.in)               : ₹124.00                      │
 │ • 1× Precision 10 mΩ 1W Shunt Resistor (WSL2512R0100FEA): ₹51.25                       │
 │ • DSO Access (Rigol / Siglent via University Lab)       : ₹0.00                        │
 │ ────────────────────────────────────────────────────────────────────────────────────── │
 │ STAGE 4 OUTLAY:                                           ₹175.25 INR (~$2.10 USD)     │
 └────────────────────────────────────────────────────────────────────────────────────────┘
```

**GRAND TOTAL EXPENDITURE (FULL 4-BUS TESTBED WITH 6 ADAPTERS): ₹39,765.09 INR (~$477 USD)**
*(If utilizing an existing lab MicroSD card, Grand Total drops to **₹37,186.09 INR (~$446 USD)**).*

---

## 5. Five Critical Buying Directives to Prevent Procurement Mistakes

1. **Avoid Marketplace Scalping on Pi 5:** Order only from official Raspberry Pi partners in India (**Silverline Electronics** or **Robu.in**). Do not pay ₹18,000+ to third-party Amazon sellers.
2. **Verify Waveshare SKU 17075 & 40 MHz Crystal:** Waveshare produces standard CAN HATs (Classic CAN 2.0B) and CAN-FD HATs. Ensure SKU is **17075**. Upon delivery, check the crystal oscillator label to ensure it reads **40.000 MHz**.
3. **Verify CANable V2.0 Firmware Compatibility & 6-Adapter Count:** Order only STM32G431-based **V2.0** adapters supporting the open-source **candleLight / `gs_usb`** firmware. Remember that Stage 1 requires **3 adapters**, and Stage 3 requires **3 more adapters (6 total)**.
4. **Mandatory Shunt Replacement on INA226:** Never connect the factory $0.1\ \Omega$ shunt of an INA226 board in series with the Raspberry Pi 5 5V rail. Replace it with an external **$10\text{ m}\Omega$ ($0.01\ \Omega$) 3W precision current shunt** to prevent brownout crashes and component burnout.
5. **Termination Multimeter Verification Before Power-Up:** Never power the testbed without verifying DC bus resistance. With DIP switches or split termination installed, measure across CAN_H and CAN_L on each bus: **it must read between 58 $\Omega$ and 62 $\Omega$**. If it reads 30–40 $\Omega$, multiple terminators are enabled and must be switched off.
