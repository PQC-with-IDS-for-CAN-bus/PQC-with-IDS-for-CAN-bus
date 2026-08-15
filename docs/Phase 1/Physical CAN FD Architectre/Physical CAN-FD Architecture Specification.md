# Physical CAN-FD Architecture Specification

**Document Version**: 1.1 (Frozen Physical Specification)  
**Purpose**: This specification freezes the physical CAN-FD communication architecture for the capstone. It defines only the physical topology, trust assumptions, and communication behavior. It intentionally excludes cryptographic protocols, secure runtime frame formats, and authentication workflows.

---

## 1. Architectural Objectives

1. Preserve a standards-compatible segmented CAN-FD architecture.
2. Maintain compatibility with CAN-FD broadcast operation.
3. Establish the **Central Intelligent Security Gateway (CISG)** as the single Root of Trust.
4. Support gateway-centric FL/LSTM IDS monitoring.
5. Provide secure inter-domain routing while preserving standard intra-domain CAN-FD communication.

---

## 2. Network Topology

The vehicle is divided into four independent CAN-FD domains:
* **Powertrain Domain**
* **Chassis Domain**
* **Body & Comfort Domain**
* **Infotainment Domain**

Each domain is an **electrically independent CAN-FD bus**.

### Domain Communication Profiles

| Domain | Priority | CAN-FD Profile |
| :--- | :--- | :--- |
| **Powertrain** | Safety Critical | High-speed CAN-FD (500 kbps / 2 Mbps) |
| **Chassis** | Safety Critical | High-speed CAN-FD (500 kbps / 2 Mbps) |
| **Body & Comfort** | Medium | Standard CAN-FD (500 kbps / 1 Mbps) |
| **Infotainment** | High Throughput | High-data CAN-FD (500 kbps / 2 Mbps) |

### External Interface Attachment
* **Bluetooth / Wi-Fi / Cellular** $\rightarrow$ Infotainment / Telematics Domain (Untrusted External Exposure).
* **OBD-II Connector** $\rightarrow$ Dedicated CISG diagnostic interface (Untrusted External Boundary).

---

## 3. Central Intelligent Security Gateway (CISG)

The CISG is the trusted hardware/software Root of Trust. It incorporates Secure Boot and an onboard Hardware Security Module (HSM). It contains **four independent CAN-FD controller/transceiver interfaces** (one per CAN-FD domain). It performs inter-domain routing, PUF verification, session management, trust management, policy enforcement, and gateway-centric IDS execution.

---

## 4. Gateway Operating Modes

### Passive Monitoring Mode (Intra-Domain)
For communication within the same CAN-FD domain, ECUs communicate directly over the shared bus. The CISG observes traffic through its attached interface for IDS analysis but **cannot physically block the first transmitted frame**.

### Active Gatekeeper Mode (Inter-Domain)
For communication between different CAN-FD domains, all traffic passes through the CISG. The gateway performs routing, policy enforcement, decryption, IDS inspection, re-encryption, and may permit or deny forwarding.

---

## 5. Physical Communication Rules

1. Each CAN-FD domain is an independent broadcast bus.
2. Every ECU on a domain physically receives broadcasts on that domain.
3. ECUs communicate directly only within their own CAN-FD domain.
4. All inter-domain communication traverses the CISG.
5. The CISG monitors all attached CAN-FD domains for IDS purposes.
6. The four CAN-FD domains remain electrically isolated through independent gateway interfaces.

---

## 6. Trust Model

| Component / Boundary | Trust Classification |
| :--- | :--- |
| **CISG (Central Gateway)** | Trusted Root of Trust |
| **Secure Boot + Onboard HSM** | Trusted |
| **ECUs before PUF Authentication** | Untrusted |
| **Authenticated ECUs** | **Authenticated, but continuously monitored** |
| **OBD-II, Bluetooth, Wi-Fi, Cellular** | Untrusted |

---

## 7. Scope Boundary

This document intentionally does **NOT** define:
* PUF workflow
* Kyber key establishment (Replaced by Ascon-wrapped random $K_i$ in v1.5/v1.6)
* Ascon-AEAD128 runtime protocol
* Secure CAN-FD frame format
* Byte-wise payload specification

> [!NOTE]
> **Blockchain Exclusion**: Blockchain is **NOT** part of this capstone architecture and is intentionally excluded from all specifications.
