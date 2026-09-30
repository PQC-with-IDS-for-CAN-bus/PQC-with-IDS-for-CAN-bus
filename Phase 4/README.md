# Phase 4: Hardware-in-the-Loop (HIL) CAN-FD Testbed Research & Procurement

## Overview
Phase 4 transitions our Post-Quantum Cryptographic (PQC) in-vehicle gateway and 3-Tier Intrusion Detection System (IDS) from software simulation (vcan) to a physical multi-domain CAN-FD network operating at 500 kbps arbitration and 2 Mbps / 5 Mbps data phases.

## Directory Contents
- Specifications/:
  - phase_4_hardware_requirements.md: Architectural specification v1.3 covering ISO 11898-1/2 compliance, crystal oscillator bit-timing, SPI contention mitigation, and core isolation (isolcpus=3).
  - Barebone_Laptop_Topology_BOM.md and Barebone_Bill_of_Materials.pdf: Production Final Barebone DIY BOM v2.4 specifying the symmetrical 1 Pi 5 + 1 Laptop + 8 DIY STM32G431 CAN-FD dongles testbed (₹12,894.25 / ₹15,473.25 total outlay, saving ₹24,291.84 vs commercial). Incorporates 10 KB CCM-SRAM PUF root-of-trust, HSM/host split for ML-DSA-44, and INA226 energy profiling.
  - bill_of_materials.md and Master_Bill_of_Materials.pdf: Full 11-item commercial reference BOM with live verified vendor pricing.
  - components_list.md: Sourcing directory and technical component evaluation.
- Code/:
  - v4_wire_codec.py: Standalone strict 64-byte CAN-FD wire codec with in-memory derived nonces and counter rollover protection.
  - test_v4_wire_codec.py: 9/9 passing unit test suite verifying bit-exact recovery and replay rejection.
- html/: Print-ready landscape HTML templates for BOM documentation.
