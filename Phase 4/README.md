# Phase 4: Hardware-in-the-Loop (HIL) CAN-FD Testbed Research & Procurement

## Overview
Phase 4 transitions our Post-Quantum Cryptographic (PQC) in-vehicle gateway and 3-Tier Intrusion Detection System (IDS) from software simulation (vcan) to a physical multi-domain CAN-FD network operating at 500 kbps arbitration and 2 Mbps / 5 Mbps data phases.

## Directory Contents
- Specifications/:
  - phase_4_hardware_requirements.md: Architectural specification v1.3 covering ISO 11898-1/2 compliance, crystal oscillator bit-timing, SPI contention mitigation, and core isolation (isolcpus=3).
  - Barebone_Laptop_Topology_BOM.md and Barebone_Bill_of_Materials.pdf: Ultra-low-cost DIY testbed design using Raspberry Pi 5 + 4x DIY STM32G431 USB dongles (Rs 10,139 total outlay, saving Rs 27,047).
  - bill_of_materials.md and Master_Bill_of_Materials.pdf: Full 11-item commercial reference BOM with live verified vendor pricing.
  - components_list.md: Sourcing directory and technical component evaluation.
- Code/:
  - v4_wire_codec.py: Standalone strict 64-byte CAN-FD wire codec with in-memory derived nonces and counter rollover protection.
  - test_v4_wire_codec.py: 9/9 passing unit test suite verifying bit-exact recovery and replay rejection.
- html/: Print-ready landscape HTML templates for BOM documentation.
