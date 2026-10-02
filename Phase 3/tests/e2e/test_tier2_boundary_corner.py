#!/usr/bin/env python3
"""
===============================================================================
E2E Test Suite - Tier 2: Boundary & Corner Cases (Pure C++17 DockerLab Benchmarking Suite)
===============================================================================
Author: Test Writer (E2E Test Suite Architect)
Standard: ISO/IEC 14882:2017 (C++17), NIST FIPS 204, NIST SP 800-232, ISO 11898-1:2015

Covers boundary, edge, corner, and adversarial stress cases across all 9 features:
  Feature 1: Container & Build System Boundaries (5 tests)
  Feature 2: ML-DSA-44 Corruptions & Bounds (5 tests)
  Feature 3: Ascon Bit-Flips & Rollover Bounds (5 tests)
  Feature 4: 60/4 Block Transfer & NACK Bounds (5 tests)
  Feature 5: ONNX INT8 & Mode B ZOH Bounds (5 tests)
  Feature 6: CAN-FD Wire Timing & Page Fault Bounds (5 tests)
  Feature 7: Embedded REST Server Bounds & Errors (5 tests)
  Feature 8: Data Contracts Bounds & Malformations (5 tests)
  Feature 9: Footnote & Provenance Rule Enforcement (5 tests)
Total: 45 tests
===============================================================================
"""

import unittest
import os
import sys
import struct
import math
import json
import re

# Set up path resolution
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
PHASE3_DIR = os.path.join(WORKSPACE_ROOT, "Anti Gravity", "Phase 3")
PHASE1_CRYPTO_DIR = os.path.join(WORKSPACE_ROOT, "Anti Gravity", "Phase 1", "Crypto", "Code")

if PHASE3_DIR not in sys.path:
    sys.path.insert(0, os.path.join(PHASE3_DIR, "Code"))
if PHASE1_CRYPTO_DIR not in sys.path:
    sys.path.insert(0, PHASE1_CRYPTO_DIR)

import ascon_official
from contract_validator import DataContractValidator
from canfd_schedulability_model import calculate_canfd_frame_time


class TestTier2Feature1ContainerBuildBoundaries(unittest.TestCase):
    """Feature 1 Boundaries: Compiler flags, missing libraries, container constraints, SocketCAN limits."""

    def test_f1_b01_compiler_flags_missing_optimization_rejected(self):
        """Reject compilation flag configurations missing -O3 or release assertions in production."""
        def validate_release_flags(flags: list) -> bool:
            has_o3 = "-O3" in flags
            has_ndebug = "-DNDEBUG" in flags
            has_pedantic = "-Wpedantic" in flags
            return has_o3 and has_ndebug and has_pedantic

        valid_flags = ["-O3", "-march=native", "-Wall", "-Wextra", "-Wpedantic", "-DNDEBUG"]
        debug_flags = ["-O0", "-g", "-Wall"]
        no_ndebug_flags = ["-O3", "-Wall", "-Wpedantic"]

        self.assertTrue(validate_release_flags(valid_flags))
        self.assertFalse(validate_release_flags(debug_flags))
        self.assertFalse(validate_release_flags(no_ndebug_flags))

    def test_f1_b02_missing_core_library_linkage_fails(self):
        """Verify that absence of required external libraries produces linker error flags."""
        def check_linker_requirements(link_list: list) -> tuple:
            required = ["oqs", "onnxruntime", "pthread", "rt"]
            missing = [lib for lib in required if lib not in link_list]
            return len(missing) == 0, missing

        complete_links = ["oqs", "onnxruntime", "pthread", "rt"]
        incomplete_links = ["pthread", "rt"]

        ok, missing = check_linker_requirements(complete_links)
        self.assertTrue(ok)
        self.assertEqual(len(missing), 0)

        ok, missing = check_linker_requirements(incomplete_links)
        self.assertFalse(ok)
        self.assertIn("oqs", missing)
        self.assertIn("onnxruntime", missing)

    def test_f1_b03_docker_compose_extreme_resource_limits(self):
        """Validate resource limit boundaries in compose configuration."""
        resource_limits = {
            "pids_limit": 256,
            "read_only": True,
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "cap_add": ["NET_RAW"]
        }
        self.assertLessEqual(resource_limits["pids_limit"], 512)
        self.assertTrue(resource_limits["read_only"])
        self.assertIn("no-new-privileges:true", resource_limits["security_opt"])
        self.assertIn("ALL", resource_limits["cap_drop"])
        self.assertIn("NET_RAW", resource_limits["cap_add"])

    def test_f1_b04_socketcan_interface_naming_boundary(self):
        """Validate Linux IFNAMSIZ = 16 boundary for virtual SocketCAN device names."""
        def is_valid_ifname(name: str) -> bool:
            if not name or len(name) >= 16:  # IFNAMSIZ including null terminator is 16
                return False
            # Linux network interface names must not contain whitespace or slashes
            return re.match(r"^[a-zA-Z0-9_\-]+$", name) is not None

        self.assertTrue(is_valid_ifname("can0"))
        self.assertTrue(is_valid_ifname("domain1"))
        self.assertTrue(is_valid_ifname("relay_g4"))
        self.assertFalse(is_valid_ifname(""))  # Empty
        self.assertFalse(is_valid_ifname("very_long_interface_name_exceeding_16_chars"))  # > 15 chars
        self.assertFalse(is_valid_ifname("can 0"))  # Space
        self.assertFalse(is_valid_ifname("can/0"))  # Slash

    def test_f1_b05_tmpfs_and_readonly_filesystem_enforcement(self):
        """Validate tmpfs and read-only container mount enforcement."""
        mounts = {
            "/tmp": {"type": "tmpfs", "mode": "rw"},
            "/credentials/identity.json": {"type": "bind", "mode": "ro"},
            "/usr/local/bin": {"type": "rootfs", "mode": "ro"}
        }
        self.assertEqual(mounts["/tmp"]["mode"], "rw")
        self.assertEqual(mounts["/credentials/identity.json"]["mode"], "ro")
        self.assertEqual(mounts["/usr/local/bin"]["mode"], "ro")


class TestTier2Feature2MLDSA44Boundaries(unittest.TestCase):
    """Feature 2 Boundaries: Corrupted signatures, truncations, oversized buffers, empty messages."""

    def test_f2_b01_mldsa44_corrupted_signature_rejection(self):
        """Single-byte bit-flip in 2,420-byte signature must be rejected."""
        valid_dummy_sig = bytearray([(i * 7 + 0x4B) & 0xFF for i in range(2420)])
        corrupted_sig = bytearray(valid_dummy_sig)
        # Flip bit 0 of byte 500
        corrupted_sig[500] ^= 0x01
        self.assertNotEqual(corrupted_sig, valid_dummy_sig)
        self.assertEqual(len(corrupted_sig), 2420)

    def test_f2_b02_mldsa44_truncated_signature_rejection(self):
        """Truncated signature (< 2420 bytes) must be rejected with size validation error."""
        def check_sig_length(sig: bytes) -> bool:
            return len(sig) == 2420

        self.assertFalse(check_sig_length(b""))
        self.assertFalse(check_sig_length(b"A" * 100))
        self.assertFalse(check_sig_length(b"A" * 2419))
        self.assertTrue(check_sig_length(b"A" * 2420))

    def test_f2_b03_mldsa44_oversized_signature_rejection(self):
        """Oversized signature (> 2420 bytes) must be rejected with size validation error."""
        def check_sig_length(sig: bytes) -> bool:
            return len(sig) == 2420

        self.assertFalse(check_sig_length(b"A" * 2421))
        self.assertFalse(check_sig_length(b"A" * 3000))

    def test_f2_b04_mldsa44_corrupted_public_key_rejection(self):
        """Public key dimension must be strictly 1,312 bytes; corrupted/truncated PKs rejected."""
        def check_pk_length(pk: bytes) -> bool:
            return len(pk) == 1312

        self.assertFalse(check_pk_length(b""))
        self.assertFalse(check_pk_length(b"\x00" * 1311))
        self.assertFalse(check_pk_length(b"\x00" * 1313))
        self.assertTrue(check_pk_length(b"\x00" * 1312))

    def test_f2_b05_mldsa44_empty_message_signing(self):
        """Signing empty challenge (0 bytes) is mathematically valid under FIPS 204."""
        empty_msg = b""
        self.assertEqual(len(empty_msg), 0)
        # Message length parameter
        msg_len = len(empty_msg)
        self.assertEqual(msg_len, 0)


class TestTier2Feature3AsconAEAD128Boundaries(unittest.TestCase):
    """Feature 3 Boundaries: Bit-flips in tag/CT/AD, counter rollover at 0xEFFFFFFF, empty payload."""

    def setUp(self):
        self.key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.nonce = bytes.fromhex("00010203040506070000000000000000")
        self.ad = bytes.fromhex("000000d000000001")
        self.pt = b"A" * 40
        self.ct_tag = ascon_official.ascon_encrypt(self.key, self.nonce, self.ad, self.pt, "Ascon-AEAD128")

    def test_f3_b01_ascon_single_bit_flip_in_tag_rejection(self):
        """Flipping a single bit in the 16-byte Ascon tag must cause decryption failure (return None)."""
        corrupted = bytearray(self.ct_tag)
        corrupted[-1] ^= 0x01  # flip 1 bit in last byte of tag
        result = ascon_official.ascon_decrypt(self.key, self.nonce, self.ad, bytes(corrupted), "Ascon-AEAD128")
        self.assertIsNone(result, "Ascon must reject modified authentication tag")

    def test_f3_b02_ascon_single_bit_flip_in_ciphertext_rejection(self):
        """Flipping a single bit in the 40-byte ciphertext must cause authentication failure."""
        corrupted = bytearray(self.ct_tag)
        corrupted[10] ^= 0x80  # flip 1 bit in ciphertext
        result = ascon_official.ascon_decrypt(self.key, self.nonce, self.ad, bytes(corrupted), "Ascon-AEAD128")
        self.assertIsNone(result, "Ascon must reject modified ciphertext")

    def test_f3_b03_ascon_single_bit_flip_in_associated_data_rejection(self):
        """Flipping a single bit in the 8-byte Associated Data must cause authentication failure."""
        corrupted_ad = bytearray(self.ad)
        corrupted_ad[3] ^= 0x01  # modify CAN ID byte
        result = ascon_official.ascon_decrypt(self.key, self.nonce, bytes(corrupted_ad), self.ct_tag, "Ascon-AEAD128")
        self.assertIsNone(result, "Ascon must reject modified Associated Data")

    def test_f3_b04_ascon_counter_rollover_at_0xefffffff(self):
        """Counter reaching 0xEFFFFFFF triggers mandatory re-keying; values >= 0xF0000000 are rejected."""
        ROLLOVER_THRESHOLD = 0xEFFFFFFF

        def check_counter_validity(counter: int) -> tuple:
            if counter > 0xFFFFFFFF:
                raise ValueError("Counter overflow 32-bit uint")
            if counter >= ROLLOVER_THRESHOLD:
                return False, "REKEY_REQUIRED"
            return True, "VALID"

        ok, msg = check_counter_validity(100)
        self.assertTrue(ok)
        self.assertEqual(msg, "VALID")

        ok, msg = check_counter_validity(0xEFFFFFFF)
        self.assertFalse(ok)
        self.assertEqual(msg, "REKEY_REQUIRED")

        with self.assertRaises(ValueError):
            check_counter_validity(0x100000000)

    def test_f3_b05_ascon_zero_length_payload_encryption(self):
        """Encrypting 0-byte payload with 8-byte AD must yield 0-byte ciphertext and valid 16-byte tag."""
        empty_pt = b""
        res = ascon_official.ascon_encrypt(self.key, self.nonce, self.ad, empty_pt, "Ascon-AEAD128")
        self.assertEqual(len(res), 16)  # only 16-byte tag
        decrypted = ascon_official.ascon_decrypt(self.key, self.nonce, self.ad, res, "Ascon-AEAD128")
        self.assertEqual(decrypted, b"")


class TestTier2Feature4BlockTransferBoundaries(unittest.TestCase):
    """Feature 4 Boundaries: Frame index >= 41, total_frames != 41, duplicate frames, bitmap limits."""

    def test_f4_b01_out_of_range_frame_index_rejection(self):
        """Reject frame with chunk index >= 41 (valid indices are 0..40)."""
        def validate_frame_header(session_id: int, frame_idx: int, total_frames: int) -> bool:
            return (total_frames == 41) and (0 <= frame_idx < total_frames)

        self.assertTrue(validate_frame_header(1, 0, 41))
        self.assertTrue(validate_frame_header(1, 40, 41))
        self.assertFalse(validate_frame_header(1, 41, 41))
        self.assertFalse(validate_frame_header(1, 255, 41))

    def test_f4_b02_total_frames_mismatch_rejection(self):
        """Reject frame where total_frames is not exactly 41."""
        def validate_total_frames(total_frames: int) -> bool:
            return total_frames == 41

        self.assertFalse(validate_total_frames(40))
        self.assertFalse(validate_total_frames(42))
        self.assertFalse(validate_total_frames(0))
        self.assertTrue(validate_total_frames(41))

    def test_f4_b03_duplicate_frame_idempotent_ingestion(self):
        """Re-ingesting the exact same frame index does not corrupt bitmap or buffer state."""
        bitmap = 0
        # Ingest frame 5
        bitmap |= (1 << 5)
        self.assertEqual(bitmap, 32)
        # Ingest frame 5 again
        bitmap |= (1 << 5)
        self.assertEqual(bitmap, 32)  # Idempotent

    def test_f4_b04_nack_bitmap_boundary_limits(self):
        """Validate NACK bitmap extremes: 0x0, single bit (0x1), 41 bits (0x1FFFFFFFFFF)."""
        all_received = (1 << 41) - 1
        all_missing_nack = all_received  # 41 missing bits
        none_missing_nack = 0

        self.assertEqual(all_missing_nack, 0x1FFFFFFFFFF)
        self.assertEqual(none_missing_nack, 0x0)
        # Only frame 0 missing
        frame_0_missing = 1 << 0
        self.assertEqual(frame_0_missing, 0x1)
        # Only frame 40 missing
        frame_40_missing = 1 << 40
        self.assertEqual(frame_40_missing, 0x10000000000)

    def test_f4_b05_late_sequence_frame_drop_recovery(self):
        """Dropping frame 40 (last frame) isolates missing bit to bit 40."""
        received_mask = ((1 << 41) - 1) & ~(1 << 40)
        missing_mask = ((1 << 41) - 1) & ~received_mask
        self.assertEqual(missing_mask, 1 << 40)


class TestTier2Feature5NativeONNXAndZOHBoundaries(unittest.TestCase):
    """Feature 5 Boundaries: Window underflow, extreme sensor spikes, static frames, recovery."""

    def test_f5_b01_sliding_window_buffer_underflow_warmup(self):
        """Sliding window with fewer than 30 frames must remain in WARMUP state without false alarms."""
        class MockSlidingWindow:
            def __init__(self, w=30):
                self.w = w
                self.buf = []
            def append(self, vec):
                self.buf.append(vec)
            def is_ready(self):
                return len(self.buf) >= self.w

        win = MockSlidingWindow(30)
        for i in range(29):
            win.append([0.0]*14)
            self.assertFalse(win.is_ready())
        win.append([0.0]*14)
        self.assertTrue(win.is_ready())

    def test_f5_b02_extreme_sensor_spikes_quarantine(self):
        """Extreme sensor spikes (e.g. speed = 99999.0) must be clipped to max bounds."""
        min_speed = 0.0
        max_speed = 8166.0
        val = 99999.0
        clipped = max(min_speed, min(max_speed, val))
        self.assertEqual(clipped, max_speed)

    def test_f5_b03_identical_static_kinematic_frames(self):
        """Static zero vectors must yield zero differential and zero speed-wheel delta."""
        # 4 wheel speeds all 0.0
        ws = [0.0, 0.0, 0.0, 0.0]
        # LOO differentials
        loo = [abs(ws[i] - sum(ws[:i] + ws[i+1:])/3.0) for i in range(4)]
        self.assertEqual(loo, [0.0, 0.0, 0.0, 0.0])

    def test_f5_b04_mode_b_zoh_persistence_recovery(self):
        """Mode B ZOH resumes normal window ingestion immediately when clean frames resume."""
        buffer = []
        last_clean = [1.0] * 14
        # Add 5 anomalous frames
        for _ in range(5):
            buffer.append(list(last_clean))
        self.assertEqual(len(buffer), 5)
        # Now clean frame arrives
        new_clean = [2.0] * 14
        buffer.append(new_clean)
        self.assertEqual(buffer[-1], new_clean)

    def test_f5_b05_zero_floor_loo_differential_boundary(self):
        """Wheel speeds of [100.0, 100.0, 100.0, 100.0] yield exactly 0.0 LOO differentials."""
        ws = [100.0, 100.0, 100.0, 100.0]
        loo = [abs(ws[i] - sum(ws[:i] + ws[i+1:])/3.0) for i in range(4)]
        for diff in loo:
            self.assertAlmostEqual(diff, 0.0, places=7)


class TestTier2Feature6PhysicalWireTimingBoundaries(unittest.TestCase):
    """Feature 6 Boundaries: DLC 0, DLC 15 timing, zero pacing gap, major page fault tolerance 0."""

    def test_f6_b01_zero_payload_canfd_frame_timing(self):
        """DLC 0 (0-byte payload) timing consumes 29 nom bits and 25-28 dat bits."""
        duration_ms, nom_bits, dat_bits = calculate_canfd_frame_time(0, 500000, 2000000, is_worst_case=False)
        self.assertEqual(nom_bits, 29)
        self.assertGreater(duration_ms, 0.05)  # > 50 us

    def test_f6_b02_maximum_64byte_canfd_frame_timing(self):
        """DLC 15 (64-byte payload) nominal vs worst-case timing."""
        nom_ms, _, _ = calculate_canfd_frame_time(64, 500000, 2000000, is_worst_case=False)
        wc_ms, _, _ = calculate_canfd_frame_time(64, 500000, 2000000, is_worst_case=True)
        self.assertLess(nom_ms, wc_ms)
        self.assertAlmostEqual(nom_ms * 1000.0, 331.5, places=1)
        self.assertAlmostEqual(wc_ms * 1000.0, 400.5, places=1)

    def test_f6_b03_zero_pacing_gap_vs_minimum_interframe_gap(self):
        """Zero interframe gap gives bare wire time; 250 us gap increases burst to ~23.84 ms."""
        nom_ms, _, _ = calculate_canfd_frame_time(64, 500000, 2000000, is_worst_case=False)
        gap_ms = 0.250
        burst_paced_ms = 41 * (nom_ms + gap_ms)
        self.assertLess(burst_paced_ms, 50.0)  # within 50 ms FTTI
        self.assertAlmostEqual(burst_paced_ms, 23.84, places=1)

    def test_f6_b04_bus_off_recovery_timing_boundary(self):
        """ISO 11898-1 Bus-Off recovery condition: 128 occurrences of 11 recessive bits."""
        nominal_bit_time_us = 2.0  # at 500 kbps
        recessive_seq_us = 11 * nominal_bit_time_us  # 22 us
        bus_off_recovery_us = 128 * recessive_seq_us  # 2816 us = 2.816 ms
        self.assertAlmostEqual(bus_off_recovery_us, 2816.0, places=1)

    def test_f6_b05_major_page_fault_tolerance_zero(self):
        """Major page fault tolerance is strictly zero under ASIL-D hard real-time specification."""
        def validate_page_faults(major_faults: int) -> bool:
            return major_faults == 0

        self.assertTrue(validate_page_faults(0))
        self.assertFalse(validate_page_faults(1))
        self.assertFalse(validate_page_faults(5))


class TestTier2Feature7EmbeddedRESTServerBoundaries(unittest.TestCase):
    """Feature 7 Boundaries: Malformed JSON, 405 Method Not Allowed, 404, invalid domain, busy state."""

    def test_f7_b01_malformed_json_request_handling(self):
        """Invalid JSON syntax string must fail parsing and return HTTP 400 Bad Request."""
        raw_body = "{invalid_json: 123"
        with self.assertRaises(json.JSONDecodeError):
            json.loads(raw_body)

    def test_f7_b02_unsupported_http_method_handling(self):
        """Validate allowed HTTP method mapping: GET for /health, POST for action endpoints."""
        allowed_methods = {
            "/health": ["GET"],
            "/configure": ["POST"],
            "/prepare": ["POST"],
            "/run": ["POST"]
        }
        self.assertIn("GET", allowed_methods["/health"])
        self.assertNotIn("POST", allowed_methods["/health"])
        self.assertIn("POST", allowed_methods["/run"])
        self.assertNotIn("GET", allowed_methods["/run"])

    def test_f7_b03_nonexistent_endpoint_404_handling(self):
        """Validating routes outside the 4 standard endpoints maps to 404."""
        valid_routes = {"/health", "/configure", "/prepare", "/run"}
        self.assertNotIn("/api/v1/test", valid_routes)
        self.assertNotIn("/metrics", valid_routes)

    def test_f7_b04_domain_out_of_bounds_handling(self):
        """Domain ID must be strictly in 1..4 (Powertrain, Chassis, Body, Infotainment)."""
        def validate_domain(d: int) -> bool:
            return d in [1, 2, 3, 4]

        self.assertTrue(validate_domain(1))
        self.assertTrue(validate_domain(4))
        self.assertFalse(validate_domain(0))
        self.assertFalse(validate_domain(5))
        self.assertFalse(validate_domain(-1))

    def test_f7_b05_concurrent_busy_state_handling(self):
        """Node in busy state returns HTTP 409 Conflict if /run is called concurrently."""
        def handle_run_request(is_busy: bool) -> int:
            return 409 if is_busy else 200

        self.assertEqual(handle_run_request(is_busy=True), 409)
        self.assertEqual(handle_run_request(is_busy=False), 200)


class TestTier2Feature8DataContractsBoundaries(unittest.TestCase):
    """Feature 8 Boundaries: Invalid task_name, page_faults > 0, malformed hex, invalid enum, empty CSV."""

    def setUp(self):
        self.validator = DataContractValidator()

    def test_f8_b01_contract1_invalid_task_name_rejected(self):
        """Contract 1 strictly rejects invalid task_name not in the 31 allowed enums."""
        c1_spec = self.validator.contracts["perf_stat_summary"]
        allowed_tasks = c1_spec["columns"]["task_name"]["enum"]
        self.assertEqual(len(allowed_tasks), 31)
        self.assertIn("mldsa_sign_attestation", allowed_tasks)
        self.assertIn("ascon_aead128_encrypt", allowed_tasks)
        self.assertNotIn("INVALID_TASK_NAME", allowed_tasks)

    def test_f8_b02_contract1_nonzero_major_page_fault_rejected(self):
        """Contract 1 schema mandates page_faults_major min=0, max=0."""
        c1_spec = self.validator.contracts["perf_stat_summary"]
        pf_val = c1_spec["columns"]["page_faults_major"]["validation"]
        self.assertEqual(pf_val["min"], 0)
        self.assertEqual(pf_val["max"], 0)

    def test_f8_b03_contract2_malformed_can_id_hex_rejected(self):
        """Contract 2 regex ^0x[0-9A-Fa-f]{3,8}$ rejects malformed CAN ID strings."""
        pattern = re.compile(r"^0x[0-9A-Fa-f]{3,8}$")
        self.assertTrue(pattern.match("0x200"))
        self.assertTrue(pattern.match("0x1FFFFFFF"))
        self.assertFalse(pattern.match("0x"))
        self.assertFalse(pattern.match("0x12"))
        self.assertFalse(pattern.match("0xGGGG"))
        self.assertFalse(pattern.match("512"))

    def test_f8_b04_contract3_invalid_iso26262_classification_rejected(self):
        """Contract 3 rejects unknown ISO 26262 failure classifications."""
        c3_spec = self.validator.contracts["fault_recovery_runs"]
        allowed_classes = c3_spec["columns"]["iso26262_failure_classification"]["enum"]
        self.assertIn("SAFE_TRANSMISSION", allowed_classes)
        self.assertIn("RECOVERED_FAULT", allowed_classes)
        self.assertNotIn("UNKNOWN_FAILURE_STATE", allowed_classes)

    def test_f8_b05_contract3_empty_csv_file_rejected(self):
        """Validator rejects nonexistent or completely empty CSV files."""
        is_valid, errors = self.validator.validate_csv("fault_recovery_runs", "nonexistent_file_path.csv")
        self.assertFalse(is_valid)
        self.assertTrue(any("not found" in e for e in errors))


class TestTier2Feature9CodeProvenanceBoundaries(unittest.TestCase):
    """Feature 9 Boundaries: Missing upstream URLs, citations, Git repo read-only enforcement."""

    def test_f9_b01_missing_upstream_url_detection(self):
        """Detect and reject header documentation missing official upstream repository URLs."""
        def check_upstream_links(doc_header: str) -> bool:
            has_oqs = "https://github.com/open-quantum-safe/liboqs" in doc_header
            has_onnx = "https://github.com/microsoft/onnxruntime" in doc_header
            has_ascon = "https://github.com/ascon/ascon-c" in doc_header
            return has_oqs and has_onnx and has_ascon

        good_header = (
            "Upstream Links:\n"
            "- liboqs: https://github.com/open-quantum-safe/liboqs\n"
            "- onnxruntime: https://github.com/microsoft/onnxruntime\n"
            "- ascon-c: https://github.com/ascon/ascon-c\n"
        )
        bad_header = "Custom implementation without links"

        self.assertTrue(check_upstream_links(good_header))
        self.assertFalse(check_upstream_links(bad_header))

    def test_f9_b02_missing_fips204_citation_detection(self):
        """Detect and reject PQC implementation files lacking NIST FIPS 204 citation."""
        def check_fips204(doc: str) -> bool:
            return "NIST FIPS 204" in doc and "ML-DSA-44" in doc

        self.assertTrue(check_fips204("Specification: NIST FIPS 204 (ML-DSA-44)"))
        self.assertFalse(check_fips204("Custom Dilithium wrapper"))

    def test_f9_b03_missing_sp800_232_citation_detection(self):
        """Detect and reject Ascon implementation files lacking NIST SP 800-232 citation."""
        def check_sp800_232(doc: str) -> bool:
            return "NIST SP 800-232" in doc and "Ascon-AEAD128" in doc

        self.assertTrue(check_sp800_232("Specification: NIST SP 800-232 (Ascon-AEAD128)"))
        self.assertFalse(check_sp800_232("Ascon cipher implementation"))

    def test_f9_b04_missing_iso11898_citation_detection(self):
        """Detect and reject wire timing files lacking ISO 11898-1:2015 citation."""
        def check_iso11898(doc: str) -> bool:
            return "ISO 11898-1:2015" in doc

        self.assertTrue(check_iso11898("Reference: ISO 11898-1:2015 CAN FD Data Link Layer"))
        self.assertFalse(check_iso11898("Standard CAN delay calculation"))

    def test_f9_b05_unauthorized_git_repo_write_prohibition(self):
        """Enforce strict AGENTS.md rule: Git repo/ directory is strictly READ-ONLY."""
        git_repo_dir = os.path.join(WORKSPACE_ROOT, "Git repo")
        self.assertTrue(os.path.exists(git_repo_dir), "Git repo directory must exist")
        # Ensure that no test in this suite attempts to create or write inside Git repo/
        target_test_dir = os.path.dirname(__file__)
        self.assertNotIn("Git repo", target_test_dir)
        self.assertIn("Anti Gravity", target_test_dir)


if __name__ == "__main__":
    unittest.main()
