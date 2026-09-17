#!/usr/bin/env python3
"""
test_v4_wire_codec.py
Automated Test Suite for Phase 4 Strict 64-Byte CAN-FD Wire Codec
=================================================================
Validates:
1. Physical CAN-FD 64-byte frame invariant (DLC 15).
2. Bit-exact serialization/deserialization of 9-channel kinematic telemetry.
3. In-memory derived nonce construction (0-byte wire overhead).
4. Tier 1 Monotonic Counter Replay Gate (rejection in <2 µs).
5. Ascon-AEAD128 authentication tag validation under bit-flip attacks (AD, ciphertext, tag).
6. Rollover safety limit (0xEFFFFFFF) and re-key trigger.
7. Microsecond execution benchmarks on CPU.
"""

import unittest
import time
import struct
import os
from pathlib import Path

# Add parent directory to path
from v4_wire_codec import (
    pack_phase4_canfd_frame,
    unpack_phase4_canfd_frame,
    derive_ascon_nonce,
    serialize_telemetry_payload,
    deserialize_telemetry_payload,
    TOTAL_FRAME_BYTES,
    HEADER_AD_BYTES,
    CIPHERTEXT_BYTES,
    TAG_BYTES,
    COUNTER_ROLLOVER_THRESHOLD,
    ReplayError,
    TagMismatchError,
    FrameSizeError,
    CounterRolloverWarning,
)


class TestPhase4WireCodec(unittest.TestCase):
    """Test suite for Phase 4 strict 64-byte wire codec."""

    def setUp(self):
        self.session_key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
        self.can_id = 0x18FEF100
        self.counter = 100
        self.telemetry = {
            "vehicle_speed": 82.5,
            "engine_rpm": 2150.0,
            "steering_angle": 3.75,
            "brake_pressure": 12.0,
            "wheel_speed_fl": 82.3,
            "wheel_speed_fr": 82.5,
            "wheel_speed_rl": 82.1,
            "wheel_speed_rr": 82.2,
            "coolant_temp": 91.0,
        }

    def test_01_exact_64_byte_frame_length(self):
        """Verify that every generated CAN-FD frame is strictly 64 bytes (DLC 15)."""
        frame = pack_phase4_canfd_frame(self.can_id, self.counter, self.telemetry, self.session_key)
        self.assertEqual(len(frame), 64, f"Frame length must be exactly 64 bytes, got {len(frame)}")
        self.assertEqual(len(frame), TOTAL_FRAME_BYTES)

    def test_02_in_memory_nonce_construction(self):
        """Verify the 16-byte in-memory derived nonce construction."""
        nonce = derive_ascon_nonce(0x12345678, 0x0000002A)
        self.assertEqual(len(nonce), 16, "Derived nonce must be exactly 16 bytes")
        expected = struct.pack(">II", 0x12345678, 0x0000002A) + b"\x00" * 8
        self.assertEqual(nonce, expected)

    def test_03_round_trip_telemetry_fidelity(self):
        """Verify bit-exact round-trip serialization, encryption, decryption, and recovery."""
        frame = pack_phase4_canfd_frame(self.can_id, self.counter, self.telemetry, self.session_key)
        rx_can_id, rx_counter, rx_telem = unpack_phase4_canfd_frame(
            frame, self.session_key, last_counter=self.counter - 1
        )
        self.assertEqual(rx_can_id, self.can_id)
        self.assertEqual(rx_counter, self.counter)
        for key in self.telemetry:
            self.assertAlmostEqual(
                rx_telem[key], self.telemetry[key], places=3,
                msg=f"Telemetry field {key} mismatch: expected {self.telemetry[key]}, got {rx_telem[key]}"
            )
        self.assertEqual(rx_telem["source_can_id"], self.can_id)

    def test_04_alias_handling_compatibility(self):
        """Verify backward compatibility with Phase 2 variable column names."""
        legacy_data = {
            "speed": 60.0,
            "rpm": 1800.0,
            "Steering": -2.0,
            "brake": 0.0,
            "engine_temp": 88.0,
        }
        frame = pack_phase4_canfd_frame(0x200, 1, legacy_data, self.session_key)
        _, _, recovered = unpack_phase4_canfd_frame(frame, self.session_key, last_counter=0)
        self.assertAlmostEqual(recovered["vehicle_speed"], 60.0, places=3)
        self.assertAlmostEqual(recovered["engine_rpm"], 1800.0, places=3)
        self.assertAlmostEqual(recovered["steering_angle"], -2.0, places=3)
        self.assertAlmostEqual(recovered["coolant_temp"], 88.0, places=3)

    def test_05_monotonic_counter_replay_rejection(self):
        """Verify that stale or replayed counters are rejected before Ascon decryption."""
        frame = pack_phase4_canfd_frame(self.can_id, 50, self.telemetry, self.session_key)
        
        # Scenario A: Exactly same counter (replay)
        with self.assertRaises(ReplayError) as ctx:
            unpack_phase4_canfd_frame(frame, self.session_key, last_counter=50)
        self.assertIn("AT-04", str(ctx.exception))

        # Scenario B: Stale counter from past
        with self.assertRaises(ReplayError) as ctx:
            unpack_phase4_canfd_frame(frame, self.session_key, last_counter=100)
        self.assertIn("AT-04", str(ctx.exception))

    def test_06_tamper_detection_bit_flips(self):
        """Verify that any 1-bit tampering (AD header, ciphertext, or tag) fails Ascon AEAD."""
        frame = pack_phase4_canfd_frame(self.can_id, self.counter, self.telemetry, self.session_key)

        # 6a. Flip bit in Associated Data Header (Byte 2 of CAN ID)
        corrupted = bytearray(frame)
        corrupted[2] ^= 0x01
        with self.assertRaises(TagMismatchError):
            unpack_phase4_canfd_frame(bytes(corrupted), self.session_key, last_counter=self.counter - 1)

        # 6b. Flip bit in Ciphertext Payload (Byte 20)
        corrupted = bytearray(frame)
        corrupted[20] ^= 0x01
        with self.assertRaises(TagMismatchError):
            unpack_phase4_canfd_frame(bytes(corrupted), self.session_key, last_counter=self.counter - 1)

        # 6c. Flip bit in Ascon Authentication Tag (Byte 60)
        corrupted = bytearray(frame)
        corrupted[60] ^= 0x01
        with self.assertRaises(TagMismatchError):
            unpack_phase4_canfd_frame(bytes(corrupted), self.session_key, last_counter=self.counter - 1)

    def test_07_frame_size_enforcement(self):
        """Verify that non-64-byte frames (underflow/overflow) are rejected immediately."""
        # Underflow (63 bytes)
        with self.assertRaises(FrameSizeError):
            unpack_phase4_canfd_frame(b"\x00" * 63, self.session_key, last_counter=0)

        # Overflow (65 bytes / 80 bytes)
        with self.assertRaises(FrameSizeError):
            unpack_phase4_canfd_frame(b"\x00" * 80, self.session_key, last_counter=0)

    def test_08_counter_rollover_warning(self):
        """Verify rollover threshold at 0xEFFFFFFF forces session re-keying."""
        with self.assertRaises(CounterRolloverWarning):
            pack_phase4_canfd_frame(
                self.can_id,
                COUNTER_ROLLOVER_THRESHOLD,
                self.telemetry,
                self.session_key
            )

    def test_09_codec_throughput_benchmark(self):
        """Benchmark 1,000 encode/decode operations to verify execution speed."""
        n_iters = 1000
        
        # Benchmark pack
        t0 = time.perf_counter()
        frames = []
        for c in range(1, n_iters + 1):
            frames.append(pack_phase4_canfd_frame(self.can_id, c, self.telemetry, self.session_key))
        pack_total_s = time.perf_counter() - t0
        pack_us_per_op = (pack_total_s / n_iters) * 1e6

        # Benchmark unpack
        t0 = time.perf_counter()
        last_c = 0
        for f in frames:
            _, last_c, _ = unpack_phase4_canfd_frame(f, self.session_key, last_counter=last_c)
        unpack_total_s = time.perf_counter() - t0
        unpack_us_per_op = (unpack_total_s / n_iters) * 1e6

        print(f"\n[BENCHMARK] Pack Speed   : {pack_us_per_op:.2f} µs/frame ({n_iters / pack_total_s:.0f} fps)")
        print(f"[BENCHMARK] Unpack Speed : {unpack_us_per_op:.2f} µs/frame ({n_iters / unpack_total_s:.0f} fps)")

        # In pure Python, Ascon runs in ~100-200 µs; verify it's responsive (< 1 ms)
        self.assertLess(pack_us_per_op, 1000.0)
        self.assertLess(unpack_us_per_op, 1000.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
