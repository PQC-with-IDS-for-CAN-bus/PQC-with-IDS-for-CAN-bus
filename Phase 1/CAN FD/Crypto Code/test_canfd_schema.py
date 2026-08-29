"""
Unit Tests for CAN-FD Byte-Wise Frame Packing, Unpacking, and Feature Extraction
"""

import os
import sys
import unittest
import struct
import time

crypto_code_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Crypto", "Code"))
if crypto_code_path not in sys.path:
    sys.path.insert(0, crypto_code_path)

from canfd_schema import (
    ProtectedRuntimeFrame,
    IndexedAttestationFrame,
    GatewayIDSExtractor,
    CANFD_DLC15_SIZE,
    PROTOCOL_VERSION,
    MSG_TYPE_RUNTIME_TELEMETRY,
)


class TestProtectedRuntimeFrame(unittest.TestCase):
    def test_pack_unencrypted_header(self):
        ecu_id = 0x10  # Engine ECU
        domain_id = 0x01  # Powertrain Domain
        counter = 1000
        
        header = ProtectedRuntimeFrame.pack_unencrypted_header(
            sender_ecu_id=ecu_id,
            domain_id=domain_id,
            counter=counter,
            is_emergency=False,
        )
        self.assertEqual(len(header), ProtectedRuntimeFrame.UNENCRYPTED_HEADER_SIZE)
        
        # Unpack and verify byte fields
        ver_type, sender, domain, flags, cnt = struct.unpack(">BBBBI", header)
        self.assertEqual(ver_type >> 4, PROTOCOL_VERSION)
        self.assertEqual(ver_type & 0x0F, MSG_TYPE_RUNTIME_TELEMETRY)
        self.assertEqual(sender, ecu_id)
        self.assertEqual(domain, domain_id)
        self.assertEqual(flags & 0x40, 0x40)  # Encrypted bit set
        self.assertEqual(flags & 0x80, 0)     # Emergency bit not set
        self.assertEqual(cnt, counter)

    def test_pack_unencrypted_header_emergency(self):
        header = ProtectedRuntimeFrame.pack_unencrypted_header(
            sender_ecu_id=0x20, domain_id=0x02, counter=42, is_emergency=True
        )
        _, _, _, flags, _ = struct.unpack(">BBBBI", header)
        self.assertEqual(flags & 0x80, 0x80)  # Emergency bit set

    def test_telemetry_payload_pack_unpack(self):
        payload = ProtectedRuntimeFrame.pack_telemetry_payload(
            speed=120.5,
            rpm=3200.0,
            steering_angle=-5.25,
            brake_pressure=0.0,
            throttle_pos=45.0,
            long_accel=1.2,
            lat_accel=-0.05,
            wheel_speed_fl=1205,
            wheel_speed_fr=1205,
            engine_temp=95,
            gear_status=5,
            dtc_flags=0b101,  # 2 active DTC flags
        )
        self.assertEqual(len(payload), ProtectedRuntimeFrame.PAYLOAD_SIZE)

        data = ProtectedRuntimeFrame.unpack_telemetry_payload(payload)
        self.assertAlmostEqual(data["vehicle_speed"], 120.5, places=2)
        self.assertAlmostEqual(data["engine_rpm"], 3200.0, places=2)
        self.assertAlmostEqual(data["steering_angle"], -5.25, places=2)
        self.assertEqual(data["wheel_speed_fl"], 1205)
        self.assertEqual(data["engine_temp"], 95)
        self.assertEqual(data["gear_status"], 5)
        self.assertEqual(data["diagnostic_flags"], 5)

    def test_unpack_telemetry_invalid_length(self):
        with self.assertRaises(ValueError):
            ProtectedRuntimeFrame.unpack_telemetry_payload(b"\x00" * 20)


class TestIndexedAttestationFrame(unittest.TestCase):
    def test_pack_unpack_frame(self):
        session_id = 0xAA
        frame_idx = 3
        total_frames = 41
        flags = 0x20
        fragment_data = b"AttestationDataFragment_1234567890"

        packed = IndexedAttestationFrame.pack_frame(
            session_id, frame_idx, total_frames, flags, fragment_data
        )
        self.assertEqual(len(packed), CANFD_DLC15_SIZE)

        header_dict, extracted_frag = IndexedAttestationFrame.unpack_frame(packed)
        self.assertEqual(header_dict["session_id"], session_id)
        self.assertEqual(header_dict["frame_index"], frame_idx)
        self.assertEqual(header_dict["total_frames"], total_frames)
        self.assertEqual(header_dict["control_flags"], flags)
        
        # Verify padded bytes match original fragment prefix
        self.assertTrue(extracted_frag.startswith(fragment_data))
        self.assertEqual(len(extracted_frag), IndexedAttestationFrame.PAYLOAD_SIZE)

    def test_pack_frame_overflow(self):
        overflow_frag = b"X" * 61
        with self.assertRaises(ValueError):
            IndexedAttestationFrame.pack_frame(1, 0, 41, 0, overflow_frag)

    def test_unpack_frame_invalid_size(self):
        with self.assertRaises(ValueError):
            IndexedAttestationFrame.unpack_frame(b"\x00" * 32)


class TestGatewayIDSExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = GatewayIDSExtractor()

    def test_extract_features_valid_tag(self):
        hdr = ProtectedRuntimeFrame.pack_unencrypted_header(
            sender_ecu_id=0x10, domain_id=0x01, counter=100
        )
        payload = ProtectedRuntimeFrame.pack_telemetry_payload(
            speed=60.0,
            rpm=2000.0,
            steering_angle=0.0,
            brake_pressure=10.0,
            throttle_pos=15.0,
            long_accel=0.1,
            lat_accel=0.0,
            wheel_speed_fl=600,
            wheel_speed_fr=600,
            engine_temp=90,
            gear_status=3,
            dtc_flags=0b11,  # 2 active flags
        )
        tag = b"\x00" * 16
        frame_bytes = hdr + payload + tag

        features = self.extractor.extract_features(
            frame_bytes=frame_bytes,
            decrypted_payload=payload,
            is_tag_valid=True,
            arrival_time=1000.0,
        )

        self.assertEqual(len(features), 12)
        self.assertEqual(features[0], 0.0)  # delta_t initial frame
        self.assertEqual(features[1], 0.0)  # counter_gap initial frame
        self.assertAlmostEqual(features[2], 0x10 / 255.0, places=4)  # sender ECU ID
        self.assertEqual(features[3], 1.0)  # domain ID
        self.assertEqual(features[4], MSG_TYPE_RUNTIME_TELEMETRY)
        self.assertEqual(features[5], 0.0)  # Auth tag valid (0.0)
        self.assertAlmostEqual(features[6], 60.0)  # Speed
        self.assertAlmostEqual(features[7], 2000.0)  # RPM
        self.assertEqual(features[11], 2.0)  # DTC bit count

    def test_extract_features_invalid_tag_fallback(self):
        hdr = ProtectedRuntimeFrame.pack_unencrypted_header(
            sender_ecu_id=0x10, domain_id=0x01, counter=101
        )
        payload = b"\x00" * 40
        frame_bytes = hdr + payload + (b"\x00" * 16)

        features = self.extractor.extract_features(
            frame_bytes=frame_bytes,
            decrypted_payload=payload,
            is_tag_valid=False,
            arrival_time=1050.0,
        )

        self.assertEqual(features[5], 1.0)  # Auth tag invalid (1.0)
        # Verify fallback zero values for sensor data
        self.assertEqual(features[6], 0.0)  # speed
        self.assertEqual(features[7], 0.0)  # rpm
        self.assertEqual(features[11], 0.0) # dtc

    def test_delta_time_and_counter_gap(self):
        hdr1 = ProtectedRuntimeFrame.pack_unencrypted_header(0x10, 0x01, counter=100)
        payload = ProtectedRuntimeFrame.pack_telemetry_payload(
            50, 1500, 0, 0, 10, 0, 0, 500, 500, 85, 2, 0
        )
        frame1 = hdr1 + payload + (b"\x00" * 16)

        # First frame at t = 1000ms
        self.extractor.extract_features(frame1, payload, is_tag_valid=True, arrival_time=1000.0)

        # Second frame at t = 1020ms, counter jumps to 103 (gap = 103 - 100 - 1 = 2)
        hdr2 = ProtectedRuntimeFrame.pack_unencrypted_header(0x10, 0x01, counter=103)
        frame2 = hdr2 + payload + (b"\x00" * 16)
        vec2 = self.extractor.extract_features(frame2, payload, is_tag_valid=True, arrival_time=1020.0)

        self.assertAlmostEqual(vec2[0], 20.0)  # Delta t = 20ms
        self.assertAlmostEqual(vec2[1], 2.0)   # Counter gap = 2 missed frames

    def test_monotonic_counter_gate_rejection(self):
        ecu_id = 0x10
        # Initial frame counter 100 -> Pass
        self.assertTrue(self.extractor.check_monotonic_counter_gate(ecu_id, counter=100))
        # Record counter 100 in state
        hdr = ProtectedRuntimeFrame.pack_unencrypted_header(ecu_id, 0x01, counter=100)
        payload = b"\x00" * 40
        self.extractor.extract_features(hdr + payload + (b"\x00" * 16), payload, is_tag_valid=True)

        # Monotonic increment 101 -> Pass
        self.assertTrue(self.extractor.check_monotonic_counter_gate(ecu_id, counter=101))

        # Replayed counter 100 -> HARD REJECT (False)
        self.assertFalse(self.extractor.check_monotonic_counter_gate(ecu_id, counter=100))

        # Stale counter 99 -> HARD REJECT (False)
        self.assertFalse(self.extractor.check_monotonic_counter_gate(ecu_id, counter=99))

    def test_reset_session_counter(self):
        ecu_id = 0x10
        # Establish session 1 state at counter 5000
        hdr = ProtectedRuntimeFrame.pack_unencrypted_header(ecu_id, 0x01, counter=5000)
        payload = b"\x00" * 40
        self.extractor.extract_features(hdr + payload + (b"\x00" * 16), payload, is_tag_valid=True)
        self.assertFalse(self.extractor.check_monotonic_counter_gate(ecu_id, counter=0))

        # Reset session counter on new K_i rekey
        self.extractor.reset_session_counter(ecu_id)

        # Fresh session 2 starting at counter 0 -> PASS
        self.assertTrue(self.extractor.check_monotonic_counter_gate(ecu_id, counter=0))

    def test_14d_physical_kinematics_profile(self):
        extractor_14d = GatewayIDSExtractor(profile="14D_PHYSICAL_KINEMATICS_LOO")
        self.assertEqual(extractor_14d.num_features, 14)
        
        hdr = ProtectedRuntimeFrame.pack_unencrypted_header(0x10, 0x01, counter=100)
        payload = ProtectedRuntimeFrame.pack_telemetry_payload(
            speed=60.0, rpm=2000.0, steering_angle=10.0, brake_pressure=0.0,
            throttle_pos=25.0, long_accel=0.5, lat_accel=0.1,
            wheel_speed_fl=600, wheel_speed_fr=600, engine_temp=90, gear_status=3, dtc_flags=0
        )
        frame = hdr + payload + (b"\x00" * 16)
        vec = extractor_14d.extract_features(frame, payload, is_tag_valid=True)
        self.assertEqual(len(vec), 14)
        self.assertEqual(vec[0], 60.0)    # speed
        self.assertEqual(vec[1], 2000.0)  # rpm
        self.assertEqual(vec[8], 90.0)    # coolant
        self.assertAlmostEqual(vec[9], 0.0) # loo_wheel_fl

        # Asymmetric test fixture: FL=650 (raw), FR=600 (raw)
        # Proxied: FL=650.0, FR=600.0, RL=650.0, RR=600.0
        # Median of {FR, RL, RR} = Median(600.0, 650.0, 600.0) = 600.0
        # LOO_FL = |650.0 - 600.0| = 50.0
        # (The legacy mean formula would have incorrectly computed |650.0 - 616.67| = 33.33)
        payload_asym = ProtectedRuntimeFrame.pack_telemetry_payload(
            speed=60.0, rpm=2000.0, steering_angle=10.0, brake_pressure=0.0,
            throttle_pos=25.0, long_accel=0.5, lat_accel=0.1,
            wheel_speed_fl=650, wheel_speed_fr=600, engine_temp=90, gear_status=3, dtc_flags=0
        )
        vec_asym = extractor_14d.extract_features(frame, payload_asym, is_tag_valid=True)
        self.assertAlmostEqual(vec_asym[9], 50.0, places=2)  # loo_wheel_fl under median (50.0 vs 33.33)


if __name__ == "__main__":
    unittest.main()



