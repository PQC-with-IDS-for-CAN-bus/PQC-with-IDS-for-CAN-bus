"""
CAN-FD Byte-Wise Frame Packing, Unpacking, and Feature Extraction Reference Implementation
Module: Phase 1 / CAN FD Frame Schematics
"""

import struct
import time
from typing import Dict, Any, Tuple, List

# Protocol Constants
CANFD_DLC15_SIZE = 64
PROTOCOL_VERSION = 0x1
MSG_TYPE_RUNTIME_TELEMETRY = 0x1
MSG_TYPE_ATTESTATION_CHALLENGE = 0x2
MSG_TYPE_NACK_RECOVERY = 0x3
MSG_TYPE_KEY_DELIVERY = 0x4


class ProtectedRuntimeFrame:
    """
    Protected Runtime Telemetry Frame (64 Bytes Total)
    Header (8B): Ver/Type (1B), Sender ECU ID (1B), Domain ID (1B), Flags (1B), Monotonic Counter (4B BE)
    Encrypted Payload (40B): 7 float32 signals + 2 uint16 + 1 int16 + 1 uint16 + 1 uint32 = 40 Bytes
    Ascon Auth Tag (16B): 128-bit authentication tag
    """

    UNENCRYPTED_HEADER_FMT = ">BBBB I"  # 8 bytes
    UNENCRYPTED_HEADER_SIZE = struct.calcsize(UNENCRYPTED_HEADER_FMT)

    PAYLOAD_FMT = ">fffffff HH h H I"  # 40 bytes
    PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FMT)

    TAG_SIZE = 16

    @classmethod
    def pack_unencrypted_header(
        cls, sender_ecu_id: int, domain_id: int, counter: int, is_emergency: bool = False
    ) -> bytes:
        ver_type = (PROTOCOL_VERSION << 4) | (MSG_TYPE_RUNTIME_TELEMETRY & 0x0F)
        flags = (1 << 7 if is_emergency else 0) | (1 << 6)  # Bit 6 = Encrypted
        return struct.pack(
            cls.UNENCRYPTED_HEADER_FMT,
            ver_type,
            sender_ecu_id,
            domain_id,
            flags,
            counter,
        )

    @classmethod
    def pack_telemetry_payload(
        cls,
        speed: float,
        rpm: float,
        steering_angle: float,
        brake_pressure: float,
        throttle_pos: float,
        long_accel: float,
        lat_accel: float,
        wheel_speed_fl: int,
        wheel_speed_fr: int,
        engine_temp: int,
        gear_status: int,
        dtc_flags: int,
    ) -> bytes:
        return struct.pack(
            cls.PAYLOAD_FMT,
            speed,
            rpm,
            steering_angle,
            brake_pressure,
            throttle_pos,
            long_accel,
            lat_accel,
            wheel_speed_fl,
            wheel_speed_fr,
            engine_temp,
            gear_status,
            dtc_flags,
        )

    @classmethod
    def unpack_telemetry_payload(cls, payload_bytes: bytes) -> Dict[str, Any]:
        if len(payload_bytes) != cls.PAYLOAD_SIZE:
            raise ValueError(f"Expected {cls.PAYLOAD_SIZE} payload bytes, got {len(payload_bytes)}")

        unpacked = struct.unpack(cls.PAYLOAD_FMT, payload_bytes)
        return {
            "vehicle_speed": unpacked[0],
            "engine_rpm": unpacked[1],
            "steering_angle": unpacked[2],
            "brake_pressure": unpacked[3],
            "throttle_pos": unpacked[4],
            "long_accel": unpacked[5],
            "lat_accel": unpacked[6],
            "wheel_speed_fl": unpacked[7],
            "wheel_speed_fr": unpacked[8],
            "engine_temp": unpacked[9],
            "gear_status": unpacked[10],
            "diagnostic_flags": unpacked[11],
        }


class IndexedAttestationFrame:
    """
    60/4 Indexed Block-Transfer Frame (64 Bytes Total)
    Header (4B): Session ID (1B), Frame Index (1B), Total Frames (1B), Control Flags (1B)
    Fragment Payload (60B): 60 bytes raw attestation fragment
    """

    HEADER_FMT = ">BBBB"
    HEADER_SIZE = struct.calcsize(HEADER_FMT)
    PAYLOAD_SIZE = 60

    @classmethod
    def pack_frame(
        cls, session_id: int, frame_idx: int, total_frames: int, flags: int, fragment: bytes
    ) -> bytes:
        if len(fragment) > cls.PAYLOAD_SIZE:
            raise ValueError(f"Fragment size {len(fragment)} exceeds max {cls.PAYLOAD_SIZE}")

        # Pad fragment to 60 bytes if needed
        padded_fragment = fragment.ljust(cls.PAYLOAD_SIZE, b"\x00")
        header = struct.pack(cls.HEADER_FMT, session_id, frame_idx, total_frames, flags)
        return header + padded_fragment

    @classmethod
    def unpack_frame(cls, frame_bytes: bytes) -> Tuple[Dict[str, int], bytes]:
        if len(frame_bytes) != CANFD_DLC15_SIZE:
            raise ValueError(f"Expected {CANFD_DLC15_SIZE} bytes, got {len(frame_bytes)}")

        header_data = struct.unpack(cls.HEADER_FMT, frame_bytes[: cls.HEADER_SIZE])
        header_dict = {
            "session_id": header_data[0],
            "frame_index": header_data[1],
            "total_frames": header_data[2],
            "control_flags": header_data[3],
        }
        fragment = frame_bytes[cls.HEADER_SIZE :]
        return header_dict, fragment


class GatewayIDSExtractor:
    """
    Tapan's Feature Extraction Hook: Converts decrypted frames & AD metadata into 12D LSTM vectors.

    Note on Feature Scaling:
    Telemetry features (Vehicle Speed in km/h, Engine RPM, Steering Angle, Brake Pressure, etc.)
    are emitted in raw, unscaled physical engineering units. Feature normalization (StandardScaler /
    MinMaxScaler) is performed during Phase 2 model training and edge ONNX pipeline preprocessing.
    """

    def __init__(self):
        self.last_timestamps: Dict[int, float] = {}
        self.last_counters: Dict[int, int] = {}

    def reset_session_counter(self, sender_ecu_id: int) -> None:
        """
        Resets the monotonic counter and timestamp baseline for an ECU.
        Must be called upon Step 5 Session Key Delivery (re-attestation / new K_i provision)
        so fresh session counters starting at 0 are not rejected against old session high-water marks.
        """
        self.last_counters.pop(sender_ecu_id, None)
        self.last_timestamps.pop(sender_ecu_id, None)

    def check_monotonic_counter_gate(self, sender_ecu_id: int, counter: int) -> bool:
        """
        Step 7b Monotonic Counter Gate (Hard Reject).
        Enforces strict monotonic increment per SENDER_ECU_ID.
        Must be called BEFORE extract_features().
        Returns True if counter is strictly greater than last accepted value (or first frame).
        Returns False if counter is <= last accepted value (Replay / Stale Attack -> Drop Frame).
        """
        last_c = self.last_counters.get(sender_ecu_id, None)
        if last_c is not None and counter <= last_c:
            return False  # Replayed or stale counter -> HARD REJECT
        return True

    def extract_features(
        self,
        frame_bytes: bytes,
        decrypted_payload: bytes,
        is_tag_valid: bool,
        arrival_time: float = None,
    ) -> List[float]:
        """
        Extracts 12D feature vector for ONNX LSTM IDS inspection.
        
        Invariant:
        This method must only be invoked on frames that passed Step 7b (check_monotonic_counter_gate).
        """
        if arrival_time is None:
            arrival_time = time.time() * 1000.0  # ms

        # Unpack 8-byte header
        ver_type, sender_ecu_id, domain_id, flags, counter = struct.unpack(
            ProtectedRuntimeFrame.UNENCRYPTED_HEADER_FMT, frame_bytes[:8]
        )

        msg_type = ver_type & 0x0F

        # Compute delta time
        prev_t = self.last_timestamps.get(sender_ecu_id, arrival_time)
        delta_t = arrival_time - prev_t

        # Compute counter gap
        prev_c = self.last_counters.get(sender_ecu_id, counter - 1)
        counter_gap = max(0, counter - prev_c - 1)

        # Update baseline state only for cryptographically valid frames
        if is_tag_valid:
            self.last_timestamps[sender_ecu_id] = arrival_time
            self.last_counters[sender_ecu_id] = counter

        tag_status = 0.0 if is_tag_valid else 1.0

        if is_tag_valid and len(decrypted_payload) == ProtectedRuntimeFrame.PAYLOAD_SIZE:
            telemetry = ProtectedRuntimeFrame.unpack_telemetry_payload(decrypted_payload)
            speed = telemetry["vehicle_speed"]
            rpm = telemetry["engine_rpm"]
            steering = telemetry["steering_angle"]
            brake = telemetry["brake_pressure"]
            long_accel = telemetry["long_accel"]
            dtc = float(bin(telemetry["diagnostic_flags"]).count("1"))
        else:
            # Default zero values if tag invalid / payload corrupted
            speed = rpm = steering = brake = long_accel = dtc = 0.0

        return [
            float(delta_t),
            float(counter_gap),
            float(sender_ecu_id) / 255.0,
            float(domain_id),
            float(msg_type),
            float(tag_status),
            float(speed),
            float(rpm),
            float(steering),
            float(brake),
            float(long_accel),
            float(dtc),
        ]


# Self-test code
if __name__ == "__main__":
    print("Testing CAN-FD Frame Packing & Feature Extraction...")
    hdr = ProtectedRuntimeFrame.pack_unencrypted_header(
        sender_ecu_id=0x10, domain_id=0x01, counter=1045
    )
    payload = ProtectedRuntimeFrame.pack_telemetry_payload(
        speed=85.5,
        rpm=2400.0,
        steering_angle=-1.5,
        brake_pressure=0.0,
        throttle_pos=35.0,
        long_accel=0.8,
        lat_accel=0.01,
        wheel_speed_fl=855,
        wheel_speed_fr=855,
        engine_temp=90,
        gear_status=4,
        dtc_flags=0,
    )
    tag = b"\xaa" * 16
    full_frame = hdr + payload + tag
    assert len(full_frame) == 64, f"Frame size error: {len(full_frame)}"

    extractor = GatewayIDSExtractor()
    vec = extractor.extract_features(full_frame, payload, is_tag_valid=True)
    print("Extracted 12D Feature Vector:", vec)
    assert len(vec) == 12
    print("All CAN-FD schema tests passed successfully!")
