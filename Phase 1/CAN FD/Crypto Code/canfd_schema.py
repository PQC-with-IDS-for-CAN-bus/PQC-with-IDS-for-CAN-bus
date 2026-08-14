"""
CAN-FD Byte-Wise Frame Packing, Unpacking, and Feature Extraction Reference Implementation
Module: Phase 1 / CAN FD Frame Schematics
"""

import struct
import time
import os
import sys
from typing import Dict, Any, Tuple, List

from crypto_engine import AsconAEAD128Engine, SessionManager, PUFEmulator, KeyDerivation, PostQuantumAttestation

# Protocol Constants
CANFD_DLC15_SIZE = 64
PROTOCOL_VERSION = 0x1
MSG_TYPE_RUNTIME_TELEMETRY = 0x1
MSG_TYPE_ATTESTATION_CHALLENGE = 0x2
MSG_TYPE_NACK_RECOVERY = 0x3
MSG_TYPE_KEY_DELIVERY = 0x4


class ChallengeFrame:
    """
    Cat 3.1 — Authenticated Boot Challenge Frame (64 Bytes Total, Plaintext)
    =========================================================================
    Sent by the CISG to an ECU at the start of the boot handshake.
    Carries a fresh RANDOM_CHALLENGE (the HKDF salt + Cat 2 Ascon nonce)
    and the SESSION_ID for this boot cycle.

    Layout
    ------
    [0]      1B   ver_type         0x12 = (PROTOCOL_VERSION=1 << 4) | MSG_TYPE_ATTESTATION_CHALLENGE=2
    [1]      1B   target_ecu_id    ECU being challenged
    [2]      1B   domain_id        Physical domain of the target ECU
    [3]      1B   flags            0x00 — plaintext frame, no encryption
    [4:8]    4B   session_id       uint32 BE — per-boot monotonic counter
    [8:24]  16B   random_challenge os.urandom(16) — used as HKDF salt and Ascon nonce in Cat 2
    [24:64] 40B   padding          0x00 * 40
    ─────────────────────────────────────────────────────────────────
    TOTAL   64B   (DLC=15)

    Security note
    -------------
    Cat 3.1 is deliberately NOT encrypted. The security of the handshake does
    not depend on the confidentiality of the challenge — only the ECU that holds
    the genuine PUF secret and the ML-DSA signing key can produce a valid Cat 2
    response. An attacker observing the challenge gains nothing without those keys.
    """

    HEADER_FMT      = ">BBBBI"        # ver_type, target_ecu_id, domain_id, flags, session_id
    HEADER_SIZE     = struct.calcsize(HEADER_FMT)   # = 8 bytes
    CHALLENGE_SIZE  = 16
    PADDING_SIZE    = CANFD_DLC15_SIZE - HEADER_SIZE - CHALLENGE_SIZE   # = 40 bytes
    FRAME_SIZE      = CANFD_DLC15_SIZE                                   # = 64 bytes

    VER_TYPE        = (PROTOCOL_VERSION << 4) | (MSG_TYPE_ATTESTATION_CHALLENGE & 0x0F)  # 0x12
    FLAGS_PLAINTEXT = 0x00

    @classmethod
    def issue(
        cls,
        target_ecu_id: int,
        domain_id: int,
        session_id: int,
    ) -> tuple:
        """
        CISG side: Build a 64-byte Cat 3.1 challenge frame with a fresh CSPRNG nonce.

        Parameters
        ----------
        target_ecu_id : int  — 8-bit CAN ECU identifier of the ECU being challenged.
        domain_id     : int  — physical domain of the target ECU.
        session_id    : int  — uint32 boot session counter.

        Returns
        -------
        tuple[bytes, bytes]  — (frame_64B, random_challenge_16B)
            Caller (CISG) keeps random_challenge for K_boot_i derivation.
        """
        if not (0 <= target_ecu_id <= 0xFF):
            raise ValueError(f"target_ecu_id must be 0-255, got {target_ecu_id}")
        if not (0 <= session_id <= 0xFFFFFFFF):
            raise ValueError("session_id must fit in uint32")

        random_challenge = SessionManager.generate_random_challenge()
        header = struct.pack(
            cls.HEADER_FMT,
            cls.VER_TYPE,
            target_ecu_id,
            domain_id,
            cls.FLAGS_PLAINTEXT,
            session_id,
        )
        frame = header + random_challenge + b"\x00" * cls.PADDING_SIZE
        assert len(frame) == cls.FRAME_SIZE
        return frame, random_challenge

    @classmethod
    def parse(
        cls,
        frame_bytes: bytes,
        expected_ecu_id: int,
        expected_session_id: int,
    ) -> tuple:
        """
        ECU side: Parse and validate a received Cat 3.1 challenge frame.

        Parameters
        ----------
        frame_bytes        : bytes — 64-byte Cat 3.1 frame from the CAN-FD bus.
        expected_ecu_id    : int   — the ECU's own ID (rejects frames targeted at other ECUs).
        expected_session_id: int   — the session_id the ECU expects from the CISG.

        Returns
        -------
        tuple[bytes, int]  — (random_challenge_16B, session_id)

        Raises
        ------
        ValueError on:
          - Wrong frame length
          - ver_type != 0x12
          - target_ecu_id mismatch
          - session_id mismatch
        """
        if len(frame_bytes) != cls.FRAME_SIZE:
            raise ValueError(f"Cat 3.1: Expected {cls.FRAME_SIZE}B frame, got {len(frame_bytes)}B")

        ver_type, target_ecu_id, domain_id, flags, session_id = struct.unpack(
            cls.HEADER_FMT, frame_bytes[:cls.HEADER_SIZE]
        )

        if ver_type != cls.VER_TYPE:
            raise ValueError(f"Cat 3.1: Invalid ver_type 0x{ver_type:02X} (expected 0x{cls.VER_TYPE:02X})")

        if target_ecu_id != expected_ecu_id:
            raise ValueError(
                f"Cat 3.1: Frame targeted at ECU 0x{target_ecu_id:02X}, "
                f"but this ECU is 0x{expected_ecu_id:02X}"
            )

        if session_id != expected_session_id:
            raise ValueError(
                f"Cat 3.1: Session mismatch: frame has {session_id}, expected {expected_session_id}"
            )

        random_challenge = frame_bytes[cls.HEADER_SIZE : cls.HEADER_SIZE + cls.CHALLENGE_SIZE]
        return random_challenge, session_id


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


class AttestationDeliveryManager:
    """
    Cat 2 ML-DSA-44 Attestation Delivery Manager
    ============================================
    Bridges the 2420B Post-Quantum ML-DSA signature and the 60B CAN-FD fragments.
    ECU side: Encrypts signature under K_boot_i (2436B PAO) and fragments into 41 frames.
    CISG side: Reassembles 41 frames, reconstructs PAO, decrypts and validates signature.
    """
    
    FLAG_DATA = 0x01
    FLAG_LAST = 0x03
    
    @classmethod
    def wrap_and_fragment(
        cls,
        signature: bytes,
        k_boot_i: bytes,
        random_challenge: bytes,
        ecu_id: int,
        session_id: int,
    ) -> List[bytes]:
        """ECU side: Wrap 2420B signature into 41 x 64B Cat 2 frames."""
        if len(signature) != 2420:
            raise ValueError(f"Expected 2420B signature, got {len(signature)}B")
        if len(k_boot_i) != 16:
            raise ValueError("k_boot_i must be 16 bytes")
        if len(random_challenge) != 16:
            raise ValueError("random_challenge must be 16 bytes")
            
        # AD binds the PAO to the source ECU and current session
        ad = struct.pack(">II", ecu_id, session_id)
        
        # AsconAEAD128 encryption (produces 2420B ciphertext + 16B tag = 2436B)
        ciphertext, tag = AsconAEAD128Engine.encrypt(
            key=k_boot_i,
            nonce=random_challenge,
            plaintext=signature,
            associated_data=ad,
        )
        pao = ciphertext + tag
        assert len(pao) == 2436, f"Expected 2436B PAO, got {len(pao)}"
        
        frames = []
        total_frames = 41
        session_byte = session_id & 0xFF
        
        for i in range(total_frames):
            start_idx = i * IndexedAttestationFrame.PAYLOAD_SIZE
            end_idx = start_idx + IndexedAttestationFrame.PAYLOAD_SIZE
            fragment = pao[start_idx:end_idx]
            
            flags = cls.FLAG_DATA
            if i == total_frames - 1:
                flags = cls.FLAG_LAST
                
            frame = IndexedAttestationFrame.pack_frame(
                session_id=session_byte,
                frame_idx=i,
                total_frames=total_frames,
                flags=flags,
                fragment=fragment,
            )
            frames.append(frame)
            
        assert len(frames) == 41
        return frames

    @classmethod
    def reassemble_and_unwrap(
        cls,
        frames: List[bytes],
        k_boot_i: bytes,
        random_challenge: bytes,
        expected_ecu_id: int,
        expected_session_id: int,
    ) -> bytes:
        """CISG side: Reassemble 41 frames and unwrap the 2420B signature."""
        if len(frames) != 41:
            raise ValueError(f"Expected exactly 41 frames, got {len(frames)}")
            
        expected_session_byte = expected_session_id & 0xFF
        pao_fragments = []
        
        # Verify sequence and extract payloads
        for expected_idx, frame_bytes in enumerate(frames):
            header_dict, fragment = IndexedAttestationFrame.unpack_frame(frame_bytes)
            
            if header_dict["session_id"] != expected_session_byte:
                raise ValueError(f"Session mismatch at frame {expected_idx}")
            if header_dict["frame_index"] != expected_idx:
                raise ValueError(f"Out of order frame: expected {expected_idx}, got {header_dict['frame_index']}")
            if header_dict["total_frames"] != 41:
                raise ValueError(f"Invalid total_frames: {header_dict['total_frames']}")
                
            is_last = expected_idx == 40
            expected_flags = cls.FLAG_LAST if is_last else cls.FLAG_DATA
            if header_dict["control_flags"] != expected_flags:
                raise ValueError(f"Invalid control flags at frame {expected_idx}")
                
            pao_fragments.append(fragment)
            
        # Reconstruct PAO
        full_pao_padded = b"".join(pao_fragments)
        # 41 * 60 = 2460 bytes. We only want the first 2436 bytes.
        pao = full_pao_padded[:2436]
        
        ciphertext = pao[:-16]
        tag = pao[-16:]
        
        ad = struct.pack(">II", expected_ecu_id, expected_session_id)
        
        signature = AsconAEAD128Engine.decrypt(
            key=k_boot_i,
            nonce=random_challenge,
            ciphertext=ciphertext,
            associated_data=ad,
            tag=tag,
        )
        
        if len(signature) != 2420:
            raise ValueError(f"Recovered signature size mismatch: {len(signature)}")
            
        return signature


class KeyDeliveryFrame:
    """
    Cat 3.3 Session Key Transport Frame (64 Bytes Total)
    =====================================================
    Header / AD (8B): ver_type (1B), sender_ecu_id (1B), target_domain_id (1B),
                      flags (1B), session_id (4B BE)
    Nonce        (16B): Fresh CSPRNG nonce for this delivery
    Ciphertext   (16B): Ascon-AEAD128 encryption of K_i (16-byte session key)
    Tag          (16B): 128-bit Ascon authentication tag
    Reserved     (4B):  0x00000000
    Frame CRC    (4B):  CRC-32 over bytes [0:60] (set 0 if not yet implemented)
    """

    HEADER_FMT  = ">BBBBI"         # ver_type, ecu_id, domain_id, flags, session_id
    HEADER_SIZE = struct.calcsize(HEADER_FMT)  # = 8 bytes
    NONCE_SIZE       = 16
    CIPHERTEXT_SIZE  = 16   # K_i is always 16 bytes → 16-byte ciphertext
    TAG_SIZE         = 16
    RESERVED_SIZE    = 4
    CRC_SIZE         = 4
    FRAME_SIZE       = HEADER_SIZE + NONCE_SIZE + CIPHERTEXT_SIZE + TAG_SIZE + RESERVED_SIZE + CRC_SIZE

    VER_TYPE         = (PROTOCOL_VERSION << 4) | (MSG_TYPE_KEY_DELIVERY & 0x0F)  # 0x14
    FLAGS_ENCRYPTED  = 0x40

    @classmethod
    def wrap(
        cls,
        k_boot_i: bytes,
        k_i: bytes,
        sender_ecu_id: int,
        target_domain_id: int,
        session_id: int,
    ) -> bytes:
        """
        CISG side: Wrap K_i into a 64-byte Cat 3.3 frame.
        """
        if len(k_boot_i) != 16:
            raise ValueError("K_boot_i must be 16 bytes")
        if len(k_i) != 16:
            raise ValueError("K_i must be 16 bytes")

        # Build header (= Associated Data)
        header_ad = struct.pack(
            cls.HEADER_FMT,
            cls.VER_TYPE,
            sender_ecu_id,
            target_domain_id,
            cls.FLAGS_ENCRYPTED,
            session_id,
        )

        # Generate per-frame nonce
        nonce_n = SessionManager.generate_nonce()

        # Encrypt K_i under K_boot_i
        ciphertext_ki, tag = AsconAEAD128Engine.encrypt(
            key=k_boot_i,
            nonce=nonce_n,
            plaintext=k_i,
            associated_data=header_ad,
        )

        # Pack frame
        frame = header_ad + nonce_n + ciphertext_ki + tag + b"\x00" * cls.RESERVED_SIZE + b"\x00" * cls.CRC_SIZE
        assert len(frame) == cls.FRAME_SIZE, f"Frame size error: {len(frame)} != {cls.FRAME_SIZE}"
        return frame

    @classmethod
    def unwrap(
        cls,
        frame_bytes: bytes,
        k_boot_i: bytes,
        expected_session_id: int,
    ) -> bytes:
        """
        ECU side: Unwrap and authenticate K_i from a 64-byte Cat 3.3 frame.
        """
        if len(frame_bytes) != cls.FRAME_SIZE:
            raise ValueError(f"Expected {cls.FRAME_SIZE}-byte frame, got {len(frame_bytes)}")

        # Parse fields
        header_ad     = frame_bytes[0:cls.HEADER_SIZE]
        nonce_n       = frame_bytes[cls.HEADER_SIZE : cls.HEADER_SIZE + cls.NONCE_SIZE]
        ciphertext_ki = frame_bytes[cls.HEADER_SIZE + cls.NONCE_SIZE :
                                    cls.HEADER_SIZE + cls.NONCE_SIZE + cls.CIPHERTEXT_SIZE]
        tag           = frame_bytes[cls.HEADER_SIZE + cls.NONCE_SIZE + cls.CIPHERTEXT_SIZE :
                                    cls.HEADER_SIZE + cls.NONCE_SIZE + cls.CIPHERTEXT_SIZE + cls.TAG_SIZE]

        # Validate header fields and session binding
        ver_type, sender_ecu_id, target_domain_id, flags, session_id_in_frame = struct.unpack(
            cls.HEADER_FMT,
            header_ad,
        )

        if ver_type != cls.VER_TYPE:
            raise ValueError(f"Invalid Cat 3.3 ver_type: 0x{ver_type:02X}")

        if flags != cls.FLAGS_ENCRYPTED:
            raise ValueError(f"Invalid Cat 3.3 flags: 0x{flags:02X}")

        if session_id_in_frame != expected_session_id:
            raise ValueError(
                f"Cat 3.3 session mismatch: "
                f"{session_id_in_frame} != expected {expected_session_id}"
            )

        # Decrypt — raises ValueError on tag mismatch (per AsconAEAD128Engine contract)
        k_i = AsconAEAD128Engine.decrypt(
            key=k_boot_i,
            nonce=nonce_n,
            ciphertext=ciphertext_ki,
            associated_data=header_ad,
            tag=tag,
        )

        if len(k_i) != 16:
            raise ValueError(f"Unexpected K_i size after decryption: {len(k_i)}")

        return k_i


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

    print("\n--- Testing Cat 3.1 ChallengeFrame ---")
    ecu_id     = 0x20
    domain_id  = 0x01
    session_id = 5

    # CISG issues challenge
    cat31_frame, challenge = ChallengeFrame.issue(
        target_ecu_id=ecu_id,
        domain_id=domain_id,
        session_id=session_id,
    )
    assert len(cat31_frame) == 64
    assert len(challenge) == 16
    print(f"[CISG] Cat 3.1 issued ({len(cat31_frame)}B): ver_type=0x{cat31_frame[0]:02X}, "
          f"ecu=0x{cat31_frame[1]:02X}, challenge={challenge[:8].hex()}...")

    # ECU parses challenge
    parsed_challenge, parsed_sid = ChallengeFrame.parse(cat31_frame, ecu_id, session_id)
    assert parsed_challenge == challenge, "Challenge mismatch after parse!"
    assert parsed_sid == session_id
    print(f"[ECU]  Cat 3.1 parsed OK: challenge={parsed_challenge[:8].hex()}..., session_id={parsed_sid}")

    # Wrong ECU ID rejection
    try:
        ChallengeFrame.parse(cat31_frame, expected_ecu_id=0x99, expected_session_id=session_id)
        assert False, "Should have rejected wrong ECU ID"
    except ValueError as e:
        print(f"[SEC]  Wrong ECU ID rejected: {e}")

    # Wrong session_id rejection
    try:
        ChallengeFrame.parse(cat31_frame, expected_ecu_id=ecu_id, expected_session_id=999)
        assert False, "Should have rejected wrong session_id"
    except ValueError as e:
        print(f"[SEC]  Wrong session_id rejected: {e}")

    print("\n--- Testing Cat 3.3 KeyDeliveryFrame ---")
    # challenge and session_id are now set from the Cat 3.1 test above


    # ---- CISG side ----
    puf_hash   = PUFEmulator.get_puf_hash(PUFEmulator.reconstruct_puf_secret(ecu_id))
    k_boot_i   = KeyDerivation.derive_bootstrap_key(puf_hash, challenge, ecu_id, session_id)
    k_i_cisg   = SessionManager.generate_session_key()

    frame = KeyDeliveryFrame.wrap(
        k_boot_i=k_boot_i,
        k_i=k_i_cisg,
        sender_ecu_id=0xFF,
        target_domain_id=domain_id,
        session_id=session_id,
    )
    assert len(frame) == 64, "Frame must be 64 bytes"
    print(f"[CISG] Wrapped Cat 3.3 frame ({len(frame)}B): {frame[:16].hex()}...")

    # ---- ECU side ----
    # ECU derives its own K_boot_i from PUF + challenge + session_id
    k_boot_i_ecu = KeyDerivation.derive_bootstrap_key(puf_hash, challenge, ecu_id, session_id)

    k_i_ecu = KeyDeliveryFrame.unwrap(
        frame_bytes=frame,
        k_boot_i=k_boot_i_ecu,
        expected_session_id=session_id,
    )
    assert k_i_ecu == k_i_cisg, "K_i mismatch between CISG and ECU!"
    print(f"[ECU]  K_i unwrapped successfully: {k_i_ecu.hex()}")

    # ---- Tamper test ----
    tampered_frame = bytearray(frame)
    tampered_frame[30] ^= 0xFF   # flip a bit inside ciphertext
    try:
        KeyDeliveryFrame.unwrap(bytes(tampered_frame), k_boot_i_ecu, session_id)
        assert False, "Should have raised ValueError on tampered frame"
    except ValueError as e:
        print(f"[SEC]  Tamper rejected correctly: {e}")
        
    # ---- AD (Header) Tamper test ----
    tampered_header = bytearray(frame)
    tampered_header[2] ^= 0x01   # flip a bit in target domain ID
    try:
        KeyDeliveryFrame.unwrap(bytes(tampered_header), k_boot_i_ecu, session_id)
        assert False, "Should have raised ValueError on tampered header"
    except ValueError as e:
        print(f"[SEC]  Header tamper rejected correctly: {e}")

    # ---- Session Mismatch check test ----
    try:
        KeyDeliveryFrame.unwrap(frame, k_boot_i_ecu, expected_session_id=999)
        assert False, "Should have raised ValueError on mismatched session_id"
    except ValueError as e:
        print(f"[SEC]  Session mismatch rejected correctly: {e}")

    print("\n--- Testing Cat 2 AttestationDeliveryManager ---")
    import hashlib
    # 1. Setup ML-DSA-44 keys and mock measurement
    print("[1] Generating ML-DSA-44 keys (takes a moment)...")
    pub_key, sec_key = PostQuantumAttestation.generate_mldsa_keypair()
    meas_hash = hashlib.sha256(b"capstone_firmware_v1").digest()
    
    # 2. ECU generates signature
    original_sig = PostQuantumAttestation.sign_attestation_transcript(
        secret_key=sec_key,
        protocol_version=1,
        ecu_id=ecu_id,
        session_id=session_id,
        random_challenge=challenge,
        measurement_hash=meas_hash
    )
    print(f"[2] ECU generated {len(original_sig)}B ML-DSA-44 signature.")
    
    # 3. ECU Wraps & Fragments
    cat2_frames = AttestationDeliveryManager.wrap_and_fragment(
        signature=original_sig,
        k_boot_i=k_boot_i_ecu,
        random_challenge=challenge,
        ecu_id=ecu_id,
        session_id=session_id
    )
    print(f"[3] ECU wrapped into {len(cat2_frames)} Cat 2 frames. Frame 0 size: {len(cat2_frames[0])}B.")
    
    # 4. CISG Reassembles & Unwraps
    recovered_sig = AttestationDeliveryManager.reassemble_and_unwrap(
        frames=cat2_frames,
        k_boot_i=k_boot_i,
        random_challenge=challenge,
        expected_ecu_id=ecu_id,
        expected_session_id=session_id
    )
    print(f"[4] CISG successfully reassembled and decrypted {len(recovered_sig)}B signature.")
    assert recovered_sig == original_sig, "Signature mismatch!"
    
    # 5. CISG Verifies Signature
    is_valid = PostQuantumAttestation.verify_attestation_signature(
        public_key=pub_key,
        signature=recovered_sig,
        protocol_version=1,
        ecu_id=ecu_id,
        session_id=session_id,
        random_challenge=challenge,
        measurement_hash=meas_hash
    )
    assert is_valid, "FIPS 204 Verification Failed!"
    print(f"[5] FIPS 204 Signature Verification: PASS")
    
    # 6. Tamper Test
    tampered_frames = list(cat2_frames)
    bad_frame = bytearray(tampered_frames[20])
    bad_frame[30] ^= 0xFF # Flip bit in ciphertext fragment
    tampered_frames[20] = bytes(bad_frame)
    
    try:
        AttestationDeliveryManager.reassemble_and_unwrap(
            tampered_frames, k_boot_i, challenge, ecu_id, session_id
        )
        assert False, "Should have rejected tampered Cat 2 fragments"
    except ValueError as e:
        print(f"[SEC] Cat 2 Tamper rejected correctly: {e}")
        
    # 7. AD (ECU ID) Mismatch Test
    try:
        AttestationDeliveryManager.reassemble_and_unwrap(
            cat2_frames, k_boot_i, challenge, expected_ecu_id=99, expected_session_id=session_id
        )
        assert False, "Should have rejected AD mismatch"
    except ValueError as e:
        print(f"[SEC] Cat 2 AD Mismatch rejected correctly: {e}")

    print("\nAll CAN-FD schema tests passed successfully!")
