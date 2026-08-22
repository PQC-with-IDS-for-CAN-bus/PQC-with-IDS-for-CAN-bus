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



# ---------------------------------------------------------------------------
# Gateway IDS Feature Profile Definitions
# ---------------------------------------------------------------------------
# Each profile is a tuple of canonical feature name strings.  The profile
# name is the single top-level selector that drives all downstream code
# (CANDatasetPreprocessor, LSTMAutoencoder, threshold calibration, red-team
# benchmark scoring).  No wire format or crypto changes are needed to switch
# profiles — all signals are already present in the decrypted 40-byte payload.
#
# Profiles:
#   12D_LEGACY        — Original Phase 1 baseline (6 header/crypto + 6 raw
#                       telemetry signals).  Retained for historical benchmarking.
#
#   12D_ENHANCED      — Same 12 slots as LEGACY, but two improvements:
#                         · delta_t replaced by frame_density (trailing causal
#                           window), which is ~100× OOD during a DoS flood.
#                         · Core telemetry replaced by EMA-deviation signals,
#                           which spike sharply on masquerade injection while
#                           remaining ≈0 during forward-fill carry-forward.
#
#   18D_FULL_FRAME    — All 12 raw physical signals from the 40-byte payload
#                       plus the 6 header/crypto fields.  Unlocks Throttle,
#                       Lateral/Longitudinal Accel, Wheel_FR, Gear, and DTC
#                       that were previously discarded after decryption.
#                       Enables correlated multi-axis masquerade detection.
# ---------------------------------------------------------------------------

IDS_PROFILES: Dict[str, tuple] = {
    "12D_LEGACY": (
        "delta_t",           # f1  : raw inter-arrival time (ms)
        "counter_gap",       # f2  : monotonic counter jump
        "ecu_id_norm",       # f3  : normalised SENDER_ECU_ID
        "domain_id",         # f4  : DOMAIN_ID (routing metadata)
        "msg_type",          # f5  : message type nibble
        "tag_status",        # f6  : Ascon-AEAD128 tag verification result
        "speed",             # f7  : Vehicle Speed (km/h)
        "rpm",               # f8  : Engine RPM
        "steering",          # f9  : Steering Angle (deg)
        "brake",             # f10 : Brake Pressure (kPa)
        "long_accel",        # f11 : Longitudinal Accel (m/s^2)
        "dtc_flags",         # f12 : DTC Error Bit Count
    ),

    "12D_ENHANCED": (
        "frame_density",     # f1  : trailing causal frame-rate (fps, W=20)
                             #       replaces raw delta_t — during a 20 kHz DoS
                             #       flood this is ~100–200× above the training
                             #       distribution, guaranteeing MSE explosion.
        "counter_gap",       # f2  : monotonic counter jump
        "ecu_id_norm",       # f3  : normalised SENDER_ECU_ID
        "domain_id",         # f4  : DOMAIN_ID (routing metadata)
        "msg_type",          # f5  : message type nibble
        "tag_status",        # f6  : Ascon-AEAD128 tag verification result
        "speed_ema_dev",     # f7  : Vehicle Speed deviation from causal EMA
        "rpm",               # f8  : Engine RPM (low-variance, raw kept)
        "steering_ema_dev",  # f9  : Steering Angle deviation from causal EMA
        "brake",             # f10 : Brake Pressure (raw kept)
        "wheel_fl_ema_dev",  # f11 : Wheel Speed FL deviation from causal EMA
        "coolant_ema_dev",   # f12 : Coolant Temp deviation from causal EMA
                             #       EMA deviations are ≈0 during forward-fill
                             #       carry-forward and spike sharply on masquerade
                             #       injection — exactly what the autoencoder
                             #       learns to reconstruct as zero.
    ),
    "18D_FULL_FRAME": (
        "frame_density",     # f1  : trailing causal frame-rate (fps, W=20)
        "counter_gap",       # f2  : monotonic counter jump
        "ecu_id_norm",       # f3  : normalised SENDER_ECU_ID
        "domain_id",         # f4  : DOMAIN_ID (routing metadata)
        "msg_type",          # f5  : message type nibble
        "tag_status",        # f6  : Ascon-AEAD128 tag verification result
        "speed",             # f7  : Vehicle Speed (km/h) — payload +00..+03
        "rpm",               # f8  : Engine RPM           — payload +04..+07
        "steering",          # f9  : Steering Angle        — payload +08..+11
        "brake",             # f10 : Brake Pressure        — payload +12..+15
        "throttle",          # f11 : Throttle Position (%)  — payload +16..+19 [WAS DISCARDED]
        "long_accel",        # f12 : Longitudinal Accel     — payload +20..+23 [WAS DISCARDED]
        "lat_accel",         # f13 : Lateral Accel          — payload +24..+27 [WAS DISCARDED]
        "wheel_fl",          # f14 : Wheel Speed FL         — payload +28..+29
        "wheel_fr",          # f15 : Wheel Speed FR         — payload +30..+31 [WAS DISCARDED]
        "coolant",           # f16 : Engine Temp/Coolant    — payload +32..+33
        "gear",              # f17 : Gear Status bitmask    — payload +34..+35 [WAS DISCARDED]
        "dtc_flags",         # f18 : DTC Error Bit Count    — payload +36..+39 [WAS DISCARDED]
    ),
}

# Active default profile used by GatewayIDSExtractor if not specified.
# Defaults to '12D_LEGACY' for 100% backward compatibility with Phase 1 unit tests.
# Phase 2 ML-IDS instantiates GatewayIDSExtractor(profile="12D_ENHANCED") or "18D_FULL_FRAME".
ACTIVE_IDS_PROFILE: str = "12D_LEGACY"



class GatewayIDSExtractor:
    """
    Tapan's Feature Extraction Hook: Converts decrypted 64-byte CAN-FD frames
    and gateway-derived metadata into an N-dimensional LSTM feature vector.

    Feature Profile
    ---------------
    The active profile is controlled by the module-level ``ACTIVE_IDS_PROFILE``
    constant (see ``IDS_PROFILES`` above).  Three profiles are defined:

        12D_LEGACY     — original Phase 1 baseline (backward-compatible)
        12D_ENHANCED   — recommended Phase 2 profile (same slot count,
                         improved DoS and masquerade detection)
        18D_FULL_FRAME — full 40-byte payload utilisation

    Backward Compatibility
    ----------------------
    The public method signature of ``extract_features()`` is unchanged.  Code
    that calls ``extractor.extract_features(frame, payload, tag_valid)`` will
    continue to work; it will simply receive a vector whose length equals
    ``len(IDS_PROFILES[ACTIVE_IDS_PROFILE])`` instead of the hardcoded 12.

    Note on Feature Scaling
    -----------------------
    All values are emitted in raw physical engineering units.  MinMax
    normalisation is applied in the Phase 2 ``CANDatasetPreprocessor`` during
    training and edge ONNX pipeline preprocessing.
    """

    # Causal trailing window size for frame_density computation (frames).
    DENSITY_WINDOW: int = 20

    # EMA smoothing factor (α).  A value of 0.05 gives a slow-tracking
    # exponential moving average — normal forward-fill carry-forward produces
    # near-zero deviations while a sudden masquerade injection produces a
    # large spike.
    EMA_ALPHA: float = 0.05

    def __init__(self, profile: str = ACTIVE_IDS_PROFILE) -> None:
        """
        Parameters
        ----------
        profile : str
            One of the keys in ``IDS_PROFILES``.  Defaults to the module-level
            ``ACTIVE_IDS_PROFILE`` constant.
        """
        if profile not in IDS_PROFILES:
            raise ValueError(
                f"Unknown IDS profile '{profile}'. "
                f"Valid options: {list(IDS_PROFILES.keys())}"
            )
        self.profile: str = profile
        self.feature_names: tuple = IDS_PROFILES[profile]
        self.num_features: int = len(self.feature_names)

        # Per-ECU stateful trackers (keyed by sender_ecu_id)
        self.last_timestamps: Dict[int, float] = {}
        self.last_counters: Dict[int, int] = {}

        # Causal circular delta-t buffer for frame_density (per ECU)
        self._delta_t_buffer: Dict[int, list] = {}

        # EMA state for each physical telemetry channel (per ECU)
        # Keys: 'speed', 'steering', 'wheel_fl', 'coolant'
        self._ema: Dict[int, Dict[str, float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reset_session_counter(self, sender_ecu_id: int) -> None:
        """
        Resets the monotonic counter, timestamp, density buffer, and EMA state
        for an ECU.  Must be called upon Step 5 Session Key Delivery
        (re-attestation / new K_i provision) so that fresh session counters
        starting at 0 are not rejected against old session high-water marks.
        """
        self.last_counters.pop(sender_ecu_id, None)
        self.last_timestamps.pop(sender_ecu_id, None)
        self._delta_t_buffer.pop(sender_ecu_id, None)
        self._ema.pop(sender_ecu_id, None)

    def check_monotonic_counter_gate(self, sender_ecu_id: int, counter: int) -> bool:
        """
        Step 7b Monotonic Counter Gate (Hard Reject).

        Enforces strict monotonic increment per SENDER_ECU_ID.
        Must be called BEFORE ``extract_features()``.

        Returns
        -------
        bool
            True  — counter is strictly greater than the last accepted value
                    (or this is the first frame for this ECU).
            False — counter is ≤ last accepted value → Replay / Stale Attack
                    → caller must DROP FRAME.
        """
        last_c = self.last_counters.get(sender_ecu_id, None)
        if last_c is not None and counter <= last_c:
            return False
        return True

    def extract_features(
        self,
        frame_bytes: bytes,
        decrypted_payload: bytes,
        is_tag_valid: bool,
        arrival_time: float = None,
    ) -> List[float]:
        """
        Extract the N-dimensional IDS feature vector from one runtime frame.

        This method must only be invoked on frames that already passed Step 7b
        (``check_monotonic_counter_gate``).  It is safe to call on
        tag-failed frames — the telemetry slots will be zero-filled per the
        Failed-Tag Handling policy defined in CAN-FD Schematic v1.6, §3.6.

        Parameters
        ----------
        frame_bytes : bytes
            Full 64-byte Category 1 CAN-FD frame (header + ciphertext + tag).
        decrypted_payload : bytes
            40-byte plaintext telemetry payload (output of Ascon decryption).
        is_tag_valid : bool
            True if the Ascon-AEAD128 tag verification passed; False otherwise.
        arrival_time : float, optional
            Gateway wall-clock timestamp in milliseconds.  Defaults to
            ``time.time() * 1000.0`` if not supplied.

        Returns
        -------
        List[float]
            Feature vector of length ``self.num_features``, ordered according
            to ``self.feature_names``.
        """
        if arrival_time is None:
            arrival_time = time.time() * 1000.0  # ms

        # ── Header Unpacking ──────────────────────────────────────────────
        ver_type, sender_ecu_id, domain_id, flags, counter = struct.unpack(
            ProtectedRuntimeFrame.UNENCRYPTED_HEADER_FMT, frame_bytes[:8]
        )
        msg_type = ver_type & 0x0F

        # ── Inter-Arrival Time (Δt) ───────────────────────────────────────
        prev_t = self.last_timestamps.get(sender_ecu_id, arrival_time)
        delta_t = max(0.0, arrival_time - prev_t)  # ms, causal (never negative)

        # ── Causal Trailing Frame-Density ─────────────────────────────────
        # Push delta_t into the per-ECU circular buffer BEFORE updating
        # last_timestamp so that the current frame's Δt is included.
        buf = self._delta_t_buffer.setdefault(sender_ecu_id, [])
        buf.append(delta_t if delta_t > 0.0 else 0.001)  # floor at 1 µs
        if len(buf) > self.DENSITY_WINDOW:
            buf.pop(0)
        # fps = W / Σ(Δt_i)  where Δt is in ms → fps = W / (Σ ms / 1000)
        sum_dt_ms = sum(buf)
        frame_density = (len(buf) * 1000.0 / sum_dt_ms) if sum_dt_ms > 0.0 else 0.0

        # ── Monotonic Counter Gap ─────────────────────────────────────────
        prev_c = self.last_counters.get(sender_ecu_id, counter - 1)
        counter_gap = max(0, counter - prev_c - 1)

        # ── Update Stateful Baselines (only on valid frames) ──────────────
        if is_tag_valid:
            self.last_timestamps[sender_ecu_id] = arrival_time
            self.last_counters[sender_ecu_id] = counter

        tag_status = 0.0 if is_tag_valid else 1.0

        # ── Telemetry Decoding ────────────────────────────────────────────
        if is_tag_valid and len(decrypted_payload) == ProtectedRuntimeFrame.PAYLOAD_SIZE:
            t = ProtectedRuntimeFrame.unpack_telemetry_payload(decrypted_payload)
            speed      = float(t["vehicle_speed"])
            rpm        = float(t["engine_rpm"])
            steering   = float(t["steering_angle"])
            brake      = float(t["brake_pressure"])
            throttle   = float(t["throttle_pos"])
            long_accel = float(t["long_accel"])
            lat_accel  = float(t["lat_accel"])
            wheel_fl   = float(t["wheel_speed_fl"])
            wheel_fr   = float(t["wheel_speed_fr"])
            coolant    = float(t["engine_temp"])
            gear       = float(t["gear_status"])
            dtc_bits   = float(bin(t["diagnostic_flags"]).count("1"))
        else:
            # Failed-Tag Handling: zero-fill all telemetry slots.
            # This matches the policy in CAN-FD Schematic v1.6, §3.6 —
            # corrupted ciphertext must not pollute the LSTM sequence state.
            speed = rpm = steering = brake = throttle = long_accel = 0.0
            lat_accel = wheel_fl = wheel_fr = coolant = gear = dtc_bits = 0.0

        # ── EMA-Deviation Computation (causal, per-ECU) ───────────────────
        # EMA tracks the slow-moving background level of each channel.
        # Normal forward-fill carry-forward: raw value ≈ EMA → deviation ≈ 0.
        # Masquerade injection:  raw value jumps suddenly → deviation spikes.
        ema_state = self._ema.setdefault(sender_ecu_id, {
            "speed": speed, "steering": steering,
            "wheel_fl": wheel_fl, "coolant": coolant,
        })
        α = self.EMA_ALPHA
        ema_state["speed"]    = α * speed    + (1 - α) * ema_state["speed"]
        ema_state["steering"] = α * steering + (1 - α) * ema_state["steering"]
        ema_state["wheel_fl"] = α * wheel_fl + (1 - α) * ema_state["wheel_fl"]
        ema_state["coolant"]  = α * coolant  + (1 - α) * ema_state["coolant"]

        speed_ema_dev    = speed    - ema_state["speed"]
        steering_ema_dev = steering - ema_state["steering"]
        wheel_fl_ema_dev = wheel_fl - ema_state["wheel_fl"]
        coolant_ema_dev  = coolant  - ema_state["coolant"]

        # ── Profile-Driven Feature Assembly ──────────────────────────────
        _slot_map = {
            # Timing / bus
            "delta_t":           float(delta_t),
            "frame_density":     float(frame_density),
            # Protocol / crypto
            "counter_gap":       float(counter_gap),
            "ecu_id_norm":       float(sender_ecu_id) / 255.0,
            "domain_id":         float(domain_id),
            "msg_type":          float(msg_type),
            "tag_status":        float(tag_status),
            # Raw telemetry (all 12 physical signals from the 40B payload)
            "speed":             speed,
            "rpm":               rpm,
            "steering":          steering,
            "brake":             brake,
            "throttle":          throttle,
            "long_accel":        long_accel,
            "lat_accel":         lat_accel,
            "wheel_fl":          wheel_fl,
            "wheel_fr":          wheel_fr,
            "coolant":           coolant,
            "gear":              gear,
            "dtc_flags":         dtc_bits,
            # EMA-deviation telemetry (12D_ENHANCED slots)
            "speed_ema_dev":     speed_ema_dev,
            "steering_ema_dev":  steering_ema_dev,
            "wheel_fl_ema_dev":  wheel_fl_ema_dev,
            "coolant_ema_dev":   coolant_ema_dev,
        }

        return [_slot_map[name] for name in self.feature_names]


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
    expected_dim = extractor.num_features
    print(f"Extracted {expected_dim}D Feature Vector (profile={extractor.profile}): {vec}")
    assert len(vec) == expected_dim, f"Feature vector length mismatch: got {len(vec)}, expected {expected_dim}"
    # Sanity-check all three profiles produce valid vectors
    for profile_name in IDS_PROFILES:
        ext = GatewayIDSExtractor(profile=profile_name)
        v = ext.extract_features(full_frame, payload, is_tag_valid=True)
        assert len(v) == len(IDS_PROFILES[profile_name]), f"Profile {profile_name} length mismatch"
        print(f"  [OK] Profile {profile_name}: {len(v)}D vector produced")


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
