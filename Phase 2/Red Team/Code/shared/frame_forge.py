"""
frame_forge.py
==============
Core Frame Construction & Mutation Engine for the Red Team Threat Emulation Suite.

Implements full 64-byte CAN-FD frame serialization (Cat 1 ProtectedRuntimeFrame):
  - 8-byte Unencrypted Header (also serves as Ascon Associated Data [AD])
  - 40-byte Ascon-AEAD128 Encrypted Payload
  - 16-byte Ascon Authentication Tag

Derives nonces deterministically from the monotonic counter per AUTOSAR SecOC / NIST SP 800-38D:
  Nonce = Counter_32bit || 0x00 * 12  (16 bytes)
"""

import os
import struct
import sys

CRYPTO_CODE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "Phase 1", "CAN FD", "Crypto Code")
)
if CRYPTO_CODE_DIR not in sys.path:
    sys.path.insert(0, CRYPTO_CODE_DIR)

from crypto_engine import AsconAEAD128Engine
from canfd_schema import ProtectedRuntimeFrame


class FrameForge:
    """Constructs, encrypts, and corrupts 64-byte ProtectedRuntimeFrame objects."""

    @staticmethod
    def derive_nonce(counter: int) -> bytes:
        """Derive 16-byte nonce from 32-bit counter."""
        return counter.to_bytes(4, "big") + b"\x00" * 12

    @classmethod
    def build_legitimate_frame(
        cls,
        sender_ecu_id: int,
        domain_id: int,
        session_key: bytes,
        counter: int,
        telemetry: dict,
    ) -> bytes:
        """
        Builds an authentic 64-byte ProtectedRuntimeFrame.
        """
        header_ad = ProtectedRuntimeFrame.pack_unencrypted_header(
            sender_ecu_id=sender_ecu_id,
            domain_id=domain_id,
            counter=counter,
            is_emergency=False,
        )
        payload_pt = ProtectedRuntimeFrame.pack_telemetry_payload(
            speed=float(telemetry.get("speed", 0.0)),
            rpm=float(telemetry.get("rpm", 600.0)),
            steering_angle=float(telemetry.get("steering_angle", 0.0)),
            brake_pressure=float(telemetry.get("brake_pressure", 0.0)),
            throttle_pos=float(telemetry.get("throttle_pos", 0.0)),
            long_accel=float(telemetry.get("long_accel", 0.0)),
            lat_accel=float(telemetry.get("lat_accel", 0.0)),
            wheel_speed_fl=int(telemetry.get("wheel_speed_fl", 0)),
            wheel_speed_fr=int(telemetry.get("wheel_speed_fr", 0)),
            engine_temp=int(telemetry.get("engine_temp", 90)),
            gear_status=int(telemetry.get("gear_status", 1)),
            dtc_flags=int(telemetry.get("dtc_flags", 0)),
        )
        nonce = cls.derive_nonce(counter)
        ct, tag = AsconAEAD128Engine.encrypt(session_key, nonce, payload_pt, header_ad)
        frame = header_ad + ct + tag
        assert len(frame) == 64, f"Frame length must be 64, got {len(frame)}"
        return frame

    @classmethod
    def build_stale_counter_frame(
        cls,
        sender_ecu_id: int,
        domain_id: int,
        session_key: bytes,
        stale_counter: int,
        telemetry: dict,
    ) -> bytes:
        """
        Builds a frame with valid Ascon tag under stale_counter.
        Fails Tier 1 monotonic counter check, but Ascon tag itself is mathematically valid.
        """
        return cls.build_legitimate_frame(
            sender_ecu_id=sender_ecu_id,
            domain_id=domain_id,
            session_key=session_key,
            counter=stale_counter,
            telemetry=telemetry,
        )

    @classmethod
    def corrupt_ascon_tag(cls, frame: bytes, flip_bit: int = 0) -> bytes:
        """
        Flips bit `flip_bit` (0..127) in the 16-byte authentication tag at bytes [48:64].
        """
        assert len(frame) == 64, "Input frame must be 64 bytes"
        tag_bytes = bytearray(frame[48:64])
        byte_idx = (flip_bit // 8) % 16
        bit_idx = flip_bit % 8
        tag_bytes[byte_idx] ^= (1 << bit_idx)
        return frame[:48] + bytes(tag_bytes)

    @classmethod
    def replace_ascon_tag(cls, frame: bytes, new_tag: bytes) -> bytes:
        """Replaces the 16-byte authentication tag at bytes [48:64]."""
        assert len(frame) == 64 and len(new_tag) == 16
        return frame[:48] + new_tag

    @classmethod
    def corrupt_associated_data(cls, frame: bytes, byte_idx: int = 0, xor_mask: int = 0xFF) -> bytes:
        """
        Mutates unencrypted header byte at index (0..7).
        Since AD integrity is covered by the tag, this causes tag verification failure.
        """
        assert len(frame) == 64
        hdr = bytearray(frame[:8])
        hdr[byte_idx % 8] ^= xor_mask
        return bytes(hdr) + frame[8:]

    @classmethod
    def build_masquerade_frame(
        cls,
        sender_ecu_id: int,
        domain_id: int,
        session_key: bytes,
        counter: int,
        spoofed_telemetry: dict,
    ) -> bytes:
        """
        Builds a legitimately encrypted and counter-fresh frame containing spoofed telemetry.
        Passes Tier 1 (valid crypto + fresh counter) to evaluate Tier 1.5 & Tier 2.
        """
        return cls.build_legitimate_frame(
            sender_ecu_id=sender_ecu_id,
            domain_id=domain_id,
            session_key=session_key,
            counter=counter,
            telemetry=spoofed_telemetry,
        )

    @classmethod
    def build_flood_frame(cls, sender_ecu_id: int = 0x00, counter: int = 0) -> bytes:
        """Builds an unauthenticated high-rate frame for DoS testing."""
        hdr = ProtectedRuntimeFrame.pack_unencrypted_header(
            sender_ecu_id=sender_ecu_id, domain_id=0x01, counter=counter, is_emergency=False
        )
        return hdr + (b"\x00" * 56)
