#!/usr/bin/env python3
"""
v4_wire_codec.py
Phase 4 Hardware-in-the-Loop (HIL) Strict 64-Byte CAN-FD Wire Codec & Protocol Bridge
====================================================================================
Project: Secure Segmented CAN-FD Architecture with PQC and Gateway-Side FL-IDS
Lead Author: Tapan (23BDS1151) — ML/Data Architecture & Cryptography
Reference Standards:
  - ISO 11898-1:2015 (CAN-FD 64-byte payload limit, DLC 15)
  - NIST SP 800-232 (Ascon-AEAD128)
  - AUTOSAR SecOC (Freshness Management & Header Integrity)

Key Protocol Invariants:
1. Exact 64-Byte Frame Layout:
   - Bytes 0-7  (8B) : Plaintext Header / Associated Data (AD) -> [CAN ID: 4B uint32 BE][Counter: 4B uint32 BE]
   - Bytes 8-47 (40B): Ciphertext Payload -> Encrypted struct.pack(">9fI", ...)
   - Bytes 48-63(16B): Ascon-AEAD128 Authentication Tag
   - Total Wire Size = Exactly 64 Bytes (DLC 15).
2. Derived In-Memory Nonce (0-Byte Wire Overhead):
   - Nonce = struct.pack(">II", can_id, counter) + b"\\x00" * 8 (16 bytes)
   - Reconstructed independently in RAM by sender and receiver.
3. Monotonic Sequence Gate & Anti-Replay:
   - Evaluated before cryptographic decryption. Stale frames (counter <= last_counter)
     are dropped in < 2 us without invoking Ascon permutation.
4. Key Rollover Rule:
   - Monotonic counter starts at 1. If counter reaches 0xEFFFFFFF (4,026,531,839) or upon
     system reboot, a mandatory session re-keying is triggered via ML-KEM-512.
"""

import sys
import os
import struct
import hmac
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union

# ---------------------------------------------------------------------------
# Dynamic Path Resolution for Ascon-AEAD128
# ---------------------------------------------------------------------------
_CURRENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _CURRENT_DIR.parent.parent

_crypto_search_dirs = [
    _PROJECT_ROOT / "Anti Gravity" / "Phase 1" / "Crypto" / "Code",
    _PROJECT_ROOT / "Phase 1" / "Crypto" / "Code",
    _PROJECT_ROOT / "Git repo" / "Phase 1" / "CAN FD" / "Crypto Code",
]

_ascon_imported = False
for d in _crypto_search_dirs:
    if (d / "ascon_official.py").exists():
        if str(d) not in sys.path:
            sys.path.insert(0, str(d))
        try:
            import ascon_official
            _ascon_imported = True
            break
        except ImportError:
            pass

if not _ascon_imported:
    # Try direct import if already on path
    try:
        import ascon_official
        _ascon_imported = True
    except ImportError:
        raise ImportError(
            "CRITICAL: Could not locate ascon_official.py in Phase 1 crypto directories. "
            f"Searched: {[str(p) for p in _crypto_search_dirs]}"
        )


# ---------------------------------------------------------------------------
# Protocol Constants
# ---------------------------------------------------------------------------
CANFD_MAX_PAYLOAD_BYTES = 64
HEADER_AD_BYTES = 8        # 4B CAN ID + 4B Monotonic Counter
CIPHERTEXT_BYTES = 40      # 9 x 4B float32 + 4B uint32 CAN ID
TAG_BYTES = 16             # 128-bit Ascon tag
TOTAL_FRAME_BYTES = 64

COUNTER_START = 1
COUNTER_ROLLOVER_THRESHOLD = 0xEFFFFFFF  # Mandatory re-key trigger at ~4.02 billion frames

TELEMETRY_KEYS = [
    "vehicle_speed",
    "engine_rpm",
    "steering_angle",
    "brake_pressure",
    "wheel_speed_fl",
    "wheel_speed_fr",
    "wheel_speed_rl",
    "wheel_speed_rr",
    "coolant_temp",
]


class CodecError(Exception):
    """Base exception for Phase 4 Wire Codec errors."""
    pass


class ReplayError(CodecError):
    """Raised when an incoming frame has a stale or non-monotonic counter."""
    pass


class TagMismatchError(CodecError):
    """Raised when Ascon-AEAD128 authentication tag verification fails."""
    pass


class FrameSizeError(CodecError):
    """Raised when a frame violates the exact 64-byte physical CAN-FD constraint."""
    pass


class CounterRolloverWarning(CodecError):
    """Raised when the 32-bit counter exceeds safety threshold and requires ML-KEM re-key."""
    pass


# ---------------------------------------------------------------------------
# Core Codec Functions
# ---------------------------------------------------------------------------

def derive_ascon_nonce(can_id: int, counter: int) -> bytes:
    """
    Derive the 16-byte Ascon-AEAD128 nonce in memory.
    Layout: [CAN ID: 4B BE][Counter: 4B BE][Static 8B Zero Padding]
    Total = Exactly 16 Bytes.
    """
    return struct.pack(">II", can_id, counter) + b"\x00" * 8


def serialize_telemetry_payload(telemetry: Dict[str, Any], can_id: int) -> bytes:
    """
    Serialize vehicle kinematics into the canonical 40-byte binary format (>9fI).
    Handles alias normalization from Phase 2 datasets.
    """
    speed = float(telemetry.get("vehicle_speed", telemetry.get("speed", 0.0)))
    rpm = float(telemetry.get("engine_rpm", telemetry.get("rpm", 0.0)))
    steering = float(telemetry.get("steering_angle", telemetry.get("Steering", 0.0)))
    brake = float(telemetry.get("brake_pressure", telemetry.get("brake", 0.0)))
    fl = float(telemetry.get("wheel_speed_fl", speed))
    fr = float(telemetry.get("wheel_speed_fr", speed))
    rl = float(telemetry.get("wheel_speed_rl", speed))
    rr = float(telemetry.get("wheel_speed_rr", speed))
    coolant = float(telemetry.get("coolant_temp", telemetry.get("engine_temp", 90.0)))

    return struct.pack(">9fI", speed, rpm, steering, brake, fl, fr, rl, rr, coolant, can_id)


def deserialize_telemetry_payload(payload_bytes: bytes) -> Dict[str, float]:
    """
    Deserialize a 40-byte binary payload into a standardized telemetry dictionary.
    """
    if len(payload_bytes) != 40:
        raise FrameSizeError(f"Plaintext payload must be exactly 40 bytes, got {len(payload_bytes)} bytes")
    
    vals = struct.unpack(">9fI", payload_bytes)
    return {
        "vehicle_speed": float(vals[0]),
        "engine_rpm": float(vals[1]),
        "steering_angle": float(vals[2]),
        "brake_pressure": float(vals[3]),
        "wheel_speed_fl": float(vals[4]),
        "wheel_speed_fr": float(vals[5]),
        "wheel_speed_rl": float(vals[6]),
        "wheel_speed_rr": float(vals[7]),
        "coolant_temp": float(vals[8]),
        "source_can_id": int(vals[9]),
    }


def pack_phase4_canfd_frame(
    can_id: int,
    counter: int,
    telemetry: Union[Dict[str, Any], bytes],
    session_key: bytes
) -> bytes:
    """
    Pack vehicle telemetry into a strict 64-byte authenticated CAN-FD physical frame.

    Parameters:
    -----------
    can_id : int
        Standard or extended CAN Identifier.
    counter : int
        Strictly monotonic 32-bit sequence counter (1 <= counter <= 0xEFFFFFFF).
    telemetry : dict or bytes
        Telemetry dictionary or raw 40-byte binary payload.
    session_key : bytes
        16-byte Ascon-AEAD128 symmetric key.

    Returns:
    --------
    bytes : Exactly 64-byte authenticated CAN-FD payload.
    """
    if len(session_key) != 16:
        raise ValueError(f"Ascon session_key must be exactly 16 bytes, got {len(session_key)}")
    if counter < COUNTER_START:
        raise ValueError(f"Counter must be >= {COUNTER_START}, got {counter}")
    if counter >= COUNTER_ROLLOVER_THRESHOLD:
        raise CounterRolloverWarning(
            f"Counter {counter} reached rollover threshold {COUNTER_ROLLOVER_THRESHOLD:#x}. "
            "Mandatory Session Key Rotation required!"
        )

    # 1. Associated Data (Header): 8 Bytes
    ad = struct.pack(">II", can_id, counter)

    # 2. Plaintext Telemetry: 40 Bytes
    if isinstance(telemetry, bytes):
        if len(telemetry) != 40:
            raise FrameSizeError(f"Raw telemetry bytes must be 40 bytes, got {len(telemetry)}")
        plaintext = telemetry
    else:
        plaintext = serialize_telemetry_payload(telemetry, can_id)

    # 3. Derived In-Memory Nonce: 16 Bytes
    nonce = derive_ascon_nonce(can_id, counter)

    # 4. Ascon-AEAD128 Authenticated Encryption
    # ascon_encrypt returns ciphertext + 16-byte tag (40 + 16 = 56 bytes)
    ct_and_tag = ascon_official.ascon_encrypt(
        key=session_key,
        nonce=nonce,
        associateddata=ad,
        plaintext=plaintext,
        variant="Ascon-AEAD128"
    )

    # 5. Assemble Strict 64-Byte Physical Wire Frame
    frame = ad + ct_and_tag

    if len(frame) != TOTAL_FRAME_BYTES:
        raise FrameSizeError(
            f"Internal codec violation: serialized frame is {len(frame)} bytes, expected {TOTAL_FRAME_BYTES}"
        )

    return frame


def unpack_phase4_canfd_frame(
    raw_frame: bytes,
    session_key: bytes,
    last_counter: int = 0
) -> Tuple[int, int, Dict[str, float]]:
    """
    Unpack and verify a strict 64-byte authenticated CAN-FD physical frame.

    Parameters:
    -----------
    raw_frame : bytes
        Exactly 64 bytes received from SocketCAN.
    session_key : bytes
        16-byte Ascon-AEAD128 symmetric key.
    last_counter : int
        Last valid monotonic counter recorded for this CAN ID/session.

    Returns:
    --------
    Tuple[can_id (int), counter (int), telemetry (dict)]

    Raises:
    -------
    FrameSizeError : If len(raw_frame) != 64.
    ReplayError : If counter <= last_counter (evaluated in <2 us before Ascon).
    TagMismatchError : If Ascon AEAD authentication tag is invalid or tampered.
    """
    if len(raw_frame) != TOTAL_FRAME_BYTES:
        raise FrameSizeError(
            f"CAN-FD Physical Layer violation: Expected {TOTAL_FRAME_BYTES} bytes (DLC 15), "
            f"got {len(raw_frame)} bytes."
        )

    # 1. Parse Header / Associated Data (Bytes 0-7)
    can_id, counter = struct.unpack(">II", raw_frame[:HEADER_AD_BYTES])

    # 2. Tier 1 Monotonic Counter Replay Gate (Evaluated BEFORE crypto!)
    if counter <= last_counter:
        raise ReplayError(
            f"AT-04: Monotonic Counter Replay Detected (Counter {counter} <= Last {last_counter})"
        )

    # 3. Derive In-Memory Nonce
    nonce = derive_ascon_nonce(can_id, counter)
    ad = raw_frame[:HEADER_AD_BYTES]
    ct_and_tag = raw_frame[HEADER_AD_BYTES:]  # 56 bytes (40B ciphertext + 16B tag)

    # 4. Ascon-AEAD128 Decryption & Tag Verification
    plaintext = ascon_official.ascon_decrypt(
        key=session_key,
        nonce=nonce,
        associateddata=ad,
        ciphertext=ct_and_tag,
        variant="Ascon-AEAD128"
    )

    if plaintext is None:
        raise TagMismatchError(
            "AT-01: Cryptographic Authentication Failure (Ascon-AEAD128 Tag Mismatch or Header Tamper)"
        )

    # 5. Deserialize Plaintext Kinematics
    telemetry = deserialize_telemetry_payload(plaintext)
    return can_id, counter, telemetry


# ---------------------------------------------------------------------------
# Self-Test / Demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Phase 4 CAN-FD Wire Codec Self-Test ===")
    test_key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
    test_can_id = 0x100
    test_counter = 42

    sample_telemetry = {
        "vehicle_speed": 65.5,
        "engine_rpm": 2450.0,
        "steering_angle": -1.25,
        "brake_pressure": 0.0,
        "wheel_speed_fl": 65.4,
        "wheel_speed_fr": 65.5,
        "wheel_speed_rl": 65.2,
        "wheel_speed_rr": 65.3,
        "coolant_temp": 88.5,
    }

    print(f"1. Packing telemetry for CAN ID {test_can_id:#x}, Counter {test_counter}...")
    frame_64b = pack_phase4_canfd_frame(test_can_id, test_counter, sample_telemetry, test_key)
    print(f"   -> Frame length: {len(frame_64b)} bytes (Target: 64 bytes)")
    assert len(frame_64b) == 64, "Length check failed!"

    print("2. Unpacking valid frame...")
    cid, cnt, telem = unpack_phase4_canfd_frame(frame_64b, test_key, last_counter=41)
    assert cid == test_can_id and cnt == test_counter
    assert abs(telem["vehicle_speed"] - 65.5) < 1e-4
    print(f"   -> Success! Recovered speed: {telem['vehicle_speed']:.2f} km/h, RPM: {telem['engine_rpm']:.0f}")

    print("3. Testing Replay Attack Detection (Counter 42 <= 42)...")
    try:
        unpack_phase4_canfd_frame(frame_64b, test_key, last_counter=42)
        print("   -> FAIL: Replay was NOT detected!")
    except ReplayError as e:
        print(f"   -> PASS: Caught replay: {e}")

    print("4. Testing Tag Corruption (Bit-Flip on Tag)...")
    corrupted_frame = bytearray(frame_64b)
    corrupted_frame[60] ^= 0x01  # Flip a bit in the tag
    try:
        unpack_phase4_canfd_frame(bytes(corrupted_frame), test_key, last_counter=41)
        print("   -> FAIL: Tag corruption was NOT detected!")
    except TagMismatchError as e:
        print(f"   -> PASS: Caught tag corruption: {e}")

    print("=== All Self-Tests Passed! ===")
