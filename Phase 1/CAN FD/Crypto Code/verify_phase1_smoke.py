"""
verify_phase1_smoke.py
======================
Automated pre-commit smoke test and technical checklist verifier
for Phase 1 CAN-FD Security Architecture.
"""

import os
import sys
import math
import struct
import hashlib

from crypto_engine import (
    PUFEmulator,
    KeyDerivation,
    PostQuantumAttestation,
    AsconAEAD128Engine,
    SessionManager,
)
from canfd_schema import (
    ChallengeFrame,
    AttestationDeliveryManager,
    IndexedAttestationFrame,
    KeyDeliveryFrame,
    ProtectedRuntimeFrame,
    GatewayIDSExtractor,
    CANFD_DLC15_SIZE,
    PROTOCOL_VERSION,
)


def test_byte_boundaries():
    print("[CHECK 1] Byte Boundary & DLC Compliance...")
    assert CANFD_DLC15_SIZE == 64
    
    # Cat 3.1: 64 bytes
    c_frame, _ = ChallengeFrame.issue(0x20, 0x01, 1)
    assert len(c_frame) == 64, f"Cat 3.1 size {len(c_frame)} != 64"
    
    # Cat 3.3: 64 bytes
    k_frame = KeyDeliveryFrame.wrap(b"\x00" * 16, b"\x01" * 16, 0xFF, 0x01, 1)
    assert len(k_frame) == 64, f"Cat 3.3 size {len(k_frame)} != 64"
    
    # Cat 1: 64 bytes
    hdr = ProtectedRuntimeFrame.pack_unencrypted_header(0x20, 0x01, 1)
    payload = ProtectedRuntimeFrame.pack_telemetry_payload(
        1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8, 9, 10, 11, 12
    )
    cat1 = hdr + payload + b"\x00" * 16
    assert len(cat1) == 64, f"Cat 1 size {len(cat1)} != 64"
    print("  [PASS] All frame categories strictly conform to 64-byte CAN-FD DLC 15.")


def test_pqc_attestation_fragmentation():
    print("[CHECK 2] PQC Attestation Fragmentation & PAO Math...")
    SIG_SIZE = 2420
    TAG_SIZE = 16
    PAO_SIZE = SIG_SIZE + TAG_SIZE  # 2436 bytes
    PAYLOAD_PER_FRAME = 60
    
    expected_frames = math.ceil(PAO_SIZE / PAYLOAD_PER_FRAME)
    assert expected_frames == 41, f"Expected 41 frames, got {expected_frames}"
    assert (40 * 60 + 36) == PAO_SIZE
    
    # Verify synthetic fragmentation round-trip
    mock_sig = os.urandom(SIG_SIZE)
    mock_key = os.urandom(16)
    mock_challenge = os.urandom(16)
    frames = AttestationDeliveryManager.wrap_and_fragment(mock_sig, mock_key, mock_challenge, 0x20, 1)
    assert len(frames) == 41
    for i, f in enumerate(frames):
        assert len(f) == 64
        h_dict, frag = IndexedAttestationFrame.unpack_frame(f)
        assert h_dict["frame_index"] == i
        assert h_dict["total_frames"] == 41
    
    recovered = AttestationDeliveryManager.reassemble_and_unwrap(frames, mock_key, mock_challenge, 0x20, 1)
    assert recovered == mock_sig
    print("  [PASS] ML-DSA-44 2420B signature -> 2436B PAO -> 41 frames fragmentation & reassembly verified.")


def test_security_invariants_and_attack_rejection():
    print("[CHECK 3] Attack Injection & Security Invariants...")
    # 1. Nonce freshness
    n1 = SessionManager.generate_nonce()
    n2 = SessionManager.generate_nonce()
    assert n1 != n2, "Nonce collision!"
    
    # 2. Monotonic counter gate (Replay & Out-of-order rejection)
    ids = GatewayIDSExtractor()
    ids.reset_session_counter(0x20)
    
    # Frame 1: counter = 1 -> accepted and committed
    assert ids.check_monotonic_counter_gate(0x20, 1) is True
    ids.extract_features(b"\x00" * 64, b"\x00" * 40, is_tag_valid=True)
    
    # Frame 2: counter = 5 -> accepted and committed
    assert ids.check_monotonic_counter_gate(0x20, 5) is True
    # Manually commit counter = 5 (simulating accepted frame)
    ids.last_counters[0x20] = 5
    
    # Attack: Replay counter = 5 -> Rejected at gate
    assert ids.check_monotonic_counter_gate(0x20, 5) is False
    # Attack: Replay older counter = 3 -> Rejected at gate
    assert ids.check_monotonic_counter_gate(0x20, 3) is False
    # Fresh frame: counter = 6 -> Accepted
    assert ids.check_monotonic_counter_gate(0x20, 6) is True
    
    # 3. Ascon AEAD tampering rejection
    k = os.urandom(16)
    n = os.urandom(16)
    ct, tag = AsconAEAD128Engine.encrypt(k, n, b"TEST_DATA" * 4, b"AD")
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0xFF
    try:
        AsconAEAD128Engine.decrypt(k, n, bytes(bad_ct), b"AD", tag)
        assert False, "Should reject modified ciphertext"
    except ValueError:
        pass
    print("  [PASS] Monotonic counter gate, Ascon integrity, and replay rejections verified.")


def test_12d_feature_vector():
    print("[CHECK 4] 12D IDS Feature Vector Schema...")
    ids = GatewayIDSExtractor()
    ids.reset_session_counter(0x20)
    hdr = ProtectedRuntimeFrame.pack_unencrypted_header(0x20, 0x01, 10)
    payload = ProtectedRuntimeFrame.pack_telemetry_payload(
        65.0, 2000.0, 0.0, 0.0, 10.0, 0.1, 0.0, 650, 650, 85, 2, 0
    )
    vec = ids.extract_features(hdr + payload + b"\x00" * 16, payload, is_tag_valid=True)
    assert len(vec) == 12, f"Expected 12 features, got {len(vec)}"
    print("  [PASS] 12D feature extraction matches LSTM input interface.")


if __name__ == "__main__":
    print("=" * 60)
    print("Running Phase 1 Pre-Commit Technical Smoke Test")
    print("=" * 60)
    try:
        test_byte_boundaries()
        test_pqc_attestation_fragmentation()
        test_security_invariants_and_attack_rejection()
        test_12d_feature_vector()
        print("=" * 60)
        print("ALL PHASE 1 SMOKE TESTS PASSED [READY FOR COMMIT]")
        print("=" * 60)
    except AssertionError as e:
        print(f"[FAIL] Verification error: {e}")
        sys.exit(1)

