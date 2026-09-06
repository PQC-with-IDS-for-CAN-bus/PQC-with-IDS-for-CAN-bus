"""
handshake_runner.py
===================
Executes Steps 0 through 6 of the CAN-FD Post-Quantum Authentication Handshake
programmatically to derive an authentic 16-byte session key (K_i).

Used by the Red Team suite to simulate authenticated ECU masquerade and injection
scenarios with cryptographically valid session credentials.
"""

import hashlib
import os
import sys

CRYPTO_CODE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "Phase 1", "CAN FD", "Crypto Code")
)
if CRYPTO_CODE_DIR not in sys.path:
    sys.path.insert(0, CRYPTO_CODE_DIR)

from crypto_engine import (
    KeyDerivation,
    PostQuantumAttestation,
    PUFEmulator,
    SessionManager,
)
from canfd_schema import (
    AttestationDeliveryManager,
    ChallengeFrame,
    KeyDeliveryFrame,
)


def derive_real_session_key(
    ecu_id: int = 0x20, domain_id: int = 0x01, session_id: int = 1
) -> tuple[bytes, int]:
    """
    Executes Steps 0-6 of the CISG <-> ECU Handshake.
    Returns (session_key_k_i [16 bytes], starting_counter [1]).
    """
    ml_dsa_pub, ml_dsa_sec = PostQuantumAttestation.generate_mldsa_keypair()
    cisg_db = {
        ecu_id: {
            "puf_hash": PUFEmulator.get_puf_hash(
                PUFEmulator.reconstruct_puf_secret(ecu_id)
            ),
            "ml_dsa_pub": ml_dsa_pub,
        }
    }
    firmware_hash = hashlib.sha256(b"capstone_ecu_firmware_v1.0").digest()

    cat31_frame, random_challenge = ChallengeFrame.issue(
        target_ecu_id=ecu_id, domain_id=domain_id, session_id=session_id
    )

    ecu_challenge, ecu_sid = ChallengeFrame.parse(
        frame_bytes=cat31_frame,
        expected_ecu_id=ecu_id,
        expected_session_id=session_id,
    )

    ecu_puf_hash = PUFEmulator.get_puf_hash(PUFEmulator.reconstruct_puf_secret(ecu_id))
    k_boot_ecu = KeyDerivation.derive_bootstrap_key(
        ecu_puf_hash, ecu_challenge, ecu_id, ecu_sid
    )
    k_boot_cisg = KeyDerivation.derive_bootstrap_key(
        cisg_db[ecu_id]["puf_hash"], random_challenge, ecu_id, session_id
    )
    assert k_boot_ecu == k_boot_cisg, "K_boot_i derivation mismatch"

    ml_dsa_sig = PostQuantumAttestation.sign_attestation_transcript(
        secret_key=ml_dsa_sec,
        protocol_version=1,
        ecu_id=ecu_id,
        session_id=ecu_sid,
        random_challenge=ecu_challenge,
        measurement_hash=firmware_hash,
    )
    cat2_frames = AttestationDeliveryManager.wrap_and_fragment(
        signature=ml_dsa_sig,
        k_boot_i=k_boot_ecu,
        random_challenge=ecu_challenge,
        ecu_id=ecu_id,
        session_id=ecu_sid,
    )

    recovered_sig = AttestationDeliveryManager.reassemble_and_unwrap(
        frames=cat2_frames,
        k_boot_i=k_boot_cisg,
        random_challenge=random_challenge,
        expected_ecu_id=ecu_id,
        expected_session_id=session_id,
    )
    sig_valid = PostQuantumAttestation.verify_attestation_signature(
        public_key=cisg_db[ecu_id]["ml_dsa_pub"],
        signature=recovered_sig,
        protocol_version=1,
        ecu_id=ecu_id,
        session_id=session_id,
        random_challenge=random_challenge,
        measurement_hash=firmware_hash,
    )
    assert sig_valid, "ML-DSA-44 verification failed during handshake"

    k_i = SessionManager.generate_session_key()
    cat33_frame = KeyDeliveryFrame.wrap(
        k_boot_i=k_boot_cisg,
        k_i=k_i,
        sender_ecu_id=0xFF,
        target_domain_id=domain_id,
        session_id=session_id,
    )

    k_i_ecu = KeyDeliveryFrame.unwrap(
        frame_bytes=cat33_frame,
        k_boot_i=k_boot_ecu,
        expected_session_id=session_id,
    )
    assert k_i_ecu == k_i, "K_i unwrap mismatch"

    return k_i, 1


if __name__ == "__main__":
    k, c = derive_real_session_key()
    print(f"[OK] Derived K_i: {k.hex()}, counter: {c}")
