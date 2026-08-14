"""
crypto_engine.py

Cryptographic Engine — CAN-FD IDS Capstone Project (Phase 1)
=============================================================
Implements all cryptographic primitives for the CISG/ECU security architecture.

Modules
-------
1. PUFEmulator             — Deterministic SRAM-PUF simulation + SHA-256 hash (IKM)
2. KeyDerivation           — HKDF-SHA256 bootstrap key derivation (RFC 5869)
3. PostQuantumAttestation  — Real ML-DSA-44 (FIPS 204) via dilithium-py
4. AsconAEAD128Engine      — NIST SP 800-232 Ascon-AEAD128 (integrated from Ascon design-team reference implementation)
5. SessionManager          — Cryptographically secure nonce / session-key generation

Dependencies
------------
    pip install cryptography dilithium-py

Notes
-----
- ML-DSA-44 (dilithium-py): pure-Python FIPS 204, produces real 2420-byte
  signatures and 1312-byte public keys. No C compiler required.

- Ascon-AEAD128: Uses `ascon_official.py`, a Python reference implementation
  from the Ascon design team (Maria Eichlseder et al., Graz University of Technology /
  https://github.com/meichlseder/pyascon), matching NIST SP 800-232.

INTEGRATION CONTRACT (for GatewayIDSExtractor)
-----------------------------------------------
AsconAEAD128Engine.decrypt() raises ValueError on authentication failure.
Always wrap at the call site and translate to is_tag_valid before calling
extract_features():

    try:
        plaintext = AsconAEAD128Engine.decrypt(key, nonce, ciphertext, ad, tag)
        is_tag_valid = True
    except ValueError:
        plaintext = None
        is_tag_valid = False

    features = extractor.extract_features(frame_bytes, plaintext or b"", is_tag_valid)

This ensures a tampered/replayed frame never poisons the feature vector or
last_counters state. See canfd_schema.py GatewayIDSExtractor for details.
"""

import os
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from dilithium_py.ml_dsa import ML_DSA_44
import ascon_official


# ---------------------------------------------------------------------------
# 1. SRAM-PUF Emulator
# ---------------------------------------------------------------------------

class PUFEmulator:
    """
    Simulates a hardware SRAM-PUF + Fuzzy Extractor pipeline.

    In real silicon the PUF secret emerges from manufacturing variations in
    SRAM startup values and is stabilised by an error-correcting Fuzzy
    Extractor.    Here we deterministically derive a per-ECU 32-byte secret using PBKDF2-HMAC-SHA256
    so that test vectors are reproducible.

    DISCLAIMER: Simulation-only deterministic seed; this does not provide hardware
    PUF security. In Phase 2 / hardware, this will be replaced by actual SRAM startup
    variability + Fuzzy Extractor.
    """

    # Software-simulation seed — treat as a manufacturing secret.
    _MASTER_SEED: bytes = b"CAPSTONE-PUF-MASTER-SEED-2026"

    @staticmethod
    def reconstruct_puf_secret(ecu_id: int) -> bytes:
        """
        Return the stable 32-byte PUF secret for *ecu_id*.

        Parameters
        ----------
        ecu_id : int
            CAN ECU identifier (up to 29-bit).

        Returns
        -------
        bytes
            32-byte secret (equivalent to Fuzzy Extractor output).
        """
        return hashlib.pbkdf2_hmac(
            "sha256",
            ecu_id.to_bytes(4, "big"),
            PUFEmulator._MASTER_SEED,
            iterations=100_000,
            dklen=32,
        )

    @staticmethod
    def get_puf_hash(puf_secret: bytes) -> bytes:
        """
        Compute SHA-256(puf_secret).

        This digest is the IKM (Input Keying Material) stored in the CISG
        enrollment database and used as input to HKDF.

        Parameters
        ----------
        puf_secret : bytes
            32-byte output of reconstruct_puf_secret.

        Returns
        -------
        bytes
            32-byte SHA-256 digest.
        """
        return hashlib.sha256(puf_secret).digest()


# ---------------------------------------------------------------------------
# 2. HKDF Key Derivation
# ---------------------------------------------------------------------------

class KeyDerivation:
    """
    Derives cryptographic keys using HKDF-SHA256 (RFC 5869).
    """

    @staticmethod
    def derive_bootstrap_key(
        puf_hash: bytes,
        random_challenge: bytes,
        target_ecu_id: int,
        session_id: int,
    ) -> bytes:
        """
        Derive the 16-byte Bootstrap Key K_boot_i (Step 3 of the architecture).

        The derivation binds K_boot_i to the ECU, challenge, and session context,
        preventing direct reuse under a different derivation context.

        Parameters
        ----------
        puf_hash : bytes
            32-byte IKM = SHA-256(PUF_secret) from the CISG enrollment DB.
        random_challenge : bytes
            16-byte nonce from the Cat 3.1 challenge frame (used as HKDF salt).
        target_ecu_id : int
            CAN ID of the target ECU.
        session_id : int
            Monotonically increasing session counter.

        Returns
        -------
        bytes
            16-byte K_boot_i (128-bit, matches Ascon-AEAD128 key size).

        Info string (per architectural spec)
        ------------------------------------
            "CAPSTONE-V1/BOOTSTRAP-KEY" || TARGET_ECU_ID (4 B BE) || SESSION_ID (4 B BE)
        """
        info = (
            b"CAPSTONE-V1/BOOTSTRAP-KEY"
            + target_ecu_id.to_bytes(4, "big")
            + session_id.to_bytes(4, "big")
        )
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=random_challenge,
            info=info,
        )
        return hkdf.derive(puf_hash)


# ---------------------------------------------------------------------------
# 3. ML-DSA-44 Post-Quantum Attestation  (FIPS 204 — real implementation)
# ---------------------------------------------------------------------------

class PostQuantumAttestation:
    """
    ML-DSA-44 digital signatures for firmware/boot-state attestation.

    Uses dilithium-py which is a pure-Python, reference implementation of
    FIPS 204 (ML-DSA). No C compiler is required.

    Signature sizes (ML-DSA-44 per FIPS 204 / dilithium-py v1.4.0):
        Signature  : 2420 bytes
        Public key : 1312 bytes
        Secret key : 2560 bytes  (includes embedded public key per FIPS 204 §5.1)
    """

    @staticmethod
    def generate_mldsa_keypair() -> tuple[bytes, bytes]:
        """
        Generate an ML-DSA-44 key pair for offline enrollment.

        Returns
        -------
        tuple[bytes, bytes]
            (public_key, secret_key) — store public_key in CISG DB,
            keep secret_key on ECU (or in simulation).
        """
        public_key, secret_key = ML_DSA_44.keygen()
        return public_key, secret_key

    @staticmethod
    def _pack_transcript(
        protocol_version: int,
        ecu_id: int,
        session_id: int,
        random_challenge: bytes,
        measurement_hash: bytes,
    ) -> bytes:
        """
        Serialise the attestation transcript to a canonical byte string.

        Transcript layout (per architectural spec):
            PROTOCOL_VERSION (2 B BE) ||
            ECU_ID           (4 B BE) ||
            SESSION_ID       (4 B BE) ||
            RANDOM_CHALLENGE (16 B)   ||
            MEASUREMENT_HASH (32 B)
        """
        if len(random_challenge) != 16:
            raise ValueError("random_challenge must be exactly 16 bytes")
        if len(measurement_hash) != 32:
            raise ValueError("measurement_hash must be exactly 32 bytes (SHA-256)")
        return (
            protocol_version.to_bytes(2, "big")
            + ecu_id.to_bytes(4, "big")
            + session_id.to_bytes(4, "big")
            + random_challenge
            + measurement_hash
        )

    @staticmethod
    def sign_attestation_transcript(
        secret_key: bytes,
        protocol_version: int,
        ecu_id: int,
        session_id: int,
        random_challenge: bytes,
        measurement_hash: bytes,
    ) -> bytes:
        """
        Sign the boot-state transcript with ML-DSA-44 (Steps 4–5).

        Parameters
        ----------
        secret_key : bytes
            2560-byte ML-DSA-44 secret key (includes embedded public key per FIPS 204 §5.1).
        protocol_version : int
            Numeric protocol version (e.g. 1).
        ecu_id : int
            CAN ECU identifier.
        session_id : int
            Current session counter.
        random_challenge : bytes
            16-byte nonce received in Cat 3.1 frame.
        measurement_hash : bytes
            32-byte SHA-256 of firmware / boot measurements.

        Returns
        -------
        bytes
            2420-byte ML-DSA-44 signature (real FIPS 204 output, no padding).
        """
        transcript = PostQuantumAttestation._pack_transcript(
            protocol_version, ecu_id, session_id, random_challenge, measurement_hash
        )
        signature = ML_DSA_44.sign(secret_key, transcript)
        assert len(signature) == 2420, f"Unexpected signature size: {len(signature)}"
        return signature

    @staticmethod
    def verify_attestation_signature(
        public_key: bytes,
        signature: bytes,
        protocol_version: int,
        ecu_id: int,
        session_id: int,
        random_challenge: bytes,
        measurement_hash: bytes,
    ) -> bool:
        """
        Verify an ML-DSA-44 attestation signature at the CISG (Step 5).

        Parameters
        ----------
        public_key : bytes
            1312-byte ML-DSA-44 public key from the enrollment database.
        signature : bytes
            2420-byte signature from the ECU's Cat 2 frames.
        (remaining) : same as sign_attestation_transcript.

        Returns
        -------
        bool
            True if the signature is valid; False otherwise.
        """
        if len(signature) != 2420:
            return False
        transcript = PostQuantumAttestation._pack_transcript(
            protocol_version, ecu_id, session_id, random_challenge, measurement_hash
        )
        return ML_DSA_44.verify(public_key, transcript, signature)


# ---------------------------------------------------------------------------
# 4. Ascon-AEAD128 Engine  (NIST SP 800-232 via official pyascon)
# ---------------------------------------------------------------------------

class AsconAEAD128Engine:
    """
    NIST SP 800-232 Ascon-AEAD128 authenticated encryption.

    Uses the official Python reference implementation from the Ascon design team
    (ascon_official.py — Maria Eichlseder et al., Graz University of Technology).

    Parameters (NIST SP 800-232)
    -----------------------------
        Key size  : 128 bits (16 bytes)
        Nonce size: 128 bits (16 bytes)
        Tag size  : 128 bits (16 bytes)

    Usage
    -----
        ciphertext, tag = AsconAEAD128Engine.encrypt(key, nonce, plaintext, ad)
        plaintext       = AsconAEAD128Engine.decrypt(key, nonce, ciphertext, ad, tag)
    """

    @classmethod
    def encrypt(
        cls,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: bytes,
    ) -> tuple[bytes, bytes]:
        """
        Ascon-AEAD128 authenticated encryption (NIST SP 800-232).

        Parameters
        ----------
        key : bytes
            16-byte key (K_boot_i or K_i).
        nonce : bytes
            16-byte nonce — must never repeat for the same key.
        plaintext : bytes
            Data to encrypt (e.g. 40-byte telemetry payload from canfd_schema.py).
        associated_data : bytes
            Data authenticated but not encrypted (e.g. CAN header + counter).

        Returns
        -------
        tuple[bytes, bytes]
            (ciphertext, tag) where tag is 16 bytes.
        """
        if len(key) != 16:
            raise ValueError("Key must be exactly 16 bytes for Ascon-AEAD128")
        if len(nonce) != 16:
            raise ValueError("Nonce must be exactly 16 bytes for Ascon-AEAD128")

        # Official ascon_encrypt returns ciphertext + 16-byte tag
        ct_and_tag = ascon_official.ascon_encrypt(
            key=key,
            nonce=nonce,
            associateddata=associated_data,
            plaintext=plaintext,
            variant="Ascon-AEAD128"
        )
        ciphertext = ct_and_tag[:-16]
        tag = ct_and_tag[-16:]
        return ciphertext, tag

    @classmethod
    def decrypt(
        cls,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes,
        tag: bytes,
    ) -> bytes:
        """
        Ascon-AEAD128 authenticated decryption (NIST SP 800-232).

        Parameters
        ----------
        key, nonce, associated_data : same as encrypt.
        ciphertext : bytes
            Encrypted payload.
        tag : bytes
            16-byte authentication tag from encrypt.

        Returns
        -------
        bytes
            Decrypted plaintext.

        Raises
        ------
        ValueError
            If the authentication tag does not match (tampering / replay).

        INTEGRATION CONTRACT
        --------------------
        Catch ValueError at the call site and map to is_tag_valid=False
        before passing to GatewayIDSExtractor.extract_features(). See the
        module docstring for the recommended wrapper pattern.
        """
        if len(key) != 16:
            raise ValueError("Key must be exactly 16 bytes for Ascon-AEAD128")
        if len(nonce) != 16:
            raise ValueError("Nonce must be exactly 16 bytes for Ascon-AEAD128")
        if len(tag) != 16:
            raise ValueError("Tag must be exactly 16 bytes for Ascon-AEAD128")

        ct_and_tag = ciphertext + tag
        plaintext = ascon_official.ascon_decrypt(
            key=key,
            nonce=nonce,
            associateddata=associated_data,
            ciphertext=ct_and_tag,
            variant="Ascon-AEAD128"
        )

        if plaintext is None:
            raise ValueError(
                "Ascon-AEAD128 authentication failed: tag mismatch. "
                "Frame may be tampered or replayed."
            )
        return plaintext


# ---------------------------------------------------------------------------
# 5. Session Manager
# ---------------------------------------------------------------------------

class SessionManager:
    """
    Generates session material using the OS CSPRNG.

    In hardware this maps to a True Random Number Generator (TRNG).
    os.urandom() is cryptographically secure on all modern OS platforms.
    """

    @staticmethod
    def generate_random_challenge() -> bytes:
        """
        Generate a 16-byte random challenge for Cat 3.1 frames.

        Returns
        -------
        bytes
            16 cryptographically random bytes.
        """
        return os.urandom(16)

    @staticmethod
    def generate_session_key() -> bytes:
        """
        Generate a fresh 16-byte session key K_i for Cat 3.3 frames.

        This key is issued per-session by the CISG and replaces K_boot_i
        for all subsequent Cat 1 telemetry encryption. Per the architecture,
        last_counters must be reset via GatewayIDSExtractor.reset_session_counter()
        whenever a new K_i is issued.

        Returns
        -------
        bytes
            16 cryptographically random bytes.
        """
        return os.urandom(16)

    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generate a 16-byte nonce for Ascon-AEAD128 frames.

        Returns
        -------
        bytes
            16 cryptographically random bytes. Must not be reused per key.
        """
        return os.urandom(16)


# ---------------------------------------------------------------------------
# Self-test (run with: python crypto_engine.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    print("=" * 60)
    print("crypto_engine.py — Self-Test Suite")
    print("=" * 60)

    # ---- 1. PUF ----
    print("\n[1] PUFEmulator")
    ecu_id = 0x123
    puf_sec = PUFEmulator.reconstruct_puf_secret(ecu_id)
    puf_sec2 = PUFEmulator.reconstruct_puf_secret(ecu_id)
    assert puf_sec == puf_sec2, "PUF must be deterministic"
    puf_hash = PUFEmulator.get_puf_hash(puf_sec)
    assert len(puf_hash) == 32
    print(f"    PUF secret (first 8B): {puf_sec[:8].hex()}")
    print(f"    PUF hash   (IKM):      {puf_hash.hex()}")
    print("    PASS ")

    # ---- 2. HKDF ----
    print("\n[2] KeyDerivation (HKDF-SHA256)")
    challenge = SessionManager.generate_random_challenge()
    session_id = 1
    k_boot = KeyDerivation.derive_bootstrap_key(puf_hash, challenge, ecu_id, session_id)
    assert len(k_boot) == 16
    # Same inputs → same output
    k_boot2 = KeyDerivation.derive_bootstrap_key(puf_hash, challenge, ecu_id, session_id)
    assert k_boot == k_boot2
    print(f"    K_boot_i: {k_boot.hex()}")
    print("    PASS ")

    # ---- 3. ML-DSA-44 ----
    print("\n[3] PostQuantumAttestation (ML-DSA-44 / FIPS 204)")
    pub_key, sec_key = PostQuantumAttestation.generate_mldsa_keypair()
    print(f"    Public key size : {len(pub_key)} bytes (expected 1312)")
    print(f"    Secret key size : {len(sec_key)} bytes (expected 2560)")
    assert len(pub_key) == 1312
    assert len(sec_key) == 2560, f"Expected 2560-byte SK, got {len(sec_key)}"

    meas_hash = hashlib.sha256(b"firmware_measurement_v1").digest()
    sig = PostQuantumAttestation.sign_attestation_transcript(
        sec_key, 1, ecu_id, session_id, challenge, meas_hash
    )
    print(f"    Signature size  : {len(sig)} bytes (expected 2420)")
    assert len(sig) == 2420

    valid = PostQuantumAttestation.verify_attestation_signature(
        pub_key, sig, 1, ecu_id, session_id, challenge, meas_hash
    )
    assert valid, "Signature verification failed"
    print(f"    Verification    : {valid}")

    # Tamper test — mutate one byte of signature
    bad_sig = bytearray(sig); bad_sig[100] ^= 0xFF
    tampered = PostQuantumAttestation.verify_attestation_signature(
        pub_key, bytes(bad_sig), 1, ecu_id, session_id, challenge, meas_hash
    )
    assert not tampered, "Tampered signature should fail"
    print(f"    Tamper rejected : {not tampered}")
    print("    PASS ")

    # ---- 4. Ascon-AEAD128 ----
    print("\n[4] AsconAEAD128Engine (NIST SP 800-232)")
    key   = SessionManager.generate_session_key()
    nonce = SessionManager.generate_nonce()
    pt    = b"CAN_FD_TELEMETRY_PAYLOAD_40BYTES!!!!!!!!"   # 40 bytes
    ad    = b"\x01\x23" + (0x456).to_bytes(4, "big")     # simulated CAN header + counter

    ciphertext, tag = AsconAEAD128Engine.encrypt(key, nonce, pt, ad)
    print(f"    Ciphertext (hex): {ciphertext[:8].hex()}...")
    print(f"    Tag (16 B):       {tag.hex()}")
    assert len(tag) == 16

    decrypted = AsconAEAD128Engine.decrypt(key, nonce, ciphertext, ad, tag)
    assert decrypted == pt, f"Decryption mismatch: {decrypted!r} != {pt!r}"
    print(f"    Decrypted OK    : {decrypted.decode()}")

    # ---- 4b. Official NIST SP 800-232 Ascon-AEAD128 KAT Validation ----
    # Source: Ascon Project — crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt
    # (https://github.com/ascon/ascon-c)

    # Vector 1: Count = 1 (Empty Plaintext, Authentication Tag Validation)
    kat1_key   = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    kat1_nonce = bytes.fromhex("101112131415161718191A1B1C1D1E1F")
    kat1_pt    = b""
    kat1_ad    = b""
    exp1_ct    = b""
    exp1_tag   = bytes.fromhex("4F9C278211BEC9316BF68F46EE8B2EC6")

    kat1_ct, kat1_tag = AsconAEAD128Engine.encrypt(kat1_key, kat1_nonce, kat1_pt, kat1_ad)
    assert kat1_ct == exp1_ct, f"KAT #1 CT mismatch: {kat1_ct.hex().upper()} != {exp1_ct.hex().upper()}"
    assert kat1_tag == exp1_tag, f"KAT #1 Tag mismatch: {kat1_tag.hex().upper()} != {exp1_tag.hex().upper()}"
    kat1_dec = AsconAEAD128Engine.decrypt(kat1_key, kat1_nonce, kat1_ct, kat1_ad, kat1_tag)
    assert kat1_dec == kat1_pt, "KAT #1 decryption failed"
    print("    KAT #1 (Count=1, Empty PT)  : PASS ")

    # Vector 2: Count = 67 (Non-Empty Plaintext 0x2021, Ciphertext + Tag Validation)
    kat67_key   = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    kat67_nonce = bytes.fromhex("101112131415161718191A1B1C1D1E1F")
    kat67_pt    = bytes.fromhex("2021")
    kat67_ad    = b""
    exp67_ct    = bytes.fromhex("E8C3")
    exp67_tag   = bytes.fromhex("5A12D2A396E76224F6EE5418F6465197")

    kat67_ct, kat67_tag = AsconAEAD128Engine.encrypt(kat67_key, kat67_nonce, kat67_pt, kat67_ad)
    assert kat67_ct == exp67_ct, f"KAT #67 CT mismatch: {kat67_ct.hex().upper()} != {exp67_ct.hex().upper()}"
    assert kat67_tag == exp67_tag, f"KAT #67 Tag mismatch: {kat67_tag.hex().upper()} != {exp67_tag.hex().upper()}"
    kat67_dec = AsconAEAD128Engine.decrypt(kat67_key, kat67_nonce, kat67_ct, kat67_ad, kat67_tag)
    assert kat67_dec == kat67_pt, "KAT #67 decryption failed"
    print("    KAT #67 (Count=67, 2B PT)   : PASS ")

    # Authentication failure test
    bad_tag = bytearray(tag); bad_tag[0] ^= 0xFF
    try:
        AsconAEAD128Engine.decrypt(key, nonce, ciphertext, ad, bytes(bad_tag))
        print("    ERROR: should have raised ValueError on bad tag")
        sys.exit(1)
    except ValueError as e:
        print(f"    Tag tamper rejected: ValueError raised ")
    print("    PASS ")

    # ---- 5. Session Manager ----
    print("\n[5] SessionManager")
    c1 = SessionManager.generate_random_challenge()
    c2 = SessionManager.generate_random_challenge()
    assert c1 != c2, "Challenges must not repeat"
    assert len(c1) == 16
    k1 = SessionManager.generate_session_key()
    assert len(k1) == 16
    n1 = SessionManager.generate_nonce()
    assert len(n1) == 16
    print(f"    Random challenge: {c1.hex()}")
    print(f"    Session key K_i : {k1.hex()}")
    print("    PASS ")

    print("\n" + "=" * 60)
    print("All tests passed. crypto_engine.py is ready.")
    print("=" * 60)
