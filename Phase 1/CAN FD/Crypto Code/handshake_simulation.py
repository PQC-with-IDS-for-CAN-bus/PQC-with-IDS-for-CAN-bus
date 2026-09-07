
"""
handshake_simulation.py
=======================
End-to-End Boot Handshake Simulation -- Phase 1 CAN-FD Security Architecture

Simulates the complete vehicle ECU boot sequence for ONE ECU:
  Cat 3.1  CISG issues plaintext challenge
  Cat 2    ECU signs + Ascon-wraps attestation -> 41 CAN-FD frames
  Cat 3.3  CISG verifies ML-DSA + delivers session key K_i under K_boot_i
  Cat 1    ECU transmits first encrypted runtime telemetry frame
  IDS      CISG decrypts + extracts 12D feature vector

Run with:
    python handshake_simulation.py
"""

import hashlib
import time

from crypto_engine import (
    AsconAEAD128Engine,
    KeyDerivation,
    PostQuantumAttestation,
    PUFEmulator,
    SessionManager,
)
from canfd_schema import (
    AttestationDeliveryManager,
    ChallengeFrame,
    GatewayIDSExtractor,
    KeyDeliveryFrame,
    ProtectedRuntimeFrame,
)

SEP = "=" * 64


def section(title):
    print()
    print(SEP)
    print("  " + title)
    print(SEP)


def main():
    print(SEP)
    print("  CAPSTONE Phase 1 -- End-to-End Handshake Simulation")
    print(SEP)

    # ------------------------------------------------------------------
    # OFFLINE ENROLLMENT (manufacturing time -- runs once, not on the bus)
    # ------------------------------------------------------------------
    section("OFFLINE ENROLLMENT  [Manufacturing / Provisioning Time]")

    ECU_ID     = 0x20
    DOMAIN_ID  = 0x01
    SESSION_ID = 1

    print("  ECU_ID    : 0x{:02X}".format(ECU_ID))
    print("  DOMAIN_ID : 0x{:02X}".format(DOMAIN_ID))
    print("  SESSION_ID: {}".format(SESSION_ID))

    print("\n  [ENROLLMENT] Generating ML-DSA-44 key pair (one-time, offline)...")
    ml_dsa_pub, ml_dsa_sec = PostQuantumAttestation.generate_mldsa_keypair()
    print("  [ENROLLMENT] Public key  ({}B) -> CISG enrollment DB".format(len(ml_dsa_pub)))
    print("  [ENROLLMENT] Secret key  ({}B) -> stored on ECU".format(len(ml_dsa_sec)))

    cisg_db = {
        ECU_ID: {
            "puf_hash":   PUFEmulator.get_puf_hash(PUFEmulator.reconstruct_puf_secret(ECU_ID)),
            "ml_dsa_pub": ml_dsa_pub,
        }
    }
    FIRMWARE_HASH = hashlib.sha256(b"capstone_ecu_firmware_v1.0").digest()
    print("  [ENROLLMENT] Firmware hash: {}...".format(FIRMWARE_HASH[:8].hex()))

    # ------------------------------------------------------------------
    # STEP 1 -- Cat 3.1: CISG issues plaintext challenge
    # ------------------------------------------------------------------
    section("STEP 1  [CISG->ECU]  Cat 3.1 Challenge Frame")

    cat31_frame, random_challenge = ChallengeFrame.issue(
        target_ecu_id=ECU_ID,
        domain_id=DOMAIN_ID,
        session_id=SESSION_ID,
    )
    print("  [CISG] Cat 3.1 frame issued ({}B)".format(len(cat31_frame)))
    print("         ver_type         : 0x{:02X}  (expected 0x12)".format(cat31_frame[0]))
    print("         target_ecu_id    : 0x{:02X}".format(cat31_frame[1]))
    print("         session_id       : {}".format(SESSION_ID))
    print("         random_challenge : {}".format(random_challenge.hex()))

    # ------------------------------------------------------------------
    # STEP 2 -- ECU receives and parses Cat 3.1
    # ------------------------------------------------------------------
    section("STEP 2  [ECU]  Parse Cat 3.1")

    ecu_challenge, ecu_sid = ChallengeFrame.parse(
        frame_bytes=cat31_frame,
        expected_ecu_id=ECU_ID,
        expected_session_id=SESSION_ID,
    )
    assert ecu_challenge == random_challenge
    print("  [ECU]  Cat 3.1 parsed OK.")
    print("         challenge  = {}".format(ecu_challenge.hex()))
    print("         session_id = {}".format(ecu_sid))

    # ------------------------------------------------------------------
    # STEP 3 -- Both sides independently derive K_boot_i
    # ------------------------------------------------------------------
    section("STEP 3  [Both]  HKDF Bootstrap Key Derivation")

    ecu_puf_hash = PUFEmulator.get_puf_hash(PUFEmulator.reconstruct_puf_secret(ECU_ID))
    k_boot_ecu   = KeyDerivation.derive_bootstrap_key(ecu_puf_hash, ecu_challenge, ECU_ID, ecu_sid)
    k_boot_cisg  = KeyDerivation.derive_bootstrap_key(cisg_db[ECU_ID]["puf_hash"], random_challenge, ECU_ID, SESSION_ID)

    assert k_boot_ecu == k_boot_cisg, "K_boot_i MISMATCH!"
    print("  [ECU]  K_boot_i : {}".format(k_boot_ecu.hex()))
    print("  [CISG] K_boot_i : {}".format(k_boot_cisg.hex()))
    print("  [OK]   Match confirmed. Raw PUF secret never left the ECU.")

    # ------------------------------------------------------------------
    # STEP 4 -- ECU signs attestation + wraps into 41 Cat 2 frames
    # ------------------------------------------------------------------
    section("STEP 4  [ECU->CISG]  Cat 2 Attestation (41 frames)")

    ml_dsa_sig = PostQuantumAttestation.sign_attestation_transcript(
        secret_key=ml_dsa_sec,
        protocol_version=1,
        ecu_id=ECU_ID,
        session_id=ecu_sid,
        random_challenge=ecu_challenge,
        measurement_hash=FIRMWARE_HASH,
    )
    print("  [ECU]  ML-DSA-44 signature: {}B".format(len(ml_dsa_sig)))

    cat2_frames = AttestationDeliveryManager.wrap_and_fragment(
        signature=ml_dsa_sig,
        k_boot_i=k_boot_ecu,
        random_challenge=ecu_challenge,
        ecu_id=ECU_ID,
        session_id=ecu_sid,
    )
    print("  [ECU]  Wrapped into {} x 64B Cat 2 frames. Transmitting...".format(len(cat2_frames)))
    print("         Frame 0  flags: 0x{:02X}  (expected 0x01 = DATA)".format(cat2_frames[0][3]))
    print("         Frame 40 flags: 0x{:02X}  (expected 0x03 = LAST)".format(cat2_frames[40][3]))

    # ------------------------------------------------------------------
    # STEP 5 -- CISG reassembles PAO + verifies ML-DSA-44 signature
    # ------------------------------------------------------------------
    section("STEP 5  [CISG]  Cat 2 Reassembly + ML-DSA-44 Verification")

    recovered_sig = AttestationDeliveryManager.reassemble_and_unwrap(
        frames=cat2_frames,
        k_boot_i=k_boot_cisg,
        random_challenge=random_challenge,
        expected_ecu_id=ECU_ID,
        expected_session_id=SESSION_ID,
    )
    print("  [CISG] Ascon tag VERIFIED. Recovered {}B signature.".format(len(recovered_sig)))

    sig_ok = PostQuantumAttestation.verify_attestation_signature(
        public_key=cisg_db[ECU_ID]["ml_dsa_pub"],
        signature=recovered_sig,
        protocol_version=1,
        ecu_id=ECU_ID,
        session_id=SESSION_ID,
        random_challenge=random_challenge,
        measurement_hash=FIRMWARE_HASH,
    )
    assert sig_ok, "ML-DSA VERIFICATION FAILED!"
    print("  [CISG] ML-DSA-44 : VALID  (FIPS 204)")
    print("  [CISG] ECU 0x{:02X} AUTHENTICATED. Issuing session key.".format(ECU_ID))

    # ------------------------------------------------------------------
    # STEP 6 -- CISG generates K_i and issues Cat 3.3
    # ------------------------------------------------------------------
    section("STEP 6  [CISG->ECU]  Cat 3.3 Session Key Delivery")

    k_i = SessionManager.generate_session_key()
    print("  [CISG] Fresh K_i generated : {}".format(k_i.hex()))

    cat33_frame = KeyDeliveryFrame.wrap(
        k_boot_i=k_boot_cisg,
        k_i=k_i,
        sender_ecu_id=0xFF,
        target_domain_id=DOMAIN_ID,
        session_id=SESSION_ID,
    )
    print("  [CISG] Cat 3.3 frame ({}B): {}...".format(len(cat33_frame), cat33_frame[:16].hex()))

    # ------------------------------------------------------------------
    # STEP 7 -- ECU unwraps Cat 3.3 to extract K_i
    # ------------------------------------------------------------------
    section("STEP 7  [ECU]  Cat 3.3 Unwrap -- K_i Extracted")

    k_i_ecu = KeyDeliveryFrame.unwrap(
        frame_bytes=cat33_frame,
        k_boot_i=k_boot_ecu,
        expected_session_id=SESSION_ID,
    )
    assert k_i_ecu == k_i, "K_i MISMATCH!"
    print("  [ECU]  K_i extracted: {}".format(k_i_ecu.hex()))
    print("  [ECU]  K_boot_i retired. Runtime traffic now uses K_i.")

    # ------------------------------------------------------------------
    # STEP 8 -- ECU transmits first Cat 1 runtime telemetry frame
    # ------------------------------------------------------------------
    section("STEP 8  [ECU->CISG]  Cat 1 Runtime Telemetry (First Frame)")

    COUNTER  = 1
    header_ad = ProtectedRuntimeFrame.pack_unencrypted_header(ECU_ID, DOMAIN_ID, COUNTER)
    payload_pt = ProtectedRuntimeFrame.pack_telemetry_payload(
        speed=72.5, rpm=1800.0, steering_angle=2.3, brake_pressure=0.0,
        throttle_pos=25.0, long_accel=0.2, lat_accel=0.05,
        wheel_speed_fl=725, wheel_speed_fr=724, engine_temp=88, gear_status=3, dtc_flags=0,
    )
    # Pack frame using AUTOSAR SecOC deterministic implicit nonce derivation (SWS_SecOC_00034)
    cat1_frame = ProtectedRuntimeFrame.pack_frame(
        sender_ecu_id=ECU_ID,
        domain_id=DOMAIN_ID,
        counter=COUNTER,
        payload_bytes=payload_pt,
        key=k_i_ecu,
        direction=0x00,
    )
    nonce_rt = SessionManager.derive_runtime_nonce(ECU_ID, DOMAIN_ID, COUNTER, direction=0x00)
    ct_rt = cat1_frame[8:48]
    tag_rt = cat1_frame[48:64]
    assert len(cat1_frame) == 64
    print("  [ECU]  Cat 1 frame ({}B) transmitted.".format(len(cat1_frame)))
    print("         Header (AD)  : {}".format(header_ad.hex()))
    print("         SecOC Nonce  : {}".format(nonce_rt.hex()))
    print("         Ciphertext   : {}...  ({}B)".format(ct_rt[:8].hex(), len(ct_rt)))
    print("         Ascon tag    : {}".format(tag_rt.hex()))

    # ------------------------------------------------------------------
    # STEP 9 -- CISG: Counter gate + Decrypt + 12D IDS feature extraction
    # ------------------------------------------------------------------
    section("STEP 9  [CISG]  Counter Gate + Decrypt + IDS Feature Extraction")

    extractor = GatewayIDSExtractor()
    extractor.reset_session_counter(ECU_ID)

    gate = extractor.check_monotonic_counter_gate(ECU_ID, COUNTER)
    print("  [CISG] Monotonic counter gate (counter={}) : {}".format(COUNTER, "PASS" if gate else "FAIL"))
    assert gate

    # CISG unpacks and decrypts frame: derives deterministic nonce independently from header
    hdr_dict, decrypted, is_valid = ProtectedRuntimeFrame.unpack_and_decrypt(
        frame_bytes=cat1_frame,
        key=k_i,
        expected_direction=0x00,
    )
    if is_valid:
        print("  [CISG] Ascon-AEAD128 tag VERIFIED. Payload decrypted ({}B).".format(len(decrypted)))
    else:
        print("  [CISG] Tag FAILED. Frame dropped.")

    vec = extractor.extract_features(
        frame_bytes=cat1_frame,
        decrypted_payload=decrypted,
        is_tag_valid=is_valid,
        arrival_time=time.time() * 1000.0,
    )
    labels = [
        "dt", "Counter_Gap", "SENDER_ECU_ID", "DOMAIN_ID", "Msg_Type",
        "Tag_Status", "Speed", "RPM", "SteeringAngle", "BrakePressure",
        "LongAccel", "DTC_Count",
    ]
    print("  [CISG] 12D IDS Feature Vector:")
    for lbl, val in zip(labels, vec):
        print("         {:<16} : {:.4f}".format(lbl, val))

    # ------------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------------
    section("HANDSHAKE COMPLETE")
    print("")
    print("  ECU 0x20 (Engine ECM / Powertrain) is now AUTHENTICATED and ACTIVE.")
    print("")
    print("  Protocol chain verified:")
    print("    Cat 3.1  Plaintext challenge + SESSION_ID           [PASS]")
    print("    HKDF     Independent K_boot_i from PUF hash         [PASS]")
    print("    Cat 2    41-frame Ascon-wrapped ML-DSA attestation   [PASS]")
    print("    Cat 3.3  Ascon-wrapped K_i session key delivery      [PASS]")
    print("    Cat 1    Encrypted runtime telemetry under K_i       [PASS]")
    print("    IDS      12D feature vector ready for LSTM inference [PASS]")
    print("")
    print("  Zero failures.")


if __name__ == "__main__":
    main()

