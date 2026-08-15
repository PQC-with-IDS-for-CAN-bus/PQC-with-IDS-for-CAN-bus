import socket
import struct
import time
import hashlib
from crypto_engine import PostQuantumAttestation, SessionManager

def send_burst():
    try:
        s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        s.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FD_FRAMES, 1)
        s.bind(('vcan0',))
    except OSError as e:
        print(f"[-] Error setting up CAN-FD socket: {e}. Ensure vcan0 is active.")
        return

    print("[*] Generating real ML-DSA-44 keypair and signed attestation transcript...")

    pub_key, secret_key = PostQuantumAttestation.generate_mldsa_keypair()

    with open("mldsa_pubkey.bin", "wb") as f:
        f.write(pub_key)

    protocol_version = 1
    ecu_id = 0x123
    session_id = 1
    random_challenge = SessionManager.generate_random_challenge()
    measurement_hash = hashlib.sha256(b"firmware_measurement_v1").digest()

    with open("session_params.bin", "wb") as f:
        f.write(struct.pack(">H I I", protocol_version, ecu_id, session_id) + random_challenge + measurement_hash)

    signature = PostQuantumAttestation.sign_attestation_transcript(
        secret_key, protocol_version, ecu_id, session_id, random_challenge, measurement_hash
    )

    # Ensure PAO is exactly 2436 bytes: 2420B signature + 16B zero padding to match buffer requirement
    pao_data = signature + b'\x00' * (2436 - len(signature))

    print(f"[*] Injecting 41-frame Category 2 attestation burst into vcan0 ({len(pao_data)} bytes)...")

    for seq_index in range(41):
        can_id = 0x200
        start_idx = seq_index * 60

        # Extract a full 60-byte chunk per frame, except for the 36-byte remainder on the last frame
        if seq_index == 40:
            chunk_data = pao_data[start_idx : ]
        else:
            chunk_data = pao_data[start_idx : start_idx + 60]

        # Pack sequence index (2 bytes) + pure PAO chunk data
        payload = struct.pack('<H', seq_index) + chunk_data

        can_dlc = len(payload)
        data_padded = payload.ljust(64, b'\x00')

        frame = struct.pack("I B B B B 64s", can_id, can_dlc, 0, 0, 0, data_padded)
        s.send(frame)
        time.sleep(0.02)

    time.sleep(0.3)
    s.close()
    print("[+] Successfully finished injecting all 41 real attestation chunks!")

if __name__ == "__main__":
    send_burst()
