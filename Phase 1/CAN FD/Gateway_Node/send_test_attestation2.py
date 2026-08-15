import socket
import struct
import time
import hashlib
from crypto_engine import PostQuantumAttestation, SessionManager

def send_burst_with_drop():
    try:
        s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        s.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FD_FRAMES, 1)
        s.bind(('vcan0',))
    except OSError as e:
        print(f"[-] Error setting up CAN-FD socket: {e}")
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

    pao_data = signature + b'\x00' * (2436 - len(signature))

    print("[*] Injecting 41-frame burst into vcan0, INTENTIONALLY DROPPING index 15...")

    for seq_index in range(41):
        if seq_index == 15:
            print("[!] SABOTAGE: Skipping Fragment Index 15")
            continue

        can_id = 0x200
        start_idx = seq_index * 60

        chunk_data = pao_data[start_idx : ] if seq_index == 40 else pao_data[start_idx : start_idx + 60]

        payload = struct.pack('<H', seq_index) + chunk_data
        can_dlc = len(payload)
        data_padded = payload.ljust(64, b'\x00')

        frame = struct.pack("I B B B B 64s", can_id, can_dlc, 0, 0, 0, data_padded)
        s.send(frame)
        time.sleep(0.02)

    print("[*] Finished sending partial burst (40/41 frames).")
    print("[*] Sniffing vcan0 for the C++ Gateway's NACK response...")

    s.settimeout(3.0)
    try:
        while True:
            recv_frame = s.recv(72)
            recv_id, recv_dlc, _, _, _, recv_data = struct.unpack("I B B B B 64s", recv_frame)

            # If we detect the NACK frame (0x201)
            if recv_id == 0x201:
                print(f"\n[<-- NACK DETECTED] Gateway requesting {recv_dlc} missing frames.")

                for i in range(recv_dlc):
                    missing_idx = recv_data[i]
                    print(f"[*] Retransmitting missing Fragment Index {missing_idx}...")

                    # Reconstruct the missing fragment
                    can_id = 0x200
                    start_idx = missing_idx * 60
                    chunk_data = pao_data[start_idx : ] if missing_idx == 40 else pao_data[start_idx : start_idx + 60]

                    payload = struct.pack('<H', missing_idx) + chunk_data
                    can_dlc = len(payload)
                    data_padded = payload.ljust(64, b'\x00')

                    frame = struct.pack("I B B B B 64s", can_id, can_dlc, 0, 0, 0, data_padded)
                    s.send(frame)
                    time.sleep(0.02)

                print("[+] Retransmission complete. C++ Gateway should now validate the PAO!")
                break

    except socket.timeout:
        print("[*] Sniffing timeout reached.")
    finally:
        s.close()

if __name__ == "__main__":
    send_burst_with_drop()
