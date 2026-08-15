import socket
import struct
from crypto_engine import PostQuantumAttestation

def run_verification_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 5000))
    server_socket.listen(1)

    print("[*] Python Crypto Bridge Server listening on port 5000...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[+] Connected to C++ Gateway from {addr}")

        pao_data = bytearray()
        while len(pao_data) < 2436:
            packet = client_socket.recv(2436 - len(pao_data))
            if not packet:
                break
            pao_data.extend(packet)

        if len(pao_data) == 2436:
            print("[+] Received full 2436B PAO from C++ gateway. Running ML-DSA-44 verification...")

            try:
                # Extract the 2420-byte signature from the PAO buffer
                signature = bytes(pao_data[:2420])

                # Load public key and active session parameters
                with open("mldsa_pubkey.bin", "rb") as f:
                    public_key = f.read()

                with open("session_params.bin", "rb") as f:
                    params_raw = f.read()
                    protocol_version = struct.unpack(">H", params_raw[0:2])[0]
                    ecu_id = struct.unpack(">I", params_raw[2:6])[0]
                    session_id = struct.unpack(">I", params_raw[6:10])[0]
                    random_challenge = params_raw[10:26]
                    measurement_hash = params_raw[26:58]

                # Invoke Kunal's verification method
                is_valid = PostQuantumAttestation.verify_attestation_signature(
                    public_key=public_key,
                    signature=signature,
                    protocol_version=protocol_version,
                    ecu_id=ecu_id,
                    session_id=session_id,
                    random_challenge=random_challenge,
                    measurement_hash=measurement_hash
                )

                response = b'\x01' if is_valid else b'\x00'
                client_socket.sendall(response)
                print(f"[+] Verification result sent back to C++: {'SUCCESS' if is_valid else 'FAILURE'}")
            except Exception as e:
                print(f"[-] Cryptographic processing error: {e}")
                client_socket.sendall(b'\x00')
        else:
            print(f"[-] Incomplete payload received: {len(pao_data)} bytes")
            client_socket.sendall(b'\x00')

        client_socket.close()

if __name__ == "__main__":
    run_verification_server()
