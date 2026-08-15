#include <iostream>
#include <cstring>
#include <cerrno>
#include <sys/time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <arpa/inet.h>
#include <linux/can/raw.h>
#include "routing_engine.hpp"
#include "ids_extractor.hpp"
#include "block_transfer.hpp" // Added block transfer manager

int main() {
    RoutingEngine engine;
    BlockTransferManager transfer_manager; // Initialize the 41-frame reassembly manager

    // Register a test ECU (e.g., Powertrain ECU in the Safety Domain)
    uint8_t dummy_key[SESSION_KEY_SIZE] = {0x01, 0x02, 0x03};
    engine.register_ecu(0x123, PolicyClass::SAFETY, dummy_key);

    // 1. Create a raw CAN socket
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) {
        std::cerr << "Error: Unable to open CAN socket." << std::endl;
        return 1;
    }

    // 2. Enable CAN-FD support on the socket
    int enable_canfd = 1;
    setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable_canfd, sizeof(enable_canfd));

    // 3. Bind the socket to the vcan0 interface
    struct sockaddr_can addr;
    struct ifreq ifr;
    std::strcpy(ifr.ifr_name, "vcan0");
    ioctl(s, SIOCGIFINDEX, &ifr);

    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cerr << "Error: Unable to bind to vcan0." << std::endl;
        return 1;
    }

    std::cout << "CISG Gateway listening on vcan0 (CAN-FD mode with Block Transfer & IDS)..." << std::endl;

    // --- FIX 1: Set 500ms receive timeout on the socket ---
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000; // 500 milliseconds
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "Warning: Failed to set socket timeout." << std::endl;
    } // <--- Added the missing closing brace here!

    // Mock values for the simulation to test the IDS Extractor
    float mock_delta_t = 0.015f;
    float mock_counter_gap = 1.0f;
    bool mock_tag_valid = false; // Start false to test the zero-fill behavior!

    // 4. The Main Listening Loop
    struct canfd_frame frame;
    int nack_retries = 0;

    while (true) {
        // Use ssize_t to prevent -Wconversion warnings
        ssize_t nbytes = read(s, &frame, sizeof(struct canfd_frame));

        if (nbytes > 0) {
            // Check frame type: Category 2 Attestation bursts vs Category 1 Runtime Traffic
            if ((frame.can_id & 0x700) == 0x200) {
                // Extract sequence index from the first 2 bytes of the payload
                uint16_t seq_index = 0;
                std::memcpy(&seq_index, &frame.data[0], sizeof(uint16_t));

                const uint8_t* chunk_data = &frame.data[2];
                size_t chunk_len = (frame.len > 2) ? (frame.len - 2) : 0;

                // Ingest into reassembly manager
                bool success = transfer_manager.ingest_fragment(seq_index, chunk_data, chunk_len);

                if (success) {
                    std::cout << "[+] Ingested Attestation Fragment Index: " << seq_index << std::endl;
                }

                // Check if all 41 blocks have arrived
                if (transfer_manager.is_complete()) {
                    std::cout << "[!] All 41 Attestation blocks received! Complete 2436B PAO reassembled." << std::endl;

                    // --- IPC Bridge: Send 2436B PAO to Python ML-DSA Verifier ---
                    int sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock >= 0) {
                        struct sockaddr_in serv_addr;
                        serv_addr.sin_family = AF_INET;
                        serv_addr.sin_port = htons(5000); // Python listener port
                        inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

                        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
                            // Send the 2436-byte buffer
                            send(sock, transfer_manager.get_reassembled_pao(), TOTAL_PAO_SIZE, 0);

                            // Read verification response from Python (1 byte: 1 = Valid, 0 = Invalid)
                            char verification_result = 0;
                            read(sock, &verification_result, 1);

                            if (verification_result == 1) {
                                std::cout << "[+] ML-DSA-44 Signature VALIDATED by Python Crypto Engine!" << std::endl;
                            } else {
                                std::cerr << "[-] ALARM: ML-DSA-44 Signature Verification FAILED!" << std::endl;
                            }
                        } else {
                            std::cerr << "[-] Error: Could not connect to Python verification server." << std::endl;
                        }
                        close(sock);
                    }

                    // Reset buffer for the next boot cycle
                    transfer_manager.reset();
                }
            } else {
                // Category 1: Standard Runtime Traffic
                std::cout << "\n[+] Runtime Frame Caught! ID: 0x" << std::hex << frame.can_id << std::dec
                          << " | Len: " << static_cast<int>(frame.len) << " bytes" << std::endl;

                // Step 7b & 9: Extract features for the LSTM and enforce zero-fill rule
                IDSFeatureVector features = IDSExtractor::extract_features(frame, mock_tag_valid, mock_delta_t, mock_counter_gap);

                // Print the resulting 12D vector for debugging
                IDSExtractor::print_vector(features);

                // Toggle the tag validity so you can observe the zero-fill rule switching on and off
                mock_tag_valid = !mock_tag_valid;
            }
        } else if (nbytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // Retrieve the list of missing sequence numbers
            std::vector<uint8_t> missing = transfer_manager.get_missing_blocks();

            // We only send a NACK if a transfer has actually started but isn't complete.
            // If missing.size() == TOTAL_BLOCKS (41), it means no transfer is active at all.
            if (!transfer_manager.is_complete() && missing.size() < 41) {
                if (nack_retries < 3) {
                                    std::cout << "[-] Timeout reached! Block transfer incomplete. Sending NACK... (Attempt " << (nack_retries + 1) << ")" << std::endl;

                                    struct canfd_frame nack_frame;
                                    std::memset(&nack_frame, 0, sizeof(struct canfd_frame));

                                    nack_frame.can_id = 0x201;
                                    nack_frame.len = static_cast<uint8_t>(missing.size());

                                    for (size_t i = 0; i < missing.size(); ++i) {
                                        nack_frame.data[i] = missing[i];
                                        std::cout << "    -> Requesting retransmission for Index: " << static_cast<int>(missing[i]) << std::endl;
                                    }

                                    if (write(s, &nack_frame, sizeof(struct canfd_frame)) != sizeof(struct canfd_frame)) {
                                        std::cerr << "[-] Error: Failed to send NACK frame." << std::endl;
                                    }
                                    nack_retries++;
                                } else {
                                    std::cerr << "[-] Max NACK retries reached. ECU unresponsive. Aborting transfer and resetting session." << std::endl;
                                    transfer_manager.reset();
                                    nack_retries = 0;
                }
            }
        }
    }

    close(s);
    return 0;
}
