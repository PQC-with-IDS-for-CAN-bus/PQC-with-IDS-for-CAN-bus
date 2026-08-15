#pragma once

#include <cstdint>
#include <array>
#include <vector>

constexpr size_t TOTAL_PAO_SIZE = 2436; // Total size of the ML-DSA-44 attestation object
constexpr size_t CHUNK_SIZE = 60;       // 60 bytes of payload per frame
constexpr size_t TOTAL_BLOCKS = 41;     // Fragmented into 41 frames

class BlockTransferManager {
private:
    std::array<uint8_t, TOTAL_PAO_SIZE> reassembly_buffer;
    std::array<bool, TOTAL_BLOCKS> received_blocks;
    size_t received_count;

public:
    BlockTransferManager();

    void reset();

    // Ingests a single fragment using its sequence index (0 to 40)
    bool ingest_fragment(uint16_t seq_index, const uint8_t* payload, size_t payload_len);

    // Checks if all 41 blocks have arrived
    bool is_complete() const;

    // Scans the bitmap and returns a list of missing sequence numbers for NACK generation
    std::vector<uint8_t> get_missing_blocks() const;

    // Returns a pointer to the fully reassembled 2436-byte PAO buffer
    const uint8_t* get_reassembled_pao() const;
};
