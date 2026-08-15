#include "block_transfer.hpp"
#include <cstring>
#include <algorithm>

BlockTransferManager::BlockTransferManager() {
    reset();
}

void BlockTransferManager::reset() {
    reassembly_buffer.fill(0);
    received_blocks.fill(false);
    received_count = 0;
}

bool BlockTransferManager::ingest_fragment(uint16_t seq_index, const uint8_t* payload, size_t payload_len) {
    if (seq_index >= TOTAL_BLOCKS) return false;

    // If already received, ignore duplicate
    if (received_blocks[seq_index]) return true;

    size_t offset = seq_index * CHUNK_SIZE;
    if (offset + payload_len > TOTAL_PAO_SIZE) return false;

    // Copy fragment payload into its exact offset position in the 2436B buffer
    std::memcpy(reassembly_buffer.data() + offset, payload, payload_len);
    received_blocks[seq_index] = true;
    received_count++;

    return true;
}

bool BlockTransferManager::is_complete() const {
    return received_count == TOTAL_BLOCKS;
}

std::vector<uint8_t> BlockTransferManager::get_missing_blocks() const {
    std::vector<uint8_t> missing;
    for (size_t i = 0; i < TOTAL_BLOCKS; ++i) {
        if (!received_blocks[i]) {
            missing.push_back(static_cast<uint8_t>(i));
        }
    }
    return missing;
}

const uint8_t* BlockTransferManager::get_reassembled_pao() const {
    return reassembly_buffer.data();
}
