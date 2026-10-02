/**
 * ============================================================================
 * block_transfer.hpp
 * ============================================================================
 *
 * 60/4 Fragmentation & 64-Bit Selective Bitmap NACK Reassembly Protocol.
 * 
 * Standards & Specifications:
 *   - ISO 11898-1:2015: Controller Area Network with Flexible Data-Rate (CAN-FD) [^1]
 *   - ISO 26262-5:2018: Automotive Safety Integrity Level D (ASIL-D) Fault Recovery [^2]
 *   - CAN-FD Payload Constraint: Maximum 64 Bytes per Frame (DLC 15)
 *   - Protected Attestation Object (PAO): 2,436 Bytes (2,420B ML-DSA-44 Sig + 16B Ascon Tag)
 *
 * Mathematical Foundations & Protocol Mechanics:
 *   1. Fragmentation Arithmetic:
 *      N_frames = ceil(2436 / 60) = ceil(40.6) = 41 Frames.
 *      Frames 0..39: 4B Header + 60B Payload = 64 Bytes (2,400 Bytes total).
 *      Frame 40:     4B Header + 36B Payload + 24B Zero Pad = 64 Bytes (36 Bytes total).
 *      Total payload reassembled = 2,400 + 36 = 2,436 Bytes.
 *   2. Attestation Burst Frame Format (CAN ID 0x200, DLC 15):
 *      [Session ID: 1B][Frame Index: 1B (0..40)][Total Frames: 1B (41)][Flags: 1B][Payload: 60B]
 *      Flags: 0x01 (FLAG_DATA), 0x03 (FLAG_LAST on frame 40).
 *   3. Selective Bitmap NACK Recovery (CAN ID 0x201, DLC 10 = 16 Bytes):
 *      [Type: 1B (0x13)][ECU ID: 1B][Round: 1B][Res: 1B][Session ID: 4B BE][Bitmap: 8B uint64_t]
 *      Missing bitmap equation:
 *      B_missing = sum_{i=0}^{40} (1 - received[i]) * 2^i
 *      Transmitter selectively retransmits only frame indices where (B_missing & (1ULL << i)) != 0.
 *
 * Upstream Provenance:
 *   - Phase 1 Codebase: Git repo/Phase 1/CAN FD/Gateway_Node/include/block_transfer.hpp
 *   - Specification Document: Phase 1/CAN FD/Gateway_Node/canfd_bytewise_schematics.md
 *
 * Footnotes:
 *   [^1]: ISO 11898-1:2015, Road Vehicles — CAN Data Link Layer and Physical Signalling.
 *   [^2]: ISO 26262-5:2018, Product development at the hardware and software level for ASIL-D.
 * ============================================================================
 */

#ifndef BLOCK_TRANSFER_HPP
#define BLOCK_TRANSFER_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <cstring>
#include <algorithm>

namespace cisg::protocol {

/**
 * @brief Block Transfer Protocol Constants
 */
struct BlockTransferConstants {
    static constexpr uint32_t CAN_ID_ATTESTATION_BURST = 0x200; // Cat 2: 60/4 Attestation
    static constexpr uint32_t CAN_ID_SELECTIVE_NACK    = 0x201; // Cat 3.2: 64-bit Bitmap NACK
    static constexpr uint32_t CAN_ID_CHALLENGE         = 0x202; // Cat 3.1: Gateway Challenge
    static constexpr uint32_t CAN_ID_SESSION_KEY       = 0x203; // Cat 3.3: Session Key Delivery

    static constexpr size_t TOTAL_PAO_BYTES   = 2436; // 2420B Sig + 16B Tag
    static constexpr size_t CHUNK_PAYLOAD     = 60;   // Payload bytes per frame
    static constexpr size_t TOTAL_FRAMES      = 41;   // ceil(2436 / 60)
    static constexpr size_t FRAME_TOTAL_BYTES = 64;   // ISO 11898-1 DLC 15

    static constexpr uint8_t FLAG_DATA = 0x01;
    static constexpr uint8_t FLAG_LAST = 0x03;
    static constexpr uint8_t NACK_TYPE_BYTE = 0x13;
    static constexpr uint64_t ALL_FRAMES_MASK = (1ULL << TOTAL_FRAMES) - 1ULL; // 41 bits set (0x1FFFFFFFFFFULL)
};

/**
 * @brief Structure representing a 64-byte CAN-FD 60/4 Attestation Fragment Frame Header
 */
#pragma pack(push, 1)
struct AttestationFragmentHeader {
    uint8_t session_id;
    uint8_t frame_index; // 0..40
    uint8_t total_frames; // 41
    uint8_t flags;        // 0x01 (data) or 0x03 (last)
};

struct SelectiveNackFrame {
    uint8_t  msg_type;      // 0x13
    uint8_t  target_ecu_id; // Domain ECU target
    uint8_t  retry_round;   // Retransmission attempt counter (0..MAX_RETRIES)
    uint8_t  reserved;      // 0x00
    uint32_t session_id;    // Big-endian session ID
    uint64_t missing_bitmap;// Little-endian 64-bit bitmask of missing frame indices (0..40)
};
#pragma pack(pop)

/**
 * @brief 60/4 Fragmentation Packetizer (Transmitter Side: ECU)
 */
class BlockTransferPacketizer {
public:
    static inline size_t packetize(const uint8_t* pao_data, size_t pao_len,
                                  uint8_t session_id,
                                  std::array<std::array<uint8_t, 64>, 41>& frames_out) {
        if (!pao_data || pao_len != BlockTransferConstants::TOTAL_PAO_BYTES) {
            return 0;
        }

        for (uint8_t idx = 0; idx < BlockTransferConstants::TOTAL_FRAMES; ++idx) {
            auto& frame = frames_out[idx];
            frame.fill(0);

            frame[0] = session_id;
            frame[1] = idx;
            frame[2] = static_cast<uint8_t>(BlockTransferConstants::TOTAL_FRAMES);
            frame[3] = (idx == BlockTransferConstants::TOTAL_FRAMES - 1)
                           ? BlockTransferConstants::FLAG_LAST
                           : BlockTransferConstants::FLAG_DATA;

            size_t offset = idx * BlockTransferConstants::CHUNK_PAYLOAD;
            size_t chunk_len = std::min(BlockTransferConstants::CHUNK_PAYLOAD, pao_len - offset);
            std::memcpy(&frame[4], pao_data + offset, chunk_len);
        }

        return BlockTransferConstants::TOTAL_FRAMES;
    }
};

/**
 * @brief Reassembly and Selective NACK Generator (Receiver Side: Gateway)
 */
class BlockTransferReassembler {
public:
    inline BlockTransferReassembler() {
        reset(0);
    }

    inline void reset(uint8_t expected_session_id) {
        session_id_ = expected_session_id;
        received_bitmap_ = 0;
        count_ = 0;
        pao_buffer_.fill(0);
        frame_received_.fill(false);
    }

    inline bool ingest_frame(const uint8_t* frame_data) {
        if (!frame_data) return false;

        uint8_t sess = frame_data[0];
        uint8_t idx  = frame_data[1];
        uint8_t tot  = frame_data[2];

        if (sess != session_id_ || tot != BlockTransferConstants::TOTAL_FRAMES || idx >= BlockTransferConstants::TOTAL_FRAMES) {
            return false;
        }

        if (frame_received_[idx]) {
            return false; // Ignore duplicate
        }

        size_t offset = idx * BlockTransferConstants::CHUNK_PAYLOAD;
        size_t chunk_len = std::min(BlockTransferConstants::CHUNK_PAYLOAD, BlockTransferConstants::TOTAL_PAO_BYTES - offset);

        std::memcpy(pao_buffer_.data() + offset, frame_data + 4, chunk_len);

        frame_received_[idx] = true;
        received_bitmap_ |= (1ULL << idx);
        count_++;
        return true;
    }

    inline bool is_complete() const noexcept {
        return (received_bitmap_ & BlockTransferConstants::ALL_FRAMES_MASK) == BlockTransferConstants::ALL_FRAMES_MASK;
    }

    inline size_t received_count() const noexcept {
        return count_;
    }

    inline uint64_t compute_missing_bitmap() const noexcept {
        return (~received_bitmap_) & BlockTransferConstants::ALL_FRAMES_MASK;
    }

    inline void build_nack_frame(uint8_t ecu_id, uint8_t round, SelectiveNackFrame& nack_frame_out) const noexcept {
        nack_frame_out.msg_type = BlockTransferConstants::NACK_TYPE_BYTE;
        nack_frame_out.target_ecu_id = ecu_id;
        nack_frame_out.retry_round = round;
        nack_frame_out.reserved = 0;
        nack_frame_out.session_id = session_id_;
        nack_frame_out.missing_bitmap = compute_missing_bitmap();
    }

    inline bool get_reassembled_pao(uint8_t* pao_out) const {
        if (!pao_out || !is_complete()) {
            return false;
        }
        std::memcpy(pao_out, pao_buffer_.data(), BlockTransferConstants::TOTAL_PAO_BYTES);
        return true;
    }

private:
    uint8_t session_id_{0};
    uint64_t received_bitmap_{0};
    size_t count_{0};
    std::array<uint8_t, BlockTransferConstants::TOTAL_PAO_BYTES> pao_buffer_{};
    std::array<bool, BlockTransferConstants::TOTAL_FRAMES> frame_received_{};
};

} // namespace cisg::protocol

#endif // BLOCK_TRANSFER_HPP
