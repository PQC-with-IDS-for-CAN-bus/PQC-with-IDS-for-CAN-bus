/**
 * ============================================================================
 * ascon_sp800_232.hpp
 * ============================================================================
 *
 * NIST SP 800-232 Compliant Ascon-AEAD128 Authenticated Encryption Engine.
 * 
 * Standards & Specifications:
 *   - NIST SP 800-232: Ascon-Based Lightweight Cryptography Standards (Oct 2023) [^1]
 *   - Algorithm: Ascon-AEAD128
 *   - Key Size (k): 128 bits (16 bytes)
 *   - Nonce Size (n): 128 bits (16 bytes)
 *   - Tag Size (t): 128 bits (16 bytes)
 *   - Rate (r): 128 bits (16 bytes per block)
 *   - Permutation Rounds: a = 12 (initialization & finalization), b = 8 (intermediate)
 *   - Initialization Vector (IV): 0x01008c0080100000ULL (Big-Endian byte encoding)
 *   - Endianness: Little-Endian 64-bit word mapping per NIST SP 800-232 §3.3
 *
 * Mathematical Foundations:
 *   1. Permutation State: S = (x_0, x_1, x_2, x_3, x_4) in (F_2^64)^5 (320 bits total).
 *   2. State Initialization:
 *      S_0 = p^12(IV || K || N)
 *      S = S xor (0^192 || K)
 *   3. Associated Data Absorption (for each 16-byte block A_i):
 *      x_0 = x_0 xor A_{i,0}
 *      x_1 = x_1 xor A_{i,1}
 *      S = p^8(S)
 *      Domain separation: S = S xor (0^319 || 1)
 *   4. Plaintext Encryption (for each 16-byte block P_i):
 *      C_{i,0} = x_0 xor P_{i,0};  x_0 = C_{i,0}
 *      C_{i,1} = x_1 xor P_{i,1};  x_1 = C_{i,1}
 *      S = p^8(S)
 *   5. Finalization & Tag Generation:
 *      S = S xor (0^128 || K || 0^64)
 *      S = p^12(S)
 *      Tag = (x_3 || x_4) xor K
 *
 * Upstream Provenance:
 *   - Reference C Repository: https://github.com/ascon/ascon-c [^2]
 *   - Python Cross-Verification Suite: Git repo/Phase 1/CAN FD/Crypto Code/ascon_official.py
 *
 * Footnotes:
 *   [^1]: National Institute of Standards and Technology (NIST). Special Publication (SP) 800-232:
 *         Ascon-Based Lightweight Cryptography Standards, October 2023. DOI: 10.6028/NIST.SP.800-232.
 *   [^2]: Ascon Team. Ascon v1.2 & SP 800-232 C Reference Implementation (Graz Univ of Technology).
 *         URL: https://github.com/ascon/ascon-c.
 * ============================================================================
 */

#ifndef ASCON_SP800_232_HPP
#define ASCON_SP800_232_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>

namespace cisg::crypto {

/**
 * @brief NIST SP 800-232 Ascon-AEAD128 Constants & Parameters
 */
struct AsconParameters {
    static constexpr size_t KEY_BYTES   = 16;  // 128-bit key
    static constexpr size_t NONCE_BYTES = 16;  // 128-bit nonce
    static constexpr size_t TAG_BYTES   = 16;  // 128-bit authentication tag
    static constexpr size_t RATE_BYTES  = 16;  // 128-bit block rate (SP 800-232)
    static constexpr int ROUNDS_A       = 12;  // Permutation rounds for init and final
    static constexpr int ROUNDS_B       = 8;   // Permutation rounds for intermediate rate

    // Big-Endian IV: 01 (Version) 00 (Res) 8c ((8<<4)|12) 0080 (TagLen) 10 (Rate 16) 0000 (Res)
    static constexpr uint64_t IV_SP800_232_BE = 0x01008c0080100000ULL;
    // Little-Endian register representation for load64_le
    static constexpr uint64_t IV_SP800_232_LE = 0x00001000808c0001ULL;

    // Strict 64-byte CAN-FD wire framing constants (ISO 11898-1 DLC 15)
    static constexpr size_t CANFD_FRAME_BYTES      = 64;
    static constexpr size_t CANFD_HEADER_AD_BYTES  = 8;   // Bytes 0..7: CAN ID (4B) + Counter (4B)
    static constexpr size_t CANFD_CIPHERTEXT_BYTES = 40;  // Bytes 8..47: Kinematic telemetry
    static constexpr size_t CANFD_TAG_OFFSET       = 48;  // Bytes 48..63: Ascon Tag (16B)
    static constexpr uint32_t COUNTER_ROLLOVER_MAX = 0xEFFFFFFFU; // Mandatory re-keying trigger
};

/**
 * @brief 320-bit internal Ascon permutation state (5 x 64-bit words)
 */
struct AsconState {
    uint64_t x[5]{0, 0, 0, 0, 0};
};

/**
 * @brief NIST SP 800-232 Ascon-AEAD128 Implementation Engine
 */
class AsconSP800232 {
public:
    /**
     * @brief Circular right shift (rotation) of a 64-bit word.
     */
    static inline uint64_t rotr(uint64_t x, int n) noexcept {
        return (x >> n) | (x << (64 - n));
    }

    /**
     * @brief Load 64-bit integer from byte buffer in little-endian order.
     */
    static inline uint64_t load64_le(const uint8_t* p) noexcept {
        uint64_t v = 0;
        std::memcpy(&v, p, sizeof(v));
        return v;
    }

    /**
     * @brief Store 64-bit integer into byte buffer in little-endian order.
     */
    static inline void store64_le(uint8_t* p, uint64_t v) noexcept {
        std::memcpy(p, &v, sizeof(v));
    }

    /**
     * @brief Load byte-padded 64-bit word for trailing incomplete blocks.
     */
    static inline uint64_t load_bytes_le(const uint8_t* bytes, size_t n) noexcept {
        uint64_t x = 0;
        for (size_t i = 0; i < n; ++i) {
            x |= static_cast<uint64_t>(bytes[i]) << (8 * i);
        }
        return x;
    }

    /**
     * @brief Store byte-padded 64-bit word for trailing incomplete blocks.
     */
    static inline void store_bytes_le(uint8_t* bytes, uint64_t x, size_t n) noexcept {
        for (size_t i = 0; i < n; ++i) {
            bytes[i] = static_cast<uint8_t>((x >> (8 * i)) & 0xFF);
        }
    }

    /**
     * @brief Ascon round constant addition and substitution-permutation round.
     */
    static inline void round_p(AsconState& s, uint64_t C) noexcept {
        // 1. Constant addition (p_C)
        s.x[2] ^= C;

        // 2. Substitution layer (p_S) via 5-bit bit-sliced S-box
        s.x[0] ^= s.x[4]; s.x[4] ^= s.x[3]; s.x[2] ^= s.x[1];
        uint64_t t0 = s.x[0] ^ (~s.x[1] & s.x[2]);
        uint64_t t1 = s.x[1] ^ (~s.x[2] & s.x[3]);
        uint64_t t2 = s.x[2] ^ (~s.x[3] & s.x[4]);
        uint64_t t3 = s.x[3] ^ (~s.x[4] & s.x[0]);
        uint64_t t4 = s.x[4] ^ (~s.x[0] & s.x[1]);
        t1 ^= t0; t0 ^= t4; t3 ^= t2; t2 = ~t2;

        // 3. Linear diffusion layer (p_L)
        s.x[0] = t0 ^ rotr(t0, 19) ^ rotr(t0, 28);
        s.x[1] = t1 ^ rotr(t1, 61) ^ rotr(t1, 39);
        s.x[2] = t2 ^ rotr(t2, 1)  ^ rotr(t2, 6);
        s.x[3] = t3 ^ rotr(t3, 10) ^ rotr(t3, 17);
        s.x[4] = t4 ^ rotr(t4, 7)  ^ rotr(t4, 41);
    }

    /**
     * @brief Execute Ascon permutation p^rounds.
     */
    static inline void permute(AsconState& s, int rounds) noexcept {
        static constexpr uint64_t RC[12] = {
            0x00000000000000f0ULL, 0x00000000000000e1ULL,
            0x00000000000000d2ULL, 0x00000000000000c3ULL,
            0x00000000000000b4ULL, 0x00000000000000a5ULL,
            0x0000000000000096ULL, 0x0000000000000087ULL,
            0x0000000000000078ULL, 0x0000000000000069ULL,
            0x000000000000005aULL, 0x000000000000004bULL
        };
        for (int i = 12 - rounds; i < 12; ++i) {
            round_p(s, RC[i]);
        }
    }

    /**
     * @brief Derives deterministic in-memory 16-byte nonce from CAN ID and monotonic counter.
     */
    static inline void derive_in_memory_nonce(uint32_t can_id, uint32_t counter,
                                             std::array<uint8_t, 16>& nonce_out) noexcept {
        nonce_out[0] = static_cast<uint8_t>((can_id >> 24) & 0xFF);
        nonce_out[1] = static_cast<uint8_t>((can_id >> 16) & 0xFF);
        nonce_out[2] = static_cast<uint8_t>((can_id >> 8) & 0xFF);
        nonce_out[3] = static_cast<uint8_t>(can_id & 0xFF);

        nonce_out[4] = static_cast<uint8_t>((counter >> 24) & 0xFF);
        nonce_out[5] = static_cast<uint8_t>((counter >> 16) & 0xFF);
        nonce_out[6] = static_cast<uint8_t>((counter >> 8) & 0xFF);
        nonce_out[7] = static_cast<uint8_t>(counter & 0xFF);

        std::memset(nonce_out.data() + 8, 0, 8);
    }

    /**
     * @brief Authenticated Encryption with Associated Data (Ascon-AEAD128).
     */
    static inline void encrypt(const uint8_t* key, const uint8_t* nonce,
                              const uint8_t* ad, size_t ad_len,
                              const uint8_t* pt, size_t pt_len,
                              uint8_t* ct_out, uint8_t* tag_out) {
        uint64_t k0 = load64_le(key);
        uint64_t k1 = load64_le(key + 8);
        uint64_t n0 = load64_le(nonce);
        uint64_t n1 = load64_le(nonce + 8);

        // 1. State Initialization: IV || K || N
        AsconState s;
        s.x[0] = AsconParameters::IV_SP800_232_LE;
        s.x[1] = k0;
        s.x[2] = k1;
        s.x[3] = n0;
        s.x[4] = n1;
        permute(s, AsconParameters::ROUNDS_A);
        s.x[3] ^= k0;
        s.x[4] ^= k1;

        // 2. Associated Data Absorption (128-bit block rate)
        if (ad_len > 0) {
            size_t ad_blocks = ad_len / AsconParameters::RATE_BYTES;
            for (size_t i = 0; i < ad_blocks; ++i) {
                s.x[0] ^= load64_le(ad + i * 16);
                s.x[1] ^= load64_le(ad + i * 16 + 8);
                permute(s, AsconParameters::ROUNDS_B);
            }
            size_t rem = ad_len % AsconParameters::RATE_BYTES;
            const uint8_t* last_ad = ad + ad_blocks * 16;
            if (rem >= 8) {
                s.x[0] ^= load64_le(last_ad);
                s.x[1] ^= load_bytes_le(last_ad + 8, rem - 8) ^ (0x01ULL << (8 * (rem - 8)));
            } else {
                s.x[0] ^= load_bytes_le(last_ad, rem) ^ (0x01ULL << (8 * rem));
            }
            permute(s, AsconParameters::ROUNDS_B);
        }
        // Domain separation
        s.x[4] ^= 0x8000000000000000ULL;

        // 3. Plaintext Encryption (128-bit block rate)
        size_t pt_blocks = pt_len / AsconParameters::RATE_BYTES;
        for (size_t i = 0; i < pt_blocks; ++i) {
            s.x[0] ^= load64_le(pt + i * 16);
            s.x[1] ^= load64_le(pt + i * 16 + 8);
            store64_le(ct_out + i * 16, s.x[0]);
            store64_le(ct_out + i * 16 + 8, s.x[1]);
            permute(s, AsconParameters::ROUNDS_B);
        }
        size_t rem_pt = pt_len % AsconParameters::RATE_BYTES;
        const uint8_t* last_pt = pt + pt_blocks * 16;
        uint8_t* last_ct = ct_out + pt_blocks * 16;
        if (rem_pt >= 8) {
            s.x[0] ^= load64_le(last_pt);
            store64_le(last_ct, s.x[0]);
            s.x[1] ^= load_bytes_le(last_pt + 8, rem_pt - 8) ^ (0x01ULL << (8 * (rem_pt - 8)));
            store_bytes_le(last_ct + 8, s.x[1], rem_pt - 8);
        } else {
            s.x[0] ^= load_bytes_le(last_pt, rem_pt) ^ (0x01ULL << (8 * rem_pt));
            store_bytes_le(last_ct, s.x[0], rem_pt);
        }

        // 4. Finalization & Tag Generation
        s.x[2] ^= k0;
        s.x[3] ^= k1;
        permute(s, AsconParameters::ROUNDS_A);
        s.x[3] ^= k0;
        s.x[4] ^= k1;
        store64_le(tag_out, s.x[3]);
        store64_le(tag_out + 8, s.x[4]);
    }

    /**
     * @brief Authenticated Decryption and Tag Verification (Ascon-AEAD128).
     */
    static inline bool decrypt_verify(const uint8_t* key, const uint8_t* nonce,
                                      const uint8_t* ad, size_t ad_len,
                                      const uint8_t* ct, size_t ct_len,
                                      const uint8_t* tag, uint8_t* pt_out) {
        uint64_t k0 = load64_le(key);
        uint64_t k1 = load64_le(key + 8);
        uint64_t n0 = load64_le(nonce);
        uint64_t n1 = load64_le(nonce + 8);

        // 1. State Initialization
        AsconState s;
        s.x[0] = AsconParameters::IV_SP800_232_LE;
        s.x[1] = k0;
        s.x[2] = k1;
        s.x[3] = n0;
        s.x[4] = n1;
        permute(s, AsconParameters::ROUNDS_A);
        s.x[3] ^= k0;
        s.x[4] ^= k1;

        // 2. Associated Data Absorption
        if (ad_len > 0) {
            size_t ad_blocks = ad_len / AsconParameters::RATE_BYTES;
            for (size_t i = 0; i < ad_blocks; ++i) {
                s.x[0] ^= load64_le(ad + i * 16);
                s.x[1] ^= load64_le(ad + i * 16 + 8);
                permute(s, AsconParameters::ROUNDS_B);
            }
            size_t rem = ad_len % AsconParameters::RATE_BYTES;
            const uint8_t* last_ad = ad + ad_blocks * 16;
            if (rem >= 8) {
                s.x[0] ^= load64_le(last_ad);
                s.x[1] ^= load_bytes_le(last_ad + 8, rem - 8) ^ (0x01ULL << (8 * (rem - 8)));
            } else {
                s.x[0] ^= load_bytes_le(last_ad, rem) ^ (0x01ULL << (8 * rem));
            }
            permute(s, AsconParameters::ROUNDS_B);
        }
        s.x[4] ^= 0x8000000000000000ULL;

        // 3. Ciphertext Decryption
        size_t ct_blocks = ct_len / AsconParameters::RATE_BYTES;
        for (size_t i = 0; i < ct_blocks; ++i) {
            uint64_t c0 = load64_le(ct + i * 16);
            uint64_t c1 = load64_le(ct + i * 16 + 8);
            store64_le(pt_out + i * 16, s.x[0] ^ c0);
            store64_le(pt_out + i * 16 + 8, s.x[1] ^ c1);
            s.x[0] = c0;
            s.x[1] = c1;
            permute(s, AsconParameters::ROUNDS_B);
        }
        size_t rem_ct = ct_len % AsconParameters::RATE_BYTES;
        const uint8_t* last_ct = ct + ct_blocks * 16;
        uint8_t* last_pt = pt_out + ct_blocks * 16;
        if (rem_ct >= 8) {
            uint64_t c0 = load64_le(last_ct);
            store64_le(last_pt, s.x[0] ^ c0);
            s.x[0] = c0;
            uint64_t c1 = load_bytes_le(last_ct + 8, rem_ct - 8);
            store_bytes_le(last_pt + 8, s.x[1] ^ c1, rem_ct - 8);
            s.x[1] = (s.x[1] & ~((1ULL << (8 * (rem_ct - 8))) - 1)) | c1;
            s.x[1] ^= (0x01ULL << (8 * (rem_ct - 8)));
        } else {
            uint64_t c0 = load_bytes_le(last_ct, rem_ct);
            store_bytes_le(last_pt, s.x[0] ^ c0, rem_ct);
            s.x[0] = (s.x[0] & ~((1ULL << (8 * rem_ct)) - 1)) | c0;
            s.x[0] ^= (0x01ULL << (8 * rem_ct));
        }

        // 4. Finalization & Constant-Time Tag Check
        s.x[2] ^= k0;
        s.x[3] ^= k1;
        permute(s, AsconParameters::ROUNDS_A);
        s.x[3] ^= k0;
        s.x[4] ^= k1;

        uint64_t expected_t0 = load64_le(tag);
        uint64_t expected_t1 = load64_le(tag + 8);
        uint64_t diff = (s.x[3] ^ expected_t0) | (s.x[4] ^ expected_t1);

        if (diff != 0) {
            // Constant-time zero-fill on tag failure (ISO 26262 ASIL-D fault mitigation)
            std::memset(pt_out, 0, ct_len);
            return false;
        }
        return true;
    }
};

} // namespace cisg::crypto

#endif // ASCON_SP800_232_HPP
