/**
 * ============================================================================
 * pqc_mldsa44.hpp
 * ============================================================================
 *
 * NIST FIPS 204 ML-DSA-44 (Module-Lattice-Based Digital Signature) C++17 Wrapper.
 * 
 * Standards & Specifications:
 *   - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (Aug 2024) [^1]
 *   - Algorithm: ML-DSA-44 (formerly CRYSTALS-Dilithium 2)
 *   - Security Category: NIST Level 2 (128-bit quantum security)
 *   - Public Key Size (pk): 1,312 Bytes
 *   - Secret Key Size (sk): 2,560 Bytes
 *   - Signature Size (sig): 2,420 Bytes
 *   - Protected Attestation Object (PAO): 2,436 Bytes (2,420B Sig + 16B Ascon Tag)
 *
 * Mathematical Foundations:
 *   1. Polynomial Ring: R_q = Z_q[X] / (X^256 + 1) where q = 8,380,417 = 2^23 - 2^13 + 1.
 *   2. Module Dimensions: Matrix A in R_q^(k x l) with k = 4, l = 4.
 *   3. Key Generation:
 *      - Sample seed rho in {0,1}^256 -> Expand Matrix A via SHAKE-128.
 *      - Sample secret vectors s_1 in S_eta^l, s_2 in S_eta^k (eta = 2).
 *      - Compute t = A * s_1 + s_2.
 *      - Compress t -> (t_1, t_0) where t_1 is high bits (320B * 4 = 1,280B).
 *      - pk = (rho || t_1) -> 32B + 1,280B = 1,312 Bytes.
 *      - sk = (rho || K || tr || s_1 || s_2 || t_0 || pk) -> 2,560 Bytes per FIPS 204 §5.1.
 *   4. Signing Algorithm:
 *      - Sample masking vector y in S_(gamma_1 - 1)^l (gamma_1 = 2^17).
 *      - Compute w = A * y; HighBits(w) -> w_1.
 *      - Challenge c_tilde = H(mu || w_1) in {0,1}^256 (SHAKE-256).
 *      - Response z = y + c * s_1. Rejection sampling ensures ||z||_inf < gamma_1 - beta.
 *      - Hints h generated to assist verifier with carry bits: ||h||_1 <= omega (omega = 80).
 *      - Signature sigma = (c_tilde || z || h) -> 32B + 2,304B + 84B = 2,420 Bytes.
 *   5. Verification:
 *      - Reject if ||z||_inf >= gamma_1 - beta or hint weight > omega.
 *      - Reconstruct w'_1 = UseHint(h, A * z - c * t_1 * 2^d).
 *      - Accept iff c_tilde == H(mu || w'_1).
 *
 * Upstream Provenance:
 *   - Open Quantum Safe (liboqs): https://github.com/open-quantum-safe/liboqs [^2]
 *   - Algorithm Identifier: OQS_SIG_alg_ml_dsa_44
 *
 * Footnotes:
 *   [^1]: National Institute of Standards and Technology (NIST). Federal Information Processing
 *         Standards Publication (FIPS) 204: Module-Lattice-Based Digital Signature Standard,
 *         August 2024. DOI: 10.6028/NIST.FIPS.204.
 *   [^2]: Open Quantum Safe Project. liboqs: Open Source C Library for Quantum-Safe Cryptography,
 *         v0.12.0, 2024. URL: https://github.com/open-quantum-safe/liboqs.
 * ============================================================================
 */

#ifndef PQC_MLDSA44_HPP
#define PQC_MLDSA44_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <iostream>
#include <cstring>

#if __has_include(<oqs/oqs.h>)
#include <oqs/oqs.h>
#define CISG_HAS_LIBOQS 1
#else
#define CISG_HAS_LIBOQS 0
#endif

namespace cisg::pqc {

/**
 * @brief Exact NIST FIPS 204 ML-DSA-44 Buffer Dimension Invariants
 */
struct MLDSA44Constants {
    static constexpr size_t PUBLIC_KEY_BYTES = 1312;
    static constexpr size_t SECRET_KEY_BYTES = 2560;
    static constexpr size_t SIGNATURE_BYTES  = 2420;
    static constexpr size_t PAO_BYTES        = 2436; // 2420B Signature + 16B Ascon Tag
    static constexpr size_t TOTAL_BLOCKS     = 41;   // 60/4 Fragmentation frame count
};

/**
 * @brief Public Key Container for ML-DSA-44
 */
using PublicKey = std::array<uint8_t, MLDSA44Constants::PUBLIC_KEY_BYTES>;

/**
 * @brief Secret Key Container for ML-DSA-44
 */
using SecretKey = std::array<uint8_t, MLDSA44Constants::SECRET_KEY_BYTES>;

/**
 * @brief Digital Signature Container for ML-DSA-44
 */
using Signature = std::array<uint8_t, MLDSA44Constants::SIGNATURE_BYTES>;

/**
 * @brief C++17 RAII Wrapper for Open Quantum Safe ML-DSA-44 Engine
 */
class MLDSA44Engine {
public:
    inline MLDSA44Engine() {
#if CISG_HAS_LIBOQS
        OQS_init();
        sig_ctx_ = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if (!sig_ctx_) {
            std::cerr << "[!] WARNING: OQS_SIG_alg_ml_dsa_44 not enabled in liboqs build.\n";
        }
#endif
    }

    inline ~MLDSA44Engine() {
#if CISG_HAS_LIBOQS
        if (sig_ctx_) {
            OQS_SIG_free(sig_ctx_);
            sig_ctx_ = nullptr;
        }
        OQS_destroy();
#endif
    }

    MLDSA44Engine(const MLDSA44Engine&) = delete;
    MLDSA44Engine& operator=(const MLDSA44Engine&) = delete;

    inline MLDSA44Engine(MLDSA44Engine&& other) noexcept {
#if CISG_HAS_LIBOQS
        sig_ctx_ = other.sig_ctx_;
        other.sig_ctx_ = nullptr;
#endif
    }

    inline MLDSA44Engine& operator=(MLDSA44Engine&& other) noexcept {
        if (this != &other) {
#if CISG_HAS_LIBOQS
            if (sig_ctx_) OQS_SIG_free(sig_ctx_);
            sig_ctx_ = other.sig_ctx_;
            other.sig_ctx_ = nullptr;
#endif
        }
        return *this;
    }

    /**
     * @brief Generates an authentic NIST FIPS 204 ML-DSA-44 public/secret keypair.
     */
    inline bool generate_keypair(PublicKey& pk_out, SecretKey& sk_out) {
#if CISG_HAS_LIBOQS
        if (!sig_ctx_) return false;
        OQS_STATUS rc = OQS_SIG_keypair(sig_ctx_, pk_out.data(), sk_out.data());
        return rc == OQS_SUCCESS;
#else
        (void)pk_out; (void)sk_out;
        return false;
#endif
    }

    /**
     * @brief Generates an authentic NIST FIPS 204 ML-DSA-44 digital signature.
     */
    inline bool sign(const uint8_t* message, size_t message_len,
                     const SecretKey& sk,
                     Signature& sig_out,
                     size_t& actual_sig_len) {
#if CISG_HAS_LIBOQS
        if (!sig_ctx_) return false;
        actual_sig_len = MLDSA44Constants::SIGNATURE_BYTES;
        OQS_STATUS rc = OQS_SIG_sign(
            sig_ctx_,
            sig_out.data(),
            &actual_sig_len,
            message,
            message_len,
            sk.data()
        );
        return (rc == OQS_SUCCESS) && (actual_sig_len == MLDSA44Constants::SIGNATURE_BYTES);
#else
        (void)message; (void)message_len; (void)sk; (void)sig_out; (void)actual_sig_len;
        return false;
#endif
    }

    /**
     * @brief Verifies an authentic NIST FIPS 204 ML-DSA-44 digital signature.
     */
    inline bool verify(const uint8_t* message, size_t message_len,
                       const uint8_t* signature, size_t signature_len,
                       const PublicKey& pk) {
        if (signature_len != MLDSA44Constants::SIGNATURE_BYTES) {
            return false;
        }
#if CISG_HAS_LIBOQS
        if (!sig_ctx_) return false;
        OQS_STATUS rc = OQS_SIG_verify(
            sig_ctx_,
            message,
            message_len,
            signature,
            signature_len,
            pk.data()
        );
        return rc == OQS_SUCCESS;
#else
        (void)message; (void)message_len; (void)signature; (void)pk;
        return false;
#endif
    }

    /**
     * @brief Returns whether genuine liboqs is compiled and active.
     */
    static constexpr bool has_native_liboqs() noexcept {
#if CISG_HAS_LIBOQS
        return true;
#else
        return false;
#endif
    }

private:
#if CISG_HAS_LIBOQS
    OQS_SIG* sig_ctx_{nullptr};
#endif
};

} // namespace cisg::pqc

#endif // PQC_MLDSA44_HPP
