/**
 * ============================================================================
 * canfd_wire_model.hpp
 * ============================================================================
 *
 * ISO 11898-1:2015 Physical CAN-FD Wire Serialization & Timing Model.
 * 
 * Standards & Specifications:
 *   - ISO 11898-1:2015: CAN-FD Physical Signalling & Bit Timing [^1]
 *   - Reference Timing Literature: Bordoloi & Samii (RTSS 2014) [^2]
 *   - Nominal Arbitration Bitrate: 500 kbps (tau_nom = 2.0 us)
 *   - Fast Data Phase Bitrate: 2.0 Mbps (tau_dat = 0.5 us)
 *   - Maximum Physical Frame Size: 64 Bytes (DLC 15)
 *
 * Mathematical Foundations:
 *   1. Bit Duration Equations:
 *      tau_nom = 1 / f_nom = 1 / 500,000 = 2.0 us.
 *      tau_dat = 1 / f_dat = 1 / 2,000,000 = 0.5 us.
 *   2. Nominal 64-Byte Frame Duration:
 *      N_nom = 29 bits (SOF, 11-bit ID, RTR, IDE, FDF, res, BRS, ACK, EOF, IFS).
 *      N_dat = 6 (Ctrl) + 512 (Payload) + 29 (CRC-21 + Stuff Count) = 547 bits.
 *      T_nom = N_nom * tau_nom + N_dat * tau_dat
 *            = 29 * 2.0 us + 547 * 0.5 us = 58.0 us + 273.5 us = 331.5 us (0.3315 ms).
 *   3. Worst-Case Bit-Stuffed 64-Byte Frame Duration (WCTT):
 *      N_nom_wc = 32 bits.
 *      term_crc = 5 * ceil((64 - 16) / 64) = 5 bits.
 *      N_dat_wc = 28 + term_crc + 10 * 64 = 28 + 5 + 640 = 673 bits.
 *      T_wc = 32 * 2.0 us + 673 * 0.5 us = 64.0 us + 336.5 us = 400.5 us (0.4005 ms).
 *   4. 41-Frame Attestation Burst Serialization:
 *      T_burst_nom = 41 * 331.5 us = 13,591.5 us = 13.59 ms (>= 13.5 ms).
 *      T_burst_wc  = 41 * 400.5 us = 16,420.5 us = 16.42 ms.
 *   5. ASIL-D Handshake Latency Bounds (FTTI = 50.0 ms):
 *      T_total = T_prep (6.56 ms) + T_burst (13.59 - 16.42 ms) + T_verify (3.21 ms) + T_ids (0.83 ms)
 *              = 24.18 ms to 27.01 ms <= 50.0 ms.
 *      Safety margin = (50.0 - 27.01) / 50.0 = 45.98% (> 40% ASIL-D margin).
 *
 * Upstream Provenance:
 *   - Phase 3 Schedulability Engine: Anti Gravity/Phase 3/Code/canfd_schedulability_model.py
 *   - Phase 3 End-to-End Latency Model: Anti Gravity/Phase 3/Code/end_to_end_latency_model.py
 *
 * Footnotes:
 *   [^1]: ISO 11898-1:2015, Road Vehicles — CAN Data Link Layer and Physical Signalling.
 *   [^2]: Bordoloi, U. D., & Samii, S. (2014). Schedulability Analysis of CAN FD Networks.
 *         IEEE Real-Time Systems Symposium (RTSS), DOI: 10.1109/RTSS.2014.28.
 * ============================================================================
 */

#ifndef CANFD_WIRE_MODEL_HPP
#define CANFD_WIRE_MODEL_HPP

#include <cstdint>
#include <cstddef>
#include <chrono>
#include <thread>
#include <cmath>
#include <ctime>

namespace cisg::timing {

/**
 * @brief Canonical ISO 11898-1 Physical Wire Timing Constants
 */
struct WireModelConstants {
    static constexpr uint32_t NOMINAL_BAUD_HZ = 500000;  // 500 kbps arbitration
    static constexpr uint32_t DATA_BAUD_HZ    = 2000000; // 2.0 Mbps data phase

    static constexpr double TAU_NOM_US = 1000000.0 / NOMINAL_BAUD_HZ; // 2.0 us
    static constexpr double TAU_DAT_US = 1000000.0 / DATA_BAUD_HZ;    // 0.5 us

    // 64-Byte frame durations in microseconds
    static constexpr double DURATION_64B_NOM_US = 331.5;  // Nominal
    static constexpr double DURATION_64B_WC_US  = 400.5;  // Worst-Case Bit Stuffed

    // 41-Frame burst durations in milliseconds
    static constexpr double BURST_41F_NOM_MS = 13.5915; // >= 13.5 ms
    static constexpr double BURST_41F_WC_MS  = 16.4205; // Worst-Case

    // ASIL-D Fault Tolerant Time Interval (FTTI)
    static constexpr double ASIL_D_FTTI_MS = 50.0;
};

/**
 * @brief ISO 11898-1 CAN-FD Physical Wire Serialization Calculator & Pacer
 */
class CANFDWireModel {
public:
    /**
     * @brief Compute physical transmission duration for arbitrary CAN-FD payload length.
     * @param payload_bytes Number of data bytes (0..64).
     * @param is_worst_case If true, includes maximum ISO 11898-1 bit-stuffing overhead.
     * @param nominal_baud Arbitration phase bitrate in bps (default 500,000).
     * @param data_baud Data phase bitrate in bps (default 2,000,000).
     * @return Frame transmission duration in microseconds.
     */
    static inline double calculate_frame_duration_us(size_t payload_bytes,
                                                     bool is_worst_case = false,
                                                     uint32_t nominal_baud = WireModelConstants::NOMINAL_BAUD_HZ,
                                                     uint32_t data_baud = WireModelConstants::DATA_BAUD_HZ) noexcept {
        double tau_nom = 1000000.0 / nominal_baud;
        double tau_dat = 1000000.0 / data_baud;

        if (is_worst_case) {
            double term_crc = 5.0 * std::ceil(std::max(0.0, static_cast<double>(payload_bytes) - 16.0) / 64.0);
            double nom_bits = 32.0;
            double data_bits = 28.0 + term_crc + 10.0 * payload_bytes;
            return (nom_bits * tau_nom) + (data_bits * tau_dat);
        } else {
            double nom_bits = 29.0;
            double ctrl_bits = 6.0;
            double payload_bits = payload_bytes * 8.0;
            double crc_bits = (payload_bytes > 16) ? (21.0 + 4.0 + 4.0) : (17.0 + 4.0 + 4.0);
            double data_bits = ctrl_bits + payload_bits + crc_bits;
            return (nom_bits * tau_nom) + (data_bits * tau_dat);
        }
    }

    /**
     * @brief Precision sleep to simulate physical copper wire serialization delay on SocketCAN.
     * @param duration_us Desired serialization delay in microseconds.
     */
    static inline void inject_wire_delay(double duration_us) noexcept {
        if (duration_us <= 0.0) return;

        auto nsecs = static_cast<long>(duration_us * 1000.0);
        struct timespec ts{};
        ts.tv_sec = nsecs / 1000000000L;
        ts.tv_nsec = nsecs % 1000000000L;

        // Use POSIX clock_nanosleep on monotonic clock for hard real-time precision
#if defined(__linux__) || defined(__unix__)
        clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, nullptr);
#else
        std::this_thread::sleep_for(std::chrono::nanoseconds(nsecs));
#endif
    }

    /**
     * @brief Pace transmission of an ISO 11898-1 64-byte frame with physical delay.
     * @param is_worst_case Apply worst-case bit-stuffing timing if true.
     */
    static inline void pace_64b_frame(bool is_worst_case = false) noexcept {
        double delay_us = is_worst_case ? WireModelConstants::DURATION_64B_WC_US
                                        : WireModelConstants::DURATION_64B_NOM_US;
        inject_wire_delay(delay_us);
    }
};

} // namespace cisg::timing

#endif // CANFD_WIRE_MODEL_HPP
