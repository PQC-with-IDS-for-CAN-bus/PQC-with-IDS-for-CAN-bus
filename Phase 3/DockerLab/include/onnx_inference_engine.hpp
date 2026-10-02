/**
 * ============================================================================
 * onnx_inference_engine.hpp
 * ============================================================================
 *
 * Microsoft ONNX Runtime C++ Native INT8 Autoencoder Inference Engine.
 * 
 * Standards & Specifications:
 *   - Model: 14D Physical Kinematics LSTM-Autoencoder (v30_physical_kinematics_dynamic_int8.onnx) [^1]
 *   - Total Parameters: 24,654 parameters (dynamic INT8 quantized)
 *   - Input Tensor Name: "input_kinematics", Shape: [1, 30, 14] (float32)
 *   - Output Tensor Name: "reconstruction_out", Shape: [1, 30, 14] (float32)
 *   - Sliding Window Context: W = 30 frames (~300 ms temporal depth), D = 14 features
 *
 * Mathematical Foundations:
 *   1. 14D Physical Kinematic Feature Vector:
 *      x = [v, omega_rpm, delta_steer, P_brake, w_fl, w_fr, w_rl, w_rr, T_cool,
 *           Delta w_fl, Delta w_fr, Delta w_rl, Delta w_rr, Delta_(speed-wheel)]^T in R^14.
 *   2. Leave-One-Out (LOO) Wheel Differentials:
 *      Delta w_i = |w_i - median({w_j | j != i})| for i in {fl, fr, rl, rr}.
 *   3. Speed-Wheel Consistency Delta:
 *      Delta_(speed-wheel) = |v - (w_fl + w_fr + w_rl + w_rr) / 4|.
 *   4. Min-Max Standardization:
 *      norm14_i = clip((x_i - min_i) / (max_i - min_i), 0.0, 1.0).
 *   5. Subsystem Anomaly Scoring:
 *      MSE_i = (1 / 30) sum_{t=0}^{29} (W_cand[t, i] - W_hat[t, i])^2
 *      z_i = (MSE_i - mu_i) / (sigma_i + epsilon)
 *      S_208  = 0.5 * mean(z_{0, 13}) + 0.5 * max(z_{0, 13})      [tau_208 = 3.7043]
 *      S_1760 = 0.5 * mean(z_{9..13}) + 0.5 * max(z_{9..13})      [tau_1760 = 5.0808]
 *      S_1255 = z_8                                              [tau_1255 = 2.7349]
 *      S_glob = 0.5 * mean(z_{0..13}) + 0.5 * max(z_{0..13})      [tau_glob = 3.6985]
 *   6. Mode B Zero-Order Hold (ZOH) Buffer Quarantine:
 *      If anomaly detected: discard candidate x_t; substitute x_clean into sliding window:
 *      W_buf^(t+1) = [x_{t-28}, ..., x_{t-1}, x_clean].
 *      Guarantees 0 residual recovery delay upon attack termination.
 *
 * Upstream Provenance:
 *   - Microsoft ONNX Runtime: https://github.com/microsoft/onnxruntime [^2]
 *   - Phase 2 IDS Lineage: Git repo/Phase 2/IDS/complete_3tier_cisg_ids.py
 *
 * Footnotes:
 *   [^1]: Capstone Phase 2 Workload Distribution & Charters: 14D Kinematic Autoencoder v30.
 *   [^2]: Microsoft Corporation. ONNX Runtime C++ API Reference, 2024.
 *         URL: https://github.com/microsoft/onnxruntime.
 * ============================================================================
 */

#ifndef ONNX_INFERENCE_ENGINE_HPP
#define ONNX_INFERENCE_ENGINE_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <deque>
#include <string>
#include <memory>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <cstring>

#if __has_include(<onnxruntime_cxx_api.h>)
#include <onnxruntime_cxx_api.h>
#define CISG_HAS_ONNXRUNTIME 1
#else
#define CISG_HAS_ONNXRUNTIME 0
#endif

namespace cisg::ml {

/**
 * @brief Kinematic Feature Dimension Constants
 */
struct KinematicsDimensions {
    static constexpr size_t FEATURE_DIM = 14;
    static constexpr size_t WINDOW_SIZE = 30;
    static constexpr size_t TENSOR_ELEMENTS = 1 * WINDOW_SIZE * FEATURE_DIM; // 420 floats
};

/**
 * @brief 14-Dimensional Raw Kinematic Feature Vector
 */
struct Kinematics14D {
    float speed{0.0f};             // 0: km/h
    float rpm{0.0f};               // 1: RPM
    float steering_angle{0.0f};    // 2: deg
    float brake_pressure{0.0f};    // 3: bar
    float wheel_speed_fl{0.0f};    // 4: km/h
    float wheel_speed_fr{0.0f};    // 5: km/h
    float wheel_speed_rl{0.0f};    // 6: km/h
    float wheel_speed_rr{0.0f};    // 7: km/h
    float coolant_temp{90.0f};     // 8: deg C
    float loo_fl{0.0f};            // 9: LOO differential FL
    float loo_fr{0.0f};            // 10: LOO differential FR
    float loo_rl{0.0f};            // 11: LOO differential RL
    float loo_rr{0.0f};            // 12: LOO differential RR
    float delta_speed_wheel{0.0f}; // 13: Speed vs Avg Wheel Delta

    static inline float median3(float a, float b, float c) noexcept {
        if ((a <= b && b <= c) || (c <= b && b <= a)) return b;
        if ((b <= a && a <= c) || (c <= a && a <= b)) return a;
        return c;
    }

    inline void compute_derived_features() noexcept {
        loo_fl = std::abs(wheel_speed_fl - median3(wheel_speed_fr, wheel_speed_rl, wheel_speed_rr));
        loo_fr = std::abs(wheel_speed_fr - median3(wheel_speed_fl, wheel_speed_rl, wheel_speed_rr));
        loo_rl = std::abs(wheel_speed_rl - median3(wheel_speed_fl, wheel_speed_fr, wheel_speed_rr));
        loo_rr = std::abs(wheel_speed_rr - median3(wheel_speed_fl, wheel_speed_fr, wheel_speed_rl));

        float avg_wheel = (wheel_speed_fl + wheel_speed_fr + wheel_speed_rl + wheel_speed_rr) * 0.25f;
        delta_speed_wheel = std::abs(speed - avg_wheel);
    }

    inline std::array<float, 14> normalize() const noexcept {
        static constexpr float min_vals[14] = {
            0.0f, 565.0f, 32649.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 82.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f
        };
        static constexpr float max_vals[14] = {
            8166.0f, 644.0f, 33473.0f, 255.0f, 7049.0f, 7059.0f, 7079.0f, 7082.0f, 153.0f, 269.0f, 370.0f, 298.0f, 251.0f, 1119.5f
        };

        const float raw[14] = {
            speed, rpm, steering_angle, brake_pressure,
            wheel_speed_fl, wheel_speed_fr, wheel_speed_rl, wheel_speed_rr,
            coolant_temp, loo_fl, loo_fr, loo_rl, loo_rr, delta_speed_wheel
        };

        std::array<float, 14> norm{};
        for (size_t i = 0; i < 14; ++i) {
            float range = max_vals[i] - min_vals[i];
            if (range <= 0.0f) range = 1.0f;
            float val = (raw[i] - min_vals[i]) / range;
            norm[i] = std::max(0.0f, std::min(1.0f, val));
        }
        return norm;
    }
};

/**
 * @brief Calibrated Anomaly Thresholds from physical_anomaly_threshold.json
 */
struct AnomalyThresholds {
    static constexpr float TAU_208  = 3.7043f; // Powertrain subsystem (Speed & Delta)
    static constexpr float TAU_1760 = 5.0808f; // Chassis subsystem (LOO & Delta)
    static constexpr float TAU_1255 = 2.7349f; // Thermal subsystem (Coolant)
    static constexpr float TAU_GLOB = 3.6985f; // Global manifold threshold
};

/**
 * @brief Anomaly Evaluation Result Verdict
 */
struct AnomalyVerdict {
    bool is_anomaly{false};
    float score_208{0.0f};
    float score_1760{0.0f};
    float score_1255{0.0f};
    float score_glob{0.0f};
    std::string subsystem_violation{""};
};

/**
 * @brief Mode B Zero-Order Hold (ZOH) Buffer Quarantine Engine
 */
class ModeBQuarantineBuffer {
public:
    inline ModeBQuarantineBuffer() = default;

    inline bool stage_candidate(const std::array<float, 14>& cand_frame,
                                std::array<float, KinematicsDimensions::TENSOR_ELEMENTS>& window_out) {
        if (!has_clean_) {
            last_clean_ = cand_frame;
            has_clean_ = true;
        }

        // Fill window context
        size_t n = buffer_.size();
        size_t pad = (n < KinematicsDimensions::WINDOW_SIZE - 1) ? (KinematicsDimensions::WINDOW_SIZE - 1 - n) : 0;

        size_t out_idx = 0;
        // Pad warmup frames with clean baseline
        for (size_t i = 0; i < pad; ++i) {
            for (size_t d = 0; d < 14; ++d) {
                window_out[out_idx++] = last_clean_[d];
            }
        }
        // Copy historical frames
        for (const auto& past_frame : buffer_) {
            for (size_t d = 0; d < 14; ++d) {
                window_out[out_idx++] = past_frame[d];
            }
        }
        // Append candidate frame
        for (size_t d = 0; d < 14; ++d) {
            window_out[out_idx++] = cand_frame[d];
        }

        return (buffer_.size() + 1 >= KinematicsDimensions::WINDOW_SIZE);
    }

    inline void commit_verdict(bool is_anomaly, const std::array<float, 14>& cand_frame) {
        if (is_anomaly) {
            // Mode B ZOH: Discard candidate; inject last clean frame into sliding window
            if (buffer_.size() >= KinematicsDimensions::WINDOW_SIZE - 1) {
                buffer_.pop_front();
            }
            buffer_.push_back(last_clean_);
        } else {
            // Nominal: accept candidate frame
            if (buffer_.size() >= KinematicsDimensions::WINDOW_SIZE - 1) {
                buffer_.pop_front();
            }
            buffer_.push_back(cand_frame);
            last_clean_ = cand_frame;
            has_clean_ = true;
        }
    }

    inline void reset() {
        buffer_.clear();
        has_clean_ = false;
    }

    bool is_warmed_up() const noexcept { return buffer_.size() >= KinematicsDimensions::WINDOW_SIZE - 1; }

private:
    std::deque<std::array<float, 14>> buffer_;
    std::array<float, 14> last_clean_{};
    bool has_clean_{false};
};

/**
 * @brief ONNX Runtime C++ Tier 2 ML Inference Engine
 */
class Tier2InferenceEngine {
public:
    inline explicit Tier2InferenceEngine(const std::string& model_path)
        : model_path_(model_path)
#if CISG_HAS_ONNXRUNTIME
          , env_(ORT_LOGGING_LEVEL_WARNING, "CISG_Tier2_IDS"),
          memory_info_(Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault))
#endif
    {
#if CISG_HAS_ONNXRUNTIME
        try {
            session_options_.SetIntraOpNumThreads(1);
            session_options_.SetInterOpNumThreads(1);
            session_options_.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
            session_ = std::make_unique<Ort::Session>(env_, model_path_.c_str(), session_options_);
            std::cout << "[+] ONNX Runtime C++ Session initialized: " << model_path_ << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[!] ONNX Session init warning: " << e.what() << "\n";
        }
#endif
    }

    inline ~Tier2InferenceEngine() = default;

    inline bool run_inference(const float* window_30x14, float* rec_out_30x14) {
#if CISG_HAS_ONNXRUNTIME
        if (!session_) return false;
        try {
            Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
                memory_info_,
                const_cast<float*>(window_30x14),
                KinematicsDimensions::TENSOR_ELEMENTS,
                input_shape_.data(),
                input_shape_.size()
            );

            auto output_tensors = session_->Run(
                Ort::RunOptions{nullptr},
                input_names_,
                &input_tensor,
                1,
                output_names_,
                1
            );

            float* out_ptr = output_tensors.front().GetTensorMutableData<float>();
            std::memcpy(rec_out_30x14, out_ptr, KinematicsDimensions::TENSOR_ELEMENTS * sizeof(float));
            return true;
        } catch (const std::exception& e) {
            std::cerr << "[!] ONNX Inference error: " << e.what() << "\n";
            return false;
        }
#else
        // Mock reconstruction for offline compilation check
        std::memcpy(rec_out_30x14, window_30x14, KinematicsDimensions::TENSOR_ELEMENTS * sizeof(float));
        return false;
#endif
    }

    static inline AnomalyVerdict evaluate_anomaly(const float* input_window, const float* rec_window) {
        // Channel MSE computation
        float mse[14]{0.0f};
        for (size_t t = 0; t < 30; ++t) {
            for (size_t c = 0; c < 14; ++c) {
                float diff = input_window[t * 14 + c] - rec_window[t * 14 + c];
                mse[c] += diff * diff;
            }
        }
        for (size_t c = 0; c < 14; ++c) {
            mse[c] /= 30.0f;
        }

        // Empirical means and stds from physical_scaler_config.json & validation calibration
        static constexpr float mu_e[14] = {
            0.0012f, 0.0015f, 0.0008f, 0.0005f, 0.0011f, 0.0011f, 0.0012f, 0.0012f,
            0.0004f, 0.0009f, 0.0009f, 0.0010f, 0.0010f, 0.0007f
        };
        static constexpr float sigma_e[14] = {
            0.0008f, 0.0009f, 0.0006f, 0.0004f, 0.0007f, 0.0007f, 0.0008f, 0.0008f,
            0.0003f, 0.0006f, 0.0006f, 0.0007f, 0.0007f, 0.0005f
        };

        float z[14];
        float sum_z = 0.0f;
        float max_z = -1000.0f;
        for (size_t c = 0; c < 14; ++c) {
            z[c] = (mse[c] - mu_e[c]) / (sigma_e[c] + 1e-4f);
            sum_z += z[c];
            if (z[c] > max_z) max_z = z[c];
        }

        AnomalyVerdict v;
        // Subsystem 208 (Powertrain: channels 0, 13)
        v.score_208 = 0.5f * (0.5f * (z[0] + z[13])) + 0.5f * std::max(z[0], z[13]);

        // Subsystem 1760 (Chassis: channels 9..13)
        float sum_chassis = z[9] + z[10] + z[11] + z[12] + z[13];
        float max_chassis = std::max({z[9], z[10], z[11], z[12], z[13]});
        v.score_1760 = 0.5f * (sum_chassis / 5.0f) + 0.5f * max_chassis;

        // Subsystem 1255 (Thermal: channel 8)
        v.score_1255 = z[8];

        // Global metric (all 14 channels)
        v.score_glob = 0.5f * (sum_z / 14.0f) + 0.5f * max_z;

        if (v.score_208 > AnomalyThresholds::TAU_208) {
            v.is_anomaly = true;
            v.subsystem_violation = "POWERTRAIN_208";
        } else if (v.score_1760 > AnomalyThresholds::TAU_1760) {
            v.is_anomaly = true;
            v.subsystem_violation = "CHASSIS_1760";
        } else if (v.score_1255 > AnomalyThresholds::TAU_1255) {
            v.is_anomaly = true;
            v.subsystem_violation = "THERMAL_1255";
        } else if (v.score_glob > AnomalyThresholds::TAU_GLOB) {
            v.is_anomaly = true;
            v.subsystem_violation = "GLOBAL_MANIFOLD";
        }

        return v;
    }

    static constexpr bool has_native_onnxruntime() noexcept {
#if CISG_HAS_ONNXRUNTIME
        return true;
#else
        return false;
#endif
    }

private:
#if CISG_HAS_ONNXRUNTIME
    Ort::Env env_;
    Ort::SessionOptions session_options_;
    std::unique_ptr<Ort::Session> session_;
    Ort::MemoryInfo memory_info_;
    std::array<int64_t, 3> input_shape_{1, 30, 14};
    const char* input_names_[1]{"input_kinematics"};
    const char* output_names_[1]{"reconstruction_out"};
#endif
    std::string model_path_;
};

} // namespace cisg::ml

#endif // ONNX_INFERENCE_ENGINE_HPP
