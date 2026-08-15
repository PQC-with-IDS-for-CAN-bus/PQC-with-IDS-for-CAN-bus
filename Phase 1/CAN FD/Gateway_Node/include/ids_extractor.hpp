#pragma once

#include <cstdint>
#include <array>
#include <linux/can.h>

// The strict 12D Feature Vector required by Tapan's LSTM Autoencoder[cite: 23]
struct IDSFeatureVector {
    // 5 Metadata Fields[cite: 23]
    float delta_t;
    float counter_gap;
    float sender_ecu_id;
    float domain_id;
    float msg_type;

    // 1 Crypto Field[cite: 23]
    float tag_verification_status; // 0.0 = Valid, 1.0 = Failed/Corrupted[cite: 23]

    // 6 Telemetry Fields[cite: 23]
    float vehicle_speed;
    float engine_rpm;
    float steering_angle;
    float brake_pressure;
    float longitudinal_accel;
    float dtc_error_count;
};

class IDSExtractor {
public:
    // Parses the raw CAN-FD frame and AEAD tag status into the 12D float vector
    static IDSFeatureVector extract_features(const struct canfd_frame& frame, bool tag_is_valid, float delta_t, float counter_gap);

    // Helper to print the vector for debugging
    static void print_vector(const IDSFeatureVector& vec);
};
