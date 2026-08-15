#include "ids_extractor.hpp"
#include <iostream>
#include <cstring>

IDSFeatureVector IDSExtractor::extract_features(const struct canfd_frame& frame, bool tag_is_valid, float delta_t, float counter_gap) {
    IDSFeatureVector vec{};

    // 1. Populate Metadata
    vec.delta_t = delta_t;
    vec.counter_gap = counter_gap;

    // For this example, we assume SENDER_ECU_ID is embedded in the CAN ID or first byte of AD
    // Masking the standard 11-bit CAN ID for the simulation
    vec.sender_ecu_id = static_cast<float>(frame.can_id & CAN_SFF_MASK);

    // Mock domain ID (e.g., 0=Safety, 1=Comfort) and Msg Type
    vec.domain_id = 0.0f;
    vec.msg_type = 1.0f; // 1.0 = Secure Data Frame (Category 1)[cite: 23]

    // 2. Populate Crypto Status
    // 0.0 = Valid Tag, 1.0 = Tag Failure / Corruption[cite: 23]
    vec.tag_verification_status = tag_is_valid ? 0.0f : 1.0f;

    // 3. Populate Telemetry & Enforce Zero-Fill Rule
    if (!tag_is_valid) {
        // CRITICAL ZERO-FILL BEHAVIOR: Forcefully zero out signals if tag fails[cite: 23]
        vec.vehicle_speed = 0.0f;
        vec.engine_rpm = 0.0f;
        vec.steering_angle = 0.0f;
        vec.brake_pressure = 0.0f;
        vec.longitudinal_accel = 0.0f;
        vec.dtc_error_count = 0.0f;
    } else {
        // If tag is valid, safely parse the decrypted 40-byte payload[cite: 23]
        // (Mock parsing logic: assuming float data is packed sequentially in the frame.data)
        if (frame.len >= 24) {
            std::memcpy(&vec.vehicle_speed, &frame.data[0], sizeof(float));
            std::memcpy(&vec.engine_rpm, &frame.data[4], sizeof(float));
            std::memcpy(&vec.steering_angle, &frame.data[8], sizeof(float));
            std::memcpy(&vec.brake_pressure, &frame.data[12], sizeof(float));
            std::memcpy(&vec.longitudinal_accel, &frame.data[16], sizeof(float));
            std::memcpy(&vec.dtc_error_count, &frame.data[20], sizeof(float));
        }
    }

    return vec;
}

void IDSExtractor::print_vector(const IDSFeatureVector& vec) {
    std::cout << "--- 12D IDS Feature Vector ---" << std::endl;
    std::cout << "Meta: [dt: " << vec.delta_t << ", gap: " << vec.counter_gap
              << ", ECU: " << vec.sender_ecu_id << ", Dom: " << vec.domain_id
              << ", Msg: " << vec.msg_type << "]" << std::endl;
    std::cout << "Crypto Tag Failed: " << vec.tag_verification_status << std::endl;
    std::cout << "Telemetry: [" << vec.vehicle_speed << ", " << vec.engine_rpm << ", "
              << vec.steering_angle << ", " << vec.brake_pressure << ", "
              << vec.longitudinal_accel << ", " << vec.dtc_error_count << "]\n" << std::endl;
}
