#pragma once

#include <cstdint>
#include <cstddef>
#include <array>

// Define system limits based on your vehicle architecture
constexpr size_t MAX_ECUS = 32;          // Maximum number of ECUs supported
constexpr size_t SESSION_KEY_SIZE = 16;  // 128-bit session key (K_i)

// Physical CAN-FD Domains mapping to Policy Classes
enum class PolicyClass {
    SAFETY,
    COMFORT,
    INFOTAINMENT,
    BLOCKED
};

// Structure representing an ECU's metadata and cryptographic context
struct ECUEntry {
    uint32_t ecu_id;
    PolicyClass policy_class;
    std::array<uint8_t, SESSION_KEY_SIZE> session_key;
    bool is_authenticated;
};

class RoutingEngine {
private:
    // Flat, pre-allocated static table to avoid dynamic memory allocation on the critical path
    std::array<ECUEntry, MAX_ECUS> ecu_table;
    size_t registered_ecus_count;

public:
    RoutingEngine();

    // Registration and Lookup
    bool register_ecu(uint32_t ecu_id, PolicyClass p_class, const uint8_t* key_bytes);
    const ECUEntry* lookup_ecu(uint32_t ecu_id) const;

    // Default-Deny Inter-Domain Routing Matrix Enforcement
    bool evaluate_routing_policy(PolicyClass source_class, PolicyClass dest_class, uint32_t can_id) const;
};
