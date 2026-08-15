#include "routing_engine.hpp"
#include <cstring>

RoutingEngine::RoutingEngine() : registered_ecus_count(0) {
    // Initialize the table
    for (auto& entry : ecu_table) {
        entry.ecu_id = 0;
        entry.policy_class = PolicyClass::BLOCKED;
        entry.is_authenticated = false;
        entry.session_key.fill(0);
    }
}

bool RoutingEngine::register_ecu(uint32_t ecu_id, PolicyClass p_class, const uint8_t* key_bytes) {
    if (registered_ecus_count >= MAX_ECUS) return false;

    ecu_table[registered_ecus_count].ecu_id = ecu_id;
    ecu_table[registered_ecus_count].policy_class = p_class;
    std::memcpy(ecu_table[registered_ecus_count].session_key.data(), key_bytes, SESSION_KEY_SIZE);
    ecu_table[registered_ecus_count].is_authenticated = true;

    registered_ecus_count++;
    return true;
}

const ECUEntry* RoutingEngine::lookup_ecu(uint32_t ecu_id) const {
    for (size_t i = 0; i < registered_ecus_count; ++i) {
        if (ecu_table[i].ecu_id == ecu_id && ecu_table[i].is_authenticated) {
            return &ecu_table[i];
        }
    }
    return nullptr; // ECU not found or unauthenticated
}

bool RoutingEngine::evaluate_routing_policy(PolicyClass source_class, PolicyClass dest_class, uint32_t can_id) const {
    // Default-Deny Rule: If classes match (intra-domain), it's handled on the local bus
    if (source_class == dest_class) {
        return true;
    }

    // Enforcing the strict Default-Deny Inter-Domain Matrix
    switch (source_class) {
        case PolicyClass::SAFETY:
            if (dest_class == PolicyClass::INFOTAINMENT) {
                return true; // ALLOW (read-only telemetry like speed/RPM)[cite: 23]
            }
            break;

        case PolicyClass::INFOTAINMENT:
            if (dest_class == PolicyClass::COMFORT) {
                // ALLOW only for a restricted whitelist of CAN IDs[cite: 23]
                return (can_id == 0x101 || can_id == 0x102);
            }
            if (dest_class == PolicyClass::SAFETY) {
                return false; // STRICTLY BLOCK[cite: 23]
            }
            break;

        case PolicyClass::COMFORT:
            if (dest_class == PolicyClass::SAFETY) {
                return false; // BLOCK[cite: 23]
            }
            break;

        default:
            break;
    }

    return false; // Default-Deny fallback
}
