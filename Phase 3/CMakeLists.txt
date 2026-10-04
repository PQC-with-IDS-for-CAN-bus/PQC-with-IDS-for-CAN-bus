# ==============================================================================
# Pure C++17 DockerLab Benchmarking Suite — Unified CMake Build Configuration
# ==============================================================================
#
# Project: Central In-Vehicle Security Gateway (CISG) with Post-Quantum Cryptography
# Target: ISO/IEC 14882:2017 (C++17) Hard Real-Time Automotive Benchmarking Suite
# Standard References:
#   - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA-44) [^1]
#   - NIST SP 800-232: Ascon-Based Lightweight Cryptography Standards (Ascon-AEAD128) [^2]
#   - ISO 11898-1:2015: Controller Area Network with Flexible Data-Rate (CAN-FD) [^3]
#   - ISO 26262:2018: Road Vehicles — Functional Safety (ASIL-D Hard Real-Time) [^4]
#   - AUTOSAR Classic Release R22-11: Secure Onboard Communication (SecOC) [^5]
#
# Upstream Repositories:
#   - Open Quantum Safe (liboqs): https://github.com/open-quantum-safe/liboqs
#   - Microsoft ONNX Runtime C++ API: https://github.com/microsoft/onnxruntime
#   - Ascon NIST SP 800-232 Reference: https://github.com/ascon/ascon-c
#
# Footnotes:
#   [^1]: NIST FIPS 204 (Aug 2024), DOI: 10.6028/NIST.FIPS.204.
#   [^2]: NIST SP 800-232 (Oct 2023), DOI: 10.6028/NIST.SP.800-232.
#   [^3]: ISO 11898-1:2015, Road Vehicles — CAN Data Link Layer and Physical Signalling.
#   [^4]: ISO 26262-5:2018, Product development at the hardware/software level for ASIL-D.
#   [^5]: AUTOSAR SWS SecOC Document ID 654, Release R22-11.
# ==============================================================================

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(DockerLab_CPP17_Suite
    VERSION 3.0.0
    DESCRIPTION "Pure C++17 Line-Rate DockerLab Benchmarking Suite for 3-Tier CISG"
    LANGUAGES C CXX
)

# ------------------------------------------------------------------------------
# 1. Enforce ISO C++17 Standard
# ------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------------------------------------------------------------------
# 2. Strict Compiler Flags for ASIL-D Production & Real-Time Performance
# ------------------------------------------------------------------------------
# -O3: Maximum optimization for line-rate cryptography and sliding-window feature extraction
# -Wall -Wextra -Wpedantic: Full diagnostic warning enforcement
# -pthread: POSIX threads support for real-time background threads and HTTP listener
add_compile_options(
    -O3
    -Wall
    -Wextra
    -Wpedantic
    -pthread
)

# Optional platform-specific architecture vectorization when available on host
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    # add_compile_options(-mavx2)
endif()

# ------------------------------------------------------------------------------
# 3. Include and Link Directories
# ------------------------------------------------------------------------------
include_directories(
    /usr/local/include
    ${CMAKE_CURRENT_SOURCE_DIR}/DockerLab/include
)

link_directories(
    /usr/local/lib
)

# ------------------------------------------------------------------------------
# 4. Dependency Declarations
# ------------------------------------------------------------------------------
find_package(Threads REQUIRED)

# Common library list:
#   - oqs: Open Quantum Safe library providing NIST FIPS 204 ML-DSA-44
#   - onnxruntime: Microsoft ONNX Runtime C++ engine for INT8 Autoencoder inference
#   - pthread: POSIX threading library
#   - rt: POSIX real-time extensions library (clock_nanosleep, timers)
set(COMMON_LIBS
    oqs
    onnxruntime
    ${CMAKE_THREAD_LIBS_INIT}
    rt
)

# ------------------------------------------------------------------------------
# 5. Executable Target 1: cisg_gateway
# ------------------------------------------------------------------------------
# Central In-Vehicle Security Gateway (CISG) Node:
#   - Tier 1: NIST SP 800-232 Ascon-AEAD128 wire tag check & sequence gate (< 15 µs)
#   - Tier 1.5: Discrete physical kinematic invariant gate (< 10 µs)
#   - Tier 2: ONNX Runtime INT8 LSTM autoencoder inference (~ 270 µs)
#   - Mode B Zero-Order Hold (ZOH) quarantine buffer management
#   - 60/4 Block transfer reassembly with 64-bit selective NACK generation
#   - NIST FIPS 204 ML-DSA-44 authentic 2,420B signature verification via liboqs
#   - Embedded HTTP REST server on port 8080
#   - Memory locking (mlockall) for ASIL-D zero major page faults
add_executable(cisg_gateway
    DockerLab/src/cisg_gateway.cpp
)

target_link_libraries(cisg_gateway
    PRIVATE
    ${COMMON_LIBS}
)

# ------------------------------------------------------------------------------
# 6. Executable Target 2: ecu_node
# ------------------------------------------------------------------------------
# Automotive Electronic Control Unit (ECU) Transmitter Node:
#   - Authentic NIST FIPS 204 ML-DSA-44 digital signature generation via liboqs
#   - NIST SP 800-232 Ascon-AEAD128 boot attestation wrapper (2,436B PAO)
#   - 60/4 Block transfer packetizer into 41 CAN-FD frames (ISO 11898-1 DLC 15)
#   - Physical wire transmission pacing (>= 13.5 ms burst time)
#   - Embedded HTTP REST server on port 8080
add_executable(ecu_node
    DockerLab/src/ecu_node.cpp
)

target_link_libraries(ecu_node
    PRIVATE
    ${COMMON_LIBS}
)

# ------------------------------------------------------------------------------
# 7. Executable Target 3: relay_node
# ------------------------------------------------------------------------------
# Inter-Domain Fault Injection & Wire Channel Emulator Node:
#   - ISO 11898-1 physical copper wire serialization delay emulation
#   - Deterministic fault injection (isolated drops, burst drops, corruption)
#   - Embedded HTTP REST server on port 8080
add_executable(relay_node
    DockerLab/src/relay_node.cpp
)

target_link_libraries(relay_node
    PRIVATE
    ${COMMON_LIBS}
)

# ------------------------------------------------------------------------------
# 8. Installation Directives
# ------------------------------------------------------------------------------
install(TARGETS cisg_gateway ecu_node relay_node
    RUNTIME DESTINATION /usr/local/bin
)

message(STATUS "Configured Pure C++17 DockerLab Benchmarking Suite")
message(STATUS "  C++ Standard: ISO C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Targets: cisg_gateway, ecu_node, relay_node")
message(STATUS "  Include directories: /usr/local/include, ${CMAKE_CURRENT_SOURCE_DIR}/DockerLab/include")
message(STATUS "  Link directories: /usr/local/lib")
message(STATUS "  Linked libraries: ${COMMON_LIBS}")
