# ==============================================================================
# Pure C++17 DockerLab Benchmarking Suite — Multi-Domain Container Image
# ==============================================================================
#
# Base: Ubuntu 22.04 LTS (Jammy Jellyfish)
# Standards & Algorithm Specifications:
#   - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA-44) [^1]
#   - NIST SP 800-232: Ascon-Based Lightweight Cryptography Standards (Ascon-AEAD128) [^2]
#   - ISO 11898-1:2015: Controller Area Network with Flexible Data-Rate (CAN-FD) [^3]
#   - ISO 26262 ASIL-D: Functional Safety & Real-Time Determinism [^4]
#
# Upstream Repositories & Pre-built Artifacts:
#   - Open Quantum Safe (liboqs): https://github.com/open-quantum-safe/liboqs (v0.12.0)
#   - Microsoft ONNX Runtime C++ API: https://github.com/microsoft/onnxruntime (v1.20.1)
#   - Ascon Reference: https://github.com/ascon/ascon-c
#
# Footnotes:
#   [^1]: NIST FIPS 204 (Aug 2024), DOI: 10.6028/NIST.FIPS.204.
#   [^2]: NIST SP 800-232 (Oct 2023), DOI: 10.6028/NIST.SP.800-232.
#   [^3]: ISO 11898-1:2015, Road Vehicles — CAN Data Link Layer.
#   [^4]: ISO 26262-5:2018, Product development at the hardware/software level for ASIL-D.
# ==============================================================================

FROM ubuntu:22.04

LABEL maintainer="Capstone PQC + IDS Research Team"
LABEL description="Pure C++17 Line-Rate Automotive Gateway, ECU, and Relay Benchmarking Container"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# ------------------------------------------------------------------------------
# 1. System Packages & Build Essentials
# ------------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    gcc \
    make \
    cmake \
    ninja-build \
    git \
    curl \
    tar \
    ca-certificates \
    iproute2 \
    can-utils \
    python3 \
    python3-pip \
    util-linux \
    tcpdump \
    libcap2-bin \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------------------
# 2. Build & Install Official liboqs (v0.12.0) from Source
# ------------------------------------------------------------------------------
# Flags:
#   -DOQS_BUILD_ONLY_LIB=ON: Strip test binaries and sample apps
#   -DOQS_USE_OPENSSL=OFF: Self-contained Keccak/SHA-3 implementations
#   -DOQS_ENABLE_SIG_ML_DSA=ON: Explicitly compile NIST FIPS 204 ML-DSA (ML-DSA-44/65/87)
WORKDIR /tmp
RUN git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build && cd build \
    && cmake -GNinja \
             -DCMAKE_BUILD_TYPE=Release \
             -DCMAKE_INSTALL_PREFIX=/usr/local \
             -DBUILD_SHARED_LIBS=ON \
             -DOQS_BUILD_ONLY_LIB=ON \
             -DOQS_USE_OPENSSL=OFF \
             -DOQS_ENABLE_SIG_ML_DSA=ON .. \
    && ninja install \
    && ldconfig \
    && rm -rf /tmp/liboqs

# ------------------------------------------------------------------------------
# 3. Provision Microsoft ONNX Runtime C++ API (v1.20.1)
# ------------------------------------------------------------------------------
# Extracts pre-compiled shared libraries and headers into /usr/local
WORKDIR /tmp
RUN curl -sSL https://github.com/microsoft/onnxruntime/releases/download/v1.20.1/onnxruntime-linux-x64-1.20.1.tgz | tar -xz \
    && cp -r onnxruntime-linux-x64-1.20.1/include/* /usr/local/include/ \
    && cp -r onnxruntime-linux-x64-1.20.1/lib/* /usr/local/lib/ \
    && ldconfig \
    && rm -rf /tmp/onnxruntime-linux-x64-1.20.1*

# ------------------------------------------------------------------------------
# 4. Provision Python Tooling for Testbed Controller and Orchestration
# ------------------------------------------------------------------------------
RUN pip3 install --no-cache-dir \
    numpy==1.26.4 \
    onnxruntime==1.20.1 \
    cryptography \
    dilithium-py

# ------------------------------------------------------------------------------
# 5. Copy Codebase, Models, Configurations, and Build Pure C++17 Targets
# ------------------------------------------------------------------------------
WORKDIR /workspace

# Copy Phase 3 source directory (including CMakeLists.txt and DockerLab/)
COPY . /workspace/

# Build and install pure C++17 targets: cisg_gateway, ecu_node, relay_node
WORKDIR /workspace
RUN if [ -f "CMakeLists.txt" ]; then \
        cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
        && cmake --build build -j$(nproc) \
        && cmake --install build; \
    elif [ -f "Phase 3/CMakeLists.txt" ]; then \
        cmake -B build -S "Phase 3" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
        && cmake --build build -j$(nproc) \
        && cmake --install build; \
    elif [ -f "Anti Gravity/Phase 3/CMakeLists.txt" ]; then \
        cmake -B build -S "Anti Gravity/Phase 3" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
        && cmake --build build -j$(nproc) \
        && cmake --install build; \
    fi

# Environment variables
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose HTTP REST server management port
EXPOSE 8080

# Default working directory and entrypoint
WORKDIR /workspace
CMD ["/usr/local/bin/cisg_gateway"]
