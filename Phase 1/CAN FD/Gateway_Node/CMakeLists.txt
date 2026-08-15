# Require a modern version of CMake
cmake_minimum_required(VERSION 3.15)

# Name your project and specify the language
project(CISG_Gateway VERSION 1.0 LANGUAGES CXX)

# Enforce modern C++ (C++20 provides excellent concurrency and memory management features)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Automatically generate the compile_commands.json file for Zed's clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Apply strict warnings to catch memory/logic errors early
set(COMMON_WARNINGS "-Wall -Wextra -Wpedantic -Wconversion -Wshadow")

# Configure High-Performance (Release) and Debug flags
# -O3: Maximum optimization
# -march=native: Optimizes the binary specifically for your CPU architecture
# -flto: Link-time optimization for faster execution boundaries
set(CMAKE_CXX_FLAGS_RELEASE "${COMMON_WARNINGS} -O3 -march=native -flto -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${COMMON_WARNINGS} -O0 -g")

# Tell CMake where to look for your header files
include_directories(include)

# Define your main executable and the source files it depends on
add_executable(cisg_router
    src/main.cpp
    src/routing_engine.cpp
    src/ids_extractor.cpp
    src/block_transfer.cpp
)

# Enable threading (essential for running concurrent CAN listeners and IPC)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Link your executable against necessary system libraries
target_link_libraries(cisg_router PRIVATE Threads::Threads)
