cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
project(Rijndael256CUDA LANGUAGES C CUDA)

# ============================================================================
# Build Options
# ============================================================================
option(BUILD_TESTS "Build test executables" ON)
option(BUILD_BENCHMARKS "Build benchmark executables" ON)
include(CTest)

# ============================================================================
# C Standard
# ============================================================================
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ============================================================================
# CUDA Configuration
# ============================================================================
# Default: RTX 4080 - Compute Capability 8.9
# Override with -DCMAKE_CUDA_ARCHITECTURES="75;89" etc.
if(NOT CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES 89)
endif()
set(CMAKE_CUDA_STANDARD 11)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# CUDA compilation flags
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler -Wall")
set(CMAKE_CUDA_FLAGS_DEBUG "-g -G")
set(CMAKE_CUDA_FLAGS_RELEASE "-O3")

# ============================================================================
# Compiler Flags
# ============================================================================
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native")

# ============================================================================
# Include Directories
# ============================================================================
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/test)

# ============================================================================
# CPU Library
# ============================================================================
add_library(rijndael_cpu STATIC
    cpu/rijndael.c
)
target_include_directories(rijndael_cpu PUBLIC ${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# CUDA Tables Library (shared by all GPU modes)
# ============================================================================
add_library(rijndael_cuda_tables STATIC
    cuda/rijndael_cuda_tables.cu
)
target_include_directories(rijndael_cuda_tables PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_target_properties(rijndael_cuda_tables PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# ============================================================================
# ECB Mode Library (V2 + V3 encrypt + decrypt)
# ============================================================================
add_library(rijndael_ecb STATIC
    cuda/rijndael_ecb.cu
)
target_include_directories(rijndael_ecb PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(rijndael_ecb PUBLIC rijndael_cpu PRIVATE rijndael_cuda_tables)
set_target_properties(rijndael_ecb PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# ============================================================================
# CTR Mode Library (V2 + V3)
# ============================================================================
add_library(rijndael_ctr STATIC
    cuda/rijndael_ctr.cu
)
target_include_directories(rijndael_ctr PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(rijndael_ctr PUBLIC rijndael_cpu PRIVATE rijndael_cuda_tables)
set_target_properties(rijndael_ctr PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# ============================================================================
# ES Mode Library (V2 + V3)
# ============================================================================
add_library(rijndael_es STATIC
    cuda/rijndael_es.cu
)
target_include_directories(rijndael_es PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(rijndael_es PUBLIC rijndael_cpu PRIVATE rijndael_cuda_tables)
set_target_properties(rijndael_es PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# ============================================================================
# Test Executables
# ============================================================================
if(BUILD_TESTS)
    # ECB Tests
    add_executable(test_ecb test/test_ecb.cu)
    target_link_libraries(test_ecb rijndael_ecb rijndael_cpu rijndael_cuda_tables)

    # CTR Tests
    add_executable(test_ctr test/test_ctr.cu)
    target_link_libraries(test_ctr rijndael_ctr rijndael_cpu rijndael_cuda_tables)

    # ES Tests
    add_executable(test_es test/test_es.cu)
    target_link_libraries(test_es rijndael_es rijndael_cpu rijndael_cuda_tables)

    if(BUILD_TESTING)
        add_test(NAME test_ecb COMMAND test_ecb)
        add_test(NAME test_ctr COMMAND test_ctr)
        add_test(NAME test_es COMMAND test_es)
        set_tests_properties(test_ecb test_ctr test_es PROPERTIES
            LABELS "correctness;gpu"
            RUN_SERIAL TRUE
        )
    endif()
endif()

# ============================================================================
# Benchmark Executables
# ============================================================================
if(BUILD_BENCHMARKS)
    # ECB Benchmark
    add_executable(benchmark_ecb benchmark/benchmark_ecb.cu)
    target_link_libraries(benchmark_ecb rijndael_ecb rijndael_cpu rijndael_cuda_tables)

    # CTR Benchmark
    add_executable(benchmark_ctr benchmark/benchmark_ctr.cu)
    target_link_libraries(benchmark_ctr rijndael_ctr rijndael_cpu rijndael_cuda_tables)

    # ES Benchmark
    add_executable(benchmark_es benchmark/benchmark_es.cu)
    target_link_libraries(benchmark_es rijndael_es rijndael_cpu rijndael_cuda_tables)
endif()

# ============================================================================
# Profiling Executables
# ============================================================================
add_executable(profile_ecb profile/profile_ecb.cu)
target_link_libraries(profile_ecb rijndael_ecb rijndael_cpu rijndael_cuda_tables)

# ============================================================================
# Utility: GPU Check
# ============================================================================
if(EXISTS ${CMAKE_SOURCE_DIR}/scripts/check_gpu.cu)
    add_executable(check_gpu scripts/check_gpu.cu)
endif()

# ============================================================================
# Print Configuration Summary
# ============================================================================
message(STATUS "============================================")
message(STATUS "Rijndael-256 CUDA Build Configuration")
message(STATUS "============================================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CUDA Architecture: ${CMAKE_CUDA_ARCHITECTURES}")
message(STATUS "BUILD_TESTS: ${BUILD_TESTS}")
message(STATUS "BUILD_TESTING: ${BUILD_TESTING}")
message(STATUS "BUILD_BENCHMARKS: ${BUILD_BENCHMARKS}")
message(STATUS "Targets: rijndael_cpu, rijndael_cuda_tables")
message(STATUS "  ECB: rijndael_ecb (V2+V3, encrypt+decrypt)")
message(STATUS "  CTR: rijndael_ctr (V2+V3)")
message(STATUS "  ES:  rijndael_es  (V2+V3)")
message(STATUS "============================================")
