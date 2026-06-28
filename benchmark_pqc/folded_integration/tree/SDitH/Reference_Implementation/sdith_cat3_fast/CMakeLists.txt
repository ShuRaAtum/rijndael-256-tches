cmake_minimum_required(VERSION 3.10)
project(aq_vole_impl)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Default build type: Release" FORCE)
endif()

# the main library is in C and low-level crypto contain assembly files
set(CMAKE_C_FLAGS_DEBUG "-O0 -g3 -Wall -Werror")
set(CMAKE_C_FLAGS_RELEASE "-O3 -g3 -Wall -Werror -DNDEBUG")
enable_language(ASM)

set(BUILD_TESTING ON CACHE BOOL "Build Tests")
set(BUILD_KATS ON CACHE BOOL "Build KATs")
set(USE_REFERENCE_CODE_ONLY OFF CACHE BOOL "Build ONLY the reference code (not constant time, C only)")

# ARM Rijndael-256 optimization options (mutually exclusive)
# USE_ARM_CRYPTO: Use ARM Crypto Extension (AESE/AESMC hardware instructions)
# USE_NEON:       Use NEON SIMD (TBL/TBX software S-box, 4-block parallel)
option(USE_ARM_CRYPTO "Use ARM Crypto Extension for Rijndael-256" OFF)
option(USE_NEON "Use NEON SIMD for Rijndael-256" OFF)
# USE_ARM_FOLDED: ARM Crypto with AddRoundKey-folded round keys (Kpre pre-shuffle)
option(USE_ARM_FOLDED "Use AddRoundKey-folded ARM Crypto for Rijndael-256" OFF)

message(STATUS "BUILD_TESTING: ${BUILD_TESTING}")
message(STATUS "BUILD_KATS: ${BUILD_KATS}")
message(STATUS "USE_ARM_CRYPTO: ${USE_ARM_CRYPTO}")
message(STATUS "USE_NEON: ${USE_NEON}")
message(STATUS "USE_ARM_FOLDED: ${USE_ARM_FOLDED}")

add_subdirectory(lib/sha3)
add_subdirectory(lib/aes)

if (BUILD_KATS)
    set(kats_incs ${CMAKE_SOURCE_DIR}/src)
    set(kats_libs)
    # searching for libcrypto (for KATs only)
    find_path(crypto_inc NAMES openssl/conf.h)
    find_library(crypto NAMES crypto)
    if (crypto_inc AND crypto)
        message(STATUS "Found libcrypto: I=${crypto_inc} L=${crypto}")
        set(kats_incs ${kats_incs} ${crypto_inc})
        set(kats_libs ${kats_libs} ${crypto})
    else ()
        message(FATAL_ERROR "Libcrypto not found (required for NIST's KATs): I=${crypto_inc} L=${crypto}")
    endif ()
endif (BUILD_KATS)


set(VOLE_SRCS
        src/commons.c
        src/vole_private.h
        src/sdith_prng.h
        src/sdith_prng.c
        src/gf256.c
        src/gf192.c
        src/matrix_vector_products_f2.c
        src/matrix_transpose_f2.c
        src/ggm.c
        src/ggm.h
        src/vole_expansion.c
        src/piop_circuit.c
        src/gf128.c
        src/rsd.c
        src/sdith_prng_private.h
        src/commons.h
        src/sdith_signature.c
        src/sdith_signature_parameters.c
        src/vole_to_piop.c
        src/vole_parameters.cpp
        src/sdith_arithmetic.h
        src/sdith_algebra.h
        src/sdith_vole_to_piop.h
        src/sdith_rsd.h
        src/sdith_piop_circuits.h
        src/vole_parameters.h
        src/vole_generation.h
        src/sdith_signature.h
)

add_library(vole STATIC ${VOLE_SRCS})
target_link_libraries(vole sha3 aes m)
target_compile_definitions(vole PRIVATE ONLY_REF_IMPLEMENTATION)

if (BUILD_TESTING)
add_executable(bench_sdith test/bench_sdith.c)
target_link_libraries(bench_sdith vole)
target_compile_definitions(bench_sdith PRIVATE CAT3B)
target_include_directories(bench_sdith PRIVATE ${test_incs} src)

enable_testing()
add_test(bench_sdith bench_sdith)
endif (BUILD_TESTING)

if (BUILD_KATS)
add_subdirectory(generator)
endif (BUILD_KATS)

