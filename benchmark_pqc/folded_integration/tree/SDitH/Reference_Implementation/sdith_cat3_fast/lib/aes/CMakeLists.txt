set(AES_SRCS_GENERIC
        rijndael256.c
        rijndael256.h
        aes_ansi_ref.c
        aes128_ctrle.h
        aes128_ctrle_ref.c
        aes128_ctrle_special_ref.c
        aes128_ctrle_generics.impl.h
        rijndael256_ctrle.h
        rijndael256_ctrle_generics.impl.h
        rijndael256_ctrle_ref.c
        rijndael256_ctrle_special_ref.c
)

# ARM optimized Rijndael-256 sources
set(AES_SRCS_ARM
        rijndael256_opt.h
        rijndael256_opt_tables.h
        rijndael256_opt_keyschedule.c
        rijndael256_arm_wrapper.c
        rijndael256_ctrle_special_arm.c
        rijndael256_arm.S
)

# NEON optimized Rijndael-256 sources (software SIMD, no AES hardware)
set(AES_SRCS_NEON
        rijndael256_opt.h
        rijndael256_opt_tables.h
        rijndael256_opt_keyschedule.c
        rijndael256_arm_wrapper.c
        rijndael256_ctrle_special_arm.c
        rijndael256_neon.S
        rijndael256_neon_interleaved.S
)

# AddRoundKey-folded ARM Crypto sources (Kpre pre-shuffle; folded AESE path)
set(AES_SRCS_ARM_FOLDED
        rijndael256_opt.h
        rijndael256_opt_tables.h
        rijndael256_opt_keyschedule.c
        rijndael256_folded_arm.h
        rijndael256_folded_arm.c
        rijndael256_arm_wrapper.c
        rijndael256_ctrle_special_arm.c
        rijndael256_arm.S
)

if(USE_ARM_FOLDED)
    add_library(aes STATIC ${AES_SRCS_GENERIC} ${AES_SRCS_ARM_FOLDED})
    # USE_ARM_CRYPTO keeps the ARM wrapper/special files active; USE_ARM_FOLDED
    # selects the folded encrypt + per-key folded_setup inside them.
    target_compile_definitions(aes PUBLIC USE_ARM_CRYPTO USE_ARM_FOLDED)
    message(STATUS "Rijndael-256: ARM Crypto + AddRoundKey-folded acceleration enabled")
elseif(USE_ARM_CRYPTO)
    add_library(aes STATIC ${AES_SRCS_GENERIC} ${AES_SRCS_ARM})
    target_compile_definitions(aes PUBLIC USE_ARM_CRYPTO)
    message(STATUS "Rijndael-256: ARM Crypto Extension acceleration enabled")
elseif(USE_NEON)
    add_library(aes STATIC ${AES_SRCS_GENERIC} ${AES_SRCS_NEON})
    target_compile_definitions(aes PUBLIC USE_NEON)
    message(STATUS "Rijndael-256: NEON SIMD acceleration enabled")
else()
    add_library(aes STATIC ${AES_SRCS_GENERIC})
    message(STATUS "Rijndael-256: Reference implementation (no ARM acceleration)")
endif()

target_include_directories(aes PUBLIC .)
