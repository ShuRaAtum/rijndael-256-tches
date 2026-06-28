/**
 * @file seed_expand_functions_arm.h
 * @brief Seed expand functions based on AES-128 (reference) and Rijndael-256 (ARM optimized)
 */

#ifndef SEED_EXPAND_FUNCTIONS_ARM_H
#define SEED_EXPAND_FUNCTIONS_ARM_H

#include "rijndael_arm.h"
#define DOMAIN_SEPARATOR_CMT 3
#define DOMAIN_SEPARATOR_PRG 4

/* ========================================================================
 * AES-128 functions (reference implementation, same as seed_expand_functions_ref.h)
 * ======================================================================== */

static inline void aes_128_expand_seed(uint8_t dst[2][16], const uint8_t salt[16], const uint32_t idx, const uint8_t seed[16]) {
    uint8_t domain_separator = (uint8_t)DOMAIN_SEPARATOR_PRG;
    uint8_t msg[16] = {0};
    aes128_round_keys_t key;

    aes_128_key_expansion(&key, seed);

    memcpy(msg, salt, sizeof(uint8_t) * 16);
    msg[0] ^= 0x00;
    for (size_t k = 0; k < 4; k++) {
        msg[k + 1] ^= ((uint8_t *)&idx)[k];
    }
    msg[5] ^= domain_separator;
    aes_128_encrypt(&key, msg, dst[0]);

    msg[0] ^= 0x01;
    aes_128_encrypt(&key, msg, dst[1]);
}

static inline void aes_128_commit(uint8_t dst[2][16], const uint8_t salt[16], const uint32_t idx, const uint8_t seed[16]) {
    uint8_t domain_separator = (uint8_t)DOMAIN_SEPARATOR_CMT;
    uint8_t msg[16] = {0};
    aes128_round_keys_t key;

    aes_128_key_expansion(&key, seed);

    memcpy(msg, salt, sizeof(uint8_t) * 16);
    msg[0] ^= 0x00;
    for (size_t k = 0; k < 4; k++) {
        msg[k + 1] ^= ((uint8_t *)&idx)[k];
    }
    msg[5] ^= domain_separator;
    aes_128_encrypt(&key, msg, dst[0]);

    msg[0] ^= 0x01;
    aes_128_encrypt(&key, msg, dst[1]);
}

static inline void aes_128_expand_share(uint8_t (*dst)[16], const uint8_t salt[16], const uint8_t seed[16], uint8_t len) {
    aes128_round_keys_t key;
    uint8_t ctr[16] = {0};

    aes_128_key_expansion(&key, seed);

    for (uint8_t i = 0; i < len; i++) {
        ctr[0] = i;
        uint8_t msg[16] = {0};
        for (size_t k = 0; k < 16; k++) {
            msg[k] = (ctr[k] ^ salt[k]);
        }
        aes_128_encrypt(&key, msg, dst[i]);
    }
}

/* ========================================================================
 * Rijndael-256 functions (ARM optimized: key schedule + encrypt)
 * ======================================================================== */

static inline void rijndael_192_expand_seed(uint8_t dst[2][24], const uint8_t salt[24], const uint32_t idx, const uint8_t seed[24]) {
    uint8_t output[2][32] = {0};
    uint8_t domain_separator = (uint8_t)DOMAIN_SEPARATOR_PRG;
    uint8_t msg[32] = {0};
    rijndael256_seed_ctx_t key;

    uint8_t seed_with_zeros[32] = {0};
    memcpy(seed_with_zeros, seed, sizeof(uint8_t) * 24);

    rijndael_256_key_expansion(&key, seed_with_zeros);

    memcpy(msg, salt, sizeof(uint8_t) * 24);
    msg[0] ^= 0x00;
    for (size_t k = 0; k < 4; k++) {
        msg[k + 1] ^= ((uint8_t *)&idx)[k];
    }
    msg[5] ^= domain_separator;
    rijndael_256_encrypt(&key, msg, output[0]);
    memcpy(dst[0], output[0], sizeof(uint8_t) * 24);

    msg[0] ^= 0x01;
    rijndael_256_encrypt(&key, msg, output[1]);
    memcpy(dst[1], output[1], sizeof(uint8_t) * 24);
}

static inline void rijndael_256_expand_seed(uint8_t dst[2][32], const uint8_t salt[32], const uint32_t idx, const uint8_t seed[32]) {
    uint8_t domain_separator = (uint8_t)DOMAIN_SEPARATOR_PRG;
    uint8_t msg[32] = {0};
    rijndael256_seed_ctx_t key;

    rijndael_256_key_expansion(&key, seed);

    memcpy(msg, salt, sizeof(uint8_t) * 32);
    msg[0] ^= 0x00;
    for (size_t k = 0; k < 4; k++) {
        msg[k + 1] ^= ((uint8_t *)&idx)[k];
    }
    msg[5] ^= domain_separator;
    rijndael_256_encrypt(&key, msg, dst[0]);

    msg[0] ^= 0x01;
    rijndael_256_encrypt(&key, msg, dst[1]);
}

static inline void rijndael_192_commit(uint8_t dst[2][24], const uint8_t salt[24], const uint32_t idx, const uint8_t seed[24]) {
    uint8_t output[2][32] = {0};
    uint8_t domain_separator = (uint8_t)DOMAIN_SEPARATOR_CMT;
    uint8_t msg[32] = {0};
    rijndael256_seed_ctx_t key;

    uint8_t seed_with_zeros[32] = {0};
    memcpy(seed_with_zeros, seed, sizeof(uint8_t) * 24);

    rijndael_256_key_expansion(&key, seed_with_zeros);

    memcpy(msg, salt, sizeof(uint8_t) * 24);
    msg[0] ^= 0x00;
    for (size_t k = 0; k < 4; k++) {
        msg[k + 1] ^= ((uint8_t *)&idx)[k];
    }
    msg[5] ^= domain_separator;
    rijndael_256_encrypt(&key, msg, output[0]);
    memcpy(dst[0], output[0], sizeof(uint8_t) * 24);

    msg[0] ^= 0x01;
    rijndael_256_encrypt(&key, msg, output[1]);
    memcpy(dst[1], output[1], sizeof(uint8_t) * 24);
}

static inline void rijndael_256_commit(uint8_t dst[2][32], const uint8_t salt[32], const uint32_t idx, const uint8_t seed[32]) {
    uint8_t domain_separator = (uint8_t)DOMAIN_SEPARATOR_CMT;
    uint8_t msg[32] = {0};
    rijndael256_seed_ctx_t key;

    rijndael_256_key_expansion(&key, seed);

    memcpy(msg, salt, sizeof(uint8_t) * 32);
    msg[0] ^= 0x00;
    for (size_t k = 0; k < 4; k++) {
        msg[k + 1] ^= ((uint8_t *)&idx)[k];
    }
    msg[5] ^= domain_separator;
    rijndael_256_encrypt(&key, msg, dst[0]);

    msg[0] ^= 0x01;
    rijndael_256_encrypt(&key, msg, dst[1]);
}

static inline void rijndael_192_expand_share(uint8_t (*dst)[24], const uint8_t salt[24], const uint8_t seed[24], uint8_t len) {
    rijndael256_seed_ctx_t key;
    uint8_t ctr[32] = {0};

    uint8_t seed_with_zeros[32] = {0};
    memcpy(seed_with_zeros, seed, sizeof(uint8_t) * 24);

    rijndael_256_key_expansion(&key, seed_with_zeros);

    for (uint8_t i = 0; i < len; i++) {
        ctr[0] = i;
        uint8_t msg[32] = {0};
        for (size_t k = 0; k < 24; k++) {
            msg[k] = (ctr[k] ^ salt[k]);
        }
        uint8_t output[32] = {0};
        rijndael_256_encrypt(&key, msg, output);
        memcpy(dst[i], output, sizeof(uint8_t) * 24);
    }
}

static inline void rijndael_256_expand_share(uint8_t (*dst)[32], const uint8_t salt[32], const uint8_t seed[32], uint8_t len) {
    rijndael256_seed_ctx_t key;
    uint8_t ctr[32] = {0};

    rijndael_256_key_expansion(&key, seed);

    for (uint8_t i = 0; i < len; i++) {
        ctr[0] = i;
        uint8_t msg[32] = {0};
        for (size_t k = 0; k < 32; k++) {
            msg[k] = (ctr[k] ^ salt[k]);
        }
        rijndael_256_encrypt(&key, msg, dst[i]);
    }
}

#endif /* SEED_EXPAND_FUNCTIONS_ARM_H */
