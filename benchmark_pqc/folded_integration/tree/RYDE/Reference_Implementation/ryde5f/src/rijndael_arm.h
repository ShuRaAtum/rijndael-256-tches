/**
 * @file rijndael_arm.h
 * @brief Content for rijndael_arm.h (AES-128 reference + Rijndael-256 ARM optimized implementation)
 *
 * AES-128: Uses reference implementation (no ARM optimization for 128-bit blocks)
 * Rijndael-256: Uses our optimized ARM Crypto Extension / NEON implementation
 */

#ifndef RIJNDAEL_ARM_H
#define RIJNDAEL_ARM_H

#include <stdint.h>
#include <string.h>
#include "rijndael256_opt.h"
#if defined(USE_ARM_FOLDED)
#include "rijndael256_folded_arm.h"
#endif

/* ========================================================================
 * AES-128: Reuse reference implementation (no ARM optimization)
 * ======================================================================== */

#define AES128_ROUNDS 10
#define RIJNDAEL256_ROUNDS 14

/* --- GF(2^8) helpers (from rijndael_ref.h, needed for AES-128 reference) --- */

typedef uint8_t bf8_t;
#define bf8_modulus (UINT8_C((1 << 4) | (1 << 3) | (1 << 1) | 1))

static inline bf8_t bf8_load(const uint8_t* src) { return *src; }
static inline void bf8_store(uint8_t* dst, bf8_t src) { *dst = src; }

static inline bf8_t bf8_mul(bf8_t lhs, bf8_t rhs) {
    bf8_t result = -(rhs & 1) & lhs;
    for (unsigned int idx = 1; idx < 8; ++idx) {
        const uint8_t mask = -((lhs >> 7) & 1);
        lhs = (lhs << 1) ^ (mask & bf8_modulus);
        result ^= -((rhs >> idx) & 1) & lhs;
    }
    return result;
}

static inline bf8_t bf8_inv(bf8_t in) {
    const bf8_t t2 = bf8_mul(in, in);
    const bf8_t t3 = bf8_mul(in, t2);
    const bf8_t t5 = bf8_mul(t3, t2);
    const bf8_t t7 = bf8_mul(t5, t2);
    const bf8_t t14 = bf8_mul(t7, t7);
    const bf8_t t28 = bf8_mul(t14, t14);
    const bf8_t t56 = bf8_mul(t28, t28);
    const bf8_t t63 = bf8_mul(t56, t7);
    const bf8_t t126 = bf8_mul(t63, t63);
    const bf8_t t252 = bf8_mul(t126, t126);
    return bf8_mul(t252, t2);
}

static inline uint8_t parity8(uint8_t n) {
    n ^= n >> 4;
    n ^= n >> 2;
    n ^= n >> 1;
    return !((~n) & 1);
}

#define set_bit(value, index) ((value) << (index))

static bf8_t compute_sbox_arm(bf8_t in) {
    bf8_t t = bf8_inv(in);
    bf8_t t0 = set_bit(parity8(t & (1 | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7))), 0);
    t0 ^= set_bit(parity8(t & (1 | (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7))), 1);
    t0 ^= set_bit(parity8(t & (1 | (1 << 1) | (1 << 2) | (1 << 6) | (1 << 7))), 2);
    t0 ^= set_bit(parity8(t & (1 | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 7))), 3);
    t0 ^= set_bit(parity8(t & (1 | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4))), 4);
    t0 ^= set_bit(parity8(t & ((1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5))), 5);
    t0 ^= set_bit(parity8(t & ((1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6))), 6);
    t0 ^= set_bit(parity8(t & ((1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7))), 7);
    return t0 ^ (1 | (1 << 1) | (1 << 5) | (1 << 6));
}

/* AES-128 types */
#define AES_NR 4
typedef uint8_t aes_word_t[4];
typedef aes_word_t aes_round_key_t[8];
typedef aes_word_t aes_block_t[8];

typedef struct {
    aes_round_key_t round_keys[AES128_ROUNDS + 1];
} aes128_round_keys_t;

#define ROUNDS_128 10
#define KEY_WORDS_128 4
#define AES_BLOCK_WORDS 4

static const bf8_t arm_round_constants[30] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
};

static int arm_contains_zero(const bf8_t* block) {
    return !block[0] | !block[1] | !block[2] | !block[3];
}

static inline void arm_xor_u8_array(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static void arm_sub_words(bf8_t* words) {
    words[0] = compute_sbox_arm(words[0]);
    words[1] = compute_sbox_arm(words[1]);
    words[2] = compute_sbox_arm(words[2]);
    words[3] = compute_sbox_arm(words[3]);
}

static void arm_rot_word(bf8_t* words) {
    bf8_t tmp = words[0];
    words[0]  = words[1];
    words[1]  = words[2];
    words[2]  = words[3];
    words[3]  = tmp;
}

static inline int arm_aes128_expand_key(aes128_round_keys_t* round_keys, const uint8_t* key,
                                        unsigned int key_words, unsigned int block_words,
                                        unsigned int num_rounds) {
    int ret = 0;
    for (unsigned int k = 0; k < key_words; k++) {
        round_keys->round_keys[k / block_words][k % block_words][0] = bf8_load(&key[4 * k]);
        round_keys->round_keys[k / block_words][k % block_words][1] = bf8_load(&key[(4 * k) + 1]);
        round_keys->round_keys[k / block_words][k % block_words][2] = bf8_load(&key[(4 * k) + 2]);
        round_keys->round_keys[k / block_words][k % block_words][3] = bf8_load(&key[(4 * k) + 3]);
    }

    for (unsigned int k = key_words; k < block_words * (num_rounds + 1); ++k) {
        bf8_t tmp[AES_NR];
        memcpy(tmp, round_keys->round_keys[(k - 1) / block_words][(k - 1) % block_words], sizeof(tmp));
        if (k % key_words == 0) {
            arm_rot_word(tmp);
            ret |= arm_contains_zero(tmp);
            arm_sub_words(tmp);
            tmp[0] ^= arm_round_constants[(k / key_words) - 1];
        }
        if (key_words > 6 && (k % key_words) == 4) {
            ret |= arm_contains_zero(tmp);
            arm_sub_words(tmp);
        }
        unsigned int m = k - key_words;
        round_keys->round_keys[k / block_words][k % block_words][0] =
                round_keys->round_keys[m / block_words][m % block_words][0] ^ tmp[0];
        round_keys->round_keys[k / block_words][k % block_words][1] =
                round_keys->round_keys[m / block_words][m % block_words][1] ^ tmp[1];
        round_keys->round_keys[k / block_words][k % block_words][2] =
                round_keys->round_keys[m / block_words][m % block_words][2] ^ tmp[2];
        round_keys->round_keys[k / block_words][k % block_words][3] =
                round_keys->round_keys[m / block_words][m % block_words][3] ^ tmp[3];
    }
    return ret;
}

static inline int aes_128_key_expansion(aes128_round_keys_t* round_key, const uint8_t* key) {
    return arm_aes128_expand_key(round_key, key, KEY_WORDS_128, AES_BLOCK_WORDS, ROUNDS_128);
}

/* AES-128 round functions (reference) */
static void arm_add_round_key(unsigned int round, aes_block_t state, const aes128_round_keys_t* round_key,
                              unsigned int block_words) {
    for (unsigned int c = 0; c < block_words; c++) {
        arm_xor_u8_array(&state[c][0], &round_key->round_keys[round][c][0], &state[c][0], AES_NR);
    }
}

static int arm_sub_bytes(aes_block_t state, unsigned int block_words) {
    int ret = 0;
    for (unsigned int c = 0; c < block_words; c++) {
        ret |= arm_contains_zero(&state[c][0]);
        for (unsigned int r = 0; r < AES_NR; r++) {
            state[c][r] = compute_sbox_arm(state[c][r]);
        }
    }
    return ret;
}

static void arm_shift_row(aes_block_t state, unsigned int block_words) {
    aes_block_t new_state;
    for (unsigned int i = 0; i < block_words; ++i) {
        new_state[i][0] = state[i][0];
        new_state[i][1] = state[(i + 1) % block_words][1];
        new_state[i][2] = state[(i + 2) % block_words][2];
        new_state[i][3] = state[(i + 3) % block_words][3];
    }
    for (unsigned int i = 0; i < block_words; ++i) {
        memcpy(&state[i][0], &new_state[i][0], AES_NR);
    }
}

static void arm_mix_column(aes_block_t state, unsigned int block_words) {
    for (unsigned int c = 0; c < block_words; c++) {
        bf8_t tmp   = bf8_mul(state[c][0], 0x02) ^ bf8_mul(state[c][1], 0x03) ^ state[c][2] ^ state[c][3];
        bf8_t tmp_1 = state[c][0] ^ bf8_mul(state[c][1], 0x02) ^ bf8_mul(state[c][2], 0x03) ^ state[c][3];
        bf8_t tmp_2 = state[c][0] ^ state[c][1] ^ bf8_mul(state[c][2], 0x02) ^ bf8_mul(state[c][3], 0x03);
        bf8_t tmp_3 = bf8_mul(state[c][0], 0x03) ^ state[c][1] ^ state[c][2] ^ bf8_mul(state[c][3], 0x02);
        state[c][0] = tmp;
        state[c][1] = tmp_1;
        state[c][2] = tmp_2;
        state[c][3] = tmp_3;
    }
}

static void arm_load_state(aes_block_t state, const uint8_t* src, unsigned int block_words) {
    for (unsigned int i = 0; i != block_words * 4; ++i) {
        state[i / 4][i % 4] = bf8_load(&src[i]);
    }
}

static void arm_store_state(uint8_t* dst, aes_block_t state, unsigned int block_words) {
    for (unsigned int i = 0; i != block_words * 4; ++i) {
        bf8_store(&dst[i], state[i / 4][i % 4]);
    }
}

static int arm_aes_encrypt(const aes128_round_keys_t* keys, aes_block_t state, unsigned int block_words,
                           unsigned int num_rounds) {
    int ret = 0;
    arm_add_round_key(0, state, keys, block_words);
    for (unsigned int round = 1; round < num_rounds; ++round) {
        ret |= arm_sub_bytes(state, block_words);
        arm_shift_row(state, block_words);
        arm_mix_column(state, block_words);
        arm_add_round_key(round, state, keys, block_words);
    }
    ret |= arm_sub_bytes(state, block_words);
    arm_shift_row(state, block_words);
    arm_add_round_key(num_rounds, state, keys, block_words);
    return ret;
}

static inline int aes_128_encrypt(const aes128_round_keys_t* key, const uint8_t* plaintext,
                                  uint8_t* ciphertext) {
    aes_block_t state;
    arm_load_state(state, plaintext, AES_BLOCK_WORDS);
    const int ret = arm_aes_encrypt(key, state, AES_BLOCK_WORDS, ROUNDS_128);
    arm_store_state(ciphertext, state, AES_BLOCK_WORDS);
    return ret;
}

/* ========================================================================
 * Rijndael-256: Use our optimized ARM implementation
 * ======================================================================== */

/* Seed-expansion key context. Under the folded build it additionally carries the
 * per-key pre-shuffled schedule (Kpre); otherwise it is exactly Rijndael256Key,
 * so the EOR/NEON builds are byte- and ABI-identical to before. */
#if defined(USE_ARM_FOLDED)
typedef struct { Rijndael256Key ctx; R256FoldedKey fk; } rijndael256_seed_ctx_t;
#else
typedef Rijndael256Key rijndael256_seed_ctx_t;
#endif

static inline int rijndael_256_key_expansion(rijndael256_seed_ctx_t* k, const uint8_t* key) {
#if defined(USE_ARM_FOLDED)
    int r = rijndael256_setup_key(key, 256, &k->ctx);
    /* Per-key pre-shuffle: Kpre = TBL(rk). Counted inside sign/verify timing
     * because seed expansion runs per GGM node, not hoisted out of the loop. */
    rijndael256_folded_setup(&k->ctx, &k->fk);
    return r;
#else
    return rijndael256_setup_key(key, 256, k);
#endif
}

/*
 * Select the best available encryption function based on compile-time flags.
 *
 * USE_ARM_CRYPTO: ARM Crypto Extension (AESE/AESMC hardware instructions)
 * USE_NEON:       NEON TBL/TBX S-box based (software, no HW AES needed)
 * Default:        ARM Crypto Extension (the common case on Apple Silicon)
 */
static inline int rijndael_256_encrypt(const rijndael256_seed_ctx_t* k, const uint8_t* plaintext,
                                       uint8_t* ciphertext) {
#if defined(USE_ARM_FOLDED)
    rijndael256_encrypt_arm_folded(&k->fk, plaintext, ciphertext);
#elif defined(USE_NEON)
    rijndael256_encrypt_neon(k, plaintext, ciphertext);
#else
    /* Default: ARM Crypto Extension */
    rijndael256_encrypt_arm(k, plaintext, ciphertext);
#endif
    return 0;
}

#endif /* RIJNDAEL_ARM_H */
