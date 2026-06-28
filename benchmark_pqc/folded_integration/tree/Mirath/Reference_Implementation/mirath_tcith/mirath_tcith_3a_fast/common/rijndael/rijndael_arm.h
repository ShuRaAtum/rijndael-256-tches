/**
 * @file rijndael_arm.h
 * @brief ARM-optimized Rijndael-256 wrapper matching Mirath's reference interface.
 *
 * Drop-in replacement for rijndael_ref.h when building on AArch64 with
 * ARM Crypto Extension or NEON.  The public API (function names and types)
 * is kept identical so that seed_expand_functions_arm.h and the rest of the
 * Mirath code can switch between reference and ARM builds by changing a
 * single include.
 *
 * Compile-time selection:
 *   -DUSE_ARM_CRYPTO   -> AESE/AESMC hardware path  (rijndael256_encrypt_arm)
 *   -DUSE_NEON         -> TBL/TBX software NEON path (rijndael256_encrypt_neon)
 *   (default)          -> ARM Crypto path
 */

#ifndef RIJNDAEL_ARM_H
#define RIJNDAEL_ARM_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "rijndael256_opt.h"
#if defined(USE_ARM_FOLDED)
#include "rijndael256_folded_arm.h"
#endif

/* ------------------------------------------------------------------ */
/* Types -- kept binary-compatible with rijndael_ref.h                */
/* ------------------------------------------------------------------ */

/*
 * Mirath's original type hierarchy:
 *   aes_word_t        = uint8_t[4]
 *   aes_round_key_t   = aes_word_t[8]   (32 bytes per round)
 *   aes_round_keys_t  = { aes_round_key_t round_keys[15]; }  (480 bytes)
 *
 * Our Rijndael256Key:
 *   uint8_t roundKeys[480]   (at offset 0)
 *   int     rounds           (at offset 480)
 *
 * The 480-byte round-key areas have identical byte layout, so we can
 * safely reinterpret-cast between the two representations.  The extra
 * `rounds` field is filled by our key-schedule and consumed by the
 * assembly encrypt routines; Mirath never inspects it.
 */

#define AES_MAX_ROUNDS 14

typedef uint8_t aes_word_t[4];
typedef aes_word_t aes_round_key_t[8];

#define AES_NR 4

typedef aes_word_t aes_block_t[8];

typedef struct {
    aes_round_key_t round_keys[AES_MAX_ROUNDS + 1];
#if defined(USE_ARM_FOLDED)
    /* AddRoundKey-folded pre-shuffled key schedule (Kpre), built once per key
     * in rijndael_256_key_expansion so its cost is counted per key. */
    R256FoldedKey fk;
#endif
} aes_round_keys_t;

/* ------------------------------------------------------------------ */
/* Key expansion wrappers                                              */
/* ------------------------------------------------------------------ */

/*
 * rijndael_256_key_expansion
 *
 * Mirath always calls this with a 32-byte (256-bit) key buffer
 * (the 192-bit case is zero-padded to 32 bytes by the caller).
 *
 * We set up our Rijndael256Key from the same 32-byte buffer and then
 * copy the resulting 480-byte round-key block into Mirath's
 * aes_round_keys_t, whose memory layout is byte-for-byte identical.
 *
 * Returns 0 on success (matches Mirath convention of returning non-zero
 * only when an intermediate S-box input is zero, which we ignore here
 * -- the ARM path does not need that information).
 */
static inline int rijndael_256_key_expansion(aes_round_keys_t *round_key,
                                             const uint8_t *key) {
    Rijndael256Key ctx;
    rijndael256_setup_key(key, 256, &ctx);
    /* Copy 480 bytes of expanded round keys */
    memcpy(round_key->round_keys, ctx.roundKeys,
           (RIJNDAEL256_MAX_ROUNDS + 1) * RIJNDAEL256_BLOCK_SIZE);
#if defined(USE_ARM_FOLDED)
    /* Per-key pre-shuffle: Kpre = TBL(rk). Counted inside sign/verify timing
     * because seed expansion runs per GGM node, not hoisted out of the loop. */
    rijndael256_folded_setup(&ctx, &round_key->fk);
#endif
    return 0;
}

/* AES-128 key expansion -- not performance-critical for Mirath's
 * Rijndael-256 usage, so we keep the reference C implementation
 * from rijndael_ref.h inline.                                       */

/* ---- begin: minimal AES-128 reference helpers (from rijndael_ref.h) ---- */

typedef uint8_t bf8_t;
#define bf8_modulus (UINT8_C((1 << 4) | (1 << 3) | (1 << 1) | 1))

static inline bf8_t bf8_load(const uint8_t *src) { return *src; }
static inline void  bf8_store(uint8_t *dst, bf8_t src) { *dst = src; }

static inline bf8_t bf8_mul(bf8_t lhs, bf8_t rhs) {
    bf8_t result = -(rhs & 1) & lhs;
    for (unsigned int idx = 1; idx < 8; ++idx) {
        const uint8_t mask = -((lhs >> 7) & 1);
        lhs = (lhs << 1) ^ (mask & bf8_modulus);
        result ^= -((rhs >> idx) & 1) & lhs;
    }
    return result;
}

static inline uint8_t parity8(uint8_t n) {
    n ^= n >> 4;
    n ^= n >> 2;
    n ^= n >> 1;
    return !((~n) & 1);
}

static inline bf8_t bf8_inv(bf8_t in) {
    const bf8_t t2  = bf8_mul(in, in);   /* square */
    const bf8_t t3  = bf8_mul(in, t2);
    const bf8_t t5  = bf8_mul(t3, t2);
    const bf8_t t7  = bf8_mul(t5, t2);
    const bf8_t t14 = bf8_mul(t7, t7);
    const bf8_t t28 = bf8_mul(t14, t14);
    const bf8_t t56 = bf8_mul(t28, t28);
    const bf8_t t63 = bf8_mul(t56, t7);
    const bf8_t t126= bf8_mul(t63, t63);
    const bf8_t t252= bf8_mul(t126, t126);
    return bf8_mul(t252, t2);
}

#define set_bit(value, index) ((value) << (index))

static inline bf8_t compute_sbox(bf8_t in) {
    bf8_t t = bf8_inv(in);
    bf8_t t0 = set_bit(parity8(t & (1 | (1<<4) | (1<<5) | (1<<6) | (1<<7))), 0);
    t0 ^= set_bit(parity8(t & (1 | (1<<1) | (1<<5) | (1<<6) | (1<<7))), 1);
    t0 ^= set_bit(parity8(t & (1 | (1<<1) | (1<<2) | (1<<6) | (1<<7))), 2);
    t0 ^= set_bit(parity8(t & (1 | (1<<1) | (1<<2) | (1<<3) | (1<<7))), 3);
    t0 ^= set_bit(parity8(t & (1 | (1<<1) | (1<<2) | (1<<3) | (1<<4))), 4);
    t0 ^= set_bit(parity8(t & ((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5))), 5);
    t0 ^= set_bit(parity8(t & ((1<<2) | (1<<3) | (1<<4) | (1<<5) | (1<<6))), 6);
    t0 ^= set_bit(parity8(t & ((1<<3) | (1<<4) | (1<<5) | (1<<6) | (1<<7))), 7);
    return t0 ^ (1 | (1<<1) | (1<<5) | (1<<6));
}

static int contains_zero(const bf8_t *block) {
    return !block[0] | !block[1] | !block[2] | !block[3];
}

static const bf8_t round_constants[30] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
};

static inline void xor_u8_array(const uint8_t *a, const uint8_t *b,
                                uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = a[i] ^ b[i];
}

/* ---- AES-128 reference helpers (sub_words, rot_word, expand_key) ---- */

static void sub_words(bf8_t *words) {
    words[0] = compute_sbox(words[0]);
    words[1] = compute_sbox(words[1]);
    words[2] = compute_sbox(words[2]);
    words[3] = compute_sbox(words[3]);
}

static void rot_word(bf8_t *words) {
    bf8_t tmp = words[0];
    words[0]  = words[1];
    words[1]  = words[2];
    words[2]  = words[3];
    words[3]  = tmp;
}

#define ROUNDS_128 10
#define ROUNDS_256 14
#define KEY_WORDS_128 4
#define KEY_WORDS_256 8
#define AES_BLOCK_WORDS 4
#define RIJNDAEL_BLOCK_WORDS_256 8

static inline int expand_key(aes_round_keys_t *round_keys, const uint8_t *key,
                             unsigned int key_words, unsigned int block_words,
                             unsigned int num_rounds) {
    int ret = 0;
    for (unsigned int k = 0; k < key_words; k++) {
        round_keys->round_keys[k / block_words][k % block_words][0] = bf8_load(&key[4*k]);
        round_keys->round_keys[k / block_words][k % block_words][1] = bf8_load(&key[4*k+1]);
        round_keys->round_keys[k / block_words][k % block_words][2] = bf8_load(&key[4*k+2]);
        round_keys->round_keys[k / block_words][k % block_words][3] = bf8_load(&key[4*k+3]);
    }
    for (unsigned int k = key_words; k < block_words * (num_rounds + 1); ++k) {
        bf8_t tmp[AES_NR];
        memcpy(tmp, round_keys->round_keys[(k-1)/block_words][(k-1)%block_words], sizeof(tmp));
        if (k % key_words == 0) {
            rot_word(tmp);
            ret |= contains_zero(tmp);
            sub_words(tmp);
            tmp[0] ^= round_constants[(k / key_words) - 1];
        }
        if (key_words > 6 && (k % key_words) == 4) {
            ret |= contains_zero(tmp);
            sub_words(tmp);
        }
        unsigned int m = k - key_words;
        round_keys->round_keys[k/block_words][k%block_words][0] =
            round_keys->round_keys[m/block_words][m%block_words][0] ^ tmp[0];
        round_keys->round_keys[k/block_words][k%block_words][1] =
            round_keys->round_keys[m/block_words][m%block_words][1] ^ tmp[1];
        round_keys->round_keys[k/block_words][k%block_words][2] =
            round_keys->round_keys[m/block_words][m%block_words][2] ^ tmp[2];
        round_keys->round_keys[k/block_words][k%block_words][3] =
            round_keys->round_keys[m/block_words][m%block_words][3] ^ tmp[3];
    }
    return ret;
}

static inline int aes_128_key_expansion(aes_round_keys_t *round_key,
                                        const uint8_t *key) {
    return expand_key(round_key, key, KEY_WORDS_128, AES_BLOCK_WORDS, ROUNDS_128);
}

/* ---- AES-128 reference encrypt (kept for Mirath's AES-128 paths) ---- */

static void add_round_key(unsigned int round, aes_block_t state,
                          const aes_round_keys_t *round_key,
                          unsigned int block_words) {
    for (unsigned int c = 0; c < block_words; c++)
        xor_u8_array(&state[c][0], &round_key->round_keys[round][c][0],
                     &state[c][0], AES_NR);
}

static int sub_bytes(aes_block_t state, unsigned int block_words) {
    int ret = 0;
    for (unsigned int c = 0; c < block_words; c++) {
        ret |= contains_zero(&state[c][0]);
        for (unsigned int r = 0; r < AES_NR; r++)
            state[c][r] = compute_sbox(state[c][r]);
    }
    return ret;
}

static void shift_row(aes_block_t state, unsigned int block_words) {
    aes_block_t new_state;
    switch (block_words) {
    case 4: case 6:
        for (unsigned int i = 0; i < block_words; ++i) {
            new_state[i][0] = state[i][0];
            new_state[i][1] = state[(i+1)%block_words][1];
            new_state[i][2] = state[(i+2)%block_words][2];
            new_state[i][3] = state[(i+3)%block_words][3];
        }
        break;
    case 8:
        for (unsigned int i = 0; i < block_words; i++) {
            new_state[i][0] = state[i][0];
            new_state[i][1] = state[(i+1)%8][1];
            new_state[i][2] = state[(i+3)%8][2];
            new_state[i][3] = state[(i+4)%8][3];
        }
        break;
    }
    for (unsigned int i = 0; i < block_words; ++i)
        memcpy(&state[i][0], &new_state[i][0], AES_NR);
}

static void mix_column(aes_block_t state, unsigned int block_words) {
    for (unsigned int c = 0; c < block_words; c++) {
        bf8_t t  = bf8_mul(state[c][0],0x02) ^ bf8_mul(state[c][1],0x03) ^ state[c][2] ^ state[c][3];
        bf8_t t1 = state[c][0] ^ bf8_mul(state[c][1],0x02) ^ bf8_mul(state[c][2],0x03) ^ state[c][3];
        bf8_t t2 = state[c][0] ^ state[c][1] ^ bf8_mul(state[c][2],0x02) ^ bf8_mul(state[c][3],0x03);
        bf8_t t3 = bf8_mul(state[c][0],0x03) ^ state[c][1] ^ state[c][2] ^ bf8_mul(state[c][3],0x02);
        state[c][0] = t;
        state[c][1] = t1;
        state[c][2] = t2;
        state[c][3] = t3;
    }
}

static void load_state(aes_block_t state, const uint8_t *src,
                       unsigned int block_words) {
    for (unsigned int i = 0; i != block_words * 4; ++i)
        state[i/4][i%4] = bf8_load(&src[i]);
}

static void store_state(uint8_t *dst, aes_block_t state,
                        unsigned int block_words) {
    for (unsigned int i = 0; i != block_words * 4; ++i)
        bf8_store(&dst[i], state[i/4][i%4]);
}

static int aes_encrypt(const aes_round_keys_t *keys, aes_block_t state,
                       unsigned int block_words, unsigned int num_rounds) {
    int ret = 0;
    add_round_key(0, state, keys, block_words);
    for (unsigned int round = 1; round < num_rounds; ++round) {
        ret |= sub_bytes(state, block_words);
        shift_row(state, block_words);
        mix_column(state, block_words);
        add_round_key(round, state, keys, block_words);
    }
    ret |= sub_bytes(state, block_words);
    shift_row(state, block_words);
    add_round_key(num_rounds, state, keys, block_words);
    return ret;
}

static inline int aes_128_encrypt(const aes_round_keys_t *key,
                                  const uint8_t *plaintext,
                                  uint8_t *ciphertext) {
    aes_block_t state;
    load_state(state, plaintext, AES_BLOCK_WORDS);
    const int ret = aes_encrypt(key, state, AES_BLOCK_WORDS, ROUNDS_128);
    store_state(ciphertext, state, AES_BLOCK_WORDS);
    return ret;
}

/* ---- end AES-128 reference helpers ---- */

/* ------------------------------------------------------------------ */
/* Rijndael-256 encryption wrapper (ARM-accelerated)                  */
/* ------------------------------------------------------------------ */

/*
 * rijndael_256_encrypt
 *
 * Wraps our ARM/NEON assembly.  We build a temporary Rijndael256Key
 * that shares the same 480-byte round-key memory as the caller's
 * aes_round_keys_t, plus the `rounds` field the assembly needs.
 */
static inline int rijndael_256_encrypt(const aes_round_keys_t *key,
                                       const uint8_t *plaintext,
                                       uint8_t *ciphertext) {
    /*
     * Build Rijndael256Key on the stack.  The round-key memory
     * layout is identical between the two structs.
     */
#if defined(USE_ARM_FOLDED)
    /* Folded path: use the per-key pre-shuffled schedule built at expansion. */
    rijndael256_encrypt_arm_folded(&key->fk, plaintext, ciphertext);
#else
    Rijndael256Key ctx;
    memcpy(ctx.roundKeys, key->round_keys,
           (RIJNDAEL256_MAX_ROUNDS + 1) * RIJNDAEL256_BLOCK_SIZE);
    ctx.rounds = ROUNDS_256;   /* always 14 for Rijndael-256 */

#if defined(USE_NEON)
    rijndael256_encrypt_neon(&ctx, plaintext, ciphertext);
#else
    /* Default: ARM Crypto Extension (AESE/AESMC) */
    rijndael256_encrypt_arm(&ctx, plaintext, ciphertext);
#endif
#endif

    return 0;
}

#endif /* RIJNDAEL_ARM_H */
