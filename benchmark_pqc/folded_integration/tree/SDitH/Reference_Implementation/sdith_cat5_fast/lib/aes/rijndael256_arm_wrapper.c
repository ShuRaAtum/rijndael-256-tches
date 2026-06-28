/*
 * Rijndael-256 ARM Optimization Wrapper for SDitH
 *
 * Bridges SDitH's Rijndael-256 API to optimized ARM implementations:
 *   - ARM Crypto Extension (AESE/AESMC hardware instructions)
 *   - NEON SIMD (TBL/TBX software implementation)
 *
 * Key insight: SDitH's rijndael256_rk_t (15 x 32-byte round keys = 480 bytes)
 * has the exact same byte layout as our Rijndael256Key.roundKeys[480].
 * Both store round keys in big-endian byte order, column-major.
 * So we can directly reuse SDitH's key schedule with our encrypt functions.
 */

#if defined(USE_ARM_CRYPTO) || defined(USE_NEON)

#include <string.h>
#include "rijndael256.h"
#include "rijndael256_ctrle.h"
#include "rijndael256_opt.h"
#if defined(USE_ARM_FOLDED)
#include "rijndael256_folded_arm.h"
#endif

/*
 * Adapter structure: maps SDitH's rijndael256_rk_t to our Rijndael256Key.
 * Both have identical round key byte layout (480 bytes), but our struct
 * also stores the round count and requires 16-byte alignment.
 */
static inline void sdith_rk_to_opt(Rijndael256Key *opt, const rijndael256_rk_t *rk) {
    memcpy(opt->roundKeys, rk->rk, 480);
    opt->rounds = Nr;  /* Always 14 for 256-bit key */
}

/* ---------- Key Schedule ---------- */

/*
 * SDitH calls rijndael256_ctrle_set_key_ref() to expand a 256-bit key
 * into round keys. Under ARM optimization, we still use SDitH's own
 * key schedule (it produces the correct byte layout), but we store
 * into our Rijndael256Key structure for the encrypt functions.
 *
 * Note: We override the _ref suffix functions so that the generic
 * CTR code in rijndael256_ctrle_generics.impl.h transparently uses
 * our optimized encrypt without changing any calling code.
 */

/* ---------- ECB Encrypt: 1 block ---------- */

void rijndael256_ecb_encrypt_1block_ref(uint8_t res[32], const uint8_t x[32],
                                        const rijndael256_rk_t *roundkeys) {
    Rijndael256Key opt_ctx;
    sdith_rk_to_opt(&opt_ctx, roundkeys);
#if defined(USE_ARM_FOLDED)
    R256FoldedKey fk;
    rijndael256_folded_setup(&opt_ctx, &fk);
    rijndael256_encrypt_arm_folded(&fk, x, res);
#elif defined(USE_ARM_CRYPTO)
    rijndael256_encrypt_arm(&opt_ctx, x, res);
#elif defined(USE_NEON)
    rijndael256_encrypt_neon(&opt_ctx, x, res);
#endif
}

/* ---------- ECB Encrypt: 2 blocks ---------- */

void rijndael256_ecb_encrypt_2blocks_ref(uint8_t res[64], const uint8_t x[64],
                                         const rijndael256_rk_t *roundkeys) {
    Rijndael256Key opt_ctx;
    sdith_rk_to_opt(&opt_ctx, roundkeys);
#if defined(USE_ARM_FOLDED)
    R256FoldedKey fk;
    rijndael256_folded_setup(&opt_ctx, &fk);
    rijndael256_encrypt_arm_folded(&fk, x, res);
    rijndael256_encrypt_arm_folded(&fk, x + 32, res + 32);
#elif defined(USE_ARM_CRYPTO)
    rijndael256_encrypt_arm(&opt_ctx, x, res);
    rijndael256_encrypt_arm(&opt_ctx, x + 32, res + 32);
#elif defined(USE_NEON)
    rijndael256_encrypt_neon(&opt_ctx, x, res);
    rijndael256_encrypt_neon(&opt_ctx, x + 32, res + 32);
#endif
}

/* ---------- ECB Encrypt: 4 blocks (KEY OPTIMIZATION TARGET) ---------- */
/*
 * This is the primary optimization target. SDitH's CTR mode calls
 * this to encrypt 4 independent blocks with the same key.
 * Maps perfectly to our neon_4pt / neon_il_4pt functions.
 */

void rijndael256_ecb_encrypt_4blocks_ref(uint8_t res[128], const uint8_t x[128],
                                         const rijndael256_rk_t *roundkeys) {
    Rijndael256Key opt_ctx;
    sdith_rk_to_opt(&opt_ctx, roundkeys);
#if defined(USE_ARM_FOLDED)
    /* Folded ARM Crypto: 4 serial single-block folded encrypts, mirroring the
     * EOR path's structure so the comparison isolates AddRoundKey folding. */
    R256FoldedKey fk;
    rijndael256_folded_setup(&opt_ctx, &fk);
    rijndael256_encrypt_arm_folded(&fk, x, res);
    rijndael256_encrypt_arm_folded(&fk, x + 32, res + 32);
    rijndael256_encrypt_arm_folded(&fk, x + 64, res + 64);
    rijndael256_encrypt_arm_folded(&fk, x + 96, res + 96);
#elif defined(USE_ARM_CRYPTO)
    /* ARM Crypto Extension: 4 serial encryptions (still faster than ref) */
    rijndael256_encrypt_arm(&opt_ctx, x, res);
    rijndael256_encrypt_arm(&opt_ctx, x + 32, res + 32);
    rijndael256_encrypt_arm(&opt_ctx, x + 64, res + 64);
    rijndael256_encrypt_arm(&opt_ctx, x + 96, res + 96);
#elif defined(USE_NEON)
    /* NEON: True 4-block parallel encryption */
    rijndael256_encrypt_neon_4pt(&opt_ctx, x, res);
#endif
}

/* ---------- CTR Encrypt: 2 blocks (one-shot) ---------- */

void rijndael256_ctr_encrypt_2blocks_ref(uint8_t res[64], const uint8_t ctr[32],
                                         const uint8_t key[32]) {
    rijndael256_rk_t roundkeys;
    rijndael256_key_schedule_ref(&roundkeys, key);

    Rijndael256Key opt_ctx;
    sdith_rk_to_opt(&opt_ctx, &roundkeys);
#if defined(USE_ARM_FOLDED)
    R256FoldedKey fk;
    rijndael256_folded_setup(&opt_ctx, &fk);
#endif

    /* Encrypt first counter block */
#if defined(USE_ARM_FOLDED)
    rijndael256_encrypt_arm_folded(&fk, ctr, res);
#elif defined(USE_ARM_CRYPTO)
    rijndael256_encrypt_arm(&opt_ctx, ctr, res);
#elif defined(USE_NEON)
    rijndael256_encrypt_neon(&opt_ctx, ctr, res);
#endif

    /* Increment counter (little-endian, matching SDitH convention) */
    ctr256_t ctr_next;
    memcpy(ctr_next.v8, ctr, 32);
    ++ctr_next.v64[0];
    if (ctr_next.v64[0] == 0) {
        ++ctr_next.v64[1];
        if (ctr_next.v64[1] == 0) {
            ++ctr_next.v64[2];
            if (ctr_next.v64[2] == 0) {
                ++ctr_next.v64[3];
            }
        }
    }

    /* Encrypt second counter block */
#if defined(USE_ARM_FOLDED)
    rijndael256_encrypt_arm_folded(&fk, ctr_next.v8, res + 32);
#elif defined(USE_ARM_CRYPTO)
    rijndael256_encrypt_arm(&opt_ctx, ctr_next.v8, res + 32);
#elif defined(USE_NEON)
    rijndael256_encrypt_neon(&opt_ctx, ctr_next.v8, res + 32);
#endif
}

#endif /* USE_ARM_CRYPTO || USE_NEON */
