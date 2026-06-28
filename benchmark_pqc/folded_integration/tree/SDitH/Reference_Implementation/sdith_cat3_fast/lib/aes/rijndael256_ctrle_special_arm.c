/*
 * Rijndael-256 CTR-LE mode - ARM optimized special functions
 *
 * Replaces rijndael256_ctrle_special_ref.c when ARM optimization is enabled.
 * Key optimization: batches 4 consecutive CTR blocks for parallel encryption
 * using our NEON 4-block parallel function.
 */

#if defined(USE_ARM_CRYPTO) || defined(USE_NEON)

#include <string.h>
#include "rijndael256.h"
#include "rijndael256_ctrle.h"
#include "rijndael256_opt.h"
#if defined(USE_ARM_FOLDED)
#include "rijndael256_folded_arm.h"
#endif

#if defined(_WIN32) || defined(__APPLE__)
#define __always_inline inline __attribute((always_inline))
#endif

__always_inline static void ctr256_increment_arm(ctr256_t* ctr) {
    ++ctr->v64[0];
    if (ctr->v64[0] == 0) {
        ++ctr->v64[1];
        if (ctr->v64[1] == 0) {
            ++ctr->v64[2];
            if (ctr->v64[2] == 0) {
                ++ctr->v64[3];
            }
        }
    }
}

/*
 * Adapter: convert SDitH round keys to our Rijndael256Key struct.
 * The byte layout is identical (480 bytes), we just need to set rounds=14.
 */
static inline void rk_to_opt_ctx(Rijndael256Key *opt, const void *round_keys) {
    memcpy(opt->roundKeys, round_keys, 480);
    opt->rounds = 14;
}

EXPORT void rijndael256_ctrle_set_key_ref(void* round_keys, const void* rijndael256key) {
    rijndael256_key_schedule_ref(round_keys, rijndael256key);
}

EXPORT void rijndael256_ctrle_encrypt_nblocks_ref(void* out, void* out_last256, void* in_out_ctr256,
                                                  const void* round_keys, uint64_t nblocks) {
    ctr256_t ctr;
    uint8_t* oo = (uint8_t*)out;
    memcpy(ctr.v8, in_out_ctr256, 32);

    Rijndael256Key opt_ctx;
    rk_to_opt_ctx(&opt_ctx, round_keys);
#if defined(USE_ARM_FOLDED)
    /* Per-key pre-shuffle Kpre = TBL(rk), built once per encrypt_nblocks call
     * (one set of round keys), amortized over all nblocks. Counted in timing. */
    R256FoldedKey fk;
    rijndael256_folded_setup(&opt_ctx, &fk);
#endif

    uint64_t i = 0;

#if defined(USE_NEON)
    /*
     * NEON 4-block parallel path: batch 4 consecutive CTR values
     * and encrypt them in parallel using neon_4pt.
     *
     * For nblocks >= 5, we can process groups of 4 (leaving the last
     * block for out_last256 handling).
     */
    while (i + 4 < nblocks) {
        /* Prepare 4 consecutive counter blocks (128 bytes) */
        uint8_t pt_buf[128];
        memcpy(pt_buf, ctr.v8, 32);
        ctr256_increment_arm(&ctr);
        memcpy(pt_buf + 32, ctr.v8, 32);
        ctr256_increment_arm(&ctr);
        memcpy(pt_buf + 64, ctr.v8, 32);
        ctr256_increment_arm(&ctr);
        memcpy(pt_buf + 96, ctr.v8, 32);
        ctr256_increment_arm(&ctr);

        /* 4-block parallel encrypt */
        rijndael256_encrypt_neon_4pt(&opt_ctx, pt_buf, oo + 32 * i);
        i += 4;
    }
#endif

    /* Process remaining blocks (up to nblocks-1) one at a time */
    while (i < nblocks - 1) {
#if defined(USE_ARM_FOLDED)
        rijndael256_encrypt_arm_folded(&fk, ctr.v8, oo + 32 * i);
#elif defined(USE_ARM_CRYPTO)
        rijndael256_encrypt_arm(&opt_ctx, ctr.v8, oo + 32 * i);
#elif defined(USE_NEON)
        rijndael256_encrypt_neon(&opt_ctx, ctr.v8, oo + 32 * i);
#endif
        ctr256_increment_arm(&ctr);
        i++;
    }

    /* Last block goes to out_last256 */
#if defined(USE_ARM_FOLDED)
    rijndael256_encrypt_arm_folded(&fk, ctr.v8, out_last256);
#elif defined(USE_ARM_CRYPTO)
    rijndael256_encrypt_arm(&opt_ctx, ctr.v8, out_last256);
#elif defined(USE_NEON)
    rijndael256_encrypt_neon(&opt_ctx, ctr.v8, out_last256);
#endif
    ctr256_increment_arm(&ctr);

    memcpy(in_out_ctr256, ctr.v8, 32);
}

/** one-shot function */
EXPORT void rijndael256_ctrle_oneshot_encrypt_2blocks_ref(void* out256, const void* rijndael256key,
                                                          const void* ctr256) {
    ctr256_t ctr;
    rijndael256_rk_t rk;
    memcpy(ctr.v8, ctr256, 32);
    rijndael256_ctrle_set_key_ref(&rk, rijndael256key);

    Rijndael256Key opt_ctx;
    rk_to_opt_ctx(&opt_ctx, &rk);

    uint8_t* oo = (uint8_t*)out256;
#if defined(USE_ARM_FOLDED)
    R256FoldedKey fk;
    rijndael256_folded_setup(&opt_ctx, &fk);
    rijndael256_encrypt_arm_folded(&fk, ctr.v8, oo);
    ctr256_increment_arm(&ctr);
    rijndael256_encrypt_arm_folded(&fk, ctr.v8, oo + 32);
#elif defined(USE_ARM_CRYPTO)
    rijndael256_encrypt_arm(&opt_ctx, ctr.v8, oo);
    ctr256_increment_arm(&ctr);
    rijndael256_encrypt_arm(&opt_ctx, ctr.v8, oo + 32);
#elif defined(USE_NEON)
    rijndael256_encrypt_neon(&opt_ctx, ctr.v8, oo);
    ctr256_increment_arm(&ctr);
    rijndael256_encrypt_neon(&opt_ctx, ctr.v8, oo + 32);
#endif
}

#endif /* USE_ARM_CRYPTO || USE_NEON */
