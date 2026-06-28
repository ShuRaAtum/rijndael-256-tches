/*
 * Rijndael-256 Fixsliced ASM Board Test — STM32F407
 *
 * Tests encrypt ASM for all key sizes (128/192/256).
 * ASM uses NOT-absorbed keys (K1..KNr planes 1,2,6,7 inverted).
 */

#include <stdint.h>
#include <string.h>
#include "rijndael256.h"
#include "test_vectors.h"

#define DWT_CTRL   (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004)
#define SCB_DEMCR  (*(volatile uint32_t *)0xE000EDFC)

typedef struct {
    uint32_t magic;        /* 0xDEADBEEF = complete */
    /* Per key size: [0]=128, [1]=192, [2]=256 */
    struct {
        uint32_t tv_pass;
        uint32_t cycles_enc;
        uint32_t cycles_ks;
    } ks[3];
    uint8_t  ct_out[32];
} Result;

static volatile Result *result = (volatile Result *)0x20001000;

extern void rijndael256_encrypt(const R256Key *ks,
                                const uint8_t *pt, uint8_t *ct);

static void dwt_init(void) {
    SCB_DEMCR |= (1 << 24);
    DWT_CYCCNT = 0;
    DWT_CTRL  |= 1;
}

static void absorb_not_into_keys(R256Key *rk) {
    int Nr = rk->rounds;
    for (int r = 1; r <= Nr; r++) {
        uint32_t *dst = &rk->roundKey[r * R256_NB];
        dst[1] ^= 0xFFFFFFFF;
        dst[2] ^= 0xFFFFFFFF;
        dst[6] ^= 0xFFFFFFFF;
        dst[7] ^= 0xFFFFFFFF;
    }
}

static const struct {
    const uint8_t *key;
    int            bits;
    const uint8_t *pt;
    const uint8_t *ct;
} tests[] = {
    { tv1_key, 128, tv1_pt, tv1_ct },
    { tv2_key, 192, tv2_pt, tv2_ct },
    { tv3_key, 256, tv3_pt, tv3_ct },
};

int main(void)
{
    R256Key rk;
    uint8_t ct[32];

    dwt_init();
    memset((void *)result, 0, sizeof(Result));

    for (int k = 0; k < 3; k++) {
        /* Key schedule benchmark */
        DWT_CYCCNT = 0;
        r256_setup_key(tests[k].key, tests[k].bits, &rk);
        result->ks[k].cycles_ks = DWT_CYCCNT;

        absorb_not_into_keys(&rk);

        /* Warm up */
        rijndael256_encrypt(&rk, tests[k].pt, ct);

        /* Encrypt benchmark (average of 16 runs) */
        uint32_t total = 0;
        for (int i = 0; i < 16; i++) {
            DWT_CYCCNT = 0;
            rijndael256_encrypt(&rk, tests[k].pt, ct);
            total += DWT_CYCCNT;
        }
        result->ks[k].cycles_enc = total / 16;

        /* Correctness */
        result->ks[k].tv_pass = (memcmp(ct, tests[k].ct, 32) == 0) ? 1 : 0;

        /* Save last ciphertext for debug */
        memcpy((void *)result->ct_out, ct, 32);
    }

    result->magic = 0xDEADBEEF;
    while (1) {}
}
