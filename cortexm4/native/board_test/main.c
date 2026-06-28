/*
 * Rijndael-256 Native C — STM32F407 Board Test
 *
 * Tests encrypt for all key sizes (128/192/256).
 * Verifies correctness + measures cycle count via DWT.
 */

#include <stdint.h>
#include <string.h>
#include "../rijndael256_native.h"
#include "test_vectors.h"

/* DWT cycle counter registers */
#define DWT_CTRL   (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004)
#define SCB_DEMCR  (*(volatile uint32_t *)0xE000EDFC)

/* Result structure at 0x20001000 */
typedef struct {
    uint32_t magic;        /* 0xDEADBEEF = complete */
    /* Per key size: [0]=128, [1]=192, [2]=256 */
    struct {
        uint32_t tv_pass;
        uint32_t cycles_enc;
        uint32_t cycles_ks;
    } ks[3];
    uint8_t  ct_out[32];   /* last ciphertext for debug */
} Result;

static volatile Result *result = (volatile Result *)0x20001000;

static void dwt_init(void) {
    SCB_DEMCR |= (1 << 24);
    DWT_CYCCNT = 0;
    DWT_CTRL  |= 1;
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
    R256NativeKey rk;
    uint8_t ct[32];

    dwt_init();
    memset((void *)result, 0, sizeof(Result));

    for (int k = 0; k < 3; k++) {
        /* Key schedule benchmark */
        DWT_CYCCNT = 0;
        r256_native_setup_key(tests[k].key, tests[k].bits, &rk);
        result->ks[k].cycles_ks = DWT_CYCCNT;

        /* Warm up */
        r256_native_encrypt(&rk, tests[k].pt, ct);

        /* Encrypt benchmark (average of 16 runs) */
        uint32_t total = 0;
        for (int i = 0; i < 16; i++) {
            DWT_CYCCNT = 0;
            r256_native_encrypt(&rk, tests[k].pt, ct);
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
