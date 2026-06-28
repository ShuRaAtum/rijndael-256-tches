/*
 * Rijndael-256 Bitsliced ASM Board Test — STM32F407
 *
 * Tests encrypt and decrypt ASM for all key sizes (128/192/256).
 * Encrypt: r256_setup_key + NOT absorption (planes 1,2,6,7 for K1..KNr)
 * Decrypt: r256_setup_decrypt_key (absorption built in)
 */

#include <stdint.h>
#include <string.h>
#include "rijndael256.h"
#include "test_vectors.h"

#define DWT_CTRL   (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004)
#define SCB_DEMCR  (*(volatile uint32_t *)0xE000EDFC)

typedef struct {
    uint32_t magic;           /* 0xDEADBEEF = complete */
    /* Per key size: [0]=128, [1]=192, [2]=256 */
    struct {
        uint32_t enc_pass;
        uint32_t dec_pass;
        uint32_t cycles_enc;
        uint32_t cycles_dec;
        uint32_t cycles_ks_enc;
        uint32_t cycles_ks_dec;
    } ks[3];
    uint8_t ct_out[32];       /* last ciphertext for debug */
} Result;

static volatile Result *result = (volatile Result *)0x20001000;

extern void rijndael256_encrypt(const R256Key *ks,
                                const uint8_t *pt, uint8_t *ct);
extern void rijndael256_decrypt(const R256Key *ks,
                                const uint8_t *ct, uint8_t *pt);

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
    R256Key enc_rk, dec_rk;
    uint8_t ct[32], pt[32];

    dwt_init();
    memset((void *)result, 0, sizeof(Result));

    for (int k = 0; k < 3; k++) {
        /* ============ ENCRYPT ============ */

        /* Encrypt key schedule benchmark */
        DWT_CYCCNT = 0;
        r256_setup_key(tests[k].key, tests[k].bits, &enc_rk);
        result->ks[k].cycles_ks_enc = DWT_CYCCNT;

        absorb_not_into_keys(&enc_rk);

        /* Warm up */
        rijndael256_encrypt(&enc_rk, tests[k].pt, ct);

        /* Encrypt benchmark (average of 16 runs) */
        uint32_t total = 0;
        for (int i = 0; i < 16; i++) {
            DWT_CYCCNT = 0;
            rijndael256_encrypt(&enc_rk, tests[k].pt, ct);
            total += DWT_CYCCNT;
        }
        result->ks[k].cycles_enc = total / 16;

        /* Encrypt correctness */
        result->ks[k].enc_pass = (memcmp(ct, tests[k].ct, 32) == 0) ? 1 : 0;

        /* ============ DECRYPT ============ */

        /* Decrypt key schedule benchmark */
        DWT_CYCCNT = 0;
        r256_setup_decrypt_key(tests[k].key, tests[k].bits, &dec_rk);
        result->ks[k].cycles_ks_dec = DWT_CYCCNT;

        /* Warm up */
        rijndael256_decrypt(&dec_rk, tests[k].ct, pt);

        /* Decrypt benchmark (average of 16 runs) */
        total = 0;
        for (int i = 0; i < 16; i++) {
            DWT_CYCCNT = 0;
            rijndael256_decrypt(&dec_rk, tests[k].ct, pt);
            total += DWT_CYCCNT;
        }
        result->ks[k].cycles_dec = total / 16;

        /* Decrypt correctness */
        result->ks[k].dec_pass = (memcmp(pt, tests[k].pt, 32) == 0) ? 1 : 0;

        /* Save last ciphertext for debug */
        memcpy((void *)result->ct_out, ct, 32);
    }

    result->magic = 0xDEADBEEF;
    while (1) {}
}
