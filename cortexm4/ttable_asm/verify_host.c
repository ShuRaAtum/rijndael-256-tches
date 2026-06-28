/*
 * Rijndael-256 T-table ASM — Host Verification
 * On host (x86), we can't run ARM ASM, so verify C key schedule only.
 * Full ASM test runs on STM32F407 board.
 */

#include <stdio.h>
#include <string.h>
#include "rijndael256_ttable_asm.h"
#include "test_vectors.h"

/* Use the C T-table encrypt for host verification of key schedule */
extern const uint32_t r256_Te0[256];
extern const uint8_t  r256_sbox[256];

static inline uint32_t get_word_be(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void put_word_be(uint32_t w, uint8_t *b) {
    b[0] = (uint8_t)(w >> 24); b[1] = (uint8_t)(w >> 16);
    b[2] = (uint8_t)(w >> 8);  b[3] = (uint8_t)w;
}

/* C T-table encrypt using single Te0 + rotation (mirrors ASM logic) */
static void encrypt_c(const uint32_t *rk, const uint8_t *pt, uint8_t *ct) {
    uint32_t s[8], t[8];

    for (int i = 0; i < 8; i++)
        s[i] = get_word_be(pt + 4 * i) ^ rk[i];
    rk += 8;

    for (int round = 1; round < 14; round++) {
        for (int c = 0; c < 8; c++) {
            int c1 = (c + 1) & 7, c3 = (c + 3) & 7, c4 = (c + 4) & 7;
            uint32_t v;
            v  = r256_Te0[(s[c]  >> 24) & 0xFF];
            v ^= ((r256_Te0[(s[c1] >> 16) & 0xFF] >> 8) | (r256_Te0[(s[c1] >> 16) & 0xFF] << 24));
            v ^= ((r256_Te0[(s[c3] >> 8)  & 0xFF] >> 16) | (r256_Te0[(s[c3] >> 8)  & 0xFF] << 16));
            v ^= ((r256_Te0[ s[c4]        & 0xFF] >> 24) | (r256_Te0[ s[c4]        & 0xFF] << 8));
            t[c] = v ^ rk[c];
        }
        memcpy(s, t, sizeof(s));
        rk += 8;
    }

    for (int c = 0; c < 8; c++) {
        int c1 = (c + 1) & 7, c3 = (c + 3) & 7, c4 = (c + 4) & 7;
        uint32_t v;
        v  = (uint32_t)r256_sbox[(s[c]  >> 24) & 0xFF] << 24;
        v |= (uint32_t)r256_sbox[(s[c1] >> 16) & 0xFF] << 16;
        v |= (uint32_t)r256_sbox[(s[c3] >> 8)  & 0xFF] << 8;
        v |= (uint32_t)r256_sbox[ s[c4]        & 0xFF];
        t[c] = v ^ rk[c];
    }

    for (int i = 0; i < 8; i++)
        put_word_be(t[i], ct + 4 * i);
}

static int test_enc(const char *name, const uint8_t *key, int keyBits,
                    const uint8_t *pt, const uint8_t *ct_exp) {
    R256TtableAsmKey rk;
    uint8_t ct[32];

    r256_ttable_asm_setup_key(key, keyBits, &rk);
    encrypt_c(rk.roundKey, pt, ct);

    if (memcmp(ct, ct_exp, 32) == 0) {
        printf("[PASS] %s\n", name);
        return 1;
    }
    printf("[FAIL] %s\n", name);
    printf("  Expected: ");
    for (int i = 0; i < 32; i++) printf("%02X", ct_exp[i]);
    printf("\n  Got:      ");
    for (int i = 0; i < 32; i++) printf("%02X", ct[i]);
    printf("\n");
    return 0;
}

int main(void) {
    int pass = 0;
    printf("=== Rijndael-256 T-table ASM — Host Verification ===\n\n");

    pass += test_enc("tv1 (128-bit, all-zeros)",    tv1_key, 128, tv1_pt, tv1_ct);
    pass += test_enc("tv2 (192-bit, all-zeros)",    tv2_key, 192, tv2_pt, tv2_ct);
    pass += test_enc("tv3 (256-bit, all-zeros)",    tv3_key, 256, tv3_pt, tv3_ct);
    pass += test_enc("tv4 (128-bit, incrementing)", tv4_key, 128, tv4_pt, tv4_ct);

    printf("\n%d/4 PASS\n", pass);
    return pass == 4 ? 0 : 1;
}
