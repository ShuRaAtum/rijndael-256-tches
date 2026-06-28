/*
 * Rijndael-256 Bitslice — Host Verification (x86/any)
 *
 * Verifies decrypt path only (decrypt key schedule + decrypt_ref).
 * Encrypt uses ARM ASM and cannot run on x86.
 *
 * Build: gcc -O3 -Wall -I. -I../../common -o verify \
 *        verify_host.c rijndael256_keysched.c rijndael256_decrypt_ref.c && ./verify
 */

#include <stdio.h>
#include <string.h>
#include "rijndael256.h"
#include "test_vectors.h"

static int test_dec(const char *name, const uint8_t *key, int keyBits,
                    const uint8_t *ct_exp, const uint8_t *pt_exp)
{
    R256Key dec_rk;
    uint8_t pt[32];

    r256_setup_decrypt_key(key, keyBits, &dec_rk);
    rijndael256_decrypt_ref(&dec_rk, ct_exp, pt);

    int ok = (memcmp(pt, pt_exp, 32) == 0);
    printf("[%s] %s  (decrypt, %d-bit key)\n", ok ? "PASS" : "FAIL", name, keyBits);
    if (!ok) {
        printf("  expected: ");
        for (int i = 0; i < 32; i++) printf("%02X", pt_exp[i]);
        printf("\n  got:      ");
        for (int i = 0; i < 32; i++) printf("%02X", pt[i]);
        printf("\n");
    }
    return ok;
}

int main(void)
{
    int pass = 0, total = 4;

    printf("=== Rijndael-256 Bitslice — Host Decrypt Verification ===\n\n");

    pass += test_dec("tv1 (128-bit, all-zeros)",    tv1_key, 128, tv1_ct, tv1_pt);
    pass += test_dec("tv2 (192-bit, all-zeros)",    tv2_key, 192, tv2_ct, tv2_pt);
    pass += test_dec("tv3 (256-bit, all-zeros)",    tv3_key, 256, tv3_ct, tv3_pt);
    pass += test_dec("tv4 (128-bit, incrementing)", tv4_key, 128, tv4_ct, tv4_pt);

    printf("\n%d/%d PASS\n", pass, total);
    return pass == total ? 0 : 1;
}
