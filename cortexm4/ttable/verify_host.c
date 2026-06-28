/*
 * Rijndael-256 T-table — Host Verification
 */

#include <stdio.h>
#include <string.h>
#include "rijndael256_ttable.h"
#include "test_vectors.h"

static int test_enc(const char *name, const uint8_t *key, int keyBits,
                    const uint8_t *pt, const uint8_t *ct_exp)
{
    R256TtableKey rk;
    uint8_t ct[32], pt2[32];

    r256_ttable_setup_key(key, keyBits, &rk);
    r256_ttable_encrypt(&rk, pt, ct);

    int enc_ok = (memcmp(ct, ct_exp, 32) == 0);
    r256_ttable_decrypt(&rk, ct, pt2);
    int dec_ok = (memcmp(pt2, pt, 32) == 0);

    if (enc_ok && dec_ok) {
        printf("[PASS] %s\n", name);
        return 1;
    }
    printf("[FAIL] %s (enc=%s, dec=%s)\n", name,
           enc_ok ? "ok" : "FAIL", dec_ok ? "ok" : "FAIL");
    return 0;
}

int main(void)
{
    int pass = 0, total = 4;

    printf("=== Rijndael-256 T-table — Host Verification ===\n\n");

    pass += test_enc("tv1 (128-bit, all-zeros)",   tv1_key, 128, tv1_pt, tv1_ct);
    pass += test_enc("tv2 (192-bit, all-zeros)",   tv2_key, 192, tv2_pt, tv2_ct);
    pass += test_enc("tv3 (256-bit, all-zeros)",   tv3_key, 256, tv3_pt, tv3_ct);
    pass += test_enc("tv4 (128-bit, incrementing)", tv4_key, 128, tv4_pt, tv4_ct);

    printf("\n%d/%d PASS\n", pass, total);
    return pass == total ? 0 : 1;
}
