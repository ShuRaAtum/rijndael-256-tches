/* Per-scheme byte-identity: each scheme's OWN folded encrypt vs its OWN EOR ARM
 * assembly, over random (key, block) pairs. Linked against that scheme's
 * rijndael256_arm.S (EOR), rijndael256_folded_arm.c, and key schedule.
 * Include only the folded header; it pulls the scheme's core Rijndael header. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "rijndael256_folded_arm.h"

static uint32_t rng = 0xC0FFEEu;
static uint8_t nb(void){ rng = rng*1103515245u + 12345u; return (uint8_t)(rng>>16); }

int main(void){
    int fails = 0, total = 0;
    for (int t = 0; t < 50000; t++) {
        uint8_t key[32], pt[32], a[32], b[32];
        for (int i=0;i<32;i++){ key[i]=nb(); pt[i]=nb(); }
        Rijndael256Key ctx;
        if (rijndael256_setup_key(key, 256, &ctx) != 0) { printf("setup fail\n"); return 2; }
        R256FoldedKey fk; rijndael256_folded_setup(&ctx, &fk);
        rijndael256_encrypt_arm(&ctx, pt, a);         /* EOR path */
        rijndael256_encrypt_arm_folded(&fk, pt, b);   /* folded path */
        total++;
        if (memcmp(a, b, 32) != 0) { fails++; if (fails<=2){ printf("MISMATCH t=%d\n", t);} }
    }
    printf("%d pairs: %s (fails=%d)\n", total,
           fails==0 ? "folded == EOR byte-identical" : "MISMATCH", fails);
    return fails != 0;
}
