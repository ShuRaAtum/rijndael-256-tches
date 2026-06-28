/*
 * Rijndael-256 T-table ASM Implementation Header
 * Single Te0 table with ROR trick for Cortex-M4
 *
 * WARNING: NOT constant-time. For performance comparison only.
 */

#ifndef RIJNDAEL256_TTABLE_ASM_H
#define RIJNDAEL256_TTABLE_ASM_H

#include <stdint.h>

typedef struct {
    uint32_t roundKey[120]; /* (14+1) * 8 = 120 words, big-endian */
    int rounds;
} R256TtableAsmKey;

int  r256_ttable_asm_setup_key(const uint8_t *key, int keyBits, R256TtableAsmKey *rk);

/* ASM encrypt (from rijndael256_encrypt.s) */
void rijndael256_encrypt(const uint32_t *roundKey, const uint8_t *pt, uint8_t *ct);

/* C wrapper */
static inline void r256_ttable_asm_encrypt(const R256TtableAsmKey *rk,
                                           const uint8_t *pt, uint8_t *ct)
{
    rijndael256_encrypt(rk->roundKey, pt, ct);
}

#endif
