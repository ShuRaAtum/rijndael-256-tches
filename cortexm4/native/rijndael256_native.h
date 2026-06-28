/*
 * Rijndael-256 Native C Implementation Header
 * Block Size: 256 bits (Nb = 8), Nr = 14 for all key sizes
 */

#ifndef RIJNDAEL256_NATIVE_H
#define RIJNDAEL256_NATIVE_H

#include <stdint.h>

#define R256_BLOCK_SIZE 32
#define R256_NB         8
#define R256_MAX_NR     14

typedef struct {
    uint32_t roundKey[120]; /* (14+1) * 8 = 120 words max */
    int rounds;
} R256NativeKey;

int  r256_native_setup_key(const uint8_t *key, int keyBits, R256NativeKey *rk);
void r256_native_encrypt(const R256NativeKey *rk, const uint8_t *pt, uint8_t *ct);
void r256_native_decrypt(const R256NativeKey *rk, const uint8_t *ct, uint8_t *pt);

#endif /* RIJNDAEL256_NATIVE_H */
