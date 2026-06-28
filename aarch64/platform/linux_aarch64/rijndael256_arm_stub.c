/*
 * Rijndael-256 ARM Crypto Extension Stub
 *
 * This file provides stub implementations for platforms without
 * ARM Cryptographic Extension support (e.g., Raspberry Pi 4).
 *
 * The rijndael256_has_arm_crypto() function returns 0, indicating
 * that hardware acceleration is not available. The encrypt/decrypt
 * functions are provided to satisfy the linker but should never be
 * called (the runtime check prevents their use).
 */

#include "rijndael256.h"
#include <stdio.h>

/*
 * Check if ARM Crypto Extension is available.
 * Returns 0 on platforms without hardware AES support.
 */
int rijndael256_has_arm_crypto(void) {
    return 0;
}

/*
 * Stub encryption function.
 * Should never be called - rijndael256_has_arm_crypto() returns 0.
 */
void rijndael256_encrypt_arm(const Rijndael256Key *ctx,
                              const uint8_t *pt,
                              uint8_t *ct) {
    (void)ctx;
    (void)pt;
    (void)ct;
    fprintf(stderr, "ERROR: rijndael256_encrypt_arm called but ARM Crypto Extension is not available\n");
}

/*
 * Stub decryption function.
 * Should never be called - rijndael256_has_arm_crypto() returns 0.
 */
void rijndael256_decrypt_arm(const Rijndael256Key *ctx,
                              const uint8_t *ct,
                              uint8_t *pt) {
    (void)ctx;
    (void)ct;
    (void)pt;
    fprintf(stderr, "ERROR: rijndael256_decrypt_arm called but ARM Crypto Extension is not available\n");
}
