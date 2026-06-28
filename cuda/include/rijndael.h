#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Rijndael-256 specific constants
#define RIJNDAEL256_BLOCK_SIZE 32
#define RIJNDAEL_MAX_ROUNDS 14

// Key Expansion Context or Key Structure
typedef struct {
    uint32_t roundKey[120]; // (14+1) * 8 = 120 words max
    int rounds;
} RijndaelKey;

/**
 * Setup the key for encryption and decryption.
 * @param key The input key bytes.
 * @param keyBits The size of the key in bits (128, 192, 256).
 * @param rk The structure to hold the expanded key.
 * @return 0 on success, -1 on invalid key size.
 */
int rijndaelSetupKey(const uint8_t *key, int keyBits, RijndaelKey *rk);

/**
 * Encrypt a single 256-bit block.
 * @param rk The expanded key structure.
 * @param pt The input plaintext (32 bytes).
 * @param ct The output ciphertext (32 bytes).
 */
void rijndaelEncrypt(const RijndaelKey *rk, const uint8_t *pt, uint8_t *ct);

/**
 * Decrypt a single 256-bit block.
 * @param rk The expanded key structure.
 * @param ct The input ciphertext (32 bytes).
 * @param pt The output plaintext (32 bytes).
 */
void rijndaelDecrypt(const RijndaelKey *rk, const uint8_t *ct, uint8_t *pt);

#ifdef __cplusplus
}
#endif

#endif // RIJNDAEL_H
