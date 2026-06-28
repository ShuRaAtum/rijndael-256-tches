#ifndef __RIJNDAEL_ARM_H__
#define __RIJNDAEL_ARM_H__

#include "rijndael_common.h"
#include "rijndael256.h"
#if defined(RIJNDAEL_ARM_FOLDED)
#include "rijndael256_folded_arm.h"
#endif

/*
 * ARM Crypto Extension implementation of Rijndael for MQOM.
 *
 * This adapter maps MQOM's Rijndael API to our optimized ARM assembly
 * implementation for Rijndael-256. AES-128 and AES-256 (128-bit block)
 * fall back to the reference implementation since the ARM crypto extension
 * instructions (AESE/AESMC) handle standard AES natively only for 128-bit
 * blocks, and our optimized code targets the 256-bit block variant.
 *
 * NOTE: For AES-128/AES-256 (128-bit block), we reuse the reference
 * implementation. The ARM AESE instruction could be used for those too,
 * but the primary optimization target here is Rijndael-256-256.
 */

/* The ARM context wraps our Rijndael256Key for 256-bit block,
 * and falls back to the reference context for 128-bit block ciphers. */
typedef struct
{
	rijndael_type rtype; /* Type of Rijndael */
	/* For Rijndael-256-256: our optimized ARM key context */
	Rijndael256Key r256_ctx;
#if defined(RIJNDAEL_ARM_FOLDED)
	/* AddRoundKey-folded pre-shuffled key schedule (Kpre). Built once per key
	 * in rijndael256_arm_setkey_enc, so its cost is counted per key. */
	R256FoldedKey r256_fk;
#endif
	/* For AES-128 / AES-256 (128-bit block): reference context fields */
	uint32_t Nr; /* Number of rounds */
	uint32_t Nk; /* Number of words in the key */
	uint32_t Nb; /* Number of words in the block */
	__attribute__((aligned(4))) uint8_t rk[480]; /* Round keys (for ref fallback) */
} rijndael_arm_ctx;


/* ==== Public API ==== */
int aes128_arm_setkey_enc(rijndael_arm_ctx *ctx, const uint8_t key[16]);
int aes256_arm_setkey_enc(rijndael_arm_ctx *ctx, const uint8_t key[32]);
int rijndael256_arm_setkey_enc(rijndael_arm_ctx *ctx, const uint8_t key[32]);
int aes128_arm_enc(const rijndael_arm_ctx *ctx, const uint8_t data_in[16], uint8_t data_out[16]);
int aes256_arm_enc(const rijndael_arm_ctx *ctx, const uint8_t data_in[16], uint8_t data_out[16]);
int rijndael256_arm_enc(const rijndael_arm_ctx *ctx, const uint8_t data_in[32], uint8_t data_out[32]);
/* x2 and x4 encryption APIs */
int aes128_arm_enc_x2(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2, const uint8_t plainText1[16], const uint8_t plainText2[16], uint8_t cipherText1[16], uint8_t cipherText2[16]);
int aes128_arm_enc_x4(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2, const rijndael_arm_ctx *ctx3, const rijndael_arm_ctx *ctx4,
                const uint8_t plainText1[16], const uint8_t plainText2[16], const uint8_t plainText3[16], const uint8_t plainText4[16],
                uint8_t cipherText1[16], uint8_t cipherText2[16], uint8_t cipherText3[16], uint8_t cipherText4[16]);
int aes256_arm_enc_x2(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2, const uint8_t plainText1[16], const uint8_t plainText2[16], uint8_t cipherText1[16], uint8_t cipherText2[16]);
int aes256_arm_enc_x4(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2, const rijndael_arm_ctx *ctx3, const rijndael_arm_ctx *ctx4,
                const uint8_t plainText1[16], const uint8_t plainText2[16], const uint8_t plainText3[16], const uint8_t plainText4[16],
                uint8_t cipherText1[16], uint8_t cipherText2[16], uint8_t cipherText3[16], uint8_t cipherText4[16]);
int rijndael256_arm_enc_x2(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2,
                        const uint8_t plainText1[32], const uint8_t plainText2[32],
                        uint8_t cipherText1[32], uint8_t cipherText2[32]);
int rijndael256_arm_enc_x4(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2, const rijndael_arm_ctx *ctx3, const rijndael_arm_ctx *ctx4,
                const uint8_t plainText1[32], const uint8_t plainText2[32], const uint8_t plainText3[32], const uint8_t plainText4[32],
                uint8_t cipherText1[32], uint8_t cipherText2[32], uint8_t cipherText3[32], uint8_t cipherText4[32]);
#endif /* __RIJNDAEL_ARM_H__ */
