#if defined(RIJNDAEL_ARM_CRYPTO) || defined(RIJNDAEL_NEON)

/*
 * ARM Crypto Extension adapter for MQOM's Rijndael API.
 *
 * For Rijndael-256-256 (256-bit block, 256-bit key):
 *   Uses our optimized ARM assembly (rijndael256_encrypt_arm).
 *   Key schedule via rijndael256_setup_key.
 *
 * For AES-128 and AES-256 (128-bit block):
 *   Falls back to the constant-time reference implementation.
 *   This is because our ARM assembly only targets 256-bit blocks.
 *
 * IMPORTANT: The x2/x4 multi-key variants for Rijndael-256 use
 * individual rijndael256_encrypt_arm() calls because each call uses
 * a DIFFERENT key context (MQOM's pattern), so we cannot use
 * same-key parallel encryption (neon_4pt).
 */

#include "rijndael_arm.h"
#include <string.h>

#if defined(RIJNDAEL_NEON)
/* Multi-key 4-block parallel NEON encryption (defined in rijndael256_neon_4pt_mk.S) */
extern void rijndael256_encrypt_neon_4pt_mk(
	const Rijndael256Key *ctx1, const Rijndael256Key *ctx2,
	const Rijndael256Key *ctx3, const Rijndael256Key *ctx4,
	const uint8_t pt[128], uint8_t ct[128]);
#endif

/* ============================================================
 * Reference implementation for AES-128/AES-256 (128-bit block)
 * Copied from rijndael_ref.c to avoid double-definition issues.
 * ============================================================ */

static const uint8_t rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

/* Rijndael primitives for reference fallback */
#define RIJNDAEL_MODULUS 0x1B
static inline uint8_t gmul(uint8_t x, uint8_t y){
	uint8_t res;
	res = (-(y >> 7) & x);
	res = (-(y >> 6 & 1) & x) ^ (-(res >> 7) & RIJNDAEL_MODULUS) ^ (res << 1);
	res = (-(y >> 5 & 1) & x) ^ (-(res >> 7) & RIJNDAEL_MODULUS) ^ (res << 1);
	res = (-(y >> 4 & 1) & x) ^ (-(res >> 7) & RIJNDAEL_MODULUS) ^ (res << 1);
	res = (-(y >> 3 & 1) & x) ^ (-(res >> 7) & RIJNDAEL_MODULUS) ^ (res << 1);
	res = (-(y >> 2 & 1) & x) ^ (-(res >> 7) & RIJNDAEL_MODULUS) ^ (res << 1);
	res = (-(y >> 1 & 1) & x) ^ (-(res >> 7) & RIJNDAEL_MODULUS) ^ (res << 1);
	res = (-(y      & 1) & x) ^ (-(res >> 7) & RIJNDAEL_MODULUS) ^ (res << 1);
	return res;
}
static inline uint8_t gsquare(uint8_t x){
	return gmul(x, x);
}

#define SBOX_BIT_EXTRACT(s, a, b, c, d, e) (((s >> a) & 1) ^ ((s >> b) & 1) ^ ((s >> c) & 1) ^ ((s >> d) & 1) ^ ((s >> e) & 1))
static inline uint8_t sbox(uint8_t s)
{
	uint8_t out;
	uint8_t s2   = gsquare(s);
	uint8_t s3   = gmul(s, s2);
	uint8_t s5   = gmul(s3, s2);
	uint8_t s7   = gmul(s5, s2);
	uint8_t s14  = gsquare(s7);
	uint8_t s28  = gsquare(s14);
	uint8_t s56  = gsquare(s28);
	uint8_t s63  = gmul(s56, s7);
	uint8_t s126 = gsquare(s63);
	uint8_t s252 = gsquare(s126);
	uint8_t sinv = gmul(s252, s2);
	uint8_t out0 = SBOX_BIT_EXTRACT(sinv, 0, 4, 5, 6, 7);
	uint8_t out1 = SBOX_BIT_EXTRACT(sinv, 0, 1, 5, 6, 7);
	uint8_t out2 = SBOX_BIT_EXTRACT(sinv, 0, 1, 2, 6, 7);
	uint8_t out3 = SBOX_BIT_EXTRACT(sinv, 0, 1, 2, 3, 7);
	uint8_t out4 = SBOX_BIT_EXTRACT(sinv, 0, 1, 2, 3, 4);
	uint8_t out5 = SBOX_BIT_EXTRACT(sinv, 1, 2, 3, 4, 5);
	uint8_t out6 = SBOX_BIT_EXTRACT(sinv, 2, 3, 4, 5, 6);
	uint8_t out7 = SBOX_BIT_EXTRACT(sinv, 3, 4, 5, 6, 7);
	out = (out0 | (out1 << 1) | (out2 << 2) | (out3 << 3) | (out4 << 4) | (out5 << 5) | (out6 << 6) | (out7 << 7)) ^ 0x63;
	return out;
}

static inline void ref_sub_bytes_sr_128(uint8_t *state){
	uint8_t s[16];
	memcpy(s, state, 16);
	state[0]  = sbox(s[0]);
	state[1]  = sbox(s[5]);
	state[2]  = sbox(s[10]);
	state[3]  = sbox(s[15]);
	state[4]  = sbox(s[4]);
	state[5]  = sbox(s[9]);
	state[6]  = sbox(s[14]);
	state[7]  = sbox(s[3]);
	state[8]  = sbox(s[8]);
	state[9]  = sbox(s[13]);
	state[10] = sbox(s[2]);
	state[11] = sbox(s[7]);
	state[12] = sbox(s[12]);
	state[13] = sbox(s[1]);
	state[14] = sbox(s[6]);
	state[15] = sbox(s[11]);
}

#define xtime(x) ((uint8_t)(((x)<<1) ^ ((((x)>>7) & 1) * 0x1b)))
static inline uint8_t gmul_mc(uint8_t x, uint8_t y){
	return ((uint8_t)(((y & 1) * x) ^ (((y>>1) & 1) * xtime(x)) ^ (((y>>2) & 1) * xtime(xtime(x))) ^ (((y>>3) & 1) * xtime(xtime(xtime(x)))) ^ (((y>>4) & 1) * xtime(xtime(xtime(xtime(x))))))) & 0xff;
}

static inline void ref_mix_columns_128(uint8_t *state){
	uint8_t s[16];
	memcpy(s, state, 16);
	state[0]  = gmul_mc(s[0], 2) ^ gmul_mc(s[3], 1) ^ gmul_mc(s[2], 1) ^ gmul_mc(s[1], 3);
	state[1]  = gmul_mc(s[1], 2) ^ gmul_mc(s[0], 1) ^ gmul_mc(s[3], 1) ^ gmul_mc(s[2], 3);
	state[2]  = gmul_mc(s[2], 2) ^ gmul_mc(s[1], 1) ^ gmul_mc(s[0], 1) ^ gmul_mc(s[3], 3);
	state[3]  = gmul_mc(s[3], 2) ^ gmul_mc(s[2], 1) ^ gmul_mc(s[1], 1) ^ gmul_mc(s[0], 3);
	state[4]  = gmul_mc(s[4], 2) ^ gmul_mc(s[7], 1) ^ gmul_mc(s[6], 1) ^ gmul_mc(s[5], 3);
	state[5]  = gmul_mc(s[5], 2) ^ gmul_mc(s[4], 1) ^ gmul_mc(s[7], 1) ^ gmul_mc(s[6], 3);
	state[6]  = gmul_mc(s[6], 2) ^ gmul_mc(s[5], 1) ^ gmul_mc(s[4], 1) ^ gmul_mc(s[7], 3);
	state[7]  = gmul_mc(s[7], 2) ^ gmul_mc(s[6], 1) ^ gmul_mc(s[5], 1) ^ gmul_mc(s[4], 3);
	state[8]  = gmul_mc(s[8], 2) ^ gmul_mc(s[11], 1) ^ gmul_mc(s[10], 1) ^ gmul_mc(s[9], 3);
	state[9]  = gmul_mc(s[9], 2) ^ gmul_mc(s[8], 1) ^ gmul_mc(s[11], 1) ^ gmul_mc(s[10], 3);
	state[10] = gmul_mc(s[10], 2) ^ gmul_mc(s[9], 1) ^ gmul_mc(s[8], 1) ^ gmul_mc(s[11], 3);
	state[11] = gmul_mc(s[11], 2) ^ gmul_mc(s[10], 1) ^ gmul_mc(s[9], 1) ^ gmul_mc(s[8], 3);
	state[12] = gmul_mc(s[12], 2) ^ gmul_mc(s[15], 1) ^ gmul_mc(s[14], 1) ^ gmul_mc(s[13], 3);
	state[13] = gmul_mc(s[13], 2) ^ gmul_mc(s[12], 1) ^ gmul_mc(s[15], 1) ^ gmul_mc(s[14], 3);
	state[14] = gmul_mc(s[14], 2) ^ gmul_mc(s[13], 1) ^ gmul_mc(s[12], 1) ^ gmul_mc(s[15], 3);
	state[15] = gmul_mc(s[15], 2) ^ gmul_mc(s[14], 1) ^ gmul_mc(s[13], 1) ^ gmul_mc(s[12], 3);
}

static inline void ref_add_rkey_128(uint8_t *state, const uint8_t *rkey){
	for(uint32_t i = 0; i < 16; i++){
		state[i] ^= rkey[i];
	}
}

static inline void ref_sched(uint8_t *in, uint8_t n){
	uint8_t t = in[0];
	in[0] = sbox(in[1]) ^ rcon[n];
	in[1] = sbox(in[2]);
	in[2] = sbox(in[3]);
	in[3] = sbox(t);
}

/* Reference key schedule for 128-bit block ciphers */
static int ref_setkey_enc_128(rijndael_arm_ctx *ctx, const uint8_t *key, rijndael_type rtype)
{
	uint32_t i, offset;

	if((ctx == NULL) || (key == NULL)){
		return -1;
	}
	switch(rtype){
		case AES128:
			ctx->Nr = 10; ctx->Nk = 4; ctx->Nb = 4;
			break;
		case AES256:
			ctx->Nr = 14; ctx->Nk = 8; ctx->Nb = 4;
			break;
		default:
			return -1;
	}
	ctx->rtype = rtype;

	memcpy(&ctx->rk, key, 4 * ctx->Nk);
	for(i = ctx->Nk; i < ctx->Nb * (ctx->Nr + 1); i++){
		uint8_t t[4];
		offset = 4 * (i - 1);
		memcpy(t, &ctx->rk[offset], 4);
		if(i % ctx->Nk == 0){
			ref_sched(t, i / ctx->Nk);
		}
		else if(i % ctx->Nk == 4){
			if(ctx->Nk > 6){
				t[0] = sbox(t[0]); t[1] = sbox(t[1]);
				t[2] = sbox(t[2]); t[3] = sbox(t[3]);
			}
		}
		offset += 4;
		ctx->rk[offset]     = ctx->rk[offset - (4 * ctx->Nk)]     ^ t[0];
		ctx->rk[offset + 1] = ctx->rk[offset - (4 * ctx->Nk) + 1] ^ t[1];
		ctx->rk[offset + 2] = ctx->rk[offset - (4 * ctx->Nk) + 2] ^ t[2];
		ctx->rk[offset + 3] = ctx->rk[offset - (4 * ctx->Nk) + 3] ^ t[3];
	}

	return 0;
}

/* Reference encryption for 128-bit block */
static int ref_enc_128(const rijndael_arm_ctx *ctx, const uint8_t *data_in, uint8_t *data_out)
{
	uint32_t r;
	uint8_t state[16];

	if((ctx == NULL) || (data_in == NULL) || (data_out == NULL)){
		return -1;
	}
	if((4 * ctx->Nb * (ctx->Nr + 1)) > sizeof(ctx->rk)){
		return -1;
	}
	memcpy(state, data_in, 16);

	ref_add_rkey_128(state, &ctx->rk[0]);

	for(r = 1; r < ctx->Nr; r++){
		ref_sub_bytes_sr_128(state);
		ref_mix_columns_128(state);
		ref_add_rkey_128(state, &ctx->rk[16 * r]);
	}
	ref_sub_bytes_sr_128(state);
	ref_add_rkey_128(state, &ctx->rk[16 * r]);

	memcpy(data_out, state, 16);
	memset(state, 0, sizeof(state));

	return 0;
}

/* ============================================================
 * Public API implementation
 * ============================================================ */

/* === Key schedule === */

int aes128_arm_setkey_enc(rijndael_arm_ctx *ctx, const uint8_t key[16])
{
	return ref_setkey_enc_128(ctx, key, AES128);
}

int aes256_arm_setkey_enc(rijndael_arm_ctx *ctx, const uint8_t key[32])
{
	return ref_setkey_enc_128(ctx, key, AES256);
}

int rijndael256_arm_setkey_enc(rijndael_arm_ctx *ctx, const uint8_t key[32])
{
	ctx->rtype = RIJNDAEL_256_256;
	/* Use our optimized key schedule for Rijndael-256-256 */
	int r = rijndael256_setup_key(key, 256, &ctx->r256_ctx);
#if defined(RIJNDAEL_ARM_FOLDED)
	/* Per-key pre-shuffle: Kpre = TBL(rk). Counted inside sign/verify timing
	 * because setkey runs per GGM node, not hoisted out of the loop. */
	rijndael256_folded_setup(&ctx->r256_ctx, &ctx->r256_fk);
#endif
	return r;
}

/* === Single encryption === */

int aes128_arm_enc(const rijndael_arm_ctx *ctx, const uint8_t data_in[16], uint8_t data_out[16])
{
	if(ctx->rtype != AES128){
		return -1;
	}
	return ref_enc_128(ctx, data_in, data_out);
}

int aes256_arm_enc(const rijndael_arm_ctx *ctx, const uint8_t data_in[16], uint8_t data_out[16])
{
	if(ctx->rtype != AES256){
		return -1;
	}
	return ref_enc_128(ctx, data_in, data_out);
}

int rijndael256_arm_enc(const rijndael_arm_ctx *ctx, const uint8_t data_in[32], uint8_t data_out[32])
{
	if(ctx->rtype != RIJNDAEL_256_256){
		return -1;
	}
	/* Use our optimized assembly for Rijndael-256 */
#if defined(RIJNDAEL_ARM_FOLDED)
	rijndael256_encrypt_arm_folded(&ctx->r256_fk, data_in, data_out);
#elif defined(RIJNDAEL_NEON)
	rijndael256_encrypt_neon(&ctx->r256_ctx, data_in, data_out);
#else
	rijndael256_encrypt_arm(&ctx->r256_ctx, data_in, data_out);
#endif
	return 0;
}

/* === x2 encryption (two different keys) === */

int aes128_arm_enc_x2(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2,
                      const uint8_t plainText1[16], const uint8_t plainText2[16],
                      uint8_t cipherText1[16], uint8_t cipherText2[16])
{
	int ret;
	ret  = aes128_arm_enc(ctx1, plainText1, cipherText1);
	ret |= aes128_arm_enc(ctx2, plainText2, cipherText2);
	return ret;
}

int aes256_arm_enc_x2(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2,
                      const uint8_t plainText1[16], const uint8_t plainText2[16],
                      uint8_t cipherText1[16], uint8_t cipherText2[16])
{
	int ret;
	ret  = aes256_arm_enc(ctx1, plainText1, cipherText1);
	ret |= aes256_arm_enc(ctx2, plainText2, cipherText2);
	return ret;
}

int rijndael256_arm_enc_x2(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2,
                           const uint8_t plainText1[32], const uint8_t plainText2[32],
                           uint8_t cipherText1[32], uint8_t cipherText2[32])
{
	int ret;
	ret  = rijndael256_arm_enc(ctx1, plainText1, cipherText1);
	ret |= rijndael256_arm_enc(ctx2, plainText2, cipherText2);
	return ret;
}

/* === x4 encryption (four different keys) === */

int aes128_arm_enc_x4(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2,
                      const rijndael_arm_ctx *ctx3, const rijndael_arm_ctx *ctx4,
                      const uint8_t plainText1[16], const uint8_t plainText2[16],
                      const uint8_t plainText3[16], const uint8_t plainText4[16],
                      uint8_t cipherText1[16], uint8_t cipherText2[16],
                      uint8_t cipherText3[16], uint8_t cipherText4[16])
{
	int ret;
	ret  = aes128_arm_enc(ctx1, plainText1, cipherText1);
	ret |= aes128_arm_enc(ctx2, plainText2, cipherText2);
	ret |= aes128_arm_enc(ctx3, plainText3, cipherText3);
	ret |= aes128_arm_enc(ctx4, plainText4, cipherText4);
	return ret;
}

int aes256_arm_enc_x4(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2,
                      const rijndael_arm_ctx *ctx3, const rijndael_arm_ctx *ctx4,
                      const uint8_t plainText1[16], const uint8_t plainText2[16],
                      const uint8_t plainText3[16], const uint8_t plainText4[16],
                      uint8_t cipherText1[16], uint8_t cipherText2[16],
                      uint8_t cipherText3[16], uint8_t cipherText4[16])
{
	int ret;
	ret  = aes256_arm_enc(ctx1, plainText1, cipherText1);
	ret |= aes256_arm_enc(ctx2, plainText2, cipherText2);
	ret |= aes256_arm_enc(ctx3, plainText3, cipherText3);
	ret |= aes256_arm_enc(ctx4, plainText4, cipherText4);
	return ret;
}

int rijndael256_arm_enc_x4(const rijndael_arm_ctx *ctx1, const rijndael_arm_ctx *ctx2,
                           const rijndael_arm_ctx *ctx3, const rijndael_arm_ctx *ctx4,
                           const uint8_t plainText1[32], const uint8_t plainText2[32],
                           const uint8_t plainText3[32], const uint8_t plainText4[32],
                           uint8_t cipherText1[32], uint8_t cipherText2[32],
                           uint8_t cipherText3[32], uint8_t cipherText4[32])
{
#if defined(RIJNDAEL_NEON)
	/* All Rijndael-256 x4 calls use multi-key parallel NEON */
	if (ctx1->rtype == RIJNDAEL_256_256 && ctx2->rtype == RIJNDAEL_256_256 &&
	    ctx3->rtype == RIJNDAEL_256_256 && ctx4->rtype == RIJNDAEL_256_256) {
		uint8_t pt_buf[128], ct_buf[128];
		memcpy(pt_buf,      plainText1, 32);
		memcpy(pt_buf + 32, plainText2, 32);
		memcpy(pt_buf + 64, plainText3, 32);
		memcpy(pt_buf + 96, plainText4, 32);
		rijndael256_encrypt_neon_4pt_mk(
			&ctx1->r256_ctx, &ctx2->r256_ctx,
			&ctx3->r256_ctx, &ctx4->r256_ctx,
			pt_buf, ct_buf);
		memcpy(cipherText1, ct_buf,      32);
		memcpy(cipherText2, ct_buf + 32, 32);
		memcpy(cipherText3, ct_buf + 64, 32);
		memcpy(cipherText4, ct_buf + 96, 32);
		return 0;
	}
#endif
	{
		int ret;
		ret  = rijndael256_arm_enc(ctx1, plainText1, cipherText1);
		ret |= rijndael256_arm_enc(ctx2, plainText2, cipherText2);
		ret |= rijndael256_arm_enc(ctx3, plainText3, cipherText3);
		ret |= rijndael256_arm_enc(ctx4, plainText4, cipherText4);
		return ret;
	}
}

#else /* !RIJNDAEL_ARM_CRYPTO && !RIJNDAEL_NEON */
/*
 * Dummy definition to avoid the empty translation unit ISO C warning
 */
typedef int dummy;
#endif
