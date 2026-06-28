/*
 * Rijndael-256 on x86-64 using *vector* AES-NI (VAES, 512-bit).
 *
 * Where rijndael256_aesni.c issues scalar 128-bit _mm_aesenc_si128 per half,
 * this path packs FOUR 128-bit lanes into one ZMM and runs them with a single
 * _mm512_aesenc_epi128.  A 256-bit R256 block is two 128-bit halves
 * L = columns 0-3, R = columns 4-7, so one ZMM holds two whole blocks:
 *
 *     ZMM = { L0 , R0 , L1 , R1 }      (lane 0..3, 16 bytes each)
 *
 * R256 ShiftRows offsets (0,1,3,4) differ from the hardware-wired (0,1,2,3)
 * and bytes cross the L/R (128-bit lane) boundary.  In the scalar path that
 * needs PBLENDVB (gather across L<->R) + PSHUFB (permute within a lane) per
 * half.  At 512-bit, AVX-512 VBMI's VPERMB (_mm512_permutexvar_epi8) is a full
 * arbitrary 64-byte gather across ALL four lanes, so the entire pre-shuffle for
 * BOTH blocks is a single instruction:
 *
 *     one round / two blocks  =  VPERMB + VAESENC      (2 insns, 8x128 AES work)
 *
 * The 64-byte permute index is derived directly from the same verified source
 * maps (SRC_L / SRC_R = the AArch64 TBL mapping): output byte i of a half is
 * source byte map[i] over that block's own {L:0-15, R:16-31} concatenation,
 * which is exactly what blendv+pshufb computes, so VPERMB reproduces it.
 *
 * As in the scalar path, AESENC's internal ShiftRows undoes the pre-shuffle, so
 * after MixColumns the state is back in natural column order and the
 * natural-order round key is XORed by AESENC directly: no key pre-shuffle, no
 * separate AddRoundKey.  Round keys are broadcast as { kL, kR, kL, kR } with a
 * single VBROADCASTI64X4 of the 32-byte {kL,kR} pair.
 *
 * Deep multi-block interleave (8 ZMM = 16 independent blocks) keeps enough
 * independent dependency chains in flight to hide VAESENC latency, the way
 * CTR-mode / independent-block throughput code does.
 *
 * Correctness: bit-identical to the portable reference, checked by KAT (test/).
 */
#include "rijndael256.h"
#include <immintrin.h>
#include <string.h>

/* Same source byte maps as rijndael256_aesni.c (== AArch64 TBL masks).
 * Values 0-15 come from the block's L half, 16-31 from its R half. */
static const unsigned char SRC_L[16] = { 0,17,22,23, 4, 5,26,27, 8, 9,14,31,12,13,18,19};
static const unsigned char SRC_R[16] = {16, 1, 6, 7,20,21,10,11,24,25,30,15,28,29, 2, 3};

static __m512i g_perm;     /* 64-byte VPERMB index for a { L0,R0,L1,R1 } ZMM */
static int     g_init = 0;

void rijndael256_vaes512_init(void)
{
    unsigned char idx[64];
    for (int i = 0; i < 16; i++) {
        /* block 0 occupies lanes 0,1 (bytes 0..31); block 1 lanes 2,3 (32..63).
         * SRC_* already index the per-block {L:0-15,R:16-31} concat, so block 1
         * just adds a +32 lane-pair offset. */
        idx[ 0 + i] = SRC_L[i];          /* out L0 */
        idx[16 + i] = SRC_R[i];          /* out R0 */
        idx[32 + i] = (unsigned char)(SRC_L[i] + 32);  /* out L1 */
        idx[48 + i] = (unsigned char)(SRC_R[i] + 32);  /* out R1 */
    }
    g_perm = _mm512_loadu_si512((const void *)idx);
    g_init = 1;
}

/* Broadcast the natural-order round key for round r as {kL,kR,kL,kR}. */
static inline __m512i rk512(const uint8_t *rk, int r)
{
    return _mm512_broadcast_i64x4(_mm256_loadu_si256((const __m256i *)(rk + 32 * r)));
}

/*
 * Encrypt 16 independent R256 blocks (512 bytes) with VAES-512.
 * NZ ZMM registers, each carrying two blocks => 2*NZ blocks per call.
 */
#define NZ 8                       /* 8 ZMM * 2 blocks = 16 blocks / call */
#define VAES512_BLOCKS (2 * NZ)

void rijndael256_encrypt_vaes512_x16(const Rijndael256Key *ctx,
                                     const uint8_t *pt, uint8_t *ct)
{
    if (!g_init) rijndael256_vaes512_init();
    const uint8_t *rk = ctx->roundKeys;
    const int Nr = ctx->rounds;          /* 14 */

    __m512i s[NZ];
    for (int z = 0; z < NZ; z++)
        s[z] = _mm512_loadu_si512((const void *)(pt + 64 * z));

    /* round 0: initial AddRoundKey */
    __m512i k = rk512(rk, 0);
    for (int z = 0; z < NZ; z++)
        s[z] = _mm512_xor_si512(s[z], k);

    /* rounds 1 .. Nr-1 : pre-shuffle (VPERMB) then VAESENC */
    for (int r = 1; r < Nr; r++) {
        k = rk512(rk, r);
        for (int z = 0; z < NZ; z++) {
            s[z] = _mm512_permutexvar_epi8(g_perm, s[z]);
            s[z] = _mm512_aesenc_epi128(s[z], k);
        }
    }

    /* final round Nr : no MixColumns */
    k = rk512(rk, Nr);
    for (int z = 0; z < NZ; z++) {
        s[z] = _mm512_permutexvar_epi8(g_perm, s[z]);
        s[z] = _mm512_aesenclast_epi128(s[z], k);
    }

    for (int z = 0; z < NZ; z++)
        _mm512_storeu_si512((void *)(ct + 64 * z), s[z]);
}

/* Single-block convenience wrapper (pads to one ZMM); used by KAT for the
 * key-size point checks.  Not on the throughput path. */
void rijndael256_encrypt_vaes512(const Rijndael256Key *ctx,
                                 const uint8_t *pt, uint8_t *ct)
{
    if (!g_init) rijndael256_vaes512_init();
    const uint8_t *rk = ctx->roundKeys;
    const int Nr = ctx->rounds;

    /* one ZMM = two blocks; duplicate the single block into both halves */
    __m512i s = _mm512_inserti64x4(
        _mm512_castsi256_si512(_mm256_loadu_si256((const __m256i *)pt)),
        _mm256_loadu_si256((const __m256i *)pt), 1);

    s = _mm512_xor_si512(s, rk512(rk, 0));
    for (int r = 1; r < Nr; r++) {
        s = _mm512_permutexvar_epi8(g_perm, s);
        s = _mm512_aesenc_epi128(s, rk512(rk, r));
    }
    s = _mm512_permutexvar_epi8(g_perm, s);
    s = _mm512_aesenclast_epi128(s, rk512(rk, Nr));

    _mm256_storeu_si256((__m256i *)ct, _mm512_castsi512_si256(s));
}
