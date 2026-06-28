/*
 * Rijndael-256 encryption on x86-64 using AES-NI + the DG22-style
 * blend/pshufb pre-shuffle.
 *
 * Block: 256 bits = two 128-bit halves  L = columns 0-3, R = columns 4-7.
 * R256 ShiftRows offsets (0,1,3,4) differ from the hardware-wired (0,1,2,3),
 * and bytes cross the L/R (128-bit lane) boundary. Since PSHUFB is lane-local,
 * we first gather the bytes for each output half across L/R with PBLENDVB,
 * then permute within the lane with PSHUFB, then run AESENC.
 *
 * AESENC = ShiftRows -> SubBytes -> MixColumns -> AddRoundKey(end). Because the
 * pre-shuffle is undone by AESENC's internal ShiftRows, after MixColumns the
 * state is back in natural column order, so the natural-order round key is XORed
 * directly by AESENC: no separate AddRoundKey and no key pre-shuffle is needed
 * (contrast the AArch64 path, where AESE's ARK precedes SubBytes and forces a
 *  separate post-AESMC EOR).
 *
 * One round per half therefore costs:  PBLENDVB + PSHUFB + AESENC  (3 insns).
 *
 * The pre-shuffle masks are derived from the same source mapping used by the
 * AArch64 TBL pre-shuffle (mask_for_L / mask_for_R): both correct the identical
 * hardware ShiftRows(0,1,2,3) applied after the pre-shuffle, so the byte
 * mapping transfers unchanged. Correctness is checked by KAT against the
 * portable reference (see test/).
 */
#include "rijndael256.h"
#include <wmmintrin.h>   /* AES-NI */
#include <tmmintrin.h>   /* SSSE3 pshufb */
#include <smmintrin.h>   /* SSE4.1 pblendvb */
#include <string.h>

/* Source byte map for the new L / R halves over the 32-byte {L:0-15, R:16-31}
 * concatenation (identical to the AArch64 TBL masks). Values >=16 come from R. */
static const unsigned char SRC_L[16] = { 0,17,22,23, 4, 5,26,27, 8, 9,14,31,12,13,18,19};
static const unsigned char SRC_R[16] = {16, 1, 6, 7,20,21,10,11,24,25,30,15,28,29, 2, 3};

/* Inverse (decryption) source maps: InvShiftRows offsets (0,7,5,4) mod 8. */
static const unsigned char ISRC_L[16] = { 0, 1,30,31, 4, 5, 2,19, 8, 9,22,23,12,29,26,27};
static const unsigned char ISRC_R[16] = {16,17,14,15,20,21,18, 3,24,25, 6, 7,28,13,10,11};

typedef struct {
    __m128i sel_L, perm_L, sel_R, perm_R;   /* encryption pre-shuffle */
} preshuffle_t;

static preshuffle_t g_enc, g_dec;
static int g_init = 0;

/* Build (blend-selector, pshufb-permutation) for a half from its source map.
 * new[i] = src(map[i]); with j = map[i]&15:
 *   perm[i] = j,  sel[j] = 0x80 iff the source byte lives in R (map[i] >= 16).
 * map is a permutation of residues mod 16, so each j is assigned exactly once. */
static void build_half(const unsigned char map[16], __m128i *sel, __m128i *perm)
{
    unsigned char s[16] = {0}, p[16];
    for (int i = 0; i < 16; i++) {
        int j = map[i] & 15;
        p[i] = (unsigned char)j;
        s[j] = (map[i] >= 16) ? 0x80 : 0x00;
    }
    memcpy(perm, p, 16);
    memcpy(sel,  s, 16);
}

void rijndael256_aesni_init(void)
{
    build_half(SRC_L,  &g_enc.sel_L, &g_enc.perm_L);
    build_half(SRC_R,  &g_enc.sel_R, &g_enc.perm_R);
    build_half(ISRC_L, &g_dec.sel_L, &g_dec.perm_L);
    build_half(ISRC_R, &g_dec.sel_R, &g_dec.perm_R);
    g_init = 1;
}

/* L,R passed/returned by pointer; one pre-shuffle producing the two new halves */
static inline void preshuffle(const preshuffle_t *m,
                              __m128i L, __m128i R,
                              __m128i *outL, __m128i *outR)
{
    /* gather across the lane boundary, then permute within the lane */
    __m128i bl = _mm_blendv_epi8(L, R, m->sel_L);   /* sel high bit -> take R */
    __m128i br = _mm_blendv_epi8(L, R, m->sel_R);
    *outL = _mm_shuffle_epi8(bl, m->perm_L);
    *outR = _mm_shuffle_epi8(br, m->perm_R);
}

void rijndael256_encrypt_aesni(const Rijndael256Key *ctx,
                               const uint8_t *pt, uint8_t *ct)
{
    if (!g_init) rijndael256_aesni_init();
    const uint8_t *rk = ctx->roundKeys;
    const int Nr = ctx->rounds;              /* 14 */

    __m128i L = _mm_loadu_si128((const __m128i *)(pt));
    __m128i R = _mm_loadu_si128((const __m128i *)(pt + 16));

    /* initial AddRoundKey (round 0) */
    L = _mm_xor_si128(L, _mm_loadu_si128((const __m128i *)(rk)));
    R = _mm_xor_si128(R, _mm_loadu_si128((const __m128i *)(rk + 16)));

    /* rounds 1 .. Nr-1 */
    for (int r = 1; r < Nr; r++) {
        __m128i pL, pR;
        preshuffle(&g_enc, L, R, &pL, &pR);
        L = _mm_aesenc_si128(pL, _mm_loadu_si128((const __m128i *)(rk + 32 * r)));
        R = _mm_aesenc_si128(pR, _mm_loadu_si128((const __m128i *)(rk + 32 * r + 16)));
    }

    /* final round Nr (no MixColumns) */
    {
        __m128i pL, pR;
        preshuffle(&g_enc, L, R, &pL, &pR);
        L = _mm_aesenclast_si128(pL, _mm_loadu_si128((const __m128i *)(rk + 32 * Nr)));
        R = _mm_aesenclast_si128(pR, _mm_loadu_si128((const __m128i *)(rk + 32 * Nr + 16)));
    }

    _mm_storeu_si128((__m128i *)(ct), L);
    _mm_storeu_si128((__m128i *)(ct + 16), R);
}

/* 4-block interleaved encryption (same key) for peak throughput. AES-NI on
 * x86 is latency-bound per block (~4-cycle AESENC); interleaving independent
 * blocks fills the pipeline. Mirrors the AArch64 4-way harness for a
 * like-for-like AES->R256 comparison. */
void rijndael256_encrypt_aesni_x4(const Rijndael256Key *ctx,
                                  const uint8_t *pt, uint8_t *ct)
{
    if (!g_init) rijndael256_aesni_init();
    const uint8_t *rk = ctx->roundKeys;
    const int Nr = ctx->rounds;

    __m128i L0 = _mm_loadu_si128((const __m128i *)(pt +   0));
    __m128i R0 = _mm_loadu_si128((const __m128i *)(pt +  16));
    __m128i L1 = _mm_loadu_si128((const __m128i *)(pt +  32));
    __m128i R1 = _mm_loadu_si128((const __m128i *)(pt +  48));
    __m128i L2 = _mm_loadu_si128((const __m128i *)(pt +  64));
    __m128i R2 = _mm_loadu_si128((const __m128i *)(pt +  80));
    __m128i L3 = _mm_loadu_si128((const __m128i *)(pt +  96));
    __m128i R3 = _mm_loadu_si128((const __m128i *)(pt + 112));

    __m128i kL = _mm_loadu_si128((const __m128i *)(rk));
    __m128i kR = _mm_loadu_si128((const __m128i *)(rk + 16));
    L0 = _mm_xor_si128(L0, kL); R0 = _mm_xor_si128(R0, kR);
    L1 = _mm_xor_si128(L1, kL); R1 = _mm_xor_si128(R1, kR);
    L2 = _mm_xor_si128(L2, kL); R2 = _mm_xor_si128(R2, kR);
    L3 = _mm_xor_si128(L3, kL); R3 = _mm_xor_si128(R3, kR);

    for (int r = 1; r < Nr; r++) {
        kL = _mm_loadu_si128((const __m128i *)(rk + 32 * r));
        kR = _mm_loadu_si128((const __m128i *)(rk + 32 * r + 16));
        __m128i a, b;
        preshuffle(&g_enc, L0, R0, &a, &b); L0 = _mm_aesenc_si128(a, kL); R0 = _mm_aesenc_si128(b, kR);
        preshuffle(&g_enc, L1, R1, &a, &b); L1 = _mm_aesenc_si128(a, kL); R1 = _mm_aesenc_si128(b, kR);
        preshuffle(&g_enc, L2, R2, &a, &b); L2 = _mm_aesenc_si128(a, kL); R2 = _mm_aesenc_si128(b, kR);
        preshuffle(&g_enc, L3, R3, &a, &b); L3 = _mm_aesenc_si128(a, kL); R3 = _mm_aesenc_si128(b, kR);
    }
    kL = _mm_loadu_si128((const __m128i *)(rk + 32 * Nr));
    kR = _mm_loadu_si128((const __m128i *)(rk + 32 * Nr + 16));
    {
        __m128i a, b;
        preshuffle(&g_enc, L0, R0, &a, &b); L0 = _mm_aesenclast_si128(a, kL); R0 = _mm_aesenclast_si128(b, kR);
        preshuffle(&g_enc, L1, R1, &a, &b); L1 = _mm_aesenclast_si128(a, kL); R1 = _mm_aesenclast_si128(b, kR);
        preshuffle(&g_enc, L2, R2, &a, &b); L2 = _mm_aesenclast_si128(a, kL); R2 = _mm_aesenclast_si128(b, kR);
        preshuffle(&g_enc, L3, R3, &a, &b); L3 = _mm_aesenclast_si128(a, kL); R3 = _mm_aesenclast_si128(b, kR);
    }
    _mm_storeu_si128((__m128i *)(ct +   0), L0); _mm_storeu_si128((__m128i *)(ct +  16), R0);
    _mm_storeu_si128((__m128i *)(ct +  32), L1); _mm_storeu_si128((__m128i *)(ct +  48), R1);
    _mm_storeu_si128((__m128i *)(ct +  64), L2); _mm_storeu_si128((__m128i *)(ct +  80), R2);
    _mm_storeu_si128((__m128i *)(ct +  96), L3); _mm_storeu_si128((__m128i *)(ct + 112), R3);
}
