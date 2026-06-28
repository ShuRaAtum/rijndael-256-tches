/* See rijndael256_folded_arm.h. AddRoundKey-folded R256 on ARMv8 Crypto. */
#include "rijndael256_folded_arm.h"
#include <string.h>

#if defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES)
#include <arm_neon.h>
#define FOLD_HW 1
#else
#define FOLD_HW 0
#endif

/* Pre-shuffle byte indices over the 32-byte {L:0-15, R:16-31} concatenation.
 * BIT-IDENTICAL to _mask_for_L / _mask_for_R in platform/apple/rijndael256_arm.S
 * (and the ELF port). The state TBL and the key pre-shuffle MUST use the same
 * permutation, otherwise AddRoundKey lands on the wrong byte positions. */
static const uint8_t MASK_L[16] = { 0,17,22,23, 4, 5,26,27, 8, 9,14,31,12,13,18,19};
static const uint8_t MASK_R[16] = {16, 1, 6, 7,20,21,10,11,24,25,30,15,28,29, 2, 3};

int rijndael256_folded_available(void) { return FOLD_HW; }

void rijndael256_folded_setup(const Rijndael256Key *ctx, R256FoldedKey *fk)
{
    int Nr = ctx->rounds;                 /* 14 */
    fk->rounds = Nr;
    /* Kpre[k] = TBL(rk[k]) over the 32-byte round key, same masks as the state.
     * rk[k] occupies ctx->roundKeys[k*32 .. k*32+31] (rkL || rkR). */
    for (int k = 0; k < Nr; k++) {
        const uint8_t *rk = ctx->roundKeys + k * 32;
        uint8_t *kL = fk->kpre + k * 32;
        uint8_t *kR = fk->kpre + k * 32 + 16;
        for (int i = 0; i < 16; i++) {
            kL[i] = rk[MASK_L[i]];        /* index >=16 selects from rkR */
            kR[i] = rk[MASK_R[i]];
        }
    }
    memcpy(fk->rk_final, ctx->roundKeys + Nr * 32, 32);  /* natural-order rk[Nr] */
}

#if FOLD_HW
void rijndael256_encrypt_arm_folded(const R256FoldedKey *fk,
                                    const uint8_t *pt, uint8_t *ct)
{
    const int Nr = fk->rounds;
    const uint8x16_t mL = vld1q_u8(MASK_L);
    const uint8x16_t mR = vld1q_u8(MASK_R);

    uint8x16x2_t st;
    st.val[0] = vld1q_u8(pt);          /* L */
    st.val[1] = vld1q_u8(pt + 16);     /* R */

    /* rounds 0 .. Nr-2 : pre-shuffle, AESE(folded key), AESMC */
    for (int k = 0; k < Nr - 1; k++) {
        uint8x16_t tL = vqtbl2q_u8(st, mL);   /* TBL over {L,R} */
        uint8x16_t tR = vqtbl2q_u8(st, mR);
        uint8x16_t kL = vld1q_u8(fk->kpre + k * 32);
        uint8x16_t kR = vld1q_u8(fk->kpre + k * 32 + 16);
        /* AESE(t,k) = SubBytes(HW_SR(t ^ k)) ; k pre-shuffled => folded ARK */
        st.val[0] = vaesmcq_u8(vaeseq_u8(tL, kL));
        st.val[1] = vaesmcq_u8(vaeseq_u8(tR, kR));
    }

    /* final round Nr-1 : pre-shuffle, AESE(folded key), then natural final ARK */
    {
        uint8x16_t tL = vqtbl2q_u8(st, mL);
        uint8x16_t tR = vqtbl2q_u8(st, mR);
        uint8x16_t kL = vld1q_u8(fk->kpre + (Nr - 1) * 32);
        uint8x16_t kR = vld1q_u8(fk->kpre + (Nr - 1) * 32 + 16);
        uint8x16_t oL = vaeseq_u8(tL, kL);    /* no MixColumns on the last round */
        uint8x16_t oR = vaeseq_u8(tR, kR);
        oL = veorq_u8(oL, vld1q_u8(fk->rk_final));
        oR = veorq_u8(oR, vld1q_u8(fk->rk_final + 16));
        vst1q_u8(ct, oL);
        vst1q_u8(ct + 16, oR);
    }
}
/* Interleaved folded encryption, N a compile-time constant (always-inlined so
 * the per-block loops unroll and the state stays in NEON registers). */
__attribute__((always_inline))
static inline void folded_xN(const R256FoldedKey *fk,
                             const uint8_t *pt, uint8_t *ct, const int N)
{
    const int Nr = fk->rounds;
    const uint8x16_t mL = vld1q_u8(MASK_L);
    const uint8x16_t mR = vld1q_u8(MASK_R);
    uint8x16_t L[8], R[8];

    for (int b = 0; b < N; b++) {
        L[b] = vld1q_u8(pt + b * 32);
        R[b] = vld1q_u8(pt + b * 32 + 16);
    }
    for (int k = 0; k < Nr - 1; k++) {
        const uint8x16_t kL = vld1q_u8(fk->kpre + k * 32);
        const uint8x16_t kR = vld1q_u8(fk->kpre + k * 32 + 16);
        uint8x16_t tL[8], tR[8];
        for (int b = 0; b < N; b++) {
            uint8x16x2_t s; s.val[0] = L[b]; s.val[1] = R[b];
            tL[b] = vqtbl2q_u8(s, mL);
            tR[b] = vqtbl2q_u8(s, mR);
        }
        for (int b = 0; b < N; b++) {
            L[b] = vaesmcq_u8(vaeseq_u8(tL[b], kL));
            R[b] = vaesmcq_u8(vaeseq_u8(tR[b], kR));
        }
    }
    const uint8x16_t kL = vld1q_u8(fk->kpre + (Nr - 1) * 32);
    const uint8x16_t kR = vld1q_u8(fk->kpre + (Nr - 1) * 32 + 16);
    const uint8x16_t fL = vld1q_u8(fk->rk_final);
    const uint8x16_t fR = vld1q_u8(fk->rk_final + 16);
    for (int b = 0; b < N; b++) {
        uint8x16x2_t s; s.val[0] = L[b]; s.val[1] = R[b];
        uint8x16_t oL = veorq_u8(vaeseq_u8(vqtbl2q_u8(s, mL), kL), fL);
        uint8x16_t oR = veorq_u8(vaeseq_u8(vqtbl2q_u8(s, mR), kR), fR);
        vst1q_u8(ct + b * 32, oL);
        vst1q_u8(ct + b * 32 + 16, oR);
    }
}

void rijndael256_encrypt_arm_folded_x2(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct)
{ folded_xN(fk, pt, ct, 2); }
void rijndael256_encrypt_arm_folded_x4(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct)
{ folded_xN(fk, pt, ct, 4); }
void rijndael256_encrypt_arm_folded_x8(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct)
{ folded_xN(fk, pt, ct, 8); }
#else
void rijndael256_encrypt_arm_folded(const R256FoldedKey *fk,
                                    const uint8_t *pt, uint8_t *ct)
{ (void)fk; (void)pt; (void)ct; }
void rijndael256_encrypt_arm_folded_x2(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct)
{ (void)fk; (void)pt; (void)ct; }
void rijndael256_encrypt_arm_folded_x4(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct)
{ (void)fk; (void)pt; (void)ct; }
void rijndael256_encrypt_arm_folded_x8(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct)
{ (void)fk; (void)pt; (void)ct; }
#endif

int rijndael256_folded_selftest(void)
{
#if !FOLD_HW
    return 0;
#else
    const int keybits[3] = {128, 192, 256};
    for (int ki = 0; ki < 3; ki++) {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 1 + ki);
        Rijndael256Key ctx;
        if (rijndael256_setup_key(key, keybits[ki], &ctx) != 0) return 100 + ki;
        R256FoldedKey fk;
        rijndael256_folded_setup(&ctx, &fk);

        /* single-block KAT */
        uint8_t pt[32], a[32], b[32];
        for (int i = 0; i < 32; i++) pt[i] = (uint8_t)(i * 7 + 5);
        rijndael256_encrypt_ref(&ctx, pt, a);
        rijndael256_encrypt_arm_folded(&fk, pt, b);
        if (memcmp(a, b, 32) != 0) return 1 + ki;

        /* 1000-block sweep with varying data */
        for (int t = 0; t < 1000; t++) {
            for (int i = 0; i < 32; i++) pt[i] = (uint8_t)(t * 13 + i * 5 + ki + 1);
            rijndael256_encrypt_ref(&ctx, pt, a);
            rijndael256_encrypt_arm_folded(&fk, pt, b);
            if (memcmp(a, b, 32) != 0) return 10 + ki;
        }

        /* interleaved variants: each of the N blocks must match the reference */
        uint8_t in[8 * 32], refN[8 * 32], gotN[8 * 32];
        for (int i = 0; i < 8 * 32; i++) in[i] = (uint8_t)(i * 11 + ki * 7 + 3);
        for (int blk = 0; blk < 8; blk++)
            rijndael256_encrypt_ref(&ctx, in + blk * 32, refN + blk * 32);
        rijndael256_encrypt_arm_folded_x2(&fk, in, gotN);
        if (memcmp(gotN, refN, 2 * 32) != 0) return 20 + ki;
        rijndael256_encrypt_arm_folded_x4(&fk, in, gotN);
        if (memcmp(gotN, refN, 4 * 32) != 0) return 30 + ki;
        rijndael256_encrypt_arm_folded_x8(&fk, in, gotN);
        if (memcmp(gotN, refN, 8 * 32) != 0) return 40 + ki;
    }
    return 0;
#endif
}
