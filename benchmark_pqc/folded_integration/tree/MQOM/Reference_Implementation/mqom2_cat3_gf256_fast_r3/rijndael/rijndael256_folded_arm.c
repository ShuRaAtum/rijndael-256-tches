/* See rijndael256_folded_arm.h. AddRoundKey-folded R256 on ARMv8 Crypto.
 *
 * PQC integration copy: identical to aarch64/rijndael256_folded_arm.c except the
 * self-test (which needs rijndael256_encrypt_ref) is compiled out so this object
 * links into the per-scheme ARM build without pulling the portable reference. */
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

/* Self-test compiled out for the PQC integration build: it depends on
 * rijndael256_encrypt_ref / rijndael256_setup_key from the portable reference,
 * which the per-scheme ARM builds do not link. Byte-identity vs the EOR path is
 * instead established end-to-end by each scheme's KAT / sign-verify round-trip. */
int rijndael256_folded_selftest(void) { return 0; }
