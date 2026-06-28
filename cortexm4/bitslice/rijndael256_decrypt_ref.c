/*
 * Rijndael-256 Bitsliced Decrypt — C Reference
 *
 * Equivalent Inverse Cipher using bitplane representation.
 *
 * Inverse S-box: InvAffine → ForwardSBox → InvAffine (no constants,
 * all absorbed into key schedule as planes 1,2,6,7 flip).
 *
 * InvMixColumns = M-transform ({04}x²+{05}) then forward MC.
 */

#include "rijndael256.h"
#include <string.h>

/*
 * Inverse affine transform (A^{-1} matrix, NO constant d=0x05)
 *
 * The constant is absorbed into the key schedule (planes 1,2,6,7 flip,
 * equivalent to XOR with A*d = 0x63 in byte domain).
 *
 * x_i = y_{(i+2)%8} ^ y_{(i+5)%8} ^ y_{(i+7)%8}
 * Convention: state[0]=bit7, state[7]=bit0
 */
static void inv_affine_noconst(uint32_t s[8])
{
    uint32_t s0=s[0],s1=s[1],s2=s[2],s3=s[3];
    uint32_t s4=s[4],s5=s[5],s6=s[6],s7=s[7];
    s[0] = s6^s3^s1;       /* bit7 */
    s[1] = s7^s4^s2;       /* bit6 */
    s[2] = s0^s5^s3;       /* bit5 */
    s[3] = s1^s6^s4;       /* bit4 */
    s[4] = s2^s7^s5;       /* bit3 */
    s[5] = s3^s0^s6;       /* bit2 */
    s[6] = s4^s1^s7;       /* bit1 */
    s[7] = s5^s2^s0;       /* bit0 */
}

/*
 * Forward S-box core (Boyar-Peralta, NO XNORs on output)
 *
 * Computes A * GF_Inv(x) without the affine constant c=0x63.
 * 109 gates: 27 XOR (top) + 34 AND + 29 XOR (mid) + 30 XOR (bot) - 4 NOT removed
 */
static void forward_sbox_noconst(uint32_t s[8])
{
    uint32_t U0=s[0],U1=s[1],U2=s[2],U3=s[3];
    uint32_t U4=s[4],U5=s[5],U6=s[6],U7=s[7];

    /* Top linear (27 XOR) */
    uint32_t T1=U0^U3, T2=U0^U5, T3=U0^U6;
    uint32_t T4=U3^U5, T5=U4^U6, T6=T1^T5;
    uint32_t T7=U1^U2, T8=U7^T6, T9=U7^T7;
    uint32_t T10=T6^T7, T11=U1^U5, T12=U2^U5;
    uint32_t T13=T3^T4, T14=T6^T11, T15=T5^T11;
    uint32_t T16=T5^T12, T17=T9^T16, T18=U3^U7;
    uint32_t T19=T7^T18, T20=T1^T19, T21=U6^U7;
    uint32_t T22=T7^T21, T23=T2^T22, T24=T2^T10;
    uint32_t T25=T20^T17, T26=T3^T16, T27=T1^T12;

    /* Non-linear middle (34 AND + 29 XOR) */
    uint32_t M1=T13&T6, M2=T23&T8, M3=T14^M1;
    uint32_t M4=T19&U7, M5=M4^M1, M6=T3&T16;
    uint32_t M7=T22&T9, M8=T26^M6, M9=T20&T17;
    uint32_t M10=M9^M6, M11=T1&T15, M12=T4&T27;
    uint32_t M13=M12^M11, M14=T2&T10, M15=M14^M11;
    uint32_t M16=M3^M2, M17=M5^T24, M18=M8^M7;
    uint32_t M19=M10^M15, M20=M16^M13, M21=M17^M15;
    uint32_t M22=M18^M13, M23=M19^T25, M24=M22^M23;
    uint32_t M25=M22&M20, M26=M21^M25, M27=M20^M21;
    uint32_t M28=M23^M25, M29=M28&M27, M30=M26&M24;
    uint32_t M31=M20&M23, M32=M27&M31, M33=M27^M25;
    uint32_t M34=M21&M22, M35=M24&M34, M36=M24^M25;
    uint32_t M37=M21^M29, M38=M32^M33, M39=M23^M30;
    uint32_t M40=M35^M36, M41=M38^M40, M42=M37^M39;
    uint32_t M43=M37^M38, M44=M39^M40, M45=M42^M41;

    uint32_t M46=M44&T6, M47=M40&T8, M48=M39&U7;
    uint32_t M49=M43&T16, M50=M38&T9, M51=M37&T17;
    uint32_t M52=M42&T15, M53=M45&T27, M54=M41&T10;
    uint32_t M55=M44&T13, M56=M40&T23, M57=M39&T19;
    uint32_t M58=M43&T3, M59=M38&T22, M60=M37&T20;
    uint32_t M61=M42&T1, M62=M45&T4, M63=M41&T2;

    /* Bottom linear (30 XOR, NO XNORs) */
    uint32_t L0=M61^M62, L1=M50^M56, L2=M46^M48;
    uint32_t L3=M47^M55, L4=M54^M58, L5=M49^M61;
    uint32_t L6=M62^L5, L7=M46^L3, L8=M51^M59;
    uint32_t L9=M52^M53, L10=M53^L4, L11=M60^L2;
    uint32_t L12=M48^M51, L13=M50^L0, L14=M52^M61;
    uint32_t L15=M55^L1, L16=M56^L0, L17=M57^L1;
    uint32_t L18=M58^L8, L19=M63^L4, L20=L0^L1;
    uint32_t L21=L1^L7, L22=L3^L12, L23=L18^L2;
    uint32_t L24=L15^L9, L25=L6^L10, L26=L7^L9;
    uint32_t L27=L8^L10, L28=L11^L14, L29=L11^L17;

    s[0] = L6 ^ L24;       /* no XNOR — constant absorbed */
    s[1] = L16 ^ L26;
    s[2] = L19 ^ L28;
    s[3] = L6 ^ L21;
    s[4] = L20 ^ L22;
    s[5] = L25 ^ L29;
    s[6] = L13 ^ L27;
    s[7] = L6 ^ L23;
}

/*
 * Inverse S-box: InvAffine → ForwardSBox → InvAffine (all constant-free)
 *
 * Mathematical proof:
 *   With key schedule absorbing A*d = 0x63 (flip planes 1,2,6,7),
 *   the input x already has the InvAffine constant d=0x05 absorbed.
 *   Then: A^{-1} * (A * GF_Inv(A^{-1} * x)) = GF_Inv(A^{-1} * x)
 *   = GF_Inv(InvAffine(original_input)) = InvSBox(original_input)
 *
 * Gate count: 20 (inv_affine) + 109 (sbox_noconst) + 20 (inv_affine) = 149
 * 0 NOTs (all absorbed).
 */
static void inv_sbox(uint32_t s[8])
{
    inv_affine_noconst(s);
    forward_sbox_noconst(s);
    inv_affine_noconst(s);
}

/*
 * Byte rotation helpers (operate on packed bitplane words)
 */
static inline uint32_t byte_rol(uint32_t w, int pos, int rot)
{
    uint32_t b = (w >> (pos * 8)) & 0xFF;
    b = ((b << rot) | (b >> (8 - rot))) & 0xFF;
    return (w & ~(0xFFu << (pos * 8))) | (b << (pos * 8));
}

static inline uint32_t byte_ror(uint32_t w, int pos, int rot)
{
    return byte_rol(w, pos, 8 - rot);
}

/*
 * Inverse ShiftRows: (0, 7, 5, 4)
 *   Row 0 (byte 3): no shift
 *   Row 1 (byte 2): ROR 1
 *   Row 2 (byte 1): ROR 3
 *   Row 3 (byte 0): ROL 4 (= nibble swap)
 */
static void inv_shift_rows(uint32_t s[8])
{
    for (int i = 0; i < 8; i++) {
        s[i] = byte_ror(s[i], 2, 1);   /* row 1: ROR 1 */
        s[i] = byte_ror(s[i], 1, 3);   /* row 2: ROR 3 */
        s[i] = byte_rol(s[i], 0, 4);   /* row 3: nibble swap */
    }
}

/*
 * InvMixColumns = M-transform + forward MC
 *
 * M-transform: multiply by {04}x² + {05} in column-byte space
 *   M(in) = {04}*(in ^ (in ror 16)) ^ in
 *
 * Then apply forward Käsper-Schwabe MC.
 */
static void inv_mix_columns(uint32_t s[8])
{
    /* Phase 1: M-transform */
    uint32_t v[8];
    for (int i = 0; i < 8; i++)
        v[i] = s[i] ^ ((s[i] << 16) | (s[i] >> 16));  /* ror 16 */

    s[0] = v[2] ^ s[0];
    s[1] = v[3] ^ s[1];
    s[2] = v[4] ^ v[0] ^ s[2];
    s[3] = v[5] ^ v[0] ^ v[1] ^ s[3];
    s[4] = v[6] ^ v[1] ^ s[4];
    s[5] = v[7] ^ v[0] ^ s[5];
    s[6] = v[0] ^ v[1] ^ s[6];
    s[7] = v[1] ^ s[7];

    /* Phase 2: Forward Käsper-Schwabe MixColumns */
    uint32_t d0 = s[0] ^ ((s[0] << 8) | (s[0] >> 24));

    uint32_t d1 = s[1] ^ ((s[1] << 8) | (s[1] >> 24));
    s[0] = (s[0] ^ d0)
         ^ ((d0 << 16) | (d0 >> 16))
         ^ d1;

    uint32_t d2 = s[2] ^ ((s[2] << 8) | (s[2] >> 24));
    s[1] = (s[1] ^ d1) ^ ((d1 << 16) | (d1 >> 16)) ^ d2;

    uint32_t d3 = s[3] ^ ((s[3] << 8) | (s[3] >> 24));
    s[2] = (s[2] ^ d2) ^ ((d2 << 16) | (d2 >> 16)) ^ d3;

    uint32_t d4 = s[4] ^ ((s[4] << 8) | (s[4] >> 24));
    s[3] = (s[3] ^ d3) ^ ((d3 << 16) | (d3 >> 16)) ^ d4 ^ d0;  /* feedback */

    uint32_t d5 = s[5] ^ ((s[5] << 8) | (s[5] >> 24));
    s[4] = (s[4] ^ d4) ^ ((d4 << 16) | (d4 >> 16)) ^ d5 ^ d0;  /* feedback */

    uint32_t d6 = s[6] ^ ((s[6] << 8) | (s[6] >> 24));
    s[5] = (s[5] ^ d5) ^ ((d5 << 16) | (d5 >> 16)) ^ d6;

    uint32_t d7 = s[7] ^ ((s[7] << 8) | (s[7] >> 24));
    s[6] = (s[6] ^ d6) ^ ((d6 << 16) | (d6 >> 16)) ^ d7 ^ d0;  /* feedback */

    s[7] = (s[7] ^ d7) ^ ((d7 << 16) | (d7 >> 16)) ^ d0;
}

static void add_round_key(uint32_t s[8], const uint32_t *rk)
{
    for (int i = 0; i < 8; i++)
        s[i] ^= rk[i];
}

/*
 * Bitsliced Decrypt (C reference, Equivalent Inverse Cipher)
 *
 * Decrypt key schedule: reversed + InvMC on middle keys +
 * planes 1,2,6,7 flipped on keys 0..Nr-1 (absorb InvSBox constants).
 */
void rijndael256_decrypt_ref(const R256Key *rk, const uint8_t *ct, uint8_t *pt)
{
    uint32_t s[8];
    int Nr = rk->rounds;

    /* Pack ciphertext to bitplanes */
    uint8_t tmp[32];
    memcpy(tmp, ct, 32);
    r256_pack(tmp, s);

    const uint32_t *rkp = rk->roundKey;

    /* Rounds 1..Nr-1: ARK + InvSBox → InvSR + InvMC */
    for (int r = 0; r < Nr - 1; r++) {
        add_round_key(s, rkp);
        rkp += 8;
        inv_sbox(s);
        inv_shift_rows(s);
        inv_mix_columns(s);
    }

    /* Round Nr: ARK + InvSBox → InvSR (no InvMC) */
    add_round_key(s, rkp);
    rkp += 8;
    inv_sbox(s);
    inv_shift_rows(s);

    /* Final ARK */
    add_round_key(s, rkp);

    /* Unpack bitplanes to bytes */
    #define SWAPMOVE(a, b, mask, n) do { \
        uint32_t t = ((b) ^ ((a) >> (n))) & (mask); \
        (b) ^= t; \
        (a) ^= t << (n); \
    } while(0)

    SWAPMOVE(s[4], s[0], 0x0f0f0f0f, 4);
    SWAPMOVE(s[5], s[1], 0x0f0f0f0f, 4);
    SWAPMOVE(s[6], s[2], 0x0f0f0f0f, 4);
    SWAPMOVE(s[7], s[3], 0x0f0f0f0f, 4);
    SWAPMOVE(s[2], s[0], 0x33333333, 2);
    SWAPMOVE(s[3], s[1], 0x33333333, 2);
    SWAPMOVE(s[6], s[4], 0x33333333, 2);
    SWAPMOVE(s[7], s[5], 0x33333333, 2);
    SWAPMOVE(s[1], s[0], 0x55555555, 1);
    SWAPMOVE(s[3], s[2], 0x55555555, 1);
    SWAPMOVE(s[5], s[4], 0x55555555, 1);
    SWAPMOVE(s[7], s[6], 0x55555555, 1);

    #undef SWAPMOVE

    for (int i = 0; i < 8; i++) {
        pt[i*4]   = (uint8_t)(s[i] >> 24);
        pt[i*4+1] = (uint8_t)(s[i] >> 16);
        pt[i*4+2] = (uint8_t)(s[i] >> 8);
        pt[i*4+3] = (uint8_t)(s[i]);
    }
}
