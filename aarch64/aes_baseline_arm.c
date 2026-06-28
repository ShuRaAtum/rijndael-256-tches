/*
 * Standard AES-128 / AES-256 on ARMv8 Crypto Extension (AESE/AESMC).
 * See aes_baseline_arm.h. Encryption uses the canonical
 *   x = AESMC(AESE(x, rk[i]))  ... ; x = AESE(x, rk[Nr-1]); x ^= rk[Nr]
 * idiom, i.e. the same AESE/AESMC primitives the R256 path is built on.
 */
#include "aes_baseline_arm.h"
#include <string.h>

#if defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES)
#include <arm_neon.h>
#define AES_HW 1
#else
#define AES_HW 0
#endif

/* AES S-box (used only for the software key expansion). */
static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Round constants (rc byte for round j). */
static const uint8_t RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

int aes_baseline_available(void) { return AES_HW; }

int aes_key_expand(const uint8_t *key, int keyBits, AesKey *ks)
{
    int Nk;
    switch (keyBits) {
        case 128: Nk = 4; break;
        case 192: Nk = 6; break;
        case 256: Nk = 8; break;
        default:  return -1;
    }
    int Nr = Nk + 6;
    ks->rounds = Nr;
    uint8_t *w = ks->roundKeys;           /* byte layout, word i = w[4i..4i+3] */
    int total = 4 * (Nr + 1);             /* number of 4-byte words */

    memcpy(w, key, (size_t)(4 * Nk));
    for (int i = Nk; i < total; i++) {
        uint8_t t[4];
        t[0] = w[4*(i-1)+0]; t[1] = w[4*(i-1)+1];
        t[2] = w[4*(i-1)+2]; t[3] = w[4*(i-1)+3];

        if (i % Nk == 0) {
            uint8_t tmp = t[0];           /* RotWord */
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            t[0] = SBOX[t[0]]; t[1] = SBOX[t[1]];  /* SubWord */
            t[2] = SBOX[t[2]]; t[3] = SBOX[t[3]];
            t[0] ^= RCON[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            t[0] = SBOX[t[0]]; t[1] = SBOX[t[1]];
            t[2] = SBOX[t[2]]; t[3] = SBOX[t[3]];
        }
        for (int k = 0; k < 4; k++)
            w[4*i+k] = w[4*(i-Nk)+k] ^ t[k];
    }
    return 0;
}

#if AES_HW
void aes128_encrypt_arm(const AesKey *ks, const uint8_t *in, uint8_t *out)
{
    const uint8_t *rk = ks->roundKeys;
    uint8x16_t x = vld1q_u8(in);
    for (int i = 0; i < 9; i++)
        x = vaesmcq_u8(vaeseq_u8(x, vld1q_u8(rk + 16 * i)));
    x = vaeseq_u8(x, vld1q_u8(rk + 16 * 9));
    x = veorq_u8(x, vld1q_u8(rk + 16 * 10));
    vst1q_u8(out, x);
}

void aes256_encrypt_arm(const AesKey *ks, const uint8_t *in, uint8_t *out)
{
    const uint8_t *rk = ks->roundKeys;
    uint8x16_t x = vld1q_u8(in);
    for (int i = 0; i < 13; i++)
        x = vaesmcq_u8(vaeseq_u8(x, vld1q_u8(rk + 16 * i)));
    x = vaeseq_u8(x, vld1q_u8(rk + 16 * 13));
    x = veorq_u8(x, vld1q_u8(rk + 16 * 14));
    vst1q_u8(out, x);
}

/* Interleaved AES, N and Nr compile-time constants (always-inlined). */
__attribute__((always_inline))
static inline void aes_xN(const AesKey *ks, const uint8_t *in, uint8_t *out,
                          const int N, const int Nr)
{
    const uint8_t *rk = ks->roundKeys;
    uint8x16_t x[8];
    for (int b = 0; b < N; b++) x[b] = vld1q_u8(in + b * 16);
    for (int r = 0; r < Nr - 1; r++) {
        const uint8x16_t k = vld1q_u8(rk + 16 * r);
        for (int b = 0; b < N; b++) x[b] = vaesmcq_u8(vaeseq_u8(x[b], k));
    }
    const uint8x16_t k1 = vld1q_u8(rk + 16 * (Nr - 1));
    const uint8x16_t k2 = vld1q_u8(rk + 16 * Nr);
    for (int b = 0; b < N; b++) x[b] = veorq_u8(vaeseq_u8(x[b], k1), k2);
    for (int b = 0; b < N; b++) vst1q_u8(out + b * 16, x[b]);
}

void aes128_encrypt_arm_x2(const AesKey *ks, const uint8_t *in, uint8_t *out){ aes_xN(ks,in,out,2,10); }
void aes128_encrypt_arm_x4(const AesKey *ks, const uint8_t *in, uint8_t *out){ aes_xN(ks,in,out,4,10); }
void aes128_encrypt_arm_x8(const AesKey *ks, const uint8_t *in, uint8_t *out){ aes_xN(ks,in,out,8,10); }
void aes256_encrypt_arm_x2(const AesKey *ks, const uint8_t *in, uint8_t *out){ aes_xN(ks,in,out,2,14); }
void aes256_encrypt_arm_x4(const AesKey *ks, const uint8_t *in, uint8_t *out){ aes_xN(ks,in,out,4,14); }
void aes256_encrypt_arm_x8(const AesKey *ks, const uint8_t *in, uint8_t *out){ aes_xN(ks,in,out,8,14); }
#else
void aes128_encrypt_arm(const AesKey *ks, const uint8_t *in, uint8_t *out)
{ (void)ks; (void)in; (void)out; }
void aes256_encrypt_arm(const AesKey *ks, const uint8_t *in, uint8_t *out)
{ (void)ks; (void)in; (void)out; }
void aes128_encrypt_arm_x2(const AesKey *ks, const uint8_t *in, uint8_t *out){ (void)ks;(void)in;(void)out; }
void aes128_encrypt_arm_x4(const AesKey *ks, const uint8_t *in, uint8_t *out){ (void)ks;(void)in;(void)out; }
void aes128_encrypt_arm_x8(const AesKey *ks, const uint8_t *in, uint8_t *out){ (void)ks;(void)in;(void)out; }
void aes256_encrypt_arm_x2(const AesKey *ks, const uint8_t *in, uint8_t *out){ (void)ks;(void)in;(void)out; }
void aes256_encrypt_arm_x4(const AesKey *ks, const uint8_t *in, uint8_t *out){ (void)ks;(void)in;(void)out; }
void aes256_encrypt_arm_x8(const AesKey *ks, const uint8_t *in, uint8_t *out){ (void)ks;(void)in;(void)out; }
#endif

int aes_baseline_selftest(void)
{
#if !AES_HW
    return 0;   /* nothing to test without crypto */
#else
    /* FIPS-197 Appendix C.1 (AES-128) and C.3 (AES-256). */
    static const uint8_t pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t k128[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t ct128[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };
    static const uint8_t k256[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t ct256[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
        0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };
    AesKey ks;
    uint8_t out[16];

    if (aes_key_expand(k128, 128, &ks) != 0) return 10;
    aes128_encrypt_arm(&ks, pt, out);
    if (memcmp(out, ct128, 16) != 0) return 1;

    if (aes_key_expand(k256, 256, &ks) != 0) return 20;
    aes256_encrypt_arm(&ks, pt, out);
    if (memcmp(out, ct256, 16) != 0) return 2;

    /* interleaved variants must agree with the single-block path (8 blocks) */
    {
        AesKey k1, k2;
        aes_key_expand(k128, 128, &k1);
        aes_key_expand(k256, 256, &k2);
        uint8_t in[8 * 16], ref[8 * 16], got[8 * 16];
        for (int i = 0; i < 8 * 16; i++) in[i] = (uint8_t)(i * 13 + 7);
        for (int b = 0; b < 8; b++) aes128_encrypt_arm(&k1, in + b * 16, ref + b * 16);
        aes128_encrypt_arm_x2(&k1, in, got); if (memcmp(got, ref, 2 * 16)) return 3;
        aes128_encrypt_arm_x4(&k1, in, got); if (memcmp(got, ref, 4 * 16)) return 4;
        aes128_encrypt_arm_x8(&k1, in, got); if (memcmp(got, ref, 8 * 16)) return 5;
        for (int b = 0; b < 8; b++) aes256_encrypt_arm(&k2, in + b * 16, ref + b * 16);
        aes256_encrypt_arm_x2(&k2, in, got); if (memcmp(got, ref, 2 * 16)) return 6;
        aes256_encrypt_arm_x4(&k2, in, got); if (memcmp(got, ref, 4 * 16)) return 7;
        aes256_encrypt_arm_x8(&k2, in, got); if (memcmp(got, ref, 8 * 16)) return 8;
    }

    return 0;
#endif
}
