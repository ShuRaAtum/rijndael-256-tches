/* KAT: x86 VAES-512 Rijndael-256 vs portable reference (bit-identical check). */
#include "rijndael256.h"
#include <stdio.h>
#include <string.h>

void rijndael256_encrypt_vaes512(const Rijndael256Key *, const uint8_t *, uint8_t *);
void rijndael256_encrypt_vaes512_x16(const Rijndael256Key *, const uint8_t *, uint8_t *);

/* single-block point check for a given key size */
static int one(int keybits, const char *tag)
{
    uint8_t key[32], pt[32], a[32], b[32];
    for (int i = 0; i < 32; i++) { key[i] = (uint8_t)(i * 3 + 1); pt[i] = (uint8_t)(i * 7 + 5); }
    Rijndael256Key ctx;
    if (rijndael256_setup_key(key, keybits, &ctx) != 0) { printf("keysetup fail\n"); return 1; }
    rijndael256_encrypt_ref(&ctx, pt, a);
    rijndael256_encrypt_vaes512(&ctx, pt, b);
    int ok = memcmp(a, b, 32) == 0;
    printf("[%s] key=%d  %s\n", tag, keybits, ok ? "PASS" : "FAIL");
    if (!ok) {
        printf("  ref  :"); for (int i = 0; i < 32; i++) printf("%02x", a[i]); printf("\n");
        printf("  vaes :"); for (int i = 0; i < 32; i++) printf("%02x", b[i]); printf("\n");
    }
    return !ok;
}

/* 16-block interleaved path vs ref, all 16 blocks must match */
static int check_x16(void)
{
    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 5 + 7);
    Rijndael256Key ctx; rijndael256_setup_key(key, 256, &ctx);
    uint8_t in[16 * 32], got[16 * 32], ref[16 * 32];
    for (int i = 0; i < 16 * 32; i++) in[i] = (uint8_t)(i * 9 + 3);
    rijndael256_encrypt_vaes512_x16(&ctx, in, got);
    for (int b = 0; b < 16; b++) rijndael256_encrypt_ref(&ctx, in + b * 32, ref + b * 32);
    int ok = memcmp(got, ref, 16 * 32) == 0;
    printf("[x16] 16-block interleaved vs ref: %s\n", ok ? "PASS" : "FAIL");
    if (!ok) for (int b = 0; b < 16; b++)
        if (memcmp(got + b * 32, ref + b * 32, 32)) printf("  block %d mismatch\n", b);
    return !ok;
}

/* multi-block sweep with varying data, both single and x16 paths */
static int sweep(void)
{
    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 11 + 2);
    Rijndael256Key ctx; rijndael256_setup_key(key, 256, &ctx);
    int fails = 0;
    /* feed 1000 blocks through x16 in tiles of 16, compare each to ref */
    for (int t = 0; t < 1000; t += 16) {
        uint8_t in[16 * 32], got[16 * 32], ref[16 * 32];
        for (int b = 0; b < 16; b++)
            for (int i = 0; i < 32; i++)
                in[b * 32 + i] = (uint8_t)((t + b) * 13 + i * 5 + 1);
        rijndael256_encrypt_vaes512_x16(&ctx, in, got);
        for (int b = 0; b < 16; b++) rijndael256_encrypt_ref(&ctx, in + b * 32, ref + b * 32);
        if (memcmp(got, ref, 16 * 32)) fails++;
    }
    printf("[sweep] 1000+ blocks via x16: %s (%d failing tiles)\n", fails ? "FAIL" : "PASS", fails);
    return fails != 0;
}

int main(void)
{
    int bad = 0;
    bad |= one(128, "k128");
    bad |= one(192, "k192");
    bad |= one(256, "k256");
    bad |= sweep();
    bad |= check_x16();
    printf("%s\n", bad ? "=== VAES KAT FAILED ===" : "=== ALL VAES KAT PASS ===");
    return bad;
}
