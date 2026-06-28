/* KAT: x86 AES-NI Rijndael-256 vs portable reference (bit-identical check). */
#include "rijndael256.h"
#include <stdio.h>
#include <string.h>

void rijndael256_encrypt_aesni(const Rijndael256Key *, const uint8_t *, uint8_t *);
void rijndael256_encrypt_aesni_x4(const Rijndael256Key *, const uint8_t *, uint8_t *);

/* verify the 4-block interleaved path matches the reference for all 4 blocks */
static int check_x4(void)
{
    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 5 + 7);
    Rijndael256Key ctx; rijndael256_setup_key(key, 256, &ctx);
    uint8_t in[128], gotx4[128], ref[128];
    for (int i = 0; i < 128; i++) in[i] = (uint8_t)(i * 9 + 3);
    rijndael256_encrypt_aesni_x4(&ctx, in, gotx4);
    for (int b = 0; b < 4; b++) rijndael256_encrypt_ref(&ctx, in + b * 32, ref + b * 32);
    int ok = memcmp(gotx4, ref, 128) == 0;
    printf("[x4]  4-block interleaved vs ref: %s\n", ok ? "PASS" : "FAIL");
    return !ok;
}

static int one(int keybits, const char *tag)
{
    uint8_t key[32], pt[32], a[32], b[32];
    for (int i = 0; i < 32; i++) { key[i] = (uint8_t)(i * 3 + 1); pt[i] = (uint8_t)(i * 7 + 5); }
    Rijndael256Key ctx;
    if (rijndael256_setup_key(key, keybits, &ctx) != 0) { printf("keysetup fail\n"); return 1; }
    rijndael256_encrypt_ref(&ctx, pt, a);
    rijndael256_encrypt_aesni(&ctx, pt, b);
    int ok = memcmp(a, b, 32) == 0;
    printf("[%s] key=%d  %s\n", tag, keybits, ok ? "PASS" : "FAIL");
    if (!ok) {
        printf("  ref :"); for (int i = 0; i < 32; i++) printf("%02x", a[i]); printf("\n");
        printf("  aesni:"); for (int i = 0; i < 32; i++) printf("%02x", b[i]); printf("\n");
    }
    return !ok;
}

/* multi-block sweep with varying data */
static int sweep(void)
{
    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 11 + 2);
    Rijndael256Key ctx; rijndael256_setup_key(key, 256, &ctx);
    int fails = 0;
    for (int t = 0; t < 1000; t++) {
        uint8_t pt[32], a[32], b[32];
        for (int i = 0; i < 32; i++) pt[i] = (uint8_t)(t * 13 + i * 5 + 1);
        rijndael256_encrypt_ref(&ctx, pt, a);
        rijndael256_encrypt_aesni(&ctx, pt, b);
        if (memcmp(a, b, 32)) fails++;
    }
    printf("[sweep] 1000 random-ish blocks: %s (%d fails)\n", fails ? "FAIL" : "PASS", fails);
    return fails != 0;
}

int main(void)
{
    int bad = 0;
    bad |= one(128, "k128");
    bad |= one(192, "k192");
    bad |= one(256, "k256");
    bad |= sweep();
    bad |= check_x4();
    printf("%s\n", bad ? "=== KAT FAILED ===" : "=== ALL KAT PASS ===");
    return bad;
}
