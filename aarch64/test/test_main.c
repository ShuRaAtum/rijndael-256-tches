/*
 * Rijndael-256 Test Suite
 *
 * Tests all three implementations against official test vectors
 * and verifies cross-implementation consistency.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "rijndael256.h"

/* Test vectors from Rijndael specification */
typedef struct {
    int keyBits;
    const char *firstEncrypt;   /* E(0) with key=0 */
    const char *secondEncrypt;  /* E(E(0)) with key=0 */
} TestVector;

static const TestVector test_vectors[] = {
    /* 256-bit block, 128-bit key */
    {128,
     "A693B288DF7DAE5B1757640276439230DB77C4CD7A871E24D6162E54AF434891",
     "5F05857C80B68EA42CCBC759D42C28D5CD490F1D180C7A9397EE585BEA770391"},

    /* 256-bit block, 192-bit key */
    {192,
    "F927363EF5B3B4984A9EB9109844152EC167F08102644E3F9028070433DF9F2A",
    "4E03389C68B2E3F623AD8F7F6BFC88613B86F334F4148029AE25F50DB144B80C"},

    /* 256-bit block, 256-bit key */
    {256,
     "C6227E7740B7E53B5CB77865278EAB0726F62366D9AABAD908936123A1FC8AF3",
     "9843E807319C32AD1EA3935EF56A2BA96E4BF19C30E47D88A2B97CBBF2E159E7"},
};

#define NUM_VECTORS (sizeof(test_vectors) / sizeof(test_vectors[0]))

/* Convert hex string to bytes */
static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int val;
        sscanf(hex + i * 2, "%2x", &val);
        bytes[i] = (uint8_t)val;
    }
}

/* Compare two byte arrays and print differences */
static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len, const char *name) {
    if (memcmp(a, b, len) == 0) {
        return 0;  /* Match */
    }

    printf("  MISMATCH in %s:\n", name);
    printf("    Expected: ");
    for (size_t i = 0; i < len; i++) printf("%02X", a[i]);
    printf("\n    Got:      ");
    for (size_t i = 0; i < len; i++) printf("%02X", b[i]);
    printf("\n");
    return 1;
}

/* Test a single implementation */
static int test_implementation(const char *name,
                                void (*encrypt)(const void*, const uint8_t*, uint8_t*),
                                void (*decrypt)(const void*, const uint8_t*, uint8_t*),
                                const void *ctx,
                                const uint8_t *expected1,
                                const uint8_t *expected2,
                                int keyBits) {
    uint8_t zero[32] = {0};
    uint8_t ct1[32], ct2[32], pt_dec[32];
    int errors = 0;

    /* First encryption: E(0) */
    encrypt(ctx, zero, ct1);
    if (compare_bytes(expected1, ct1, 32, "first encrypt") != 0) {
        errors++;
    }

    /* Second encryption: E(E(0)) */
    encrypt(ctx, ct1, ct2);
    if (compare_bytes(expected2, ct2, 32, "second encrypt") != 0) {
        errors++;
    }

    /* Decryption test: D(E(E(0))) should equal E(0) */
    if (decrypt) {
        decrypt(ctx, ct2, pt_dec);
        if (compare_bytes(ct1, pt_dec, 32, "decryption") != 0) {
            errors++;
        }
    }

    if (errors == 0) {
        printf("  [%s] PASS\n", name);
    } else {
        printf("  [%s] FAIL (%d errors)\n", name, errors);
    }

    return errors;
}

/* Wrapper functions to handle different context types */
static void encrypt_ref_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_ref((const Rijndael256Key*)ctx, pt, ct);
}

static void decrypt_ref_wrapper(const void *ctx, const uint8_t *ct, uint8_t *pt) {
    rijndael256_decrypt_ref((const Rijndael256Key*)ctx, ct, pt);
}

static void encrypt_ttable_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_ttable((const Rijndael256KeyTTable*)ctx, pt, ct);
}

static void decrypt_ttable_wrapper(const void *ctx, const uint8_t *ct, uint8_t *pt) {
    rijndael256_decrypt_ttable((const Rijndael256KeyTTable*)ctx, ct, pt);
}

static void encrypt_arm_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_arm((const Rijndael256Key*)ctx, pt, ct);
}

static void decrypt_arm_wrapper(const void *ctx, const uint8_t *ct, uint8_t *pt) {
    rijndael256_decrypt_arm((const Rijndael256Key*)ctx, ct, pt);
}

/* NEON wrappers */
static void encrypt_neon_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_neon((const Rijndael256Key*)ctx, pt, ct);
}

static void encrypt_neon_4pt_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    /* 4PT expects 4 blocks input/output, replicate single block */
    uint8_t pt4[128], ct4[128];
    memcpy(pt4, pt, 32);
    memcpy(pt4 + 32, pt, 32);
    memcpy(pt4 + 64, pt, 32);
    memcpy(pt4 + 96, pt, 32);
    rijndael256_encrypt_neon_4pt((const Rijndael256Key*)ctx, pt4, ct4);
    memcpy(ct, ct4, 32);  /* Return first block */
}

static void encrypt_neon_il_4pt_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    /* 4PT expects 4 blocks input/output, replicate single block */
    uint8_t pt4[128], ct4[128];
    memcpy(pt4, pt, 32);
    memcpy(pt4 + 32, pt, 32);
    memcpy(pt4 + 64, pt, 32);
    memcpy(pt4 + 96, pt, 32);
    rijndael256_encrypt_neon_il_4pt((const Rijndael256Key*)ctx, pt4, ct4);
    memcpy(ct, ct4, 32);  /* Return first block */
}

/* Run all tests for a specific key size */
static int run_tests_for_keysize(int keyBits, const char *expected1_hex, const char *expected2_hex) {
    uint8_t key[32] = {0};
    uint8_t expected1[32], expected2[32];
    int errors = 0;

    hex_to_bytes(expected1_hex, expected1, 32);
    hex_to_bytes(expected2_hex, expected2, 32);

    printf("\n=== Testing Key Size: %d bits ===\n", keyBits);

    /* Setup keys for each implementation */
    Rijndael256Key ctx_ref;
    Rijndael256KeyTTable ctx_ttable;
    Rijndael256Key ctx_arm;

    rijndael256_setup_key(key, keyBits, &ctx_ref);
    rijndael256_setup_key_ttable(key, keyBits, &ctx_ttable);
    rijndael256_setup_key(key, keyBits, &ctx_arm);

    printf("  Rounds: %d\n\n", ctx_ref.rounds);

    /* Test Reference implementation */
    errors += test_implementation("Reference",
                                   encrypt_ref_wrapper,
                                   decrypt_ref_wrapper,
                                   &ctx_ref,
                                   expected1, expected2,
                                   keyBits);

    /* Test T-table implementation */
    errors += test_implementation("T-table",
                                   encrypt_ttable_wrapper,
                                   decrypt_ttable_wrapper,
                                   &ctx_ttable,
                                   expected1, expected2,
                                   keyBits);

    /* Test ARM Crypto implementation */
    if (rijndael256_has_arm_crypto()) {
        errors += test_implementation("ARM Crypto",
                                       encrypt_arm_wrapper,
                                       decrypt_arm_wrapper,
                                       &ctx_arm,
                                       expected1, expected2,
                                       keyBits);
    } else {
        printf("  [ARM Crypto] SKIPPED (not available)\n");
    }

    /* Test NEON implementations (encrypt only, no decrypt) */
    errors += test_implementation("NEON Single",
                                   encrypt_neon_wrapper,
                                   NULL,  /* no decrypt */
                                   &ctx_ref,
                                   expected1, expected2,
                                   keyBits);

    errors += test_implementation("NEON 4PT",
                                   encrypt_neon_4pt_wrapper,
                                   NULL,
                                   &ctx_ref,
                                   expected1, expected2,
                                   keyBits);

    errors += test_implementation("NEON IL 4PT",
                                   encrypt_neon_il_4pt_wrapper,
                                   NULL,
                                   &ctx_ref,
                                   expected1, expected2,
                                   keyBits);

    return errors;
}

/* Cross-implementation consistency test */
static int test_cross_implementation(void) {
    printf("\n=== Cross-Implementation Consistency Test ===\n");

    uint8_t key[32], pt[32];
    uint8_t ct_ref[32], ct_ttable[32], ct_arm[32];
    int errors = 0;

    /* Generate pseudo-random test data */
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(i * 17 + 5);
        pt[i] = (uint8_t)(i * 31 + 11);
    }

    /* Setup keys */
    Rijndael256Key ctx_ref, ctx_arm;
    Rijndael256KeyTTable ctx_ttable;

    rijndael256_setup_key(key, 256, &ctx_ref);
    rijndael256_setup_key_ttable(key, 256, &ctx_ttable);
    rijndael256_setup_key(key, 256, &ctx_arm);

    /* Encrypt with each implementation */
    rijndael256_encrypt_ref(&ctx_ref, pt, ct_ref);
    rijndael256_encrypt_ttable(&ctx_ttable, pt, ct_ttable);

    if (rijndael256_has_arm_crypto()) {
        rijndael256_encrypt_arm(&ctx_arm, pt, ct_arm);
    }

    /* Compare results */
    printf("  Plaintext:  ");
    for (int i = 0; i < 32; i++) printf("%02X", pt[i]);
    printf("\n");

    printf("  Reference:  ");
    for (int i = 0; i < 32; i++) printf("%02X", ct_ref[i]);
    printf("\n");

    printf("  T-table:    ");
    for (int i = 0; i < 32; i++) printf("%02X", ct_ttable[i]);
    printf("\n");

    if (memcmp(ct_ref, ct_ttable, 32) != 0) {
        printf("  ERROR: Reference != T-table\n");
        errors++;
    }

    if (rijndael256_has_arm_crypto()) {
        printf("  ARM Crypto: ");
        for (int i = 0; i < 32; i++) printf("%02X", ct_arm[i]);
        printf("\n");

        if (memcmp(ct_ref, ct_arm, 32) != 0) {
            printf("  ERROR: Reference != ARM Crypto\n");
            errors++;
        }
    }

    if (errors == 0) {
        printf("  All implementations match!\n");
    }

    return errors;
}

int main(void) {
    int total_errors = 0;

    printf("========================================\n");
    printf("    Rijndael-256 Test Suite\n");
    printf("========================================\n");

    /* Test each key size */
    for (size_t i = 0; i < NUM_VECTORS; i++) {
        total_errors += run_tests_for_keysize(
            test_vectors[i].keyBits,
            test_vectors[i].firstEncrypt,
            test_vectors[i].secondEncrypt
        );
    }

    /* Cross-implementation test */
    total_errors += test_cross_implementation();

    /* Summary */
    printf("\n========================================\n");
    if (total_errors == 0) {
        printf("    All tests PASSED!\n");
    } else {
        printf("    %d test(s) FAILED\n", total_errors);
    }
    printf("========================================\n");

    return total_errors > 0 ? 1 : 0;
}
