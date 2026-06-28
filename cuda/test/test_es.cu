#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "rijndael.h"
#include "rijndael_es.cuh"
#include "test_utils.h"

/*
 * Exhaustive Search (ES) Tests:
 * 1. Known key placed at small offset -> search finds it (V2 + V3)
 * 2. Key not in range -> reports not found (V2 + V3)
 * 3. 128-bit key search (V2 + V3)
 * 4. 192-bit key search (V2 + V3)
 * 5. Zero-length and non-zero baseOffset windows
 * 6. Invalid parameters fail fast
 */

static void write_key_offset(uint8_t *key, int keyBytes, uint64_t offset) {
    int start = keyBytes - 8;
    for (int i = 0; i < 8; i++) {
        key[start + i] = (uint8_t)(offset >> (56 - 8 * i));
    }
}

static int run_child_expect_failure(void (*child_fn)(void), const char *message) {
    pid_t pid = fork();
    TEST_ASSERT(pid >= 0, "fork succeeded");

    if (pid == 0) {
        child_fn();
        exit(EXIT_SUCCESS);
    }

    int status = 0;
    TEST_ASSERT(waitpid(pid, &status, 0) == pid, "waitpid succeeded");
    TEST_ASSERT(WIFEXITED(status), message);
    TEST_ASSERT(WEXITSTATUS(status) != 0, message);
    return 0;
}

static int test_es_find_known_key(void) {
    TEST_SECTION("ES Find Known Key");

    /* Create a known plaintext-ciphertext pair */
    uint8_t baseKey[32];
    memset(baseKey, 0, sizeof(baseKey));

    /* Place the target key at offset 12345 */
    uint64_t targetOffset = 12345;
    uint8_t targetKey[32];
    memset(targetKey, 0, sizeof(targetKey));
    /* Set lower 64 bits to targetOffset (big-endian in last 8 bytes of key) */
    /* For 256-bit key: Nk=8, lower 64 bits = words 6,7 = bytes 24-31 */
    targetKey[24] = (uint8_t)(targetOffset >> 56);
    targetKey[25] = (uint8_t)(targetOffset >> 48);
    targetKey[26] = (uint8_t)(targetOffset >> 40);
    targetKey[27] = (uint8_t)(targetOffset >> 32);
    targetKey[28] = (uint8_t)(targetOffset >> 24);
    targetKey[29] = (uint8_t)(targetOffset >> 16);
    targetKey[30] = (uint8_t)(targetOffset >> 8);
    targetKey[31] = (uint8_t)(targetOffset);

    /* Encrypt known plaintext with target key */
    uint8_t pt[32], ct[32];
    memset(pt, 0x42, sizeof(pt)); /* Known plaintext */

    RijndaelKey rk;
    rijndaelSetupKey(targetKey, 256, &rk);
    rijndaelEncrypt(&rk, pt, ct);

    printf("  Target key offset: %lu\n", (unsigned long)targetOffset);
    PRINT_HEX("  Known PT", pt, 32);
    PRINT_HEX("  Known CT", ct, 32);

    /* Search with V2 */
    ESResult result_v2;
    uint64_t searchRange = 1 << 16; /* 64K keys */
    rijndael256_es_search_v2(pt, ct, baseKey, 256, 0, searchRange,
                              &result_v2, 256, 256);

    printf("  V2: found=%d, offset=%lu\n", result_v2.found,
           (unsigned long)result_v2.keyOffset);
    TEST_ASSERT(result_v2.found == 1, "V2 ES found the key");
    TEST_ASSERT(result_v2.keyOffset == targetOffset, "V2 ES found correct offset");

    /* Search with V3 */
    ESResult result_v3;
    rijndael256_es_search_v3(pt, ct, baseKey, 256, 0, searchRange,
                              &result_v3, 256, 256);

    printf("  V3: found=%d, offset=%lu\n", result_v3.found,
           (unsigned long)result_v3.keyOffset);
    TEST_ASSERT(result_v3.found == 1, "V3 ES found the key");
    TEST_ASSERT(result_v3.keyOffset == targetOffset, "V3 ES found correct offset");

    printf(COLOR_GREEN "  ✓ ES find known key passed (V2, V3)" COLOR_RESET "\n");
    return 0;
}

static int test_es_not_found(void) {
    TEST_SECTION("ES Key Not In Range");

    uint8_t baseKey[32];
    memset(baseKey, 0, sizeof(baseKey));

    /* Target at offset 100000, but search only 0..999 */
    uint64_t targetOffset = 100000;
    uint8_t targetKey[32];
    memset(targetKey, 0, sizeof(targetKey));
    targetKey[28] = (uint8_t)(targetOffset >> 24);
    targetKey[29] = (uint8_t)(targetOffset >> 16);
    targetKey[30] = (uint8_t)(targetOffset >> 8);
    targetKey[31] = (uint8_t)(targetOffset);

    uint8_t pt[32], ct[32];
    memset(pt, 0x99, sizeof(pt));

    RijndaelKey rk;
    rijndaelSetupKey(targetKey, 256, &rk);
    rijndaelEncrypt(&rk, pt, ct);

    /* V2 not-found */
    ESResult result_v2;
    rijndael256_es_search_v2(pt, ct, baseKey, 256, 0, 1000,
                              &result_v2, 256, 4);
    TEST_ASSERT(result_v2.found == 0, "V2 ES correctly reports key not found");

    /* V3 not-found */
    ESResult result_v3;
    rijndael256_es_search_v3(pt, ct, baseKey, 256, 0, 1000,
                              &result_v3, 256, 4);
    TEST_ASSERT(result_v3.found == 0, "V3 ES correctly reports key not found");

    printf(COLOR_GREEN "  ✓ ES not-found test passed (V2, V3)" COLOR_RESET "\n");
    return 0;
}

static int test_es_128bit_key(void) {
    TEST_SECTION("ES 128-bit Key");

    uint8_t baseKey[16];
    memset(baseKey, 0, sizeof(baseKey));

    uint64_t targetOffset = 777;
    uint8_t targetKey[16];
    memset(targetKey, 0, sizeof(targetKey));
    /* For 128-bit key: Nk=4, lower 64 bits = words 2,3 = bytes 8-15 */
    targetKey[8]  = (uint8_t)(targetOffset >> 56);
    targetKey[9]  = (uint8_t)(targetOffset >> 48);
    targetKey[10] = (uint8_t)(targetOffset >> 40);
    targetKey[11] = (uint8_t)(targetOffset >> 32);
    targetKey[12] = (uint8_t)(targetOffset >> 24);
    targetKey[13] = (uint8_t)(targetOffset >> 16);
    targetKey[14] = (uint8_t)(targetOffset >> 8);
    targetKey[15] = (uint8_t)(targetOffset);

    uint8_t pt[32], ct[32];
    memset(pt, 0x55, sizeof(pt));

    RijndaelKey rk;
    rijndaelSetupKey(targetKey, 128, &rk);
    rijndaelEncrypt(&rk, pt, ct);

    /* V2 */
    ESResult result_v2;
    rijndael256_es_search_v2(pt, ct, baseKey, 128, 0, 2048,
                              &result_v2, 256, 8);
    TEST_ASSERT(result_v2.found == 1, "V2 ES 128-bit key found");
    TEST_ASSERT(result_v2.keyOffset == targetOffset, "V2 ES 128-bit correct offset");

    /* V3 */
    ESResult result_v3;
    rijndael256_es_search_v3(pt, ct, baseKey, 128, 0, 2048,
                              &result_v3, 256, 8);
    TEST_ASSERT(result_v3.found == 1, "V3 ES 128-bit key found");
    TEST_ASSERT(result_v3.keyOffset == targetOffset, "V3 ES 128-bit correct offset");

    printf(COLOR_GREEN "  ✓ ES 128-bit key test passed (V2, V3)" COLOR_RESET "\n");
    return 0;
}

static int test_es_192bit_key(void) {
    TEST_SECTION("ES 192-bit Key");

    uint8_t baseKey[24];
    memset(baseKey, 0, sizeof(baseKey));

    uint64_t targetOffset = 4321;
    uint8_t targetKey[24];
    memset(targetKey, 0, sizeof(targetKey));
    /* For 192-bit key: Nk=6, lower 64 bits = words 4,5 = bytes 16-23 */
    targetKey[16] = (uint8_t)(targetOffset >> 56);
    targetKey[17] = (uint8_t)(targetOffset >> 48);
    targetKey[18] = (uint8_t)(targetOffset >> 40);
    targetKey[19] = (uint8_t)(targetOffset >> 32);
    targetKey[20] = (uint8_t)(targetOffset >> 24);
    targetKey[21] = (uint8_t)(targetOffset >> 16);
    targetKey[22] = (uint8_t)(targetOffset >> 8);
    targetKey[23] = (uint8_t)(targetOffset);

    uint8_t pt[32], ct[32];
    memset(pt, 0xBB, sizeof(pt));

    RijndaelKey rk;
    rijndaelSetupKey(targetKey, 192, &rk);
    rijndaelEncrypt(&rk, pt, ct);

    /* V2 */
    ESResult result_v2;
    rijndael256_es_search_v2(pt, ct, baseKey, 192, 0, 8192,
                              &result_v2, 256, 32);
    TEST_ASSERT(result_v2.found == 1, "V2 ES 192-bit key found");
    TEST_ASSERT(result_v2.keyOffset == targetOffset, "V2 ES 192-bit correct offset");

    /* V3 */
    ESResult result_v3;
    rijndael256_es_search_v3(pt, ct, baseKey, 192, 0, 8192,
                              &result_v3, 256, 32);
    TEST_ASSERT(result_v3.found == 1, "V3 ES 192-bit key found");
    TEST_ASSERT(result_v3.keyOffset == targetOffset, "V3 ES 192-bit correct offset");

    printf(COLOR_GREEN "  ✓ ES 192-bit key test passed (V2, V3)" COLOR_RESET "\n");
    return 0;
}

static int test_es_zero_search_range(void) {
    TEST_SECTION("ES Zero Search Range");

    uint8_t pt[32], ct[32], baseKey[32];
    memset(pt, 0x11, sizeof(pt));
    memset(ct, 0x22, sizeof(ct));
    memset(baseKey, 0, sizeof(baseKey));

    ESResult result_v2 = {1, 99};
    rijndael256_es_search_v2(pt, ct, baseKey, 256, 1234, 0,
                              &result_v2, 256, 8);
    TEST_ASSERT(result_v2.found == 0, "V2 zero search range reports not found");
    TEST_ASSERT(result_v2.keyOffset == 0, "V2 zero search range clears offset");

    ESResult result_v3 = {1, 99};
    rijndael256_es_search_v3(pt, ct, baseKey, 256, 1234, 0,
                              &result_v3, 256, 8);
    TEST_ASSERT(result_v3.found == 0, "V3 zero search range reports not found");
    TEST_ASSERT(result_v3.keyOffset == 0, "V3 zero search range clears offset");

    printf(COLOR_GREEN "  ✓ ES zero search range passed (V2, V3)" COLOR_RESET "\n");
    return 0;
}

static int test_es_base_offset_window(void) {
    TEST_SECTION("ES Non-Zero Base Offset");

    uint8_t baseKey[32];
    memset(baseKey, 0, sizeof(baseKey));

    uint64_t baseOffset = (1ULL << 20) + 512;
    uint64_t delta = 321;
    uint64_t targetOffset = baseOffset + delta;
    uint64_t searchRange = 1024;

    uint8_t targetKey[32];
    memset(targetKey, 0, sizeof(targetKey));
    write_key_offset(targetKey, (int)sizeof(targetKey), targetOffset);

    uint8_t pt[32], ct[32];
    memset(pt, 0x3C, sizeof(pt));

    RijndaelKey rk;
    rijndaelSetupKey(targetKey, 256, &rk);
    rijndaelEncrypt(&rk, pt, ct);

    ESResult result_v2;
    rijndael256_es_search_v2(pt, ct, baseKey, 256, baseOffset, searchRange,
                              &result_v2, 256, 4);
    TEST_ASSERT(result_v2.found == 1, "V2 ES finds key inside non-zero baseOffset window");
    TEST_ASSERT(result_v2.keyOffset == targetOffset, "V2 ES returns absolute offset");

    ESResult result_v3;
    rijndael256_es_search_v3(pt, ct, baseKey, 256, baseOffset, searchRange,
                              &result_v3, 256, 4);
    TEST_ASSERT(result_v3.found == 1, "V3 ES finds key inside non-zero baseOffset window");
    TEST_ASSERT(result_v3.keyOffset == targetOffset, "V3 ES returns absolute offset");

    printf(COLOR_GREEN "  ✓ ES non-zero baseOffset passed (V2, V3)" COLOR_RESET "\n");
    return 0;
}

static void child_invalid_threads_v2(void) {
    uint8_t pt[32], ct[32], baseKey[32];
    ESResult result;
    memset(pt, 0, sizeof(pt));
    memset(ct, 0, sizeof(ct));
    memset(baseKey, 0, sizeof(baseKey));
    rijndael256_es_search_v2(pt, ct, baseKey, 256, 0, 16, &result, 0, 1);
}

static void child_invalid_key_bits_v3(void) {
    uint8_t pt[32], ct[32], baseKey[32];
    ESResult result;
    memset(pt, 0, sizeof(pt));
    memset(ct, 0, sizeof(ct));
    memset(baseKey, 0, sizeof(baseKey));
    rijndael256_es_search_v3(pt, ct, baseKey, 160, 0, 16, &result, 256, 1);
}

static void child_overflow_window_v2(void) {
    uint8_t pt[32], ct[32], baseKey[32];
    ESResult result;
    memset(pt, 0, sizeof(pt));
    memset(ct, 0, sizeof(ct));
    memset(baseKey, 0, sizeof(baseKey));
    rijndael256_es_search_v2(pt, ct, baseKey, 256, UINT64_MAX - 4, 8,
                              &result, 256, 1);
}

static int test_es_invalid_params_fail_fast(void) {
    TEST_SECTION("ES Invalid Parameters");

    if (run_child_expect_failure(child_invalid_threads_v2,
                                 "V2 rejects non-positive threadsPerBlock") != 0) {
        return -1;
    }
    if (run_child_expect_failure(child_invalid_key_bits_v3,
                                 "V3 rejects unsupported keyBits") != 0) {
        return -1;
    }
    if (run_child_expect_failure(child_overflow_window_v2,
                                 "V2 rejects overflowing search window") != 0) {
        return -1;
    }

    printf(COLOR_GREEN "  ✓ ES invalid-parameter checks passed" COLOR_RESET "\n");
    return 0;
}

int main(void) {
    TEST_RESET();
    printf("Rijndael-256 ES Mode Tests\n");

    test_es_find_known_key();
    test_es_not_found();
    test_es_128bit_key();
    test_es_192bit_key();
    test_es_zero_search_range();
    test_es_base_offset_window();
    test_es_invalid_params_fail_fast();

    TEST_SUMMARY("ES Mode");
    return TEST_EXIT_CODE();
}
