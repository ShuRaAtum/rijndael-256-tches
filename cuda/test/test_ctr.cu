#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>
#include "rijndael.h"
#include "rijndael_ctr.cuh"
#include "test_utils.h"

/*
 * CTR Mode Tests:
 * 1. Encrypt-decrypt roundtrip (CTR encrypt twice = original)
 * 2. CPU CTR vs GPU CTR consistency
 * 3. V2 vs V3 result consistency
 * 4. Multi-block test
 * 5. 128/192-bit key tests
 * 6. Nonce carry boundary test
 */

/* CPU CTR reference implementation */
static void cpu_ctr_crypt(const uint8_t *nonce, const uint8_t *input,
                           uint8_t *output, const RijndaelKey *rk,
                           size_t numBlocks)
{
    uint8_t counter[32];
    memcpy(counter, nonce, 32);

    for (size_t b = 0; b < numBlocks; b++) {
        /* Encrypt counter */
        uint8_t keystream[32];
        rijndaelEncrypt(rk, counter, keystream);

        /* XOR with input */
        if (input) {
            for (int i = 0; i < 32; i++)
                output[b * 32 + i] = keystream[i] ^ input[b * 32 + i];
        } else {
            memcpy(output + b * 32, keystream, 32);
        }

        /* Increment counter (lower 64 bits, big-endian) */
        for (int i = 31; i >= 24; i--) {
            counter[i]++;
            if (counter[i] != 0) break;
        }
    }
}

static int test_ctr_roundtrip(void) {
    TEST_SECTION("CTR Roundtrip");

    uint8_t key[32], nonce[32], pt[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(i * 7 + 13);
        nonce[i] = (uint8_t)(i * 3 + 5);
        pt[i] = (uint8_t)(i * 11 + 1);
    }

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    /* V2: encrypt then decrypt should give back original */
    uint8_t v2Ct[32], v2Dec[32];
    rijndael256_ctr_crypt_v2(nonce, pt, v2Ct, &rk, 1, 256);
    rijndael256_ctr_crypt_v2(nonce, v2Ct, v2Dec, &rk, 1, 256);
    TEST_ASSERT_BYTES_EQUAL(pt, v2Dec, 32, "V2 CTR roundtrip");

    /* V3: encrypt then decrypt */
    uint8_t v3Ct[32], v3Dec[32];
    rijndael256_ctr_crypt_v3(nonce, pt, v3Ct, &rk, 1, 256);
    rijndael256_ctr_crypt_v3(nonce, v3Ct, v3Dec, &rk, 1, 256);
    TEST_ASSERT_BYTES_EQUAL(pt, v3Dec, 32, "V3 CTR roundtrip");

    /* V2 == V3 */
    TEST_ASSERT_BYTES_EQUAL(v2Ct, v3Ct, 32, "V2 vs V3 CTR consistency");

    printf(COLOR_GREEN "  ✓ CTR roundtrip passed (V2, V3)" COLOR_RESET "\n");
    return 0;
}

static int test_ctr_cpu_gpu(void) {
    TEST_SECTION("CTR CPU vs GPU");

    uint8_t key[32], nonce[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(i * 5 + 17);
        nonce[i] = (uint8_t)(i * 2 + 9);
    }

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    int numBlocks = 128;
    size_t dataSize = numBlocks * 32;
    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *cpuCt = (uint8_t *)malloc(dataSize);
    uint8_t *v2Ct = (uint8_t *)malloc(dataSize);
    uint8_t *v3Ct = (uint8_t *)malloc(dataSize);

    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 41 + 7);

    cpu_ctr_crypt(nonce, pt, cpuCt, &rk, numBlocks);
    rijndael256_ctr_crypt_v2(nonce, pt, v2Ct, &rk, numBlocks, 256);
    rijndael256_ctr_crypt_v3(nonce, pt, v3Ct, &rk, numBlocks, 256);

    int v2Errors = compareResults(cpuCt, v2Ct, numBlocks, "V2 CTR vs CPU");
    TEST_ASSERT(v2Errors == 0, "V2 CTR matches CPU");

    int v3Errors = compareResults(cpuCt, v3Ct, numBlocks, "V3 CTR vs CPU");
    TEST_ASSERT(v3Errors == 0, "V3 CTR matches CPU");

    free(pt); free(cpuCt); free(v2Ct); free(v3Ct);
    return 0;
}

static int test_ctr_keystream_only(void) {
    TEST_SECTION("CTR Keystream Only");

    uint8_t key[32], nonce[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
        nonce[i] = 0;
    }

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    /* Keystream only (plaintext = NULL) */
    uint8_t v2Ks[32], v3Ks[32], cpuKs[32];
    rijndael256_ctr_crypt_v2(nonce, NULL, v2Ks, &rk, 1, 256);
    rijndael256_ctr_crypt_v3(nonce, NULL, v3Ks, &rk, 1, 256);
    cpu_ctr_crypt(nonce, NULL, cpuKs, &rk, 1);

    TEST_ASSERT_BYTES_EQUAL(cpuKs, v2Ks, 32, "V2 keystream matches CPU");
    TEST_ASSERT_BYTES_EQUAL(cpuKs, v3Ks, 32, "V3 keystream matches CPU");

    printf(COLOR_GREEN "  ✓ Keystream-only test passed" COLOR_RESET "\n");
    return 0;
}

static int test_ctr_multiblock(void) {
    TEST_SECTION("CTR Multi-Block (4096 blocks)");

    uint8_t key[32], nonce[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(i ^ 0xDE);
        nonce[i] = (uint8_t)(i ^ 0xAD);
    }

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    int numBlocks = 4096;
    size_t dataSize = numBlocks * 32;
    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *v2Ct = (uint8_t *)malloc(dataSize);
    uint8_t *v3Ct = (uint8_t *)malloc(dataSize);
    uint8_t *v2Dec = (uint8_t *)malloc(dataSize);
    uint8_t *v3Dec = (uint8_t *)malloc(dataSize);

    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 53 + 29);

    rijndael256_ctr_crypt_v2(nonce, pt, v2Ct, &rk, numBlocks, 256);
    rijndael256_ctr_crypt_v3(nonce, pt, v3Ct, &rk, numBlocks, 256);

    /* V2 == V3 */
    int consistencyErrors = compareResults(v2Ct, v3Ct, numBlocks, "V2 vs V3 multi-block");
    TEST_ASSERT(consistencyErrors == 0, "V2 vs V3 multi-block consistency");

    /* Decrypt roundtrip */
    rijndael256_ctr_crypt_v2(nonce, v2Ct, v2Dec, &rk, numBlocks, 256);
    int rtErrors = compareResults(pt, v2Dec, numBlocks, "CTR multi-block roundtrip");
    TEST_ASSERT(rtErrors == 0, "CTR multi-block roundtrip");

    rijndael256_ctr_crypt_v3(nonce, v3Ct, v3Dec, &rk, numBlocks, 256);
    int rtV3Errors = compareResults(pt, v3Dec, numBlocks, "CTR multi-block roundtrip V3");
    TEST_ASSERT(rtV3Errors == 0, "CTR multi-block roundtrip V3");

    free(pt); free(v2Ct); free(v3Ct); free(v2Dec); free(v3Dec);
    return 0;
}

static int test_ctr_128bit_key(void) {
    TEST_SECTION("CTR 128-bit Key");

    uint8_t key[16], nonce[32];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 3 + 0xAA);
    for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(i * 5 + 0x11);

    RijndaelKey rk;
    rijndaelSetupKey(key, 128, &rk);

    int numBlocks = 64;
    size_t dataSize = numBlocks * 32;
    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *cpuCt = (uint8_t *)malloc(dataSize);
    uint8_t *v2Ct = (uint8_t *)malloc(dataSize);
    uint8_t *v3Ct = (uint8_t *)malloc(dataSize);

    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 17 + 3);

    cpu_ctr_crypt(nonce, pt, cpuCt, &rk, numBlocks);
    rijndael256_ctr_crypt_v2(nonce, pt, v2Ct, &rk, numBlocks, 256);
    rijndael256_ctr_crypt_v3(nonce, pt, v3Ct, &rk, numBlocks, 256);

    int v2Errors = compareResults(cpuCt, v2Ct, numBlocks, "V2 CTR 128-bit vs CPU");
    TEST_ASSERT(v2Errors == 0, "V2 CTR 128-bit matches CPU");

    int v3Errors = compareResults(cpuCt, v3Ct, numBlocks, "V3 CTR 128-bit vs CPU");
    TEST_ASSERT(v3Errors == 0, "V3 CTR 128-bit matches CPU");

    /* Roundtrip */
    uint8_t *v2Dec = (uint8_t *)malloc(dataSize);
    rijndael256_ctr_crypt_v2(nonce, v2Ct, v2Dec, &rk, numBlocks, 256);
    int rtErrors = compareResults(pt, v2Dec, numBlocks, "CTR 128-bit roundtrip");
    TEST_ASSERT(rtErrors == 0, "CTR 128-bit roundtrip");

    free(pt); free(cpuCt); free(v2Ct); free(v3Ct); free(v2Dec);
    printf(COLOR_GREEN "  ✓ CTR 128-bit key passed" COLOR_RESET "\n");
    return 0;
}

static int test_ctr_192bit_key(void) {
    TEST_SECTION("CTR 192-bit Key");

    uint8_t key[24], nonce[32];
    for (int i = 0; i < 24; i++) key[i] = (uint8_t)(i * 7 + 0xCC);
    for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(i * 2 + 0x33);

    RijndaelKey rk;
    rijndaelSetupKey(key, 192, &rk);

    int numBlocks = 64;
    size_t dataSize = numBlocks * 32;
    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *cpuCt = (uint8_t *)malloc(dataSize);
    uint8_t *v2Ct = (uint8_t *)malloc(dataSize);
    uint8_t *v3Ct = (uint8_t *)malloc(dataSize);

    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 19 + 7);

    cpu_ctr_crypt(nonce, pt, cpuCt, &rk, numBlocks);
    rijndael256_ctr_crypt_v2(nonce, pt, v2Ct, &rk, numBlocks, 256);
    rijndael256_ctr_crypt_v3(nonce, pt, v3Ct, &rk, numBlocks, 256);

    int v2Errors = compareResults(cpuCt, v2Ct, numBlocks, "V2 CTR 192-bit vs CPU");
    TEST_ASSERT(v2Errors == 0, "V2 CTR 192-bit matches CPU");

    int v3Errors = compareResults(cpuCt, v3Ct, numBlocks, "V3 CTR 192-bit vs CPU");
    TEST_ASSERT(v3Errors == 0, "V3 CTR 192-bit matches CPU");

    free(pt); free(cpuCt); free(v2Ct); free(v3Ct);
    printf(COLOR_GREEN "  ✓ CTR 192-bit key passed" COLOR_RESET "\n");
    return 0;
}

static int test_ctr_nonce_carry(void) {
    TEST_SECTION("CTR Nonce Carry Boundary");

    /*
     * Set lower 64 bits of nonce near overflow (0xFFFFFFFF_FFFFFFFC).
     * With 8 blocks, counters will be:
     * ...FFFFFFFC, ...FFFFFFFD, ...FFFFFFFE, ...FFFFFFFF,
     * ...00000000 (carry), ...00000001, ...00000002, ...00000003
     *
     * CPU reference handles carry via byte-level increment, so
     * GPU must match for correctness at the wrap boundary.
     */
    uint8_t key[32], nonce[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    memset(nonce, 0, sizeof(nonce));
    /* Set nonce bytes 24-31 to 0xFFFFFFFF_FFFFFFFC */
    nonce[24] = 0xFF; nonce[25] = 0xFF; nonce[26] = 0xFF; nonce[27] = 0xFF;
    nonce[28] = 0xFF; nonce[29] = 0xFF; nonce[30] = 0xFF; nonce[31] = 0xFC;

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    int numBlocks = 8;
    size_t dataSize = numBlocks * 32;
    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *cpuCt = (uint8_t *)malloc(dataSize);
    uint8_t *v2Ct = (uint8_t *)malloc(dataSize);
    uint8_t *v3Ct = (uint8_t *)malloc(dataSize);

    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 13);

    cpu_ctr_crypt(nonce, pt, cpuCt, &rk, numBlocks);
    rijndael256_ctr_crypt_v2(nonce, pt, v2Ct, &rk, numBlocks, 256);
    rijndael256_ctr_crypt_v3(nonce, pt, v3Ct, &rk, numBlocks, 256);

    int v2Errors = compareResults(cpuCt, v2Ct, numBlocks, "V2 CTR carry boundary");
    TEST_ASSERT(v2Errors == 0, "V2 CTR carry boundary matches CPU");

    int v3Errors = compareResults(cpuCt, v3Ct, numBlocks, "V3 CTR carry boundary");
    TEST_ASSERT(v3Errors == 0, "V3 CTR carry boundary matches CPU");

    free(pt); free(cpuCt); free(v2Ct); free(v3Ct);
    printf(COLOR_GREEN "  ✓ CTR nonce carry boundary passed" COLOR_RESET "\n");
    return 0;
}

static int test_ctr_zero_block_noop(void) {
    TEST_SECTION("CTR Zero-Block No-Op");

    uint8_t key[32], nonce[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(0xE0 + i);
        nonce[i] = (uint8_t)(0x10 + i);
    }

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    uint8_t out[32];
    memset(out, 0x6D, sizeof(out));
    uint8_t expected[32];
    memcpy(expected, out, sizeof(out));

    rijndael256_ctr_crypt_v2(nonce, NULL, out, &rk, 0, 256);
    TEST_ASSERT_BYTES_EQUAL(expected, out, 32, "CTR V2 zero-block is a no-op");

    rijndael256_ctr_crypt_v3(nonce, NULL, out, &rk, 0, 256);
    TEST_ASSERT_BYTES_EQUAL(expected, out, 32, "CTR V3 zero-block is a no-op");

    printf(COLOR_GREEN "  ✓ CTR zero-block no-op passed" COLOR_RESET "\n");
    return 0;
}

static int test_ctr_thread_configs(void) {
    TEST_SECTION("CTR Thread Config Consistency");

    const int numBlocks = 512;
    const size_t dataSize = numBlocks * 32;
    uint8_t key[32], nonce[32];
    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *refCt = (uint8_t *)malloc(dataSize);
    uint8_t *testCt = (uint8_t *)malloc(dataSize);

    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(i * 11 + 0x21);
        nonce[i] = (uint8_t)(i * 5 + 0x13);
    }
    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 31 + 9);

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    rijndael256_ctr_crypt_v2(nonce, pt, refCt, &rk, numBlocks, 256);

    int threadConfigs[] = {128, 512, 1024};
    int numConfigs = sizeof(threadConfigs) / sizeof(int);

    for (int ci = 0; ci < numConfigs; ci++) {
        int tpb = threadConfigs[ci];
        char msg[128];

        rijndael256_ctr_crypt_v2(nonce, pt, testCt, &rk, numBlocks, tpb);
        sprintf(msg, "CTR V2 tpb=%d matches tpb=256", tpb);
        TEST_ASSERT(compareResults(refCt, testCt, numBlocks, "CTR V2 thread config") == 0, msg);

        rijndael256_ctr_crypt_v3(nonce, pt, testCt, &rk, numBlocks, tpb);
        sprintf(msg, "CTR V3 tpb=%d matches tpb=256", tpb);
        TEST_ASSERT(compareResults(refCt, testCt, numBlocks, "CTR V3 thread config") == 0, msg);
    }

    free(pt);
    free(refCt);
    free(testCt);
    printf(COLOR_GREEN "  ✓ CTR thread config consistency passed" COLOR_RESET "\n");
    return 0;
}

static int test_ctr_kernel_only_api(void) {
    TEST_SECTION("CTR Kernel-Only API");

    const size_t numBlocks = 8;
    const size_t dataSize = numBlocks * 32;
    uint8_t key[32], nonce[32];
    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *cpuCt = (uint8_t *)malloc(dataSize);
    uint8_t *kernelCt = (uint8_t *)malloc(dataSize);
    uint8_t *kernelPt = (uint8_t *)malloc(dataSize);
    uint8_t *d_in = NULL;
    uint8_t *d_out = NULL;

    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(0x80 + i * 3);
        nonce[i] = (uint8_t)(0x10 + i * 7);
    }
    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 47 + 5);

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    cpu_ctr_crypt(nonce, pt, cpuCt, &rk, numBlocks);

    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemcpy(d_in, pt, dataSize, cudaMemcpyHostToDevice));

    rijndael256_ctr_setup(nonce, &rk);

    rijndael256_ctr_launch_v2(d_in, d_out, &rk, numBlocks, 256);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelCt, d_out, dataSize, cudaMemcpyDeviceToHost));
    TEST_ASSERT_BYTES_EQUAL(cpuCt, kernelCt, (int)dataSize, "CTR kernel-only V2 matches CPU");

    CUDA_CHECK(cudaMemcpy(d_in, cpuCt, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ctr_launch_v2(d_in, d_out, &rk, numBlocks, 256);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelPt, d_out, dataSize, cudaMemcpyDeviceToHost));
    TEST_ASSERT_BYTES_EQUAL(pt, kernelPt, (int)dataSize, "CTR kernel-only V2 roundtrip");

    CUDA_CHECK(cudaMemcpy(d_in, pt, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ctr_launch_v3(d_in, d_out, &rk, numBlocks, 256);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelCt, d_out, dataSize, cudaMemcpyDeviceToHost));
    TEST_ASSERT_BYTES_EQUAL(cpuCt, kernelCt, (int)dataSize, "CTR kernel-only V3 matches CPU");

    CUDA_CHECK(cudaMemcpy(d_in, cpuCt, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ctr_launch_v3(d_in, d_out, &rk, numBlocks, 256);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelPt, d_out, dataSize, cudaMemcpyDeviceToHost));
    TEST_ASSERT_BYTES_EQUAL(pt, kernelPt, (int)dataSize, "CTR kernel-only V3 roundtrip");

    rijndael256_ctr_launch_v2(d_in, d_out, &rk, 0, 256);
    rijndael256_ctr_launch_v3(d_in, d_out, &rk, 0, 256);
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
    free(pt);
    free(cpuCt);
    free(kernelCt);
    free(kernelPt);

    printf(COLOR_GREEN "  ✓ CTR kernel-only API passed" COLOR_RESET "\n");
    return 0;
}

int main(void) {
    TEST_RESET();
    printf("Rijndael-256 CTR Mode Tests\n");

    test_ctr_roundtrip();
    test_ctr_cpu_gpu();
    test_ctr_keystream_only();
    test_ctr_multiblock();
    test_ctr_128bit_key();
    test_ctr_192bit_key();
    test_ctr_nonce_carry();
    test_ctr_zero_block_noop();
    test_ctr_thread_configs();
    test_ctr_kernel_only_api();

    TEST_SUMMARY("CTR Mode");
    return TEST_EXIT_CODE();
}
