#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>
#include "rijndael.h"
#include "rijndael_ecb.cuh"
#include "test-vectors.h"
#include "test_utils.h"

/*
 * ECB Mode Tests:
 * 1. Known Answer Test (KAT) - encrypt matches expected ciphertext
 * 2. KAT decrypt - decrypt(ciphertext) == plaintext
 * 3. Encrypt-Decrypt roundtrip
 * 4. V2 vs V3 result consistency
 * 5. Multi-block test
 * 6. Different threadsPerBlock produce same results
 */

static int test_kat_encrypt(void) {
    TEST_SECTION("ECB KAT Encrypt");

    for (int v = 0; v < (int)NUM_TEST_VECTORS; v++) {
        const RijndaelTestVector *tv = &RIJNDAEL_256_TEST_VECTORS[v];
        uint8_t pt[32], key[32], expectedCt[32];
        hexStringToBytes(tv->plaintext, pt, 32);
        hexStringToBytes(tv->ciphertext, expectedCt, 32);
        memset(key, 0, sizeof(key));

        RijndaelKey rk;
        rijndaelSetupKey(key, tv->keySize, &rk);

        /* CPU reference */
        uint8_t cpuCt[32];
        rijndaelEncrypt(&rk, pt, cpuCt);

        char msg[128];
        sprintf(msg, "CPU KAT encrypt keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(expectedCt, cpuCt, 32, msg);

        /* GPU V2 */
        uint8_t gpuCt_v2[32];
        rijndael256_ecb_encrypt_v2(pt, gpuCt_v2, &rk, 1, 256);
        sprintf(msg, "GPU V2 KAT encrypt keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(expectedCt, gpuCt_v2, 32, msg);

        /* GPU V3 */
        uint8_t gpuCt_v3[32];
        rijndael256_ecb_encrypt_v3(pt, gpuCt_v3, &rk, 1, 256);
        sprintf(msg, "GPU V3 KAT encrypt keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(expectedCt, gpuCt_v3, 32, msg);

        printf(COLOR_GREEN "  ✓ KAT encrypt keySize=%d passed (CPU, V2, V3)" COLOR_RESET "\n",
               tv->keySize);
    }
    return 0;
}

static int test_kat_decrypt(void) {
    TEST_SECTION("ECB KAT Decrypt");

    for (int v = 0; v < (int)NUM_TEST_VECTORS; v++) {
        const RijndaelTestVector *tv = &RIJNDAEL_256_TEST_VECTORS[v];
        uint8_t pt[32], key[32], ct[32];
        hexStringToBytes(tv->plaintext, pt, 32);
        hexStringToBytes(tv->ciphertext, ct, 32);
        memset(key, 0, sizeof(key));

        RijndaelKey rk;
        rijndaelSetupKey(key, tv->keySize, &rk);

        /* CPU decrypt */
        uint8_t cpuDec[32];
        rijndaelDecrypt(&rk, ct, cpuDec);

        char msg[128];
        sprintf(msg, "CPU KAT decrypt keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(pt, cpuDec, 32, msg);

        /* GPU V2 decrypt */
        uint8_t gpuDec_v2[32];
        rijndael256_ecb_decrypt_v2(ct, gpuDec_v2, &rk, 1, 256);
        sprintf(msg, "GPU V2 KAT decrypt keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(pt, gpuDec_v2, 32, msg);

        /* GPU V3 decrypt */
        uint8_t gpuDec_v3[32];
        rijndael256_ecb_decrypt_v3(ct, gpuDec_v3, &rk, 1, 256);
        sprintf(msg, "GPU V3 KAT decrypt keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(pt, gpuDec_v3, 32, msg);

        printf(COLOR_GREEN "  ✓ KAT decrypt keySize=%d passed (CPU, V2, V3)" COLOR_RESET "\n",
               tv->keySize);
    }
    return 0;
}

static int test_kat_nontrivial(void) {
    TEST_SECTION("ECB KAT Non-Trivial");

    for (int v = 0; v < (int)NUM_NONTRIVIAL_VECTORS; v++) {
        const RijndaelNonTrivialVector *tv = &RIJNDAEL_256_NONTRIVIAL_VECTORS[v];
        int keyBytes = tv->keySize / 8;
        uint8_t key[32], pt[32], expectedCt[32];
        hexStringToBytes(tv->key, key, keyBytes);
        hexStringToBytes(tv->plaintext, pt, 32);
        hexStringToBytes(tv->ciphertext, expectedCt, 32);

        RijndaelKey rk;
        rijndaelSetupKey(key, tv->keySize, &rk);

        /* CPU */
        uint8_t cpuCt[32];
        rijndaelEncrypt(&rk, pt, cpuCt);
        char msg[128];
        sprintf(msg, "CPU non-trivial KAT keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(expectedCt, cpuCt, 32, msg);

        /* GPU V2 */
        uint8_t gpuCt_v2[32];
        rijndael256_ecb_encrypt_v2(pt, gpuCt_v2, &rk, 1, 256);
        sprintf(msg, "GPU V2 non-trivial KAT keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(expectedCt, gpuCt_v2, 32, msg);

        /* GPU V3 */
        uint8_t gpuCt_v3[32];
        rijndael256_ecb_encrypt_v3(pt, gpuCt_v3, &rk, 1, 256);
        sprintf(msg, "GPU V3 non-trivial KAT keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(expectedCt, gpuCt_v3, 32, msg);

        /* Decrypt roundtrip */
        uint8_t gpuDec[32];
        rijndael256_ecb_decrypt_v2(gpuCt_v2, gpuDec, &rk, 1, 256);
        sprintf(msg, "V2 non-trivial decrypt roundtrip keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(pt, gpuDec, 32, msg);

        rijndael256_ecb_decrypt_v3(gpuCt_v3, gpuDec, &rk, 1, 256);
        sprintf(msg, "V3 non-trivial decrypt roundtrip keySize=%d", tv->keySize);
        TEST_ASSERT_BYTES_EQUAL(pt, gpuDec, 32, msg);

        printf(COLOR_GREEN "  ✓ Non-trivial KAT keySize=%d passed (CPU, V2, V3, roundtrip)" COLOR_RESET "\n",
               tv->keySize);
    }
    return 0;
}

static int test_roundtrip(void) {
    TEST_SECTION("ECB Encrypt-Decrypt Roundtrip");

    int keySizes[] = {128, 192, 256};
    int numKeySizes = sizeof(keySizes) / sizeof(int);

    for (int ki = 0; ki < numKeySizes; ki++) {
        int keySize = keySizes[ki];
        int keyBytes = keySize / 8;

        uint8_t pt[32], key[32];
        for (int i = 0; i < 32; i++) pt[i] = (uint8_t)(i * 7 + 13);
        memset(key, 0, sizeof(key));
        for (int i = 0; i < keyBytes; i++) key[i] = (uint8_t)(i * 11 + 3);

        RijndaelKey rk;
        rijndaelSetupKey(key, keySize, &rk);

        /* CPU roundtrip */
        uint8_t cpuCt[32], cpuDec[32];
        rijndaelEncrypt(&rk, pt, cpuCt);
        rijndaelDecrypt(&rk, cpuCt, cpuDec);
        char msg[128];
        sprintf(msg, "CPU roundtrip keySize=%d", keySize);
        TEST_ASSERT_BYTES_EQUAL(pt, cpuDec, 32, msg);

        /* V2 roundtrip */
        uint8_t v2Ct[32], v2Dec[32];
        rijndael256_ecb_encrypt_v2(pt, v2Ct, &rk, 1, 256);
        rijndael256_ecb_decrypt_v2(v2Ct, v2Dec, &rk, 1, 256);
        sprintf(msg, "V2 roundtrip keySize=%d", keySize);
        TEST_ASSERT_BYTES_EQUAL(pt, v2Dec, 32, msg);

        /* V3 roundtrip */
        uint8_t v3Ct[32], v3Dec[32];
        rijndael256_ecb_encrypt_v3(pt, v3Ct, &rk, 1, 256);
        rijndael256_ecb_decrypt_v3(v3Ct, v3Dec, &rk, 1, 256);
        sprintf(msg, "V3 roundtrip keySize=%d", keySize);
        TEST_ASSERT_BYTES_EQUAL(pt, v3Dec, 32, msg);

        /* V2 vs V3 vs CPU consistency */
        sprintf(msg, "V2 vs V3 encrypt consistency keySize=%d", keySize);
        TEST_ASSERT_BYTES_EQUAL(v2Ct, v3Ct, 32, msg);
        sprintf(msg, "CPU vs V2 encrypt match keySize=%d", keySize);
        TEST_ASSERT_BYTES_EQUAL(cpuCt, v2Ct, 32, msg);

        printf(COLOR_GREEN "  ✓ Roundtrip keySize=%d passed (CPU, V2, V3)" COLOR_RESET "\n", keySize);
    }
    return 0;
}

static int test_multiblock(void) {
    TEST_SECTION("ECB Multi-Block");

    int numBlocks = 1024;
    size_t dataSize = numBlocks * 32;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0xAA);

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *cpuCt = (uint8_t *)malloc(dataSize);
    uint8_t *v2Ct = (uint8_t *)malloc(dataSize);
    uint8_t *v3Ct = (uint8_t *)malloc(dataSize);
    uint8_t *v2Dec = (uint8_t *)malloc(dataSize);
    uint8_t *v3Dec = (uint8_t *)malloc(dataSize);

    /* Fill with pseudo-random data */
    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 37 + 17);

    /* CPU encrypt */
    for (int b = 0; b < numBlocks; b++) {
        rijndaelEncrypt(&rk, pt + b * 32, cpuCt + b * 32);
    }

    /* GPU encrypt */
    rijndael256_ecb_encrypt_v2(pt, v2Ct, &rk, numBlocks, 256);
    rijndael256_ecb_encrypt_v3(pt, v3Ct, &rk, numBlocks, 256);

    int v2Errors = compareResults(cpuCt, v2Ct, numBlocks, "V2 multi-block encrypt");
    TEST_ASSERT(v2Errors == 0, "V2 multi-block encrypt matches CPU");

    int v3Errors = compareResults(cpuCt, v3Ct, numBlocks, "V3 multi-block encrypt");
    TEST_ASSERT(v3Errors == 0, "V3 multi-block encrypt matches CPU");

    /* GPU decrypt roundtrip */
    rijndael256_ecb_decrypt_v2(v2Ct, v2Dec, &rk, numBlocks, 256);
    rijndael256_ecb_decrypt_v3(v3Ct, v3Dec, &rk, numBlocks, 256);

    int decV2Errors = compareResults(pt, v2Dec, numBlocks, "V2 multi-block decrypt");
    TEST_ASSERT(decV2Errors == 0, "V2 multi-block decrypt roundtrip");

    int decV3Errors = compareResults(pt, v3Dec, numBlocks, "V3 multi-block decrypt");
    TEST_ASSERT(decV3Errors == 0, "V3 multi-block decrypt roundtrip");

    free(pt); free(cpuCt); free(v2Ct); free(v3Ct); free(v2Dec); free(v3Dec);
    return 0;
}

static int test_thread_configs(void) {
    TEST_SECTION("ECB Thread Config Consistency");

    int numBlocks = 512;
    size_t dataSize = numBlocks * 32;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 13 + 0x55);

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    uint8_t *pt = (uint8_t *)malloc(dataSize);
    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 23 + 5);

    /* Reference: 256 threads */
    uint8_t *refCt = (uint8_t *)malloc(dataSize);
    rijndael256_ecb_encrypt_v2(pt, refCt, &rk, numBlocks, 256);

    int threadConfigs[] = {128, 512, 1024};
    int numConfigs = sizeof(threadConfigs) / sizeof(int);

    for (int ci = 0; ci < numConfigs; ci++) {
        int tpb = threadConfigs[ci];
        uint8_t *testCt = (uint8_t *)malloc(dataSize);

        /* V2 with different thread count */
        rijndael256_ecb_encrypt_v2(pt, testCt, &rk, numBlocks, tpb);
        int v2Errors = compareResults(refCt, testCt, numBlocks, "V2 thread config");
        char msg[128];
        sprintf(msg, "V2 encrypt tpb=%d matches tpb=256", tpb);
        TEST_ASSERT(v2Errors == 0, msg);

        /* V3 with different thread count */
        rijndael256_ecb_encrypt_v3(pt, testCt, &rk, numBlocks, tpb);
        int v3Errors = compareResults(refCt, testCt, numBlocks, "V3 thread config");
        sprintf(msg, "V3 encrypt tpb=%d matches tpb=256", tpb);
        TEST_ASSERT(v3Errors == 0, msg);

        free(testCt);
    }

    free(pt); free(refCt);
    printf(COLOR_GREEN "  ✓ Thread config consistency passed" COLOR_RESET "\n");
    return 0;
}

static int test_zero_block_noop(void) {
    TEST_SECTION("ECB Zero-Block No-Op");

    uint8_t key[32];
    memset(key, 0xA5, sizeof(key));

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    uint8_t out[32];
    memset(out, 0x5C, sizeof(out));
    uint8_t expected[32];
    memcpy(expected, out, sizeof(out));

    rijndael256_ecb_encrypt_v2(NULL, out, &rk, 0, 256);
    TEST_ASSERT_BYTES_EQUAL(expected, out, 32, "ECB encrypt V2 zero-block is a no-op");

    rijndael256_ecb_decrypt_v2(NULL, out, &rk, 0, 256);
    TEST_ASSERT_BYTES_EQUAL(expected, out, 32, "ECB decrypt V2 zero-block is a no-op");

    rijndael256_ecb_encrypt_v3(NULL, out, &rk, 0, 256);
    TEST_ASSERT_BYTES_EQUAL(expected, out, 32, "ECB encrypt V3 zero-block is a no-op");

    rijndael256_ecb_decrypt_v3(NULL, out, &rk, 0, 256);
    TEST_ASSERT_BYTES_EQUAL(expected, out, 32, "ECB decrypt V3 zero-block is a no-op");

    printf(COLOR_GREEN "  ✓ ECB zero-block no-op passed" COLOR_RESET "\n");
    return 0;
}

static int test_kernel_only_api(void) {
    TEST_SECTION("ECB Kernel-Only API");

    const size_t numBlocks = 8;
    const size_t dataSize = numBlocks * 32;
    uint8_t key[32];
    uint8_t *pt = (uint8_t *)malloc(dataSize);
    uint8_t *cpuCt = (uint8_t *)malloc(dataSize);
    uint8_t *kernelCt = (uint8_t *)malloc(dataSize);
    uint8_t *kernelPt = (uint8_t *)malloc(dataSize);
    uint8_t *d_in = NULL;
    uint8_t *d_out = NULL;

    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x30 + i * 9);
    for (int i = 0; i < (int)dataSize; i++) pt[i] = (uint8_t)(i * 29 + 7);

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    for (size_t b = 0; b < numBlocks; b++) {
        rijndaelEncrypt(&rk, pt + b * 32, cpuCt + b * 32);
    }

    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemcpy(d_in, pt, dataSize, cudaMemcpyHostToDevice));

    rijndael256_ecb_setup_keys(&rk);

    rijndael256_ecb_launch_encrypt_v2(d_in, d_out, &rk, numBlocks, 256);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelCt, d_out, dataSize, cudaMemcpyDeviceToHost));
    TEST_ASSERT_BYTES_EQUAL(cpuCt, kernelCt, (int)dataSize, "ECB kernel-only V2 encrypt matches CPU");

    CUDA_CHECK(cudaMemcpy(d_in, cpuCt, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ecb_launch_decrypt_v2(d_in, d_out, &rk, numBlocks, 256);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelPt, d_out, dataSize, cudaMemcpyDeviceToHost));
    TEST_ASSERT_BYTES_EQUAL(pt, kernelPt, (int)dataSize, "ECB kernel-only V2 decrypt roundtrip");

    CUDA_CHECK(cudaMemcpy(d_in, pt, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ecb_launch_encrypt_v3(d_in, d_out, &rk, numBlocks, 256);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelCt, d_out, dataSize, cudaMemcpyDeviceToHost));
    TEST_ASSERT_BYTES_EQUAL(cpuCt, kernelCt, (int)dataSize, "ECB kernel-only V3 encrypt matches CPU");

    CUDA_CHECK(cudaMemcpy(d_in, cpuCt, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ecb_launch_decrypt_v3(d_in, d_out, &rk, numBlocks, 256);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelPt, d_out, dataSize, cudaMemcpyDeviceToHost));
    TEST_ASSERT_BYTES_EQUAL(pt, kernelPt, (int)dataSize, "ECB kernel-only V3 decrypt roundtrip");

    rijndael256_ecb_launch_encrypt_v2(d_in, d_out, &rk, 0, 256);
    rijndael256_ecb_launch_encrypt_v3(d_in, d_out, &rk, 0, 256);
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
    free(pt);
    free(cpuCt);
    free(kernelCt);
    free(kernelPt);

    printf(COLOR_GREEN "  ✓ ECB kernel-only API passed" COLOR_RESET "\n");
    return 0;
}

int main(void) {
    TEST_RESET();
    printf("Rijndael-256 ECB Mode Tests\n");

    test_kat_encrypt();
    test_kat_decrypt();
    test_kat_nontrivial();
    test_roundtrip();
    test_multiblock();
    test_thread_configs();
    test_zero_block_noop();
    test_kernel_only_api();

    TEST_SUMMARY("ECB Mode");
    return TEST_EXIT_CODE();
}
