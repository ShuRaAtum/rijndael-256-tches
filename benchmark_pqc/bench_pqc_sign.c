/*
 * PQC Signature Algorithm Benchmark
 *
 * Measures keygen, sign, verify for NIST PQC signature algorithms
 * with Rijndael-256 integration (Reference, NEON, ARM Crypto).
 *
 * Usage:
 *   ./bench_pqc_sign [--csv] [--iterations N]
 *
 * This file is compiled alongside each algorithm's implementation.
 * Define one of: BENCH_SDITH, BENCH_MIRATH, BENCH_RYDE, BENCH_MQOM, BENCH_FAEST
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* NIST PQC KEM/Sign API */
#include "api.h"

#ifndef ALGORITHM_NAME
#define ALGORITHM_NAME "unknown"
#endif

#ifndef IMPL_NAME
#define IMPL_NAME "ref"
#endif

#ifndef SECURITY_LEVEL
#define SECURITY_LEVEL "unknown"
#endif

#define DEFAULT_ITERATIONS 100
#define WARMUP_ITERATIONS 5
#define MSG_LEN 32  /* 32-byte message */

/* Get time in nanoseconds for high precision */
static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Median of sorted array */
static double median_ms(uint64_t *times, int n) {
    /* Simple insertion sort */
    for (int i = 1; i < n; i++) {
        uint64_t key = times[i];
        int j = i - 1;
        while (j >= 0 && times[j] > key) {
            times[j + 1] = times[j];
            j--;
        }
        times[j + 1] = key;
    }
    if (n % 2 == 0) {
        return ((double)times[n/2 - 1] + (double)times[n/2]) / 2.0 / 1e6;
    } else {
        return (double)times[n/2] / 1e6;
    }
}

int main(int argc, char *argv[]) {
    int csv_mode = 0;
    int iterations = DEFAULT_ITERATIONS;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--csv") == 0) {
            csv_mode = 1;
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iterations = atoi(argv[++i]);
            if (iterations < 1) iterations = DEFAULT_ITERATIONS;
        }
    }

    /* Allocate buffers */
    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char *sig = malloc(CRYPTO_BYTES + MSG_LEN);
    unsigned char msg[MSG_LEN];
    unsigned long long siglen = 0;

    if (!pk || !sk || !sig) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    /* Initialize message */
    for (int i = 0; i < MSG_LEN; i++) {
        msg[i] = (unsigned char)(i * 17 + 5);
    }

    /* Allocate timing arrays */
    uint64_t *keygen_times = malloc(iterations * sizeof(uint64_t));
    uint64_t *sign_times = malloc(iterations * sizeof(uint64_t));
    uint64_t *verify_times = malloc(iterations * sizeof(uint64_t));

    if (!keygen_times || !sign_times || !verify_times) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    if (!csv_mode) {
        printf("========================================\n");
        printf("  PQC Signature Benchmark\n");
        printf("  Algorithm: %s\n", ALGORITHM_NAME);
        printf("  Level:     %s\n", SECURITY_LEVEL);
        printf("  Impl:      %s\n", IMPL_NAME);
        printf("  Iterations: %d\n", iterations);
        printf("  PK size:   %d bytes\n", CRYPTO_PUBLICKEYBYTES);
        printf("  SK size:   %d bytes\n", CRYPTO_SECRETKEYBYTES);
        printf("  Sig size:  %d bytes\n", CRYPTO_BYTES);
        printf("========================================\n\n");
    }

    /* Warmup */
    if (!csv_mode) printf("Warming up (%d iterations)...\n", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        crypto_sign_keypair(pk, sk);
        crypto_sign(sig, &siglen, msg, MSG_LEN, sk);
        crypto_sign_open(msg, (unsigned long long *)&siglen, sig, siglen, pk);
    }

    /* Benchmark keygen */
    if (!csv_mode) printf("Benchmarking keygen...\n");
    for (int i = 0; i < iterations; i++) {
        uint64_t start = get_time_ns();
        crypto_sign_keypair(pk, sk);
        uint64_t end = get_time_ns();
        keygen_times[i] = end - start;
    }

    /* Generate a keypair for sign/verify benchmarks */
    crypto_sign_keypair(pk, sk);

    /* Benchmark sign */
    if (!csv_mode) printf("Benchmarking sign...\n");
    for (int i = 0; i < iterations; i++) {
        uint64_t start = get_time_ns();
        crypto_sign(sig, &siglen, msg, MSG_LEN, sk);
        uint64_t end = get_time_ns();
        sign_times[i] = end - start;
    }

    /* Benchmark verify */
    if (!csv_mode) printf("Benchmarking verify...\n");
    /* Generate a valid signature first */
    crypto_sign(sig, &siglen, msg, MSG_LEN, sk);
    for (int i = 0; i < iterations; i++) {
        unsigned char msg_out[MSG_LEN + CRYPTO_BYTES];
        unsigned long long msg_out_len = 0;
        uint64_t start = get_time_ns();
        int ret = crypto_sign_open(msg_out, &msg_out_len, sig, siglen, pk);
        uint64_t end = get_time_ns();
        verify_times[i] = end - start;
        if (ret != 0) {
            fprintf(stderr, "ERROR: verify failed at iteration %d\n", i);
            return 1;
        }
    }

    /* Compute medians */
    double keygen_ms = median_ms(keygen_times, iterations);
    double sign_ms = median_ms(sign_times, iterations);
    double verify_ms = median_ms(verify_times, iterations);

    if (csv_mode) {
        /* CSV: algorithm,level,impl,keygen_ms,sign_ms,verify_ms */
        printf("%s,%s,%s,%.3f,%.3f,%.3f\n",
               ALGORITHM_NAME, SECURITY_LEVEL, IMPL_NAME,
               keygen_ms, sign_ms, verify_ms);
    } else {
        printf("\n========================================\n");
        printf("  Results (median of %d iterations)\n", iterations);
        printf("========================================\n\n");
        printf("  %-12s: %10.3f ms\n", "Keygen", keygen_ms);
        printf("  %-12s: %10.3f ms\n", "Sign", sign_ms);
        printf("  %-12s: %10.3f ms\n", "Verify", verify_ms);
        printf("\n");
    }

    /* Cleanup */
    free(pk);
    free(sk);
    free(sig);
    free(keygen_times);
    free(sign_times);
    free(verify_times);

    return 0;
}
