/*
 * Rijndael-256 Benchmark
 *
 * Compares performance of four implementations:
 * - Native C (reference)
 * - T-table (lookup table optimization)
 * - NEON SIMD (TBL/TBX software, 4-block parallel)
 * - ARM Crypto Extension (hardware accelerated)
 *
 * Supports:
 * - Multiple key sizes (128, 192, 256 bits)
 * - Encrypt and decrypt benchmarks
 * - CSV output (--csv flag)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "rijndael256.h"
#include "aes_baseline_arm.h"
#include "rijndael256_folded_arm.h"

#define BLOCK_SIZE 32                   /* 256 bits = 32 bytes */
#define NUM_BLOCKS (1024 * 1024)        /* 1M blocks = 32 MB */
#define NUM_ITERATIONS 10               /* Number of benchmark runs */

/* Get time in milliseconds */
static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

/* Function pointer type for single-block encrypt/decrypt */
typedef void (*encrypt_func_t)(const void*, const uint8_t*, uint8_t*);

/* Benchmark a single implementation (single-block) */
static double benchmark_impl(const char *name,
                              encrypt_func_t func,
                              const void *ctx,
                              const uint8_t *data,
                              size_t num_blocks) {
    uint8_t ct[BLOCK_SIZE];
    volatile uint8_t sink;  /* Prevent optimization */

    double start = get_time_ms();

    for (size_t i = 0; i < num_blocks; i++) {
        func(ctx, data + i * BLOCK_SIZE, ct);
    }

    double end = get_time_ms();

    /* Use the result to prevent optimization */
    sink = ct[0];
    (void)sink;

    return end - start;
}

/* Benchmark 4-block parallel implementations */
static double benchmark_impl_4pt(const char *name,
                                  void (*encrypt_4pt)(const Rijndael256Key*, const uint8_t*, uint8_t*),
                                  const Rijndael256Key *ctx,
                                  const uint8_t *data,
                                  size_t num_blocks) {
    uint8_t ct[128];  /* 4 blocks */
    volatile uint8_t sink;

    double start = get_time_ms();

    /* Process 4 blocks at a time */
    for (size_t i = 0; i < num_blocks; i += 4) {
        encrypt_4pt(ctx, data + i * BLOCK_SIZE, ct);
    }

    double end = get_time_ms();

    sink = ct[0];
    (void)sink;

    return end - start;
}

/* Batched harness: f processes N blocks per call; loop over num_blocks. */
static double benchmark_batched(encrypt_func_t f, const void *ctx,
                                const uint8_t *data, size_t num_blocks,
                                int N, int block_bytes) {
    uint8_t out[8 * 32];           /* up to 8 blocks * 32 bytes */
    volatile uint8_t sink;
    double start = get_time_ms();
    for (size_t i = 0; i + (size_t)N <= num_blocks; i += (size_t)N)
        f(ctx, data + i * (size_t)block_bytes, out);
    double end = get_time_ms();
    sink = out[0]; (void)sink;
    return end - start;
}

/* best-of-NUM_ITERATIONS wall time (ms) for single-block and batched paths */
static double best_single(encrypt_func_t f, const void *ctx, const uint8_t *data) {
    double best = 1e30;
    for (int it = 0; it < NUM_ITERATIONS; it++) {
        double t = benchmark_impl("", f, ctx, data, NUM_BLOCKS);
        if (t < best) best = t;
    }
    return best;
}
static double best_batched(encrypt_func_t f, const void *ctx, const uint8_t *data,
                           int N, int block_bytes) {
    double best = 1e30;
    for (int it = 0; it < NUM_ITERATIONS; it++) {
        double t = benchmark_batched(f, ctx, data, NUM_BLOCKS, N, block_bytes);
        if (t < best) best = t;
    }
    return best;
}

/* ---- Encrypt wrapper functions ---- */

static void encrypt_ref_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_ref((const Rijndael256Key*)ctx, pt, ct);
}

static void encrypt_ttable_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_ttable((const Rijndael256KeyTTable*)ctx, pt, ct);
}

static void encrypt_arm_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_arm((const Rijndael256Key*)ctx, pt, ct);
}

static void encrypt_neon_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_neon((const Rijndael256Key*)ctx, pt, ct);
}

/* AES hardware baselines (16-byte block) routed through the same harness */
static void aes128_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    aes128_encrypt_arm((const AesKey*)ctx, pt, ct);
}

static void aes256_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    aes256_encrypt_arm((const AesKey*)ctx, pt, ct);
}

/* R256 ARM-Crypto with AddRoundKey folded into AESE (pre-shuffled round keys) */
static void encrypt_arm_folded_wrapper(const void *ctx, const uint8_t *pt, uint8_t *ct) {
    rijndael256_encrypt_arm_folded((const R256FoldedKey*)ctx, pt, ct);
}

/* Interleaved (xN) wrappers for the batched harness */
#define WRAP_XN(name, fn, KT) \
    static void name(const void *c, const uint8_t *i, uint8_t *o) { fn((const KT*)c, i, o); }
WRAP_XN(aes128_x2_w, aes128_encrypt_arm_x2, AesKey)
WRAP_XN(aes128_x4_w, aes128_encrypt_arm_x4, AesKey)
WRAP_XN(aes128_x8_w, aes128_encrypt_arm_x8, AesKey)
WRAP_XN(aes256_x2_w, aes256_encrypt_arm_x2, AesKey)
WRAP_XN(aes256_x4_w, aes256_encrypt_arm_x4, AesKey)
WRAP_XN(aes256_x8_w, aes256_encrypt_arm_x8, AesKey)
WRAP_XN(folded_x2_w, rijndael256_encrypt_arm_folded_x2, R256FoldedKey)
WRAP_XN(folded_x4_w, rijndael256_encrypt_arm_folded_x4, R256FoldedKey)
WRAP_XN(folded_x8_w, rijndael256_encrypt_arm_folded_x8, R256FoldedKey)

/* ---- Decrypt wrapper functions ---- */

static void decrypt_ref_wrapper(const void *ctx, const uint8_t *ct, uint8_t *pt) {
    rijndael256_decrypt_ref((const Rijndael256Key*)ctx, ct, pt);
}

static void decrypt_ttable_wrapper(const void *ctx, const uint8_t *ct, uint8_t *pt) {
    rijndael256_decrypt_ttable((const Rijndael256KeyTTable*)ctx, ct, pt);
}

static void decrypt_arm_wrapper(const void *ctx, const uint8_t *ct, uint8_t *pt) {
    rijndael256_decrypt_arm((const Rijndael256Key*)ctx, ct, pt);
}

/* Print results (human-readable mode) */
static void print_result(const char *name, double time_ms, size_t bytes, double baseline_ms) {
    double mb = bytes / (1024.0 * 1024.0);
    double throughput = mb / (time_ms / 1000.0);
    double speedup = baseline_ms / time_ms;

    printf("  %-15s: %8.2f ms  %8.2f MB/s  %6.2fx\n",
           name, time_ms, throughput, speedup);
}

/* Print CSV row */
static void print_csv_row(int key_bits, const char *impl, const char *direction,
                           double time_ms, size_t bytes) {
    double mb = bytes / (1024.0 * 1024.0);
    double throughput = mb / (time_ms / 1000.0);
    printf("%d,%s,%s,%.2f,%.2f\n", key_bits, impl, direction, time_ms, throughput);
}

/* Print N/A CSV row (for unavailable decrypt) */
static void print_csv_row_na(int key_bits, const char *impl, const char *direction) {
    printf("%d,%s,%s,N/A,N/A\n", key_bits, impl, direction);
}

int main(int argc, char *argv[]) {
    int csv_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--csv") == 0) {
            csv_mode = 1;
        }
    }

    if (!csv_mode) {
        printf("========================================\n");
        printf("    Rijndael-256 Benchmark\n");
        printf("========================================\n\n");
    }

    /* Allocate test data */
    size_t data_size = NUM_BLOCKS * BLOCK_SIZE;
    uint8_t *data = (uint8_t*)malloc(data_size);
    if (!data) {
        fprintf(stderr, "Failed to allocate %zu bytes\n", data_size);
        return 1;
    }

    /* Initialize test data with pseudo-random values */
    for (size_t i = 0; i < data_size; i++) {
        data[i] = (uint8_t)(i * 17 + 5);
    }

    /* Setup key (32 bytes covers all key sizes) */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(i * 31 + 11);
    }

    /* Check ARM Crypto availability */
    int has_arm = rijndael256_has_arm_crypto();

    if (!csv_mode) {
        printf("Configuration:\n");
        printf("  Block size:    %d bytes (256 bits)\n", BLOCK_SIZE);
        printf("  Key sizes:     128, 192, 256 bits\n");
        printf("  Blocks:        %d (%.1f MB)\n", NUM_BLOCKS, data_size / (1024.0 * 1024.0));
        printf("  Iterations:    %d\n", NUM_ITERATIONS);
        printf("\n");
        printf("ARM Crypto Extension: %s\n\n", has_arm ? "Available" : "Not available");
    }

    /* Key sizes to benchmark */
    int key_sizes[] = {128, 192, 256};
    int num_key_sizes = 3;

    /* CSV header */
    if (csv_mode) {
        printf("key_bits,impl,direction,time_ms,throughput_mbps\n");
    }

    for (int ks = 0; ks < num_key_sizes; ks++) {
        int keyBits = key_sizes[ks];

        /* Setup keys for this key size */
        Rijndael256Key ctx_ref, ctx_arm, ctx_neon;
        Rijndael256KeyTTable ctx_ttable;

        rijndael256_setup_key(key, keyBits, &ctx_ref);
        rijndael256_setup_key_ttable(key, keyBits, &ctx_ttable);
        rijndael256_setup_key(key, keyBits, &ctx_arm);
        rijndael256_setup_key(key, keyBits, &ctx_neon);

        if (!csv_mode) {
            printf("========================================\n");
            printf("    Key Size: %d bits (%d rounds)\n", keyBits, ctx_ref.rounds);
            printf("========================================\n\n");

            /* Warmup */
            printf("Warming up...\n");
        }

        uint8_t dummy[BLOCK_SIZE];
        for (int i = 0; i < 10000; i++) {
            rijndael256_encrypt_ref(&ctx_ref, data, dummy);
            rijndael256_encrypt_ttable(&ctx_ttable, data, dummy);
            rijndael256_encrypt_neon(&ctx_neon, data, dummy);
            rijndael256_decrypt_ref(&ctx_ref, data, dummy);
            rijndael256_decrypt_ttable(&ctx_ttable, data, dummy);
            if (has_arm) {
                rijndael256_encrypt_arm(&ctx_arm, data, dummy);
                rijndael256_decrypt_arm(&ctx_arm, data, dummy);
            }
        }

        /* Accumulators for encrypt */
        double total_enc_ref = 0, total_enc_ttable = 0;
        double total_enc_neon = 0, total_enc_neon_4pt = 0, total_enc_neon_il_4pt = 0;
        double total_enc_arm = 0;

        /* Accumulators for decrypt */
        double total_dec_ref = 0, total_dec_ttable = 0;
        double total_dec_arm = 0;

        if (!csv_mode) {
            printf("\nRunning benchmarks (%d iterations)...\n\n", NUM_ITERATIONS);
        }

        for (int iter = 0; iter < NUM_ITERATIONS; iter++) {
            if (!csv_mode) {
                printf("Iteration %d/%d:\n", iter + 1, NUM_ITERATIONS);
            }

            /* ---- Encrypt benchmarks ---- */

            double time_enc_ref = benchmark_impl("Reference",
                                                  encrypt_ref_wrapper,
                                                  &ctx_ref,
                                                  data, NUM_BLOCKS);
            total_enc_ref += time_enc_ref;

            double time_enc_ttable = benchmark_impl("T-table",
                                                     encrypt_ttable_wrapper,
                                                     &ctx_ttable,
                                                     data, NUM_BLOCKS);
            total_enc_ttable += time_enc_ttable;

            double time_enc_neon = benchmark_impl("NEON Single",
                                                   encrypt_neon_wrapper,
                                                   &ctx_neon,
                                                   data, NUM_BLOCKS);
            total_enc_neon += time_enc_neon;

            double time_enc_neon_4pt = benchmark_impl_4pt("NEON 4PT",
                                                           rijndael256_encrypt_neon_4pt,
                                                           &ctx_neon,
                                                           data, NUM_BLOCKS);
            total_enc_neon_4pt += time_enc_neon_4pt;

            double time_enc_neon_il_4pt = benchmark_impl_4pt("NEON IL 4PT",
                                                              rijndael256_encrypt_neon_il_4pt,
                                                              &ctx_neon,
                                                              data, NUM_BLOCKS);
            total_enc_neon_il_4pt += time_enc_neon_il_4pt;

            double time_enc_arm = 0;
            if (has_arm) {
                time_enc_arm = benchmark_impl("ARM Crypto",
                                               encrypt_arm_wrapper,
                                               &ctx_arm,
                                               data, NUM_BLOCKS);
                total_enc_arm += time_enc_arm;
            }

            /* ---- Decrypt benchmarks ---- */

            double time_dec_ref = benchmark_impl("Reference",
                                                  decrypt_ref_wrapper,
                                                  &ctx_ref,
                                                  data, NUM_BLOCKS);
            total_dec_ref += time_dec_ref;

            double time_dec_ttable = benchmark_impl("T-table",
                                                     decrypt_ttable_wrapper,
                                                     &ctx_ttable,
                                                     data, NUM_BLOCKS);
            total_dec_ttable += time_dec_ttable;

            double time_dec_arm = 0;
            if (has_arm) {
                time_dec_arm = benchmark_impl("ARM Crypto",
                                               decrypt_arm_wrapper,
                                               &ctx_arm,
                                               data, NUM_BLOCKS);
                total_dec_arm += time_dec_arm;
            }

            /* Print per-iteration results */
            if (!csv_mode) {
                printf("  [Encrypt]\n");
                print_result("Reference", time_enc_ref, data_size, time_enc_ref);
                print_result("T-table", time_enc_ttable, data_size, time_enc_ref);
                print_result("NEON Single", time_enc_neon, data_size, time_enc_ref);
                print_result("NEON 4PT", time_enc_neon_4pt, data_size, time_enc_ref);
                print_result("NEON IL 4PT", time_enc_neon_il_4pt, data_size, time_enc_ref);
                if (has_arm) {
                    print_result("ARM Crypto", time_enc_arm, data_size, time_enc_ref);
                }

                printf("  [Decrypt]\n");
                print_result("Reference", time_dec_ref, data_size, time_dec_ref);
                print_result("T-table", time_dec_ttable, data_size, time_dec_ref);
                printf("  %-15s: %8s     %8s       %6s\n", "NEON Single", "N/A", "N/A", "N/A");
                printf("  %-15s: %8s     %8s       %6s\n", "NEON 4PT", "N/A", "N/A", "N/A");
                printf("  %-15s: %8s     %8s       %6s\n", "NEON IL 4PT", "N/A", "N/A", "N/A");
                if (has_arm) {
                    print_result("ARM Crypto", time_dec_arm, data_size, time_dec_ref);
                }

                printf("\n");
            }
        }

        /* Calculate averages */
        double avg_enc_ref = total_enc_ref / NUM_ITERATIONS;
        double avg_enc_ttable = total_enc_ttable / NUM_ITERATIONS;
        double avg_enc_neon = total_enc_neon / NUM_ITERATIONS;
        double avg_enc_neon_4pt = total_enc_neon_4pt / NUM_ITERATIONS;
        double avg_enc_neon_il_4pt = total_enc_neon_il_4pt / NUM_ITERATIONS;
        double avg_enc_arm = has_arm ? total_enc_arm / NUM_ITERATIONS : 0;

        double avg_dec_ref = total_dec_ref / NUM_ITERATIONS;
        double avg_dec_ttable = total_dec_ttable / NUM_ITERATIONS;
        double avg_dec_arm = has_arm ? total_dec_arm / NUM_ITERATIONS : 0;

        if (csv_mode) {
            /* CSV output: one row per (key_size, impl, direction) */
            print_csv_row(keyBits, "Reference",   "encrypt", avg_enc_ref, data_size);
            print_csv_row(keyBits, "Reference",   "decrypt", avg_dec_ref, data_size);
            print_csv_row(keyBits, "T-table",     "encrypt", avg_enc_ttable, data_size);
            print_csv_row(keyBits, "T-table",     "decrypt", avg_dec_ttable, data_size);
            print_csv_row(keyBits, "NEON Single", "encrypt", avg_enc_neon, data_size);
            print_csv_row_na(keyBits, "NEON Single", "decrypt");
            print_csv_row(keyBits, "NEON 4PT",    "encrypt", avg_enc_neon_4pt, data_size);
            print_csv_row_na(keyBits, "NEON 4PT",    "decrypt");
            print_csv_row(keyBits, "NEON IL 4PT", "encrypt", avg_enc_neon_il_4pt, data_size);
            print_csv_row_na(keyBits, "NEON IL 4PT", "decrypt");
            if (has_arm) {
                print_csv_row(keyBits, "ARM Crypto", "encrypt", avg_enc_arm, data_size);
                print_csv_row(keyBits, "ARM Crypto", "decrypt", avg_dec_arm, data_size);
            }
        } else {
            /* Human-readable summary for this key size */
            printf("========================================\n");
            printf("    Summary: %d-bit key (avg over %d runs)\n", keyBits, NUM_ITERATIONS);
            printf("========================================\n\n");

            printf("%-15s  %10s  %12s  %8s\n", "Implementation", "Time (ms)", "Throughput", "Speedup");
            printf("%-15s  %10s  %12s  %8s\n", "---------------", "----------", "------------", "--------");

            printf("\n  [Encrypt]\n");
            print_result("Reference", avg_enc_ref, data_size, avg_enc_ref);
            print_result("T-table", avg_enc_ttable, data_size, avg_enc_ref);
            print_result("NEON Single", avg_enc_neon, data_size, avg_enc_ref);
            print_result("NEON 4PT", avg_enc_neon_4pt, data_size, avg_enc_ref);
            print_result("NEON IL 4PT", avg_enc_neon_il_4pt, data_size, avg_enc_ref);
            if (has_arm) {
                print_result("ARM Crypto", avg_enc_arm, data_size, avg_enc_ref);
            }

            printf("\n  [Decrypt]\n");
            print_result("Reference", avg_dec_ref, data_size, avg_dec_ref);
            print_result("T-table", avg_dec_ttable, data_size, avg_dec_ref);
            printf("  %-15s: %8s     %8s       %6s\n", "NEON Single", "N/A", "N/A", "N/A");
            printf("  %-15s: %8s     %8s       %6s\n", "NEON 4PT", "N/A", "N/A", "N/A");
            printf("  %-15s: %8s     %8s       %6s\n", "NEON IL 4PT", "N/A", "N/A", "N/A");
            if (has_arm) {
                print_result("ARM Crypto", avg_dec_arm, data_size, avg_dec_ref);
            }

            /* Performance analysis */
            printf("\n  Performance Analysis (Encrypt):\n");
            printf("    T-table vs Reference:      %.2fx faster\n", avg_enc_ref / avg_enc_ttable);
            printf("    NEON 4PT vs Reference:     %.2fx faster\n", avg_enc_ref / avg_enc_neon_4pt);
            printf("    NEON 4PT vs T-table:       %.2fx faster\n", avg_enc_ttable / avg_enc_neon_4pt);
            printf("    NEON IL 4PT vs Reference:  %.2fx faster\n", avg_enc_ref / avg_enc_neon_il_4pt);
            printf("    NEON IL 4PT vs NEON 4PT:   %.2fx\n", avg_enc_neon_4pt / avg_enc_neon_il_4pt);
            if (has_arm) {
                printf("    ARM Crypto vs Reference:   %.2fx faster\n", avg_enc_ref / avg_enc_arm);
                printf("    ARM Crypto vs T-table:     %.2fx faster\n", avg_enc_ttable / avg_enc_arm);
                printf("    ARM Crypto vs NEON 4PT:    %.2fx faster\n", avg_enc_neon_4pt / avg_enc_arm);
            }

            printf("\n  Performance Analysis (Decrypt):\n");
            printf("    T-table vs Reference:      %.2fx faster\n", avg_dec_ref / avg_dec_ttable);
            if (has_arm) {
                printf("    ARM Crypto vs Reference:   %.2fx faster\n", avg_dec_ref / avg_dec_arm);
                printf("    ARM Crypto vs T-table:     %.2fx faster\n", avg_dec_ttable / avg_dec_arm);
            }

            printf("\n");
        }
    }

    /* ================================================================
     * AES -> R256 hardware baseline (same single-block harness).
     * AES-128 (10R) and AES-256 (14R, round-matched to R256) measured with
     * benchmark_impl exactly like the R256 ARM-Crypto path, so the per-byte
     * slowdown ratio is internally consistent (same binary, same method).
     * ================================================================ */
    if (has_arm && aes_baseline_available()) {
        int st = aes_baseline_selftest();
        if (st != 0) {
            fprintf(stderr, "FATAL: AES baseline FIPS-197 self-test FAILED (code %d)\n", st);
            free(data);
            return 2;
        }

        /* Folded variant self-test (KAT vs reference) */
        if (rijndael256_folded_available()) {
            int fst = rijndael256_folded_selftest();
            if (fst != 0) {
                fprintf(stderr, "FATAL: R256 folded variant KAT FAILED (code %d)\n", fst);
                free(data);
                return 3;
            }
        }

        AesKey aes128, aes256;
        aes_key_expand(key, 128, &aes128);
        aes_key_expand(key, 256, &aes256);
        Rijndael256Key ctx_r256;
        rijndael256_setup_key(key, 256, &ctx_r256);   /* 256-bit key, 14 rounds */
        R256FoldedKey fk_r256;
        rijndael256_folded_setup(&ctx_r256, &fk_r256);

        /* Warmup (single + interleaved paths) */
        uint8_t wbig[8 * 32];
        for (int i = 0; i < 10000; i++) {
            aes128_encrypt_arm(&aes128, data, wbig);
            aes256_encrypt_arm(&aes256, data, wbig);
            rijndael256_encrypt_arm(&ctx_r256, data, wbig);
            rijndael256_encrypt_arm_folded(&fk_r256, data, wbig);
            rijndael256_encrypt_arm_folded_x4(&fk_r256, data, wbig);
            aes256_encrypt_arm_x4(&aes256, data, wbig);
        }

        const double mb_aes = (double)NUM_BLOCKS * 16.0 / (1024.0 * 1024.0);
        const double mb_r   = (double)NUM_BLOCKS * 32.0 / (1024.0 * 1024.0);
        #define MBPS(best_ms, mb) ((mb) / ((best_ms) / 1000.0))

        /* single-block (best-of NUM_ITERATIONS) */
        double s_a128 = MBPS(best_single(aes128_wrapper,             &aes128,   data), mb_aes);
        double s_a256 = MBPS(best_single(aes256_wrapper,             &aes256,   data), mb_aes);
        double s_eor  = MBPS(best_single(encrypt_arm_wrapper,        &ctx_r256, data), mb_r);
        double s_fold = MBPS(best_single(encrypt_arm_folded_wrapper, &fk_r256,  data), mb_r);

        /* interleaved N = 2,4,8 */
        const int Ns[3] = {2, 4, 8};
        encrypt_func_t a128f[3] = {aes128_x2_w, aes128_x4_w, aes128_x8_w};
        encrypt_func_t a256f[3] = {aes256_x2_w, aes256_x4_w, aes256_x8_w};
        encrypt_func_t foldf[3] = {folded_x2_w, folded_x4_w, folded_x8_w};
        double i_a128[3], i_a256[3], i_fold[3];
        for (int j = 0; j < 3; j++) {
            i_a128[j] = MBPS(best_batched(a128f[j], &aes128,  data, Ns[j], 16), mb_aes);
            i_a256[j] = MBPS(best_batched(a256f[j], &aes256,  data, Ns[j], 16), mb_aes);
            i_fold[j] = MBPS(best_batched(foldf[j], &fk_r256, data, Ns[j], 32), mb_r);
        }
        int bj = 0;
        for (int j = 1; j < 3; j++) if (i_fold[j] > i_fold[bj]) bj = j;
        int bestN = Ns[bj];

        if (csv_mode) {
            printf("%d,%s,%s,%.2f\n", 128, "AES-128",     "single",  s_a128);
            printf("%d,%s,%s,%.2f\n", 256, "AES-256",     "single",  s_a256);
            printf("%d,%s,%s,%.2f\n", 256, "R256-folded", "single",  s_fold);
            for (int j = 0; j < 3; j++) {
                printf("%d,%s,x%d,%.2f\n", 128, "AES-128",     Ns[j], i_a128[j]);
                printf("%d,%s,x%d,%.2f\n", 256, "AES-256",     Ns[j], i_a256[j]);
                printf("%d,%s,x%d,%.2f\n", 256, "R256-folded", Ns[j], i_fold[j]);
            }
        } else {
            printf("========================================\n");
            printf("    AES -> R256 : single-block vs interleaved (matched N)\n");
            printf("========================================\n\n");
            printf("  AES FIPS-197 self-test    : PASS\n");
            printf("  R256 folded KAT (+xN)     : PASS\n\n");
            printf("  %-14s %10s %9s %9s %9s   (MB/s)\n", "Path", "single", "x2", "x4", "x8");
            printf("  %-14s %10.1f %9.1f %9.1f %9.1f\n", "AES-128 (10R)", s_a128, i_a128[0], i_a128[1], i_a128[2]);
            printf("  %-14s %10.1f %9.1f %9.1f %9.1f\n", "AES-256 (14R)", s_a256, i_a256[0], i_a256[1], i_a256[2]);
            printf("  %-14s %10.1f %9.1f %9.1f %9.1f\n", "R256 folded",   s_fold, i_fold[0], i_fold[1], i_fold[2]);
            printf("  %-14s %10.1f   (reference; folded is the recommended path)\n", "R256 EOR", s_eor);
            printf("\n  Best interleave depth for R256 folded: N=%d\n", bestN);

            printf("\n  AES -> R256 per-byte slowdown (folded):\n");
            printf("    single-block     : %.2fx vs AES-256 | %.2fx vs AES-128\n",
                   s_a256 / s_fold, s_a128 / s_fold);
            printf("    interleaved N=%d  : %.2fx vs AES-256 | %.2fx vs AES-128   <- regime-matched to x86 VAES\n",
                   bestN, i_a256[bj] / i_fold[bj], i_a128[bj] / i_fold[bj]);
            printf("\n");
        }
        #undef MBPS
    }

    /* Cleanup */
    free(data);

    return 0;
}
