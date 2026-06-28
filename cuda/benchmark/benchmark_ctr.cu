#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rijndael.h"
#include "rijndael_ctr.cuh"
#include "benchmark_common.h"

extern __global__ void rijndael256_ctr_kernel_v2(
    const uint8_t *, uint8_t *, size_t, int, int);
extern __global__ void rijndael256_ctr_kernel_v3(
    const uint8_t *, uint8_t *, size_t, int, int);

typedef void (*ctr_host_fn_t)(const uint8_t *, const uint8_t *, uint8_t *,
                              const RijndaelKey *, size_t, int);
typedef void (*ctr_launch_fn_t)(uint8_t *, uint8_t *, const RijndaelKey *,
                                size_t, int);

typedef struct {
    const uint8_t *nonce;
    const uint8_t *input;
    uint8_t *output;
    const RijndaelKey *rk;
    size_t num_blocks;
    int threads_per_block;
    ctr_host_fn_t fn;
} CtrHostRunnerCtx;

typedef struct {
    uint8_t *d_in;
    uint8_t *d_out;
    const RijndaelKey *rk;
    size_t num_blocks;
    int threads_per_block;
    ctr_launch_fn_t fn;
} CtrLaunchRunnerCtx;

static void cpu_ctr_crypt(const uint8_t *nonce, const uint8_t *input,
                          uint8_t *output, const RijndaelKey *rk,
                          size_t numBlocks)
{
    uint8_t counter[RIJNDAEL256_BLOCK_SIZE];
    memcpy(counter, nonce, sizeof(counter));

    for (size_t b = 0; b < numBlocks; b++) {
        uint8_t keystream[RIJNDAEL256_BLOCK_SIZE];
        rijndaelEncrypt(rk, counter, keystream);

        if (input != NULL) {
            for (int i = 0; i < RIJNDAEL256_BLOCK_SIZE; i++) {
                output[b * RIJNDAEL256_BLOCK_SIZE + i] =
                    keystream[i] ^ input[b * RIJNDAEL256_BLOCK_SIZE + i];
            }
        } else {
            memcpy(output + b * RIJNDAEL256_BLOCK_SIZE, keystream,
                   RIJNDAEL256_BLOCK_SIZE);
        }

        for (int i = 31; i >= 24; i--) {
            counter[i]++;
            if (counter[i] != 0) break;
        }
    }
}

static void host_runner(void *ctx)
{
    CtrHostRunnerCtx *runner = (CtrHostRunnerCtx *)ctx;
    runner->fn(runner->nonce, runner->input, runner->output, runner->rk,
               runner->num_blocks, runner->threads_per_block);
}

static void launch_runner(void *ctx)
{
    CtrLaunchRunnerCtx *runner = (CtrLaunchRunnerCtx *)ctx;
    runner->fn(runner->d_in, runner->d_out, runner->rk, runner->num_blocks,
               runner->threads_per_block);
}

static void benchmark_ctr_validate_case(const uint8_t *nonce, const RijndaelKey *rk,
                                        int threadsPerBlock)
{
    const size_t numBlocks = 16;
    const size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;
    uint8_t *plaintext = benchmark_malloc_bytes(dataSize);
    uint8_t *cpuCt = benchmark_malloc_bytes(dataSize);
    uint8_t *hostV2 = benchmark_malloc_bytes(dataSize);
    uint8_t *hostV3 = benchmark_malloc_bytes(dataSize);
    uint8_t *kernelOut = benchmark_malloc_bytes(dataSize);
    uint8_t *roundtrip = benchmark_malloc_bytes(dataSize);
    uint8_t *d_in = NULL;
    uint8_t *d_out = NULL;

    benchmark_fill_pattern(plaintext, dataSize, 41u, 7u);
    cpu_ctr_crypt(nonce, plaintext, cpuCt, rk, numBlocks);

    rijndael256_ctr_crypt_v2(nonce, plaintext, hostV2, rk, numBlocks, threadsPerBlock);
    rijndael256_ctr_crypt_v3(nonce, plaintext, hostV3, rk, numBlocks, threadsPerBlock);
    benchmark_require(memcmp(cpuCt, hostV2, dataSize) == 0,
                      "CTR V2 host API validation failed");
    benchmark_require(memcmp(cpuCt, hostV3, dataSize) == 0,
                      "CTR V3 host API validation failed");

    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemcpy(d_in, plaintext, dataSize, cudaMemcpyHostToDevice));

    rijndael256_ctr_setup(nonce, rk);
    rijndael256_ctr_launch_v2(d_in, d_out, rk, numBlocks, threadsPerBlock);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelOut, d_out, dataSize, cudaMemcpyDeviceToHost));
    benchmark_require(memcmp(cpuCt, kernelOut, dataSize) == 0,
                      "CTR V2 kernel-only validation failed");

    CUDA_CHECK(cudaMemcpy(d_in, plaintext, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ctr_launch_v3(d_in, d_out, rk, numBlocks, threadsPerBlock);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelOut, d_out, dataSize, cudaMemcpyDeviceToHost));
    benchmark_require(memcmp(cpuCt, kernelOut, dataSize) == 0,
                      "CTR V3 kernel-only validation failed");

    rijndael256_ctr_crypt_v2(nonce, hostV2, roundtrip, rk, numBlocks, threadsPerBlock);
    benchmark_require(memcmp(plaintext, roundtrip, dataSize) == 0,
                      "CTR V2 roundtrip validation failed");
    rijndael256_ctr_crypt_v3(nonce, hostV3, roundtrip, rk, numBlocks, threadsPerBlock);
    benchmark_require(memcmp(plaintext, roundtrip, dataSize) == 0,
                      "CTR V3 roundtrip validation failed");

    rijndael256_ctr_launch_v2(d_in, d_out, rk, 0, threadsPerBlock);
    rijndael256_ctr_launch_v3(d_in, d_out, rk, 0, threadsPerBlock);
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
    free(plaintext);
    free(cpuCt);
    free(hostV2);
    free(hostV3);
    free(kernelOut);
    free(roundtrip);
}

static void print_usage(const char *argv0)
{
    printf("Usage: %s [options]\n", argv0);
    printf("  --sizes <mib,mib,...>    Data sizes in MiB (default: 1,100)\n");
    printf("  --threads <n,n,...>      Threads per block (default: 128,256,512,1024)\n");
    printf("  --warmup <n>             Override warmup iterations for all sections\n");
    printf("  --iterations <n>         Override timed iterations for all sections\n");
    printf("  --csv <path>             Write CSV output for paper plots\n");
    printf("  --no-device-info         Suppress device metadata header\n");
    printf("  --skip-validation        Skip correctness validation before timing\n");
    printf("  --no-occupancy           Skip occupancy summary\n");
    printf("  --help                   Show this help message\n");
}

int main(int argc, char **argv)
{
    BenchmarkCommonOptions common;
    BenchmarkDeviceInfo device;
    FILE *csv = NULL;
    size_t dataSizes[8] = {1024 * 1024, 100 * 1024 * 1024};
    int threadConfigs[8] = {128, 256, 512, 1024};
    int numSizes = 2;
    int numThreads = 4;
    int e2eWarmup = 2;
    int e2eIterations = 5;
    int kernelWarmup = 3;
    int kernelIterations = 10;

    benchmark_init_common_options(&common);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--sizes") == 0) {
            benchmark_require(i + 1 < argc, "--sizes requires a value");
            numSizes = (int)benchmark_parse_mib_list(argv[++i], dataSizes, 8, "--sizes");
            continue;
        }
        if (strcmp(argv[i], "--threads") == 0) {
            benchmark_require(i + 1 < argc, "--threads requires a value");
            numThreads = benchmark_parse_int_list(argv[++i], threadConfigs, 8, "--threads");
            continue;
        }
        if (benchmark_handle_common_option(argc, argv, &i, &common)) {
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (common.warmup_override >= 0) {
        e2eWarmup = common.warmup_override;
        kernelWarmup = common.warmup_override;
    }
    if (common.iterations_override >= 0) {
        e2eIterations = common.iterations_override;
        kernelIterations = common.iterations_override;
    }

    benchmark_query_device_info(&device);
    benchmark_print_run_metadata("Rijndael-256 CTR Benchmark", argc, argv,
                                 &common, &device);

    if (common.csv_path != NULL) {
        csv = benchmark_open_csv(common.csv_path);
    }

    uint8_t key[32];
    uint8_t nonce[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(i * 7 + 0x42);
        nonce[i] = (uint8_t)(i * 3 + 0x11);
    }

    RijndaelKey rk;
    benchmark_require(rijndaelSetupKey(key, 256, &rk) == 0,
                      "rijndaelSetupKey failed");

    if (common.enable_validation) {
        for (int ti = 0; ti < numThreads; ti++) {
            benchmark_ctr_validate_case(nonce, &rk, threadConfigs[ti]);
        }
        printf("Validation: passed for CTR host and kernel-only APIs\n\n");
    }

    for (int si = 0; si < numSizes; si++) {
        size_t dataSize = dataSizes[si];
        size_t numBlocks = dataSize / RIJNDAEL256_BLOCK_SIZE;
        uint8_t *data = benchmark_malloc_bytes(dataSize);
        uint8_t *out = benchmark_malloc_bytes(dataSize);
        uint8_t *d_in = NULL;
        uint8_t *d_out = NULL;

        benchmark_fill_pattern(data, dataSize, 37u, 0u);

        printf("Data size: %.1f MiB (%zu blocks)\n",
               (double)dataSize / (1024.0 * 1024.0), numBlocks);

        printf("  E2E (malloc + copies + kernel + copies + free)\n");
        printf("  warmup=%d iterations=%d\n", e2eWarmup, e2eIterations);
        printf("  %-8s  %-12s %-12s\n", "Threads", "V2 (ms)", "V3 (ms)");
        printf("  -------------------------------------------\n");

        double bestE2EV2 = 0.0;
        double bestE2EV3 = 0.0;
        int bestE2ETpbV2 = 0;
        int bestE2ETpbV3 = 0;

        for (int ti = 0; ti < numThreads; ti++) {
            int tpb = threadConfigs[ti];
            CtrHostRunnerCtx v2Ctx = {nonce, data, out, &rk, numBlocks, tpb,
                                      rijndael256_ctr_crypt_v2};
            CtrHostRunnerCtx v3Ctx = {nonce, data, out, &rk, numBlocks, tpb,
                                      rijndael256_ctr_crypt_v3};

            double v2Ms = benchmark_measure_wall_ms(host_runner, &v2Ctx,
                                                    e2eWarmup, e2eIterations);
            double v3Ms = benchmark_measure_wall_ms(host_runner, &v3Ctx,
                                                    e2eWarmup, e2eIterations);
            double v2GiBs = benchmark_throughput_gib_s(dataSize, v2Ms);
            double v3GiBs = benchmark_throughput_gib_s(dataSize, v3Ms);

            printf("  %-8d  %-12.3f %-12.3f\n", tpb, v2Ms, v3Ms);

            benchmark_csv_write_row(csv, "ctr", "e2e", "V2", "crypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    e2eWarmup, e2eIterations, v2Ms, v2GiBs, 0.0);
            benchmark_csv_write_row(csv, "ctr", "e2e", "V3", "crypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    e2eWarmup, e2eIterations, v3Ms, v3GiBs, 0.0);

            if (v2GiBs > bestE2EV2) {
                bestE2EV2 = v2GiBs;
                bestE2ETpbV2 = tpb;
            }
            if (v3GiBs > bestE2EV3) {
                bestE2EV3 = v3GiBs;
                bestE2ETpbV3 = tpb;
            }
        }

        printf("  Best E2E throughput: V2 %.2f GiB/s @ %d threads, "
               "V3 %.2f GiB/s @ %d threads\n\n",
               bestE2EV2, bestE2ETpbV2, bestE2EV3, bestE2ETpbV3);

        CUDA_CHECK(cudaMalloc(&d_in, dataSize));
        CUDA_CHECK(cudaMalloc(&d_out, dataSize));
        CUDA_CHECK(cudaMemcpy(d_in, data, dataSize, cudaMemcpyHostToDevice));
        rijndael256_ctr_setup(nonce, &rk);

        printf("  Kernel-only (pre-allocated buffers)\n");
        printf("  warmup=%d iterations=%d\n", kernelWarmup, kernelIterations);
        printf("  %-8s  %-12s %-12s\n", "Threads", "V2 (ms)", "V3 (ms)");
        printf("  -------------------------------------------\n");

        double bestKernelV2 = 0.0;
        double bestKernelV3 = 0.0;
        int bestKernelTpbV2 = 0;
        int bestKernelTpbV3 = 0;

        for (int ti = 0; ti < numThreads; ti++) {
            int tpb = threadConfigs[ti];
            CtrLaunchRunnerCtx v2Ctx = {d_in, d_out, &rk, numBlocks, tpb,
                                        rijndael256_ctr_launch_v2};
            CtrLaunchRunnerCtx v3Ctx = {d_in, d_out, &rk, numBlocks, tpb,
                                        rijndael256_ctr_launch_v3};

            double v2Ms = benchmark_measure_ms(launch_runner, &v2Ctx,
                                               kernelWarmup, kernelIterations);
            double v3Ms = benchmark_measure_ms(launch_runner, &v3Ctx,
                                               kernelWarmup, kernelIterations);
            double v2GiBs = benchmark_throughput_gib_s(dataSize, v2Ms);
            double v3GiBs = benchmark_throughput_gib_s(dataSize, v3Ms);

            printf("  %-8d  %-12.3f %-12.3f\n", tpb, v2Ms, v3Ms);

            benchmark_csv_write_row(csv, "ctr", "kernel", "V2", "crypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    kernelWarmup, kernelIterations, v2Ms,
                                    v2GiBs, 0.0);
            benchmark_csv_write_row(csv, "ctr", "kernel", "V3", "crypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    kernelWarmup, kernelIterations, v3Ms,
                                    v3GiBs, 0.0);

            if (v2GiBs > bestKernelV2) {
                bestKernelV2 = v2GiBs;
                bestKernelTpbV2 = tpb;
            }
            if (v3GiBs > bestKernelV3) {
                bestKernelV3 = v3GiBs;
                bestKernelTpbV3 = tpb;
            }
        }

        printf("  Best kernel-only throughput: V2 %.2f GiB/s @ %d threads, "
               "V3 %.2f GiB/s @ %d threads\n\n",
               bestKernelV2, bestKernelTpbV2, bestKernelV3, bestKernelTpbV3);

        CUDA_CHECK(cudaFree(d_in));
        CUDA_CHECK(cudaFree(d_out));
        free(data);
        free(out);
    }

    if (common.print_occupancy) {
        printf("Occupancy summary:\n");
        for (int ti = 0; ti < numThreads; ti++) {
            int tpb = threadConfigs[ti];
            benchmark_print_occupancy("CTR V2",
                                      (const void *)rijndael256_ctr_kernel_v2, tpb);
            benchmark_print_occupancy("CTR V3",
                                      (const void *)rijndael256_ctr_kernel_v3, tpb);
        }
        printf("\n");
    }

    if (csv != NULL) {
        fclose(csv);
    }
    return 0;
}
