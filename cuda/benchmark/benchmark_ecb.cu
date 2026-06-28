#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rijndael.h"
#include "rijndael_ecb.cuh"
#include "benchmark_common.h"

extern __global__ void rijndael256_ecb_encrypt_kernel_v2(
    const uint8_t *, uint8_t *, size_t, int);
extern __global__ void rijndael256_ecb_encrypt_kernel_v3(
    const uint8_t *, uint8_t *, size_t, int);

typedef void (*ecb_host_fn_t)(const uint8_t *, uint8_t *, const RijndaelKey *,
                              size_t, int);
typedef void (*ecb_launch_fn_t)(uint8_t *, uint8_t *, const RijndaelKey *,
                                size_t, int);

typedef struct {
    const uint8_t *input;
    uint8_t *output;
    const RijndaelKey *rk;
    size_t num_blocks;
    int threads_per_block;
    ecb_host_fn_t fn;
} EcbHostRunnerCtx;

typedef struct {
    uint8_t *d_in;
    uint8_t *d_out;
    const RijndaelKey *rk;
    size_t num_blocks;
    int threads_per_block;
    ecb_launch_fn_t fn;
} EcbLaunchRunnerCtx;

static void cpu_ecb_encrypt_many(const RijndaelKey *rk, const uint8_t *input,
                                 uint8_t *output, size_t numBlocks)
{
    for (size_t i = 0; i < numBlocks; i++) {
        rijndaelEncrypt(rk, input + i * RIJNDAEL256_BLOCK_SIZE,
                        output + i * RIJNDAEL256_BLOCK_SIZE);
    }
}

static void host_runner(void *ctx)
{
    EcbHostRunnerCtx *runner = (EcbHostRunnerCtx *)ctx;
    runner->fn(runner->input, runner->output, runner->rk, runner->num_blocks,
               runner->threads_per_block);
}

static void launch_runner(void *ctx)
{
    EcbLaunchRunnerCtx *runner = (EcbLaunchRunnerCtx *)ctx;
    runner->fn(runner->d_in, runner->d_out, runner->rk, runner->num_blocks,
               runner->threads_per_block);
}

static int buffers_equal(const uint8_t *lhs, const uint8_t *rhs, size_t size)
{
    return memcmp(lhs, rhs, size) == 0;
}

static void benchmark_ecb_validate_case(const RijndaelKey *rk, int threadsPerBlock)
{
    const size_t numBlocks = 16;
    const size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;
    uint8_t *plaintext = benchmark_malloc_bytes(dataSize);
    uint8_t *cpuCt = benchmark_malloc_bytes(dataSize);
    uint8_t *cpuDec = benchmark_malloc_bytes(dataSize);
    uint8_t *hostV2 = benchmark_malloc_bytes(dataSize);
    uint8_t *hostV3 = benchmark_malloc_bytes(dataSize);
    uint8_t *kernelOut = benchmark_malloc_bytes(dataSize);
    uint8_t *kernelDec = benchmark_malloc_bytes(dataSize);
    uint8_t *d_in = NULL;
    uint8_t *d_out = NULL;

    benchmark_fill_pattern(plaintext, dataSize, 37u, 11u);
    cpu_ecb_encrypt_many(rk, plaintext, cpuCt, numBlocks);
    for (size_t i = 0; i < numBlocks; i++) {
        rijndaelDecrypt(rk, cpuCt + i * RIJNDAEL256_BLOCK_SIZE,
                        cpuDec + i * RIJNDAEL256_BLOCK_SIZE);
    }
    benchmark_require(buffers_equal(plaintext, cpuDec, dataSize),
                      "CPU ECB validation roundtrip failed");

    rijndael256_ecb_encrypt_v2(plaintext, hostV2, rk, numBlocks, threadsPerBlock);
    rijndael256_ecb_encrypt_v3(plaintext, hostV3, rk, numBlocks, threadsPerBlock);
    benchmark_require(buffers_equal(cpuCt, hostV2, dataSize),
                      "ECB V2 host API validation failed");
    benchmark_require(buffers_equal(cpuCt, hostV3, dataSize),
                      "ECB V3 host API validation failed");

    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemcpy(d_in, plaintext, dataSize, cudaMemcpyHostToDevice));

    rijndael256_ecb_setup_keys(rk);

    rijndael256_ecb_launch_encrypt_v2(d_in, d_out, rk, numBlocks, threadsPerBlock);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelOut, d_out, dataSize, cudaMemcpyDeviceToHost));
    benchmark_require(buffers_equal(cpuCt, kernelOut, dataSize),
                      "ECB V2 kernel-only encrypt validation failed");

    CUDA_CHECK(cudaMemcpy(d_in, cpuCt, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ecb_launch_decrypt_v2(d_in, d_out, rk, numBlocks, threadsPerBlock);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelDec, d_out, dataSize, cudaMemcpyDeviceToHost));
    benchmark_require(buffers_equal(plaintext, kernelDec, dataSize),
                      "ECB V2 kernel-only decrypt validation failed");

    CUDA_CHECK(cudaMemcpy(d_in, plaintext, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ecb_launch_encrypt_v3(d_in, d_out, rk, numBlocks, threadsPerBlock);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelOut, d_out, dataSize, cudaMemcpyDeviceToHost));
    benchmark_require(buffers_equal(cpuCt, kernelOut, dataSize),
                      "ECB V3 kernel-only encrypt validation failed");

    CUDA_CHECK(cudaMemcpy(d_in, cpuCt, dataSize, cudaMemcpyHostToDevice));
    rijndael256_ecb_launch_decrypt_v3(d_in, d_out, rk, numBlocks, threadsPerBlock);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(kernelDec, d_out, dataSize, cudaMemcpyDeviceToHost));
    benchmark_require(buffers_equal(plaintext, kernelDec, dataSize),
                      "ECB V3 kernel-only decrypt validation failed");

    rijndael256_ecb_launch_encrypt_v2(d_in, d_out, rk, 0, threadsPerBlock);
    rijndael256_ecb_launch_encrypt_v3(d_in, d_out, rk, 0, threadsPerBlock);
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
    free(plaintext);
    free(cpuCt);
    free(cpuDec);
    free(hostV2);
    free(hostV3);
    free(kernelOut);
    free(kernelDec);
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
    benchmark_print_run_metadata("Rijndael-256 ECB Benchmark", argc, argv,
                                 &common, &device);

    if (common.csv_path != NULL) {
        csv = benchmark_open_csv(common.csv_path);
    }

    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(i * 7 + 0x42);
    }

    RijndaelKey rk;
    benchmark_require(rijndaelSetupKey(key, 256, &rk) == 0,
                      "rijndaelSetupKey failed");

    if (common.enable_validation) {
        for (int ti = 0; ti < numThreads; ti++) {
            benchmark_ecb_validate_case(&rk, threadConfigs[ti]);
        }
        printf("Validation: passed for ECB host and kernel-only APIs\n\n");
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
        printf("  %-8s  %-12s %-12s %-12s %-12s\n",
               "Threads", "V2 Enc(ms)", "V2 Dec(ms)", "V3 Enc(ms)", "V3 Dec(ms)");
        printf("  --------------------------------------------------------------\n");

        double bestE2EV2 = 0.0;
        double bestE2EV3 = 0.0;
        int bestE2ETpbV2 = 0;
        int bestE2ETpbV3 = 0;

        for (int ti = 0; ti < numThreads; ti++) {
            int tpb = threadConfigs[ti];
            EcbHostRunnerCtx v2EncCtx = {data, out, &rk, numBlocks, tpb, rijndael256_ecb_encrypt_v2};
            EcbHostRunnerCtx v2DecCtx = {data, out, &rk, numBlocks, tpb, rijndael256_ecb_decrypt_v2};
            EcbHostRunnerCtx v3EncCtx = {data, out, &rk, numBlocks, tpb, rijndael256_ecb_encrypt_v3};
            EcbHostRunnerCtx v3DecCtx = {data, out, &rk, numBlocks, tpb, rijndael256_ecb_decrypt_v3};

            double v2EncMs = benchmark_measure_wall_ms(host_runner, &v2EncCtx,
                                                       e2eWarmup, e2eIterations);
            double v2DecMs = benchmark_measure_wall_ms(host_runner, &v2DecCtx,
                                                       e2eWarmup, e2eIterations);
            double v3EncMs = benchmark_measure_wall_ms(host_runner, &v3EncCtx,
                                                       e2eWarmup, e2eIterations);
            double v3DecMs = benchmark_measure_wall_ms(host_runner, &v3DecCtx,
                                                       e2eWarmup, e2eIterations);

            double v2EncGiBs = benchmark_throughput_gib_s(dataSize, v2EncMs);
            double v2DecGiBs = benchmark_throughput_gib_s(dataSize, v2DecMs);
            double v3EncGiBs = benchmark_throughput_gib_s(dataSize, v3EncMs);
            double v3DecGiBs = benchmark_throughput_gib_s(dataSize, v3DecMs);

            printf("  %-8d  %-12.3f %-12.3f %-12.3f %-12.3f\n",
                   tpb, v2EncMs, v2DecMs, v3EncMs, v3DecMs);

            benchmark_csv_write_row(csv, "ecb", "e2e", "V2", "encrypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    e2eWarmup, e2eIterations, v2EncMs, v2EncGiBs, 0.0);
            benchmark_csv_write_row(csv, "ecb", "e2e", "V2", "decrypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    e2eWarmup, e2eIterations, v2DecMs, v2DecGiBs, 0.0);
            benchmark_csv_write_row(csv, "ecb", "e2e", "V3", "encrypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    e2eWarmup, e2eIterations, v3EncMs, v3EncGiBs, 0.0);
            benchmark_csv_write_row(csv, "ecb", "e2e", "V3", "decrypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    e2eWarmup, e2eIterations, v3DecMs, v3DecGiBs, 0.0);

            if (v2EncGiBs > bestE2EV2) {
                bestE2EV2 = v2EncGiBs;
                bestE2ETpbV2 = tpb;
            }
            if (v3EncGiBs > bestE2EV3) {
                bestE2EV3 = v3EncGiBs;
                bestE2ETpbV3 = tpb;
            }
        }

        printf("  Best E2E encrypt throughput: V2 %.2f GiB/s @ %d threads, "
               "V3 %.2f GiB/s @ %d threads\n\n",
               bestE2EV2, bestE2ETpbV2, bestE2EV3, bestE2ETpbV3);

        CUDA_CHECK(cudaMalloc(&d_in, dataSize));
        CUDA_CHECK(cudaMalloc(&d_out, dataSize));
        CUDA_CHECK(cudaMemcpy(d_in, data, dataSize, cudaMemcpyHostToDevice));
        rijndael256_ecb_setup_keys(&rk);

        printf("  Kernel-only (pre-allocated buffers)\n");
        printf("  warmup=%d iterations=%d\n", kernelWarmup, kernelIterations);
        printf("  %-8s  %-12s %-12s %-12s %-12s\n",
               "Threads", "V2 Enc(ms)", "V2 Dec(ms)", "V3 Enc(ms)", "V3 Dec(ms)");
        printf("  --------------------------------------------------------------\n");

        double bestKernelV2 = 0.0;
        double bestKernelV3 = 0.0;
        int bestKernelTpbV2 = 0;
        int bestKernelTpbV3 = 0;

        for (int ti = 0; ti < numThreads; ti++) {
            int tpb = threadConfigs[ti];
            EcbLaunchRunnerCtx v2EncCtx = {d_in, d_out, &rk, numBlocks, tpb,
                                           rijndael256_ecb_launch_encrypt_v2};
            EcbLaunchRunnerCtx v2DecCtx = {d_in, d_out, &rk, numBlocks, tpb,
                                           rijndael256_ecb_launch_decrypt_v2};
            EcbLaunchRunnerCtx v3EncCtx = {d_in, d_out, &rk, numBlocks, tpb,
                                           rijndael256_ecb_launch_encrypt_v3};
            EcbLaunchRunnerCtx v3DecCtx = {d_in, d_out, &rk, numBlocks, tpb,
                                           rijndael256_ecb_launch_decrypt_v3};

            double v2EncMs = benchmark_measure_ms(launch_runner, &v2EncCtx,
                                                  kernelWarmup, kernelIterations);
            double v2DecMs = benchmark_measure_ms(launch_runner, &v2DecCtx,
                                                  kernelWarmup, kernelIterations);
            double v3EncMs = benchmark_measure_ms(launch_runner, &v3EncCtx,
                                                  kernelWarmup, kernelIterations);
            double v3DecMs = benchmark_measure_ms(launch_runner, &v3DecCtx,
                                                  kernelWarmup, kernelIterations);

            double v2EncGiBs = benchmark_throughput_gib_s(dataSize, v2EncMs);
            double v2DecGiBs = benchmark_throughput_gib_s(dataSize, v2DecMs);
            double v3EncGiBs = benchmark_throughput_gib_s(dataSize, v3EncMs);
            double v3DecGiBs = benchmark_throughput_gib_s(dataSize, v3DecMs);

            printf("  %-8d  %-12.3f %-12.3f %-12.3f %-12.3f\n",
                   tpb, v2EncMs, v2DecMs, v3EncMs, v3DecMs);

            benchmark_csv_write_row(csv, "ecb", "kernel", "V2", "encrypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    kernelWarmup, kernelIterations, v2EncMs,
                                    v2EncGiBs, 0.0);
            benchmark_csv_write_row(csv, "ecb", "kernel", "V2", "decrypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    kernelWarmup, kernelIterations, v2DecMs,
                                    v2DecGiBs, 0.0);
            benchmark_csv_write_row(csv, "ecb", "kernel", "V3", "encrypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    kernelWarmup, kernelIterations, v3EncMs,
                                    v3EncGiBs, 0.0);
            benchmark_csv_write_row(csv, "ecb", "kernel", "V3", "decrypt",
                                    &device, dataSize, numBlocks, 0, tpb, 0,
                                    kernelWarmup, kernelIterations, v3DecMs,
                                    v3DecGiBs, 0.0);

            if (v2EncGiBs > bestKernelV2) {
                bestKernelV2 = v2EncGiBs;
                bestKernelTpbV2 = tpb;
            }
            if (v3EncGiBs > bestKernelV3) {
                bestKernelV3 = v3EncGiBs;
                bestKernelTpbV3 = tpb;
            }
        }

        printf("  Best kernel-only encrypt throughput: V2 %.2f GiB/s @ %d threads, "
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
            benchmark_print_occupancy("ECB V2 encrypt",
                                      (const void *)rijndael256_ecb_encrypt_kernel_v2,
                                      tpb);
            benchmark_print_occupancy("ECB V3 encrypt",
                                      (const void *)rijndael256_ecb_encrypt_kernel_v3,
                                      tpb);
        }
        printf("\n");
    }

    if (csv != NULL) {
        fclose(csv);
    }
    return 0;
}
