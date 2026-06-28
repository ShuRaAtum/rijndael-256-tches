#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rijndael.h"
#include "rijndael_es.cuh"
#include "benchmark_common.h"

extern __global__ void rijndael256_es_kernel_v2(
    uint64_t, uint64_t, int, int, uint64_t);
extern __global__ void rijndael256_es_kernel_v3(
    uint64_t, uint64_t, int, int, uint64_t);

typedef void (*es_host_fn_t)(const uint8_t *, const uint8_t *, const uint8_t *,
                             int, uint64_t, uint64_t, ESResult *, int, int);
typedef void (*es_launch_fn_t)(int, uint64_t, uint64_t, int, int);

typedef struct {
    const uint8_t *pt;
    const uint8_t *ct;
    const uint8_t *base_key;
    int key_bits;
    uint64_t base_offset;
    uint64_t search_range;
    ESResult *result;
    int threads_per_block;
    int num_cuda_blocks;
    es_host_fn_t fn;
} EsHostRunnerCtx;

typedef struct {
    int key_bits;
    uint64_t base_offset;
    uint64_t search_range;
    int threads_per_block;
    int num_cuda_blocks;
    es_launch_fn_t fn;
} EsLaunchRunnerCtx;

static void write_key_offset(uint8_t *key, int keyBytes, uint64_t offset)
{
    int start = keyBytes - 8;
    for (int i = 0; i < 8; i++) {
        key[start + i] = (uint8_t)(offset >> (56 - 8 * i));
    }
}

static void host_runner(void *ctx)
{
    EsHostRunnerCtx *runner = (EsHostRunnerCtx *)ctx;
    runner->fn(runner->pt, runner->ct, runner->base_key, runner->key_bits,
               runner->base_offset, runner->search_range, runner->result,
               runner->threads_per_block, runner->num_cuda_blocks);
}

static void launch_runner(void *ctx)
{
    EsLaunchRunnerCtx *runner = (EsLaunchRunnerCtx *)ctx;
    runner->fn(runner->key_bits, runner->base_offset, runner->search_range,
               runner->threads_per_block, runner->num_cuda_blocks);
}

static void build_not_found_case(uint64_t searchRange, uint8_t *baseKey,
                                 uint8_t *pt, uint8_t *ct)
{
    uint64_t targetOffset = searchRange + 12345;
    uint8_t targetKey[32];
    memset(baseKey, 0, 32);
    memset(targetKey, 0, sizeof(targetKey));
    memset(pt, 0x42, 32);
    write_key_offset(targetKey, (int)sizeof(targetKey), targetOffset);

    RijndaelKey rk;
    benchmark_require(rijndaelSetupKey(targetKey, 256, &rk) == 0,
                      "rijndaelSetupKey failed for ES benchmark");
    rijndaelEncrypt(&rk, pt, ct);
}

static void benchmark_es_validate_case(uint64_t searchRange,
                                       int threadsPerBlock,
                                       int numCudaBlocks)
{
    uint8_t baseKey[32];
    uint8_t pt[32];
    uint8_t ct[32];
    ESResult result;

    build_not_found_case(searchRange, baseKey, pt, ct);

    rijndael256_es_search_v2(pt, ct, baseKey, 256, 0, searchRange, &result,
                              threadsPerBlock, numCudaBlocks);
    benchmark_require(result.found == 0,
                      "ES V2 validation produced a false positive");

    rijndael256_es_search_v3(pt, ct, baseKey, 256, 0, searchRange, &result,
                              threadsPerBlock, numCudaBlocks);
    benchmark_require(result.found == 0,
                      "ES V3 validation produced a false positive");

    rijndael256_es_setup(pt, ct, baseKey, 256);
    rijndael256_es_launch_v2(256, 0, searchRange, threadsPerBlock, numCudaBlocks);
    CUDA_CHECK(cudaDeviceSynchronize());
    rijndael256_es_get_result(&result);
    benchmark_require(result.found == 0,
                      "ES V2 launch-only validation produced a false positive");

    rijndael256_es_setup(pt, ct, baseKey, 256);
    rijndael256_es_launch_v3(256, 0, searchRange, threadsPerBlock, numCudaBlocks);
    CUDA_CHECK(cudaDeviceSynchronize());
    rijndael256_es_get_result(&result);
    benchmark_require(result.found == 0,
                      "ES V3 launch-only validation produced a false positive");
}

static void print_usage(const char *argv0)
{
    printf("Usage: %s [options]\n", argv0);
    printf("  --range-bits <b,b,...>   Search ranges as powers of two (default: 18,20,22)\n");
    printf("  --grids <BxT,...>        Grid configs like 256x256,512x512\n");
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
    int rangeBits[8] = {18, 20, 22};
    uint64_t searchRanges[8] = {1ULL << 18, 1ULL << 20, 1ULL << 22};
    int numRanges = 3;
    int gridConfigs[8][2] = {
        {256, 256},
        {512, 512},
        {1024, 256},
        {1024, 1024},
    };
    int numGrids = 4;
    int fullWarmup = 1;
    int fullIterations = 3;
    int launchWarmup = 2;
    int launchIterations = 5;

    benchmark_init_common_options(&common);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--range-bits") == 0) {
            benchmark_require(i + 1 < argc, "--range-bits requires a value");
            numRanges = benchmark_parse_int_list(argv[++i], rangeBits, 8, "--range-bits");
            for (int ri = 0; ri < numRanges; ri++) {
                benchmark_require(rangeBits[ri] > 0 && rangeBits[ri] < 63,
                                  "--range-bits values must be in [1, 62]");
                searchRanges[ri] = 1ULL << rangeBits[ri];
            }
            continue;
        }
        if (strcmp(argv[i], "--grids") == 0) {
            benchmark_require(i + 1 < argc, "--grids requires a value");
            numGrids = benchmark_parse_grid_list(argv[++i], gridConfigs, 8, "--grids");
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
        fullWarmup = common.warmup_override;
        launchWarmup = common.warmup_override;
    }
    if (common.iterations_override >= 0) {
        fullIterations = common.iterations_override;
        launchIterations = common.iterations_override;
    }

    benchmark_query_device_info(&device);
    benchmark_print_run_metadata("Rijndael-256 ES Benchmark", argc, argv,
                                 &common, &device);

    if (common.csv_path != NULL) {
        csv = benchmark_open_csv(common.csv_path);
    }

    if (common.enable_validation) {
        for (int gi = 0; gi < numGrids; gi++) {
            benchmark_es_validate_case(searchRanges[0],
                                       gridConfigs[gi][1], gridConfigs[gi][0]);
        }
        printf("Validation: passed for ES full and launch-only paths\n\n");
    }

    for (int ri = 0; ri < numRanges; ri++) {
        uint8_t baseKey[32];
        uint8_t pt[32];
        uint8_t ct[32];
        uint64_t searchRange = searchRanges[ri];

        build_not_found_case(searchRange, baseKey, pt, ct);

        printf("Search range: 2^%d = %" PRIu64 " keys\n",
               rangeBits[ri], searchRange);

        printf("  Full API (setup + launch + synchronize + fetch)\n");
        printf("  warmup=%d iterations=%d\n", fullWarmup, fullIterations);
        printf("  %-12s %-12s %-14s %-14s %-14s %-14s\n",
               "Blocks", "Threads", "V2 (ms)", "V3 (ms)",
               "V2 keys/s", "V3 keys/s");
        printf("  ----------------------------------------------------------------------\n");

        double bestFullV2 = 0.0;
        double bestFullV3 = 0.0;
        int bestFullBlocksV2 = 0;
        int bestFullThreadsV2 = 0;
        int bestFullBlocksV3 = 0;
        int bestFullThreadsV3 = 0;

        for (int gi = 0; gi < numGrids; gi++) {
            ESResult resultV2 = {0, 0};
            ESResult resultV3 = {0, 0};
            int numCudaBlocks = gridConfigs[gi][0];
            int threadsPerBlock = gridConfigs[gi][1];
            EsHostRunnerCtx v2Ctx = {
                pt, ct, baseKey, 256, 0, searchRange, &resultV2,
                threadsPerBlock, numCudaBlocks, rijndael256_es_search_v2
            };
            EsHostRunnerCtx v3Ctx = {
                pt, ct, baseKey, 256, 0, searchRange, &resultV3,
                threadsPerBlock, numCudaBlocks, rijndael256_es_search_v3
            };

            double v2Ms = benchmark_measure_wall_ms(host_runner, &v2Ctx,
                                                    fullWarmup, fullIterations);
            double v3Ms = benchmark_measure_wall_ms(host_runner, &v3Ctx,
                                                    fullWarmup, fullIterations);
            double v2Kps = benchmark_keys_per_second(searchRange, v2Ms);
            double v3Kps = benchmark_keys_per_second(searchRange, v3Ms);

            benchmark_require(resultV2.found == 0,
                              "ES V2 full benchmark produced a false positive");
            benchmark_require(resultV3.found == 0,
                              "ES V3 full benchmark produced a false positive");

            printf("  %-12d %-12d %-14.3f %-14.3f %-14.0f %-14.0f\n",
                   numCudaBlocks, threadsPerBlock, v2Ms, v3Ms, v2Kps, v3Kps);

            benchmark_csv_write_row(csv, "es", "full_api", "V2", "search",
                                    &device, 0, 0, searchRange, threadsPerBlock,
                                    numCudaBlocks, fullWarmup, fullIterations,
                                    v2Ms, 0.0, v2Kps);
            benchmark_csv_write_row(csv, "es", "full_api", "V3", "search",
                                    &device, 0, 0, searchRange, threadsPerBlock,
                                    numCudaBlocks, fullWarmup, fullIterations,
                                    v3Ms, 0.0, v3Kps);

            if (v2Kps > bestFullV2) {
                bestFullV2 = v2Kps;
                bestFullBlocksV2 = numCudaBlocks;
                bestFullThreadsV2 = threadsPerBlock;
            }
            if (v3Kps > bestFullV3) {
                bestFullV3 = v3Kps;
                bestFullBlocksV3 = numCudaBlocks;
                bestFullThreadsV3 = threadsPerBlock;
            }
        }

        printf("  Best full API throughput: V2 %.0f keys/s (%d x %d), "
               "V3 %.0f keys/s (%d x %d)\n\n",
               bestFullV2, bestFullBlocksV2, bestFullThreadsV2,
               bestFullV3, bestFullBlocksV3, bestFullThreadsV3);

        printf("  Launch-only (setup once, timed kernel launches)\n");
        printf("  warmup=%d iterations=%d\n", launchWarmup, launchIterations);
        printf("  %-12s %-12s %-14s %-14s %-14s %-14s\n",
               "Blocks", "Threads", "V2 (ms)", "V3 (ms)",
               "V2 keys/s", "V3 keys/s");
        printf("  ----------------------------------------------------------------------\n");

        double bestLaunchV2 = 0.0;
        double bestLaunchV3 = 0.0;
        int bestLaunchBlocksV2 = 0;
        int bestLaunchThreadsV2 = 0;
        int bestLaunchBlocksV3 = 0;
        int bestLaunchThreadsV3 = 0;

        for (int gi = 0; gi < numGrids; gi++) {
            ESResult result;
            int numCudaBlocks = gridConfigs[gi][0];
            int threadsPerBlock = gridConfigs[gi][1];
            EsLaunchRunnerCtx v2Ctx = {
                256, 0, searchRange, threadsPerBlock, numCudaBlocks,
                rijndael256_es_launch_v2
            };
            EsLaunchRunnerCtx v3Ctx = {
                256, 0, searchRange, threadsPerBlock, numCudaBlocks,
                rijndael256_es_launch_v3
            };

            rijndael256_es_setup(pt, ct, baseKey, 256);
            double v2Ms = benchmark_measure_ms(launch_runner, &v2Ctx,
                                               launchWarmup, launchIterations);
            rijndael256_es_get_result(&result);
            benchmark_require(result.found == 0,
                              "ES V2 launch benchmark produced a false positive");

            rijndael256_es_setup(pt, ct, baseKey, 256);
            double v3Ms = benchmark_measure_ms(launch_runner, &v3Ctx,
                                               launchWarmup, launchIterations);
            rijndael256_es_get_result(&result);
            benchmark_require(result.found == 0,
                              "ES V3 launch benchmark produced a false positive");

            double v2Kps = benchmark_keys_per_second(searchRange, v2Ms);
            double v3Kps = benchmark_keys_per_second(searchRange, v3Ms);

            printf("  %-12d %-12d %-14.3f %-14.3f %-14.0f %-14.0f\n",
                   numCudaBlocks, threadsPerBlock, v2Ms, v3Ms, v2Kps, v3Kps);

            benchmark_csv_write_row(csv, "es", "launch_only", "V2", "search",
                                    &device, 0, 0, searchRange, threadsPerBlock,
                                    numCudaBlocks, launchWarmup, launchIterations,
                                    v2Ms, 0.0, v2Kps);
            benchmark_csv_write_row(csv, "es", "launch_only", "V3", "search",
                                    &device, 0, 0, searchRange, threadsPerBlock,
                                    numCudaBlocks, launchWarmup, launchIterations,
                                    v3Ms, 0.0, v3Kps);

            if (v2Kps > bestLaunchV2) {
                bestLaunchV2 = v2Kps;
                bestLaunchBlocksV2 = numCudaBlocks;
                bestLaunchThreadsV2 = threadsPerBlock;
            }
            if (v3Kps > bestLaunchV3) {
                bestLaunchV3 = v3Kps;
                bestLaunchBlocksV3 = numCudaBlocks;
                bestLaunchThreadsV3 = threadsPerBlock;
            }
        }

        printf("  Best launch-only throughput: V2 %.0f keys/s (%d x %d), "
               "V3 %.0f keys/s (%d x %d)\n\n",
               bestLaunchV2, bestLaunchBlocksV2, bestLaunchThreadsV2,
               bestLaunchV3, bestLaunchBlocksV3, bestLaunchThreadsV3);
    }

    if (common.print_occupancy) {
        printf("Occupancy summary:\n");
        for (int gi = 0; gi < numGrids; gi++) {
            int tpb = gridConfigs[gi][1];
            benchmark_print_occupancy("ES V2",
                                      (const void *)rijndael256_es_kernel_v2, tpb);
            benchmark_print_occupancy("ES V3",
                                      (const void *)rijndael256_es_kernel_v3, tpb);
        }
        printf("\n");
    }

    if (csv != NULL) {
        fclose(csv);
    }
    return 0;
}
