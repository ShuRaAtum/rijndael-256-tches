#ifndef RIJNDAEL_BENCHMARK_COMMON_H
#define RIJNDAEL_BENCHMARK_COMMON_H

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cuda_runtime.h>

typedef void (*benchmark_runner_t)(void *ctx);

typedef struct {
    int warmup_override;
    int iterations_override;
    const char *csv_path;
    int print_device_info;
    int enable_validation;
    int print_occupancy;
} BenchmarkCommonOptions;

typedef struct {
    int ordinal;
    char name[256];
    int compute_major;
    int compute_minor;
    size_t global_mem_bytes;
    int multiprocessors;
    int warp_size;
    int max_threads_per_block;
    size_t shared_mem_per_block;
    size_t shared_mem_per_sm;
    int runtime_version;
    int driver_version;
} BenchmarkDeviceInfo;

static inline void benchmark_fail(const char *message) {
    fprintf(stderr, "benchmark error: %s\n", message);
    exit(EXIT_FAILURE);
}

static inline void benchmark_require(int condition, const char *message) {
    if (!condition) {
        benchmark_fail(message);
    }
}

static inline int benchmark_parse_positive_int(const char *value,
                                               const char *option_name) {
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (value[0] == '\0' || end == value || *end != '\0' || parsed <= 0 ||
        parsed > 1 << 30) {
        fprintf(stderr, "Invalid value for %s: %s\n", option_name, value);
        exit(EXIT_FAILURE);
    }
    return (int)parsed;
}

static inline uint64_t benchmark_parse_u64(const char *value,
                                           const char *option_name) {
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (value[0] == '\0' || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", option_name, value);
        exit(EXIT_FAILURE);
    }
    return (uint64_t)parsed;
}

static inline size_t benchmark_parse_mib_list(const char *csv, size_t *out,
                                              int max_items,
                                              const char *option_name) {
    char *copy = (char *)malloc(strlen(csv) + 1);
    benchmark_require(copy != NULL, "malloc failed");
    strcpy(copy, csv);

    size_t count = 0;
    char *token = strtok(copy, ",");
    while (token != NULL) {
        if ((int)count >= max_items) {
            fprintf(stderr, "%s accepts at most %d values\n",
                    option_name, max_items);
            free(copy);
            exit(EXIT_FAILURE);
        }

        char *end = NULL;
        unsigned long long mib = strtoull(token, &end, 10);
        if (token[0] == '\0' || end == token || *end != '\0' || mib == 0ULL) {
            fprintf(stderr, "Invalid MiB value for %s: %s\n",
                    option_name, token);
            free(copy);
            exit(EXIT_FAILURE);
        }
        out[count++] = (size_t)mib * 1024ULL * 1024ULL;
        token = strtok(NULL, ",");
    }

    free(copy);
    return count;
}

static inline int benchmark_parse_int_list(const char *csv, int *out,
                                           int max_items,
                                           const char *option_name) {
    char *copy = (char *)malloc(strlen(csv) + 1);
    benchmark_require(copy != NULL, "malloc failed");
    strcpy(copy, csv);

    int count = 0;
    char *token = strtok(copy, ",");
    while (token != NULL) {
        if (count >= max_items) {
            fprintf(stderr, "%s accepts at most %d values\n",
                    option_name, max_items);
            free(copy);
            exit(EXIT_FAILURE);
        }
        out[count++] = benchmark_parse_positive_int(token, option_name);
        token = strtok(NULL, ",");
    }

    free(copy);
    return count;
}

static inline int benchmark_parse_grid_list(const char *csv,
                                            int (*out)[2],
                                            int max_items,
                                            const char *option_name) {
    char *copy = (char *)malloc(strlen(csv) + 1);
    benchmark_require(copy != NULL, "malloc failed");
    strcpy(copy, csv);

    int count = 0;
    char *token = strtok(copy, ",");
    while (token != NULL) {
        int blocks = 0;
        int threads = 0;
        if (count >= max_items) {
            fprintf(stderr, "%s accepts at most %d values\n",
                    option_name, max_items);
            free(copy);
            exit(EXIT_FAILURE);
        }
        if (sscanf(token, "%dx%d", &blocks, &threads) != 2 &&
            sscanf(token, "%dX%d", &blocks, &threads) != 2) {
            fprintf(stderr, "Invalid grid config for %s: %s\n",
                    option_name, token);
            free(copy);
            exit(EXIT_FAILURE);
        }
        benchmark_require(blocks > 0 && threads > 0,
                          "grid config values must be positive");
        out[count][0] = blocks;
        out[count][1] = threads;
        count++;
        token = strtok(NULL, ",");
    }

    free(copy);
    return count;
}

static inline void benchmark_init_common_options(BenchmarkCommonOptions *options) {
    options->warmup_override = -1;
    options->iterations_override = -1;
    options->csv_path = NULL;
    options->print_device_info = 1;
    options->enable_validation = 1;
    options->print_occupancy = 1;
}

static inline int benchmark_handle_common_option(int argc, char **argv,
                                                 int *index,
                                                 BenchmarkCommonOptions *options) {
    const char *arg = argv[*index];
    if (strcmp(arg, "--warmup") == 0) {
        if (*index + 1 >= argc) benchmark_fail("--warmup requires a value");
        options->warmup_override =
            benchmark_parse_positive_int(argv[++(*index)], "--warmup");
        return 1;
    }
    if (strcmp(arg, "--iterations") == 0) {
        if (*index + 1 >= argc) benchmark_fail("--iterations requires a value");
        options->iterations_override =
            benchmark_parse_positive_int(argv[++(*index)], "--iterations");
        return 1;
    }
    if (strcmp(arg, "--csv") == 0) {
        if (*index + 1 >= argc) benchmark_fail("--csv requires a path");
        options->csv_path = argv[++(*index)];
        return 1;
    }
    if (strcmp(arg, "--no-device-info") == 0) {
        options->print_device_info = 0;
        return 1;
    }
    if (strcmp(arg, "--skip-validation") == 0) {
        options->enable_validation = 0;
        return 1;
    }
    if (strcmp(arg, "--no-occupancy") == 0) {
        options->print_occupancy = 0;
        return 1;
    }
    return 0;
}

static inline void benchmark_query_device_info(BenchmarkDeviceInfo *info) {
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDevice(&info->ordinal));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, info->ordinal));
    CUDA_CHECK(cudaRuntimeGetVersion(&info->runtime_version));
    CUDA_CHECK(cudaDriverGetVersion(&info->driver_version));

    strncpy(info->name, prop.name, sizeof(info->name) - 1);
    info->name[sizeof(info->name) - 1] = '\0';
    info->compute_major = prop.major;
    info->compute_minor = prop.minor;
    info->global_mem_bytes = prop.totalGlobalMem;
    info->multiprocessors = prop.multiProcessorCount;
    info->warp_size = prop.warpSize;
    info->max_threads_per_block = prop.maxThreadsPerBlock;
    info->shared_mem_per_block = prop.sharedMemPerBlock;
    info->shared_mem_per_sm = prop.sharedMemPerMultiprocessor;
}

static inline void benchmark_format_utc_now(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm tm_utc;
#if defined(_WIN32)
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

static inline void benchmark_print_run_metadata(const char *title,
                                                int argc, char **argv,
                                                const BenchmarkCommonOptions *options,
                                                const BenchmarkDeviceInfo *device) {
    char timestamp[32];
    benchmark_format_utc_now(timestamp, sizeof(timestamp));

    printf("=== %s ===\n\n", title);
    printf("Run metadata:\n");
    printf("  UTC timestamp: %s\n", timestamp);
    printf("  Validation: %s\n", options->enable_validation ? "enabled" : "disabled");
    printf("  CSV output: %s\n", options->csv_path != NULL ? options->csv_path : "(none)");
    printf("  Command:");
    for (int i = 0; i < argc; i++) {
        printf(" %s", argv[i]);
    }
    printf("\n");

    if (options->print_device_info) {
        printf("  Device %d: %s\n", device->ordinal, device->name);
        printf("  Compute capability: %d.%d\n",
               device->compute_major, device->compute_minor);
        printf("  Global memory: %.2f GiB\n",
               (double)device->global_mem_bytes /
                   (1024.0 * 1024.0 * 1024.0));
        printf("  Multiprocessors: %d\n", device->multiprocessors);
        printf("  Warp size: %d\n", device->warp_size);
        printf("  Max threads/block: %d\n", device->max_threads_per_block);
        printf("  Shared memory/block: %zu bytes\n", device->shared_mem_per_block);
        printf("  Shared memory/SM: %zu bytes\n", device->shared_mem_per_sm);
        printf("  CUDA runtime version: %d\n", device->runtime_version);
        printf("  CUDA driver version: %d\n", device->driver_version);
    }
    printf("\n");
}

static inline FILE *benchmark_open_csv(const char *path) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open CSV path %s: %s\n",
                path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    fprintf(fp,
            "benchmark,section,variant,operation,device_name,compute_capability,"
            "data_bytes,num_blocks,search_range,threads_per_block,num_cuda_blocks,"
            "warmup,iterations,avg_ms,throughput_gib_s,keys_per_second\n");
    return fp;
}

static inline void benchmark_csv_write_row(FILE *fp,
                                           const char *benchmark_name,
                                           const char *section,
                                           const char *variant,
                                           const char *operation,
                                           const BenchmarkDeviceInfo *device,
                                           size_t data_bytes,
                                           size_t num_blocks,
                                           uint64_t search_range,
                                           int threads_per_block,
                                           int num_cuda_blocks,
                                           int warmup,
                                           int iterations,
                                           double avg_ms,
                                           double throughput_gib_s,
                                           double keys_per_second) {
    if (fp == NULL) {
        return;
    }

    fprintf(fp,
            "%s,%s,%s,%s,\"%s\",%d.%d,%zu,%zu,%" PRIu64 ",%d,%d,%d,%d,%.6f,%.6f,%.6f\n",
            benchmark_name,
            section,
            variant,
            operation,
            device->name,
            device->compute_major,
            device->compute_minor,
            data_bytes,
            num_blocks,
            search_range,
            threads_per_block,
            num_cuda_blocks,
            warmup,
            iterations,
            avg_ms,
            throughput_gib_s,
            keys_per_second);
    fflush(fp);
}

static inline double benchmark_measure_ms(benchmark_runner_t runner, void *ctx,
                                          int warmup, int iterations) {
    cudaEvent_t start;
    cudaEvent_t stop;
    float total_ms = 0.0f;

    benchmark_require(iterations > 0, "iterations must be positive");
    benchmark_require(warmup >= 0, "warmup must be non-negative");

    for (int i = 0; i < warmup; i++) {
        runner(ctx);
        CUDA_CHECK(cudaDeviceSynchronize());
    }

    CUDA_CHECK(cudaEventCreate(&start));
    CUDA_CHECK(cudaEventCreate(&stop));
    CUDA_CHECK(cudaEventRecord(start));
    for (int i = 0; i < iterations; i++) {
        runner(ctx);
    }
    CUDA_CHECK(cudaEventRecord(stop));
    CUDA_CHECK(cudaEventSynchronize(stop));
    CUDA_CHECK(cudaEventElapsedTime(&total_ms, start, stop));
    CUDA_CHECK(cudaEventDestroy(start));
    CUDA_CHECK(cudaEventDestroy(stop));

    return (double)total_ms / (double)iterations;
}

static inline double benchmark_measure_wall_ms(benchmark_runner_t runner, void *ctx,
                                               int warmup, int iterations) {
    struct timespec start;
    struct timespec stop;

    benchmark_require(iterations > 0, "iterations must be positive");
    benchmark_require(warmup >= 0, "warmup must be non-negative");

    for (int i = 0; i < warmup; i++) {
        runner(ctx);
    }

    benchmark_require(clock_gettime(CLOCK_MONOTONIC, &start) == 0,
                      "clock_gettime start failed");
    for (int i = 0; i < iterations; i++) {
        runner(ctx);
    }
    benchmark_require(clock_gettime(CLOCK_MONOTONIC, &stop) == 0,
                      "clock_gettime stop failed");

    double elapsed_ms =
        (double)(stop.tv_sec - start.tv_sec) * 1000.0 +
        (double)(stop.tv_nsec - start.tv_nsec) / 1000000.0;
    return elapsed_ms / (double)iterations;
}

static inline double benchmark_throughput_gib_s(size_t bytes, double avg_ms) {
    if (avg_ms <= 0.0) {
        return 0.0;
    }
    return ((double)bytes / (1024.0 * 1024.0 * 1024.0)) / (avg_ms / 1000.0);
}

static inline double benchmark_keys_per_second(uint64_t keys, double avg_ms) {
    if (avg_ms <= 0.0) {
        return 0.0;
    }
    return (double)keys / (avg_ms / 1000.0);
}

static inline uint8_t *benchmark_malloc_bytes(size_t size) {
    uint8_t *ptr = (uint8_t *)malloc(size);
    benchmark_require(ptr != NULL, "malloc failed");
    return ptr;
}

static inline void benchmark_fill_pattern(uint8_t *data, size_t size,
                                          unsigned int multiplier,
                                          unsigned int offset) {
    for (size_t i = 0; i < size; i++) {
        data[i] = (uint8_t)((i * multiplier + offset) & 0xFFu);
    }
}

static inline void benchmark_print_occupancy(const char *label, const void *kernel,
                                             int threads_per_block) {
    int max_blocks = 0;
    int device_ordinal = 0;
    cudaDeviceProp prop;

    CUDA_CHECK(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &max_blocks, kernel, threads_per_block, 0));
    CUDA_CHECK(cudaGetDevice(&device_ordinal));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device_ordinal));

    int warps_per_sm = max_blocks * (threads_per_block / prop.warpSize);
    int max_warps_per_sm = prop.maxThreadsPerMultiProcessor / prop.warpSize;
    double occupancy = 100.0 * (double)warps_per_sm / (double)max_warps_per_sm;

    printf("  %s @ %d threads: %d blocks/SM, %.1f%% occupancy\n",
           label, threads_per_block, max_blocks, occupancy);
}

#endif
