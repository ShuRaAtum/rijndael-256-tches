#include <stdio.h>
#include <cuda_runtime.h>

int main(void) {
    int deviceCount = 0;
    cudaError_t err = cudaGetDeviceCount(&deviceCount);

    if (err != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(err));
        return 1;
    }

    printf("CUDA devices found: %d\n\n", deviceCount);

    for (int i = 0; i < deviceCount; i++) {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);

        printf("Device %d: %s\n", i, prop.name);
        printf("  Compute Capability: %d.%d\n", prop.major, prop.minor);
        printf("  Global Memory: %.0f MB\n", prop.totalGlobalMem / (1024.0 * 1024.0));
        printf("  Shared Memory per Block: %zu bytes\n", prop.sharedMemPerBlock);
        printf("  Shared Memory per SM: %zu bytes\n", prop.sharedMemPerMultiprocessor);
        printf("  Max Threads per Block: %d\n", prop.maxThreadsPerBlock);
        printf("  Multiprocessors: %d\n", prop.multiProcessorCount);
        printf("  Warp Size: %d\n", prop.warpSize);
        printf("  Clock Rate: %.0f MHz\n", prop.clockRate / 1000.0);
        printf("  Memory Clock Rate: %.0f MHz\n", prop.memoryClockRate / 1000.0);
        printf("\n");

        /* Shared memory analysis for Rijndael-256 */
        const size_t ecb_ctr_v2 = 8 * 1024;
        const size_t ecb_ctr_v3 = 36 * 1024;
        const size_t es_v2 = ecb_ctr_v2 + 256;
        const size_t es_v3 = ecb_ctr_v3 + 256;

        printf("  Rijndael-256 Shared Memory Analysis:\n");
        printf("    ECB/CTR V2: %zu bytes (%.0f%% of per-block shared memory)\n",
               ecb_ctr_v2, ecb_ctr_v2 * 100.0 / prop.sharedMemPerBlock);
        printf("    ECB/CTR V3: %zu bytes (%.0f%% of per-block shared memory)\n",
               ecb_ctr_v3, ecb_ctr_v3 * 100.0 / prop.sharedMemPerBlock);
        printf("    ES V2:      %zu bytes (%.0f%% of per-block shared memory)\n",
               es_v2, es_v2 * 100.0 / prop.sharedMemPerBlock);
        printf("    ES V3:      %zu bytes (%.0f%% of per-block shared memory)\n",
               es_v3, es_v3 * 100.0 / prop.sharedMemPerBlock);
        printf("    Note: V3 is bank-conflict-free in the main rounds only;\n");
        printf("          final-round T4/T4i tables remain plain 1D shared arrays.\n");
        printf("    ECB/CTR V2 max blocks per SM (memory limited): %d\n",
               (int)(prop.sharedMemPerMultiprocessor / ecb_ctr_v2));
        printf("    ECB/CTR V3 max blocks per SM (memory limited): %d\n",
               (int)(prop.sharedMemPerMultiprocessor / ecb_ctr_v3));
        printf("    ES V2 max blocks per SM (memory limited): %d\n",
               (int)(prop.sharedMemPerMultiprocessor / es_v2));
        printf("    ES V3 max blocks per SM (memory limited): %d\n",
               (int)(prop.sharedMemPerMultiprocessor / es_v3));
    }

    return 0;
}
