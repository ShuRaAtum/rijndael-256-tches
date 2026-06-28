/*
 * FEAT_DIT (Data-Independent Timing) on/off A/B micro-benchmark — Apple M2.
 *
 * Measures the throughput overhead of enabling PSTATE.DIT around the
 * AddRoundKey-folded ARM-Crypto Rijndael-256 encrypt loop (single-block and
 * interleaved x4 = the M2-optimal regime). AESE/AESMC are already
 * data-independent on Apple Silicon regardless of DIT, so the expected overhead
 * is ~0; this run measures that overhead directly.
 *
 * DIT is toggled at EL0 via `msr DIT, #1/#0` and read back via `mrs Xt, DIT`
 * (bit 24) to confirm the write took effect. Build requires armv8.4-a (FEAT_DIT)
 * for the assembler; the folded impl objects are linked from the normal build.
 *
 * Off/on passes are interleaved and reduced with best-of-N to cancel thermal drift.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/sysctl.h>
#include "rijndael256.h"
#include "rijndael256_folded_arm.h"

#define BLOCK    32
#define NBLOCKS  (1024 * 1024)   /* 32 MB; AES-limited (~4 GB/s) so compute-bound, DIT-sensitive */
#define ROUNDS   50

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static inline void dit_set(int on) {
    if (on) __asm__ volatile("msr DIT, #1" ::: "memory");
    else    __asm__ volatile("msr DIT, #0" ::: "memory");
}
static inline unsigned long dit_get(void) {
    unsigned long d;
    __asm__ volatile("mrs %0, DIT" : "=r"(d));
    return (d >> 24) & 1UL;   /* PSTATE.DIT is bit 24 of the DIT system register */
}

static int feat_dit_available(void) {
    int v = 0; size_t sz = sizeof(v);
    if (sysctlbyname("hw.optional.arm.FEAT_DIT", &v, &sz, NULL, 0) != 0) return -1;
    return v;
}

/* one timed pass over NBLOCKS, N blocks per call; returns ms */
static double pass(const R256FoldedKey *fk, const uint8_t *data, int N) {
    uint8_t out[8 * 32];
    volatile uint8_t sink;
    double t0 = now_ms();
    if (N == 1)
        for (size_t i = 0; i < (size_t)NBLOCKS; i++)
            rijndael256_encrypt_arm_folded(fk, data + i * BLOCK, out);
    else
        for (size_t i = 0; i + (size_t)N <= (size_t)NBLOCKS; i += (size_t)N)
            rijndael256_encrypt_arm_folded_x4(fk, data + i * BLOCK, out);
    double t1 = now_ms();
    sink = out[0]; (void)sink;
    return t1 - t0;
}

int main(void) {
    int dit = feat_dit_available();
    printf("FEAT_DIT (hw.optional.arm.FEAT_DIT): %s\n",
           dit < 0 ? "sysctl-missing" : (dit ? "available" : "unavailable"));
    if (dit <= 0) {
        printf("DIT unavailable on this host — cannot A/B. Paper should state 'not measured'.\n");
        return dit < 0 ? 2 : 1;
    }

    /* confirm the toggle actually takes effect at EL0 */
    dit_set(1); unsigned long on_ok = dit_get();
    dit_set(0); unsigned long off_ok = dit_get();
    printf("DIT toggle read-back: set#1 -> %lu, set#0 -> %lu  (%s)\n",
           on_ok, off_ok, (on_ok == 1 && off_ok == 0) ? "OK" : "FAILED");
    if (!(on_ok == 1 && off_ok == 0)) return 4;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 31 + 11);
    uint8_t *data = (uint8_t *)malloc((size_t)NBLOCKS * BLOCK);
    if (!data) return 3;
    for (size_t i = 0; i < (size_t)NBLOCKS * BLOCK; i++) data[i] = (uint8_t)(i * 17 + 5);

    Rijndael256Key ctx;
    rijndael256_setup_key(key, 256, &ctx);   /* 256-bit, Nr=14 */
    R256FoldedKey fk;
    rijndael256_folded_setup(&ctx, &fk);

    const double mb = (double)NBLOCKS * BLOCK / (1024.0 * 1024.0);
    for (int i = 0; i < 5; i++) { (void)pass(&fk, data, 1); (void)pass(&fk, data, 4); }

    const int Ns[2] = {1, 4};
    const char *nm[2] = {"single", "x4"};
    double best_off[2] = {1e30, 1e30}, best_on[2] = {1e30, 1e30};
    for (int r = 0; r < ROUNDS; r++) {
        for (int k = 0; k < 2; k++) {
            dit_set(0); double toff = pass(&fk, data, Ns[k]); if (toff < best_off[k]) best_off[k] = toff;
            dit_set(1); double ton  = pass(&fk, data, Ns[k]); if (ton  < best_on[k])  best_on[k]  = ton;
        }
    }
    dit_set(0);

    printf("\nregime,dit,throughput_mbps,time_ms\n");
    for (int k = 0; k < 2; k++) {
        double off_mbps = mb / (best_off[k] / 1000.0), on_mbps = mb / (best_on[k] / 1000.0);
        printf("%s,off,%.2f,%.3f\n", nm[k], off_mbps, best_off[k]);
        printf("%s,on,%.2f,%.3f\n",  nm[k], on_mbps,  best_on[k]);
    }
    printf("\nDIT overhead (best-of-%d; positive = slower with DIT on):\n", ROUNDS);
    for (int k = 0; k < 2; k++) {
        double off_mbps = mb / (best_off[k] / 1000.0), on_mbps = mb / (best_on[k] / 1000.0);
        double ov = (off_mbps - on_mbps) / off_mbps * 100.0;
        printf("  %-6s : DIT-off %.1f MB/s | DIT-on %.1f MB/s | overhead %+.2f%%\n",
               nm[k], off_mbps, on_mbps, ov);
    }
    free(data);
    return 0;
}
