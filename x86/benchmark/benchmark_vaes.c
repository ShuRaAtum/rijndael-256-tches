/*
 * x86-64 Rijndael-256 (VAES-512) vs AES-128/AES-256 (VAES-512 baseline).
 *
 * All hot paths use vector AES-NI (_mm512_aesenc_epi128): one ZMM = 4 x 128-bit
 * lanes.  For the AES baselines a ZMM holds 4 independent AES blocks; for R256
 * a ZMM holds 2 whole 256-bit blocks (L0,R0,L1,R1).  Both tile to 512 bytes per
 * call across 8 ZMM => 8 independent dependency chains, hiding VAESENC latency
 * for a like-for-like, round-matched comparison.
 *
 * Metrics: peak interleaved throughput (cache-resident) in GB/s and cycles/byte
 * via RDTSC.  cpb assumes a constant TSC tracking nominal frequency; pin the
 * core / use perf counters for turbo-accurate cpb.  Best-of-ITERS, 3 trials.
 */
#include "rijndael256.h"
#include <immintrin.h>
#include <x86intrin.h>     /* __rdtsc */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

void rijndael256_encrypt_vaes512_x16(const Rijndael256Key *, const uint8_t *, uint8_t *);
void rijndael256_encrypt_aesni_x4(const Rijndael256Key *, const uint8_t *, uint8_t *);

/* ---- AES baseline on VAES-512: 8 ZMM * 4 blocks = 32 blocks (512 B) / call.
 * Round key broadcast to all four 128-bit lanes. Dummy keys (throughput only). */
static void aes_vaes512_x32(const uint8_t *rk, int Nr, const uint8_t *pt, uint8_t *ct)
{
    __m512i s[8];
    for (int z = 0; z < 8; z++) s[z] = _mm512_loadu_si512((const void *)(pt + 64 * z));
    __m512i k = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(rk)));
    for (int z = 0; z < 8; z++) s[z] = _mm512_xor_si512(s[z], k);
    for (int r = 1; r < Nr; r++) {
        k = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(rk + 16 * r)));
        for (int z = 0; z < 8; z++) s[z] = _mm512_aesenc_epi128(s[z], k);
    }
    k = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(rk + 16 * Nr)));
    for (int z = 0; z < 8; z++) s[z] = _mm512_aesenclast_epi128(s[z], k);
    for (int z = 0; z < 8; z++) _mm512_storeu_si512((void *)(ct + 64 * z), s[z]);
}

/* ---- scalar AES-NI R256 (4-block interleaved) reference for the 0.947 cpb point */

#define TILE   512            /* bytes per call for every path */
#define GROUP  64             /* tiles; GROUP*TILE = 32 KiB working set (L1-resident) */
#define REPEAT 8000           /* reuse the cache-hot buffer to measure compute peak */
#define ITERS  30
static double ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e3+t.tv_nsec/1e6;}

static uint8_t bufin[GROUP * TILE], bufout[GROUP * TILE];

/* run a kernel that processes TILE bytes per call; return best ms and cycles */
typedef void (*tile_fn)(const void *ctx, const uint8_t *in, uint8_t *out);

static void run(tile_fn f, const void *ctx, double *best_ms, uint64_t *best_cyc)
{
    double bm = 1e30; uint64_t bc = ~0ull; volatile uint8_t sink = 0;
    for (int it = 0; it < ITERS; it++) {
        double a = ms(); uint64_t t = __rdtsc();
        for (int r = 0; r < REPEAT; r++)
            for (unsigned i = 0; i < GROUP; i++)
                f(ctx, bufin + i * TILE, bufout + i * TILE);
        uint64_t c = __rdtsc() - t; double e = ms();
        sink ^= bufout[0];
        if (e - a < bm) bm = e - a;
        if (c < bc) bc = c;
    }
    (void)sink; *best_ms = bm; *best_cyc = bc;
}

/* thin adapters to the common tile_fn signature */
static const uint8_t *g_rk; static int g_nr;
static void k_aes(const void *c, const uint8_t *in, uint8_t *out){(void)c; aes_vaes512_x32(g_rk, g_nr, in, out);}
static void k_r256(const void *c, const uint8_t *in, uint8_t *out){
    const Rijndael256Key *ctx = c;
    for (int t = 0; t < TILE; t += 16 * 32) rijndael256_encrypt_vaes512_x16(ctx, in + t, out + t);
}
static void k_r256_scalar(const void *c, const uint8_t *in, uint8_t *out){
    const Rijndael256Key *ctx = c;
    for (int t = 0; t < TILE; t += 128) rijndael256_encrypt_aesni_x4(ctx, in + t, out + t);
}

int main(void)
{
    uint8_t key[32] = {0}; Rijndael256Key ctx; rijndael256_setup_key(key, 256, &ctx);
    static uint8_t rk[240]; memset(rk, 0x3c, sizeof rk); memset(bufin, 0xa5, sizeof bufin);

    printf("CPU ISA: avx512f=%d avx512bw=%d avx512vbmi=%d vaes=%d vpclmulqdq=%d\n",
           __builtin_cpu_supports("avx512f"), __builtin_cpu_supports("avx512bw"),
           __builtin_cpu_supports("avx512vbmi"), __builtin_cpu_supports("vaes"),
           __builtin_cpu_supports("vpclmulqdq"));

    double bytes = (double)GROUP * TILE * REPEAT;
    const char *names[5];
    double bm[5]; uint64_t bc[5];

    for (int trial = 0; trial < 3; trial++) {
        printf("\n=== trial %d ===\n", trial + 1);
        g_rk = rk; g_nr = 10; run(k_aes,          NULL, &bm[0], &bc[0]); names[0]="AES-128 VAES512 (10R)";
        g_rk = rk; g_nr = 14; run(k_aes,          NULL, &bm[1], &bc[1]); names[1]="AES-256 VAES512 (14R)";
                              run(k_r256,        &ctx, &bm[2], &bc[2]); names[2]="R256    VAES512 (14R)";
                              run(k_r256_scalar, &ctx, &bm[3], &bc[3]); names[3]="R256    AES-NI x4(14R)";
        printf("                          GB/s     cyc/byte\n");
        for (int i = 0; i < 4; i++)
            printf("%-24s %6.2f   %7.3f\n", names[i],
                   bytes / (bm[i] / 1e3) / 1e9, (double)bc[i] / bytes);
        printf("\nR256(VAES512) slowdown/byte: vs AES-128 %.2fx ; vs AES-256 %.2fx (round-matched)\n",
               (bm[2] / bm[0]), (bm[2] / bm[1]));
        printf("R256(VAES512) cpb=%.3f  vs scalar 4-way cpb=%.3f  => %.2fx faster\n",
               (double)bc[2] / bytes, (double)bc[3] / bytes,
               (double)bc[3] / (double)bc[2]);
    }
    return 0;
}
