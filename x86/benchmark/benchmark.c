/*
 * x86-64 Rijndael-256 vs AES-128/AES-256 throughput & cycles-per-byte.
 *
 * Purpose: quantify the AES->R256 slowdown on x86 hardware-accelerated paths
 * (AES-NI) for a like-for-like comparison with the AArch64 ARM-Crypto results.
 * Run this on a REAL x86 machine (not under Rosetta) for representative numbers.
 *
 * Metrics: peak 4-block-interleaved throughput (cache-resident) and cycles/byte
 * via RDTSC. cpb assumes a constant TSC tracking the core's nominal frequency;
 * for turbo-accurate cpb pin the frequency or use perf counters.
 */
#include "rijndael256.h"
#include <wmmintrin.h>
#include <x86intrin.h>     /* __rdtsc */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

void rijndael256_encrypt_aesni(const Rijndael256Key *, const uint8_t *, uint8_t *);
void rijndael256_encrypt_aesni_x4(const Rijndael256Key *, const uint8_t *, uint8_t *);

/* ---- standard AES-NI baselines (4-block interleaved), key schedule = rk ---- */
#define AESENC4(k) \
    do { __m128i K=_mm_loadu_si128((const __m128i*)(rk+16*(k))); \
         b0=_mm_aesenc_si128(b0,K); b1=_mm_aesenc_si128(b1,K); \
         b2=_mm_aesenc_si128(b2,K); b3=_mm_aesenc_si128(b3,K); } while(0)
#define AESLAST4(k) \
    do { __m128i K=_mm_loadu_si128((const __m128i*)(rk+16*(k))); \
         b0=_mm_aesenclast_si128(b0,K); b1=_mm_aesenclast_si128(b1,K); \
         b2=_mm_aesenclast_si128(b2,K); b3=_mm_aesenclast_si128(b3,K); } while(0)

static void aes_x4(const uint8_t *rk, int Nr, const uint8_t *pt, uint8_t *ct)
{
    __m128i b0=_mm_loadu_si128((const __m128i*)(pt));
    __m128i b1=_mm_loadu_si128((const __m128i*)(pt+16));
    __m128i b2=_mm_loadu_si128((const __m128i*)(pt+32));
    __m128i b3=_mm_loadu_si128((const __m128i*)(pt+48));
    __m128i K0=_mm_loadu_si128((const __m128i*)(rk));
    b0=_mm_xor_si128(b0,K0); b1=_mm_xor_si128(b1,K0);
    b2=_mm_xor_si128(b2,K0); b3=_mm_xor_si128(b3,K0);
    for (int r=1;r<Nr;r++) AESENC4(r);
    AESLAST4(Nr);
    _mm_storeu_si128((__m128i*)(ct),    b0); _mm_storeu_si128((__m128i*)(ct+16), b1);
    _mm_storeu_si128((__m128i*)(ct+32), b2); _mm_storeu_si128((__m128i*)(ct+48), b3);
}

#define GROUP 4096
#define REPEAT 2000
#define ITERS 20
static double ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e3+t.tv_nsec/1e6;}

static uint8_t bufin[GROUP*32], bufout[GROUP*32];

int main(void)
{
    uint8_t key[32]={0}; Rijndael256Key ctx; rijndael256_setup_key(key,256,&ctx);
    static uint8_t rk[240]; memset(rk,0x3c,sizeof rk); memset(bufin,0xa5,sizeof bufin);
    volatile uint8_t s=0;

    /* throughput (ms) and cpb (rdtsc), best-of-ITERS */
    double ba=1e30,b2=1e30,br=1e30; uint64_t ca=~0ull,c2=~0ull,cr=~0ull;
    for(int it=0;it<ITERS;it++){double a=ms();uint64_t t=__rdtsc();
        for(int r=0;r<REPEAT;r++) for(unsigned i=0;i<GROUP;i+=4) aes_x4(rk,10,bufin+i*16,bufout+i*16);
        uint64_t c=__rdtsc()-t;double e=ms();s^=bufout[0];if(e-a<ba)ba=e-a;if(c<ca)ca=c;}
    for(int it=0;it<ITERS;it++){double a=ms();uint64_t t=__rdtsc();
        for(int r=0;r<REPEAT;r++) for(unsigned i=0;i<GROUP;i+=4) aes_x4(rk,14,bufin+i*16,bufout+i*16);
        uint64_t c=__rdtsc()-t;double e=ms();s^=bufout[0];if(e-a<b2)b2=e-a;if(c<c2)c2=c;}
    for(int it=0;it<ITERS;it++){double a=ms();uint64_t t=__rdtsc();
        for(int r=0;r<REPEAT;r++) for(unsigned i=0;i<GROUP;i+=4) rijndael256_encrypt_aesni_x4(&ctx,bufin+i*32,bufout+i*32);
        uint64_t c=__rdtsc()-t;double e=ms();s^=bufout[0];if(e-a<br)br=e-a;if(c<cr)cr=c;}
    (void)s;

    double Baes=(double)GROUP*16.0*REPEAT, Br=(double)GROUP*32.0*REPEAT;
    printf("                 GB/s     cyc/byte\n");
    printf("AES-128 (10R): %6.2f   %7.3f\n", Baes/(ba/1e3)/1e9, (double)ca/Baes);
    printf("AES-256 (14R): %6.2f   %7.3f\n", Baes/(b2/1e3)/1e9, (double)c2/Baes);
    printf("R256    (14R): %6.2f   %7.3f\n", Br/(br/1e3)/1e9,  (double)cr/Br);
    printf("\nAES->R256 slowdown/byte : vs AES-128 %.2fx ; vs AES-256 %.2fx (round-matched)\n",
           (Baes/ba)/(Br/br), (Baes/b2)/(Br/br));
    return 0;
}
