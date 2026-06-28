# x86-64 AES-NI — Rijndael-256 (secondary 128-bit baseline)

> **Role.** This is a **secondary, narrow-vector baseline**, *not* the paper's x86
> result. The x86 contribution is the faithful reproduction of **[DG22]**
> (Drucker & Gueron, "Software Optimization of Rijndael for Modern x86-64
> Platforms", ITNG 2022) using **VAES-512**, which reaches ~0.255 cpb /
> **1.09× vs AES-256** — see `x86/rijndael256_vaes512.c` and
> [`../../docs/results/x86_i7-1165g7_2026-06-18.csv`](../../docs/results/x86_i7-1165g7_2026-06-18.csv).
> The numbers here exist only to show that **without wide vector AES, x86 is
> roughly as slow as ARM** (~3.4×), and that this scalar slowdown is
> microarchitecture-independent. Do **not** label this path as [DG22].

## What this measures

The **AES-NI 128-bit, 4-block-interleaved** path (`rijndael256_encrypt_aesni_x4`):
a `blend + pshufb` pre-shuffle corrects Rijndael-256's `ShiftRows(0,1,3,4)`, then
`AESENC` runs the round. It shares the *pre-shuffle idea* with the VAES-512 path
but at 128-bit width. Benchmarked against 4-block-interleaved AES-128/AES-256 on
the same hardware for a within-platform AES→R256 slowdown.

## Environment

| | |
|---|---|
| Host | 13th Gen Intel Core i7-13700KF (Raptor Lake) |
| ISA features | AES-NI, VAES, AVX2 — **no AVX-512** (cannot run the VAES-512 path) |
| Compiler | gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) |
| Flags | `-O3 -maes -mavx -mssse3 -msse4.1` (committed Makefile) |
| Governor | powersave (max 5400 MHz / min 800 MHz) |
| Date | 2026-06-18 |

## How to reproduce

```sh
cd x86
make test        # KAT vs portable reference — all PASS (128/192/256 + sweep + x4)
make benchmark   # throughput + cycles/byte vs AES-128/AES-256
```

cpb uses RDTSC and assumes a constant TSC tracking nominal frequency; pin the
frequency or use perf counters for turbo-accurate cpb. Throughput (GB/s) is
wall-clock (`CLOCK_MONOTONIC`) and turbo-independent.

## Results

KAT: `[k128] PASS  [k192] PASS  [k256] PASS  [sweep 1000] PASS  [x4] PASS`

| Cipher (rounds) | Impl | GB/s | cyc/byte |
|---|---|---:|---:|
| AES-128 (10R) | AES-NI x4 | 17.22 | 0.198 |
| AES-256 (14R) | AES-NI x4 | 12.29 | 0.278 |
| Rijndael-256 (14R) | AES-NI blend+pshufb x4 | 3.61 | 0.947 |

**AES→R256 slowdown/byte: 4.77× vs AES-128, 3.41× vs AES-256 (round-matched).**

Stable across 3 runs and `-march=native` (path unchanged — explicit `__m128i`
intrinsics). Raw output: [`x86_i7-13700kf_2026-06-18.txt`](x86_i7-13700kf_2026-06-18.txt);
CSV: [`x86_i7-13700kf_2026-06-18.csv`](x86_i7-13700kf_2026-06-18.csv).

## Where this fits in the cross-platform comparison

The comparison axis is the **within-platform AES→R256 slowdown** (frequency- and
width-independent ratio). Same adaptation strategy (pre-shuffle, then reuse the
HW AES round), realized per-ISA:

| x86 path | R256 vs AES-256 | note |
|---|---|---|
| **VAES-512** ([DG22], headline) | **1.09×** | one `VPERMB` on a separate port overlaps the AES units; multi-block/instr |
| AES-NI scalar x4 (this dir) | **3.41×** | 128-bit; per-half `blend+pshufb` cannot overlap, ≈ ARM single-block EOR (~3.6×) |

So the wide-vector path recovers R256 to near-AES; the narrow path does not.
The AES-NI scalar slowdown (3.41×/4.77× here) is consistent with the i7-1165G7
measurement (3.61 GB/s on both hosts), i.e. microarchitecture-independent — which
is exactly why it serves as a baseline rather than a result.
