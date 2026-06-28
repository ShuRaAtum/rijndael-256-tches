# Rijndael-256 on x86-64 (AES-NI)

Hardware-accelerated R256 using AES-NI with a DG22-style **blend + pshufb**
pre-shuffle, for an apples-to-apples AES→R256 comparison against the AArch64
ARM-Crypto path.

## Technique

R256's `ShiftRows(0,1,3,4)` differs from the hardware-wired `(0,1,2,3)` and
moves bytes across the 128-bit lane boundary. Since `PSHUFB` is lane-local, each
output half is built by gathering bytes across `L`/`R` with `PBLENDVB`, then
permuting within the lane with `PSHUFB`, then running `AESENC`:

```
L' = pshufb(blendv(L, R, sel_L), perm_L)
R' = pshufb(blendv(L, R, sel_R), perm_R)
L  = aesenc(L', rk_L)        # ShiftRows→SubBytes→MixColumns→AddRoundKey
R  = aesenc(R', rk_R)
```

`AESENC` bundles MixColumns **and** AddRoundKey (applied at the end, in natural
column order), so — unlike the AArch64 path (`AESE`+`AESMC`+separate `EOR`) — no
separate AddRoundKey and no key pre-shuffle is needed. Per half a round is
`PBLENDVB + PSHUFB + AESENC` (3 instructions). Pre-shuffle masks are derived from
the same source mapping as the AArch64 `TBL` masks (both correct the identical
post-pre-shuffle hardware `ShiftRows(0,1,2,3)`).

## Build / run (on a real x86-64 host with AES-NI)

```
make test        # KAT vs portable reference (128/192/256 + sweep + 4-way)
make benchmark   # GB/s and cycles/byte vs AES-128 / AES-256 baselines
```

Files: `rijndael256_aesni.c` (impl + 4-block interleaved `_x4`),
`test/test_kat.c`, `benchmark/benchmark.c`. Reference and key schedule are reused
from `../aarch64` (portable C).

> Correctness was cross-checked on Apple Silicon via Rosetta 2 (which executes
> AES-NI/AVX). **Performance must be measured on native x86-64** — Rosetta timing
> is not representative.
