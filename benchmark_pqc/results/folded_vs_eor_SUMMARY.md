# PQC Rijndael-256: folded vs EOR (Apple M2)

**Question.** §4 (bulk / key-reuse throughput) already shows the *folded* Rijndael-256
path — round keys pre-shuffled to `Kpre = TBL(rk)` so AddRoundKey is absorbed into
`AESE` — beats the shipped *EOR* path (AESMC then a separate EOR AddRoundKey). PQC,
however, rekeys constantly (a fresh key per GGM/seed-tree node), so every key pays a
`Kpre` pre-shuffle. Does folded still help inside sign/verify? This measures it.

> Scope: PQC only. §4 numbers were **not** re-measured.

## Environment
- **CPU**: Apple M2 (arm64), `cntvct_el0` cycle counter
- **OS**: macOS 26.2 (build 25C56)
- **Compiler**: Apple clang 17.0.0 (clang-1700.6.3.2) — defines `__ARM_FEATURE_CRYPTO`/`AES` by default
- Schemes present: SDitH, Mirath, RYDE, MQOM (no FAEST tree on this machine)
- Data: `benchmark_20260624_141142.csv` (median of 3 runs; ITERS fast=300, SDitH=60)
  raw log `folded_vs_eor_raw_20260624_141142.log`

## Build variant
A new `USE_ARM_FOLDED` build was added to every scheme (Make: `RIJNDAEL_ARM_FOLDED=1`
for MQOM, `make arm_folded` for Mirath, `ryde{3f,5f}-arm-folded-bench` for RYDE;
CMake: `-DUSE_ARM_FOLDED=ON` for SDitH). It defines the ARM-crypto path and selects
`rijndael256_encrypt_arm_folded`. **`rijndael256_folded_setup` (the per-key `Kpre`
pre-shuffle) runs once per key, inside the seed/key-expansion that sign/verify call per
node — i.e. its cost is counted in the timing, not hoisted out of the loop.** Folded
encrypt is single-block (mirroring the EOR path's serial structure) so the comparison
isolates AddRoundKey folding, not block interleaving.

## Byte-identity (KAT / round-trip)
**PASS — folded is byte-identical to EOR for every scheme.**
- Per-scheme block test (`folded_vs_eor_identity_20260624_143709.txt`): each scheme's own
  `rijndael256_encrypt_arm_folded` vs its own EOR `rijndael256_arm.S` over **50 000 random
  (key, block) pairs → 0 mismatches**, all 8 variants.
- Every scheme's `rijndael256_arm.S` is SHA-256-identical to the canonical
  `aarch64/platform/apple/rijndael256_arm.S`, and folded `MASK_L/MASK_R` equals the asm
  `_mask_for_L/_R`, so folded ≡ EOR by construction.
- Every `arm_folded` benchmark run completed its internal **sign→verify round-trip** (a
  wrong Rijndael byte would invalidate the signature and abort the bench); none did.
- (The schemes' bundled NIST `PQCgenKAT` generators have pre-existing link errors
  unrelated to folding, so block-level + round-trip identity is used instead.)

## Results — folded / EOR cycle ratio (lower = folded faster)
Two columns per stage: **Rijndael-only** cycles (where folding acts) and **whole-stage**
cycles. `>1.00` means folded is **slower**.

| Scheme | Lvl | Stage  | EOR Rij | Fold Rij | Rij ratio | EOR total | Fold total | Total ratio |
|--------|-----|--------|--------:|---------:|----------:|----------:|-----------:|------------:|
| MQOM   | 3   | sign   | 247 485 | 299 683  | **1.211** |   583 157 |    635 448 | 1.090 |
| MQOM   | 3   | verify | 246 594 | 298 380  | **1.210** |   443 979 |    495 635 | 1.116 |
| MQOM   | 5   | sign   | 349 409 | 423 475  | **1.212** | 1 102 562 |  1 178 234 | 1.069 |
| MQOM   | 5   | verify | 348 295 | 421 622  | **1.211** |   761 275 |    835 977 | 1.098 |
| Mirath | 3   | sign   |  97 400 | 111 460  | **1.144** |   835 070 |    850 663 | 1.019 |
| Mirath | 3   | verify | 111 979 | 129 410  | **1.156** |   534 644 |    553 160 | 1.035 |
| Mirath | 5   | sign   | 128 122 | 138 072  | **1.078** | 2 042 284 |  2 027 172 | 0.993 |
| Mirath | 5   | verify | 148 281 | 144 421  | _0.974_   | 1 153 912 |  1 146 712 | 0.994 |
| RYDE   | 3   | sign   | 123 753 | 142 424  | **1.151** |   550 212 |    571 777 | 1.039 |
| RYDE   | 3   | verify | 122 399 | 139 859  | **1.143** |   482 773 |    500 535 | 1.037 |
| RYDE   | 5   | sign   | 164 663 | 192 026  | **1.166** | 1 284 106 |  1 316 929 | 1.026 |
| RYDE   | 5   | verify | 161 943 | 189 344  | **1.169** | 1 058 984 |  1 096 617 | 1.036 |
| SDitH  | 3   | sign   |  72 284 |  93 054  | **1.287** | 4 962 094 |  4 993 776 | 1.006 |
| SDitH  | 3   | verify |  71 819 |  92 904  | **1.294** | 4 654 403 |  4 696 307 | 1.009 |
| SDitH  | 5   | sign   |  90 871 | 108 981  | **1.199** | 7 580 677 |  7 614 262 | 1.004 |
| SDitH  | 5   | verify |  90 866 | 107 046  | **1.178** | 6 940 190 |  6 976 141 | 1.005 |

(cycles = median `avg_total_cycles` / `avg_rijndael_cycles` over 3 runs.)

## Where folded wins / loses
**EOR wins essentially everywhere; folded does not pay off inside PQC.**

- **On the Rijndael-256 portion, folded is 8–29 % *slower* than EOR** in 15 of 16
  cells. The single exception (Mirath L5 verify, −2.6 %) is within run-to-run noise and
  its whole-stage time is a tie (0.994). No scheme/level shows a real folded win.
- **MQOM** is hit hardest end-to-end (whole-stage **+7 to +12 %**): its multi-key x2/x4
  expansion encrypts only a handful of blocks per key, so `Kpre` is amortized over very
  little, and Rijndael is a large fraction of MQOM's work.
- **RYDE +3–4 %**, **Mirath ±1–3 %** end-to-end: same per-key `Kpre` penalty, smaller
  because the Rijndael share is lower.
- **SDitH** end-to-end is a wash (**+0.4 to +0.9 %**) even though its Rijndael portion is
  18–29 % slower — Rijndael is only ~1.5 % of an SDitH sign/verify.

**Why folded loses here, opposite to §4.** Two effects, both absent in §4's bulk case:
1. **Per-key `Kpre`.** Every GGM/seed node rebuilds the pre-shuffled schedule
   (14×32-byte byte-gather). §4 amortizes one `Kpre` over megabytes; PQC amortizes it
   over ~2–`len` blocks.
2. **Single-block folded vs single-block EOR asm.** PQC uses one block per counter/seed
   with the key changing constantly, so the folded *interleaved* kernels
   (`_x4/_x8`, which give §4 its win by hiding AESE latency) don't apply. Block-for-block,
   the folded C-intrinsic path does not beat the hand-scheduled EOR assembly.

## Conclusion
Folding AddRoundKey into `AESE` is a **throughput** optimization (bulk, fixed key,
interleaved blocks — §4). In the PQC signature setting (per-node rekeying, serial
single-block encryption) it **does not help**: the per-key `Kpre` cost and the loss of
block interleaving make it 8–29 % slower on the Rijndael portion and up to ~12 % slower
end-to-end (MQOM), with no scheme benefiting. **Keep the EOR path as the PQC default**;
reserve folded for the bulk/key-reuse workloads of §4.
