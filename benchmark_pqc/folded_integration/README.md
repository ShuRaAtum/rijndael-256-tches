# Folded (AddRoundKey-folded) Rijndael-256 — PQC integration

The PQC schemes live in `../../../2nd-additional_signature/`, which is **outside this
git repository**. This directory captures the folded-variant source/build changes so
they are committed and reviewable here, and can be re-applied to a fresh checkout.

## What the folded variant does
The shipped *EOR* path feeds a zero key to `AESE` then applies AddRoundKey as a separate
post-`AESMC` EOR. The *folded* path pre-shuffles each round key to `Kpre = TBL(rk)` so
AddRoundKey is absorbed into `AESE` (`AESE(TBL(state), TBL(rk)) = SubBytes(R256_SR(state^rk))`),
costing only a one-time per-key pre-shuffle. API: `aarch64/rijndael256_folded_arm.{c,h}`
(`rijndael256_folded_setup`, `rijndael256_encrypt_arm_folded[_x2/_x4/_x8]`).

## Build toggle per scheme (`USE_ARM_FOLDED`)
- **MQOM**  `make bench RIJNDAEL_ARM_FOLDED=1`
- **Mirath** `make arm_folded`
- **RYDE**  `make ryde{3f,5f}-arm-folded-bench`
- **SDitH** `cmake .. -DUSE_ARM_FOLDED=ON` (+`-DBUILD_KATS=OFF`)

Each toggle also defines the ARM-crypto path. The per-key `Kpre` is built by
`rijndael256_folded_setup` **inside** the seed/key expansion that sign/verify run per
GGM node, so its cost is counted in the timing (not hoisted out of the loop). Wiring
points: a `R256FoldedKey` carried in each scheme's per-key context
(`rijndael_arm_ctx` / `aes_round_keys_t` / `rijndael256_seed_ctx_t`), or computed per
`encrypt_nblocks`/`ecb` call (SDitH), then `rijndael256_encrypt_arm_folded` in place of
`rijndael256_encrypt_arm`.

## Contents
- `tree/` — snapshot of every added/modified file under its scheme-relative path
  (`pack_folded_integration.sh` regenerates it from the live tree;
  `apply_folded_integration.sh` copies it back onto `2nd-additional_signature/`).
- `folded_vs_eor_block.c` — per-scheme byte-identity harness (folded vs EOR asm).

## Reproduce
```bash
cd ..                                  # benchmark_pqc/
./run_folded_vs_eor.sh                 # builds EOR + folded, both in one run -> results/*.csv + raw log
./verify_folded_identity.sh            # folded == EOR over 50000 random pairs, per scheme
```

## Result
See `../results/folded_vs_eor_SUMMARY.md`. Short version: byte-identical to EOR, but
folded does **not** help in PQC — the per-key `Kpre` cost plus serial single-block use
make it 8–29 % slower on the Rijndael portion (up to ~12 % end-to-end for MQOM). EOR
stays the PQC default; folded's win is the bulk/key-reuse case of §4.
