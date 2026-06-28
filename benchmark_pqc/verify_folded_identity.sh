#!/bin/bash
# Per-scheme byte-identity: each scheme's folded encrypt vs its own EOR ARM asm.
# Compiles folded_integration/folded_vs_eor_block.c against that scheme's
# rijndael256_arm.S + rijndael256_folded_arm.c + key schedule, runs 50000 random
# (key,block) pairs. This is the definitive folded==EOR check per scheme; the
# scheme-level NIST KAT generators are pre-broken (link errors unrelated to folding).
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIST="$(cd "$SCRIPT_DIR/../../2nd-additional_signature" && pwd)"
HARNESS="$SCRIPT_DIR/folded_integration/folded_vs_eor_block.c"
RESULTS_DIR="$SCRIPT_DIR/results"; mkdir -p "$RESULTS_DIR"
TS=$(date +%Y%m%d_%H%M%S)
OUT="$RESULTS_DIR/folded_vs_eor_identity_${TS}.txt"
CC=${CC:-clang}
FLAGS="-O2 -arch arm64 -march=armv8-a+crypto"
log(){ echo "$@" | tee -a "$OUT"; }
TMP=$(mktemp -d)

log "Per-scheme folded==EOR byte-identity (50000 random key/block pairs each)"
log "$(date)"
log "================================================================"

# check $1=label  $2=rijndaeldir  $3=arm.S  $4=keyschedule.c  $5=folded.c
chk() {
  local label="$1" inc="$2" armS="$3" ks="$4" folded="$5"
  local bin="$TMP/t"
  if $CC $FLAGS -I"$inc" -o "$bin" "$HARNESS" "$armS" "$ks" "$folded" 2>"$TMP/cc.log"; then
    local res; res=$("$bin")
    if echo "$res" | grep -q "byte-identical"; then log "  $label : PASS  ($res)"; else log "  $label : FAIL  ($res)"; fi
  else
    log "  $label : BUILD FAIL"; sed 's/^/      /' "$TMP/cc.log" | head -6 | tee -a "$OUT"
  fi
}

M="$NIST/MQOM/Reference_Implementation"
for v in cat3 cat5; do
  d="$M/mqom2_${v}_gf256_fast_r3/rijndael"
  chk "MQOM-$v" "$d" "$d/rijndael256_arm.S" "$d/rijndael256_keyschedule.c" "$d/rijndael256_folded_arm.c"
done
MR="$NIST/Mirath/Reference_Implementation/mirath_tcith"
for v in 3a 5a; do
  d="$MR/mirath_tcith_${v}_fast/common/rijndael"
  chk "Mirath-$v" "$d" "$d/rijndael256_arm.S" "$d/rijndael256_keyschedule.c" "$d/rijndael256_folded_arm.c"
done
RY="$NIST/RYDE/Reference_Implementation"
for v in 3f 5f; do
  d="$RY/ryde${v}/src"
  chk "RYDE-$v" "$d" "$d/rijndael256_arm.S" "$d/rijndael256_keyschedule.c" "$d/rijndael256_folded_arm.c"
done
SD="$NIST/SDitH/Reference_Implementation"
for v in cat3 cat5; do
  d="$SD/sdith_${v}_fast/lib/aes"
  chk "SDitH-$v" "$d" "$d/rijndael256_arm.S" "$d/rijndael256_opt_keyschedule.c" "$d/rijndael256_folded_arm.c"
done

log "================================================================"
rm -rf "$TMP"
echo "OUT=$OUT"
