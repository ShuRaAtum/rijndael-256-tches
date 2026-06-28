#!/bin/bash
# Snapshot the folded-variant source/build changes from ../2nd-additional_signature
# (which is OUTSIDE this git repo) into this directory so they are committed and
# reviewable. Preserves the scheme-relative path under ./tree/. Re-runnable.
#
#   ./pack_folded_integration.sh          # copy live edits -> ./tree/
# To re-apply the snapshot onto a fresh 2nd-additional_signature checkout:
#   ./apply_folded_integration.sh
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIST="$(cd "$HERE/../../../2nd-additional_signature" && pwd)"
DST="$HERE/tree"
rm -rf "$DST"; mkdir -p "$DST"

# All files added or modified for the folded variant (scheme-relative paths).
FILES=(
  # MQOM
  MQOM/Reference_Implementation/mqom2_cat3_gf256_fast_r3/rijndael/rijndael256_folded_arm.c
  MQOM/Reference_Implementation/mqom2_cat3_gf256_fast_r3/rijndael/rijndael256_folded_arm.h
  MQOM/Reference_Implementation/mqom2_cat3_gf256_fast_r3/rijndael/rijndael_arm.c
  MQOM/Reference_Implementation/mqom2_cat3_gf256_fast_r3/rijndael/rijndael_arm.h
  MQOM/Reference_Implementation/mqom2_cat3_gf256_fast_r3/Makefile
  MQOM/Reference_Implementation/mqom2_cat5_gf256_fast_r3/rijndael/rijndael256_folded_arm.c
  MQOM/Reference_Implementation/mqom2_cat5_gf256_fast_r3/rijndael/rijndael256_folded_arm.h
  MQOM/Reference_Implementation/mqom2_cat5_gf256_fast_r3/rijndael/rijndael_arm.c
  MQOM/Reference_Implementation/mqom2_cat5_gf256_fast_r3/rijndael/rijndael_arm.h
  MQOM/Reference_Implementation/mqom2_cat5_gf256_fast_r3/Makefile
  # Mirath
  Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_3a_fast/common/rijndael/rijndael256_folded_arm.c
  Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_3a_fast/common/rijndael/rijndael256_folded_arm.h
  Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_3a_fast/common/rijndael/rijndael_arm.h
  Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_3a_fast/Makefile
  Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_5a_fast/common/rijndael/rijndael256_folded_arm.c
  Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_5a_fast/common/rijndael/rijndael256_folded_arm.h
  Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_5a_fast/common/rijndael/rijndael_arm.h
  Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_5a_fast/Makefile
  # RYDE
  RYDE/Reference_Implementation/ryde3f/src/rijndael256_folded_arm.c
  RYDE/Reference_Implementation/ryde3f/src/rijndael256_folded_arm.h
  RYDE/Reference_Implementation/ryde3f/src/rijndael_arm.h
  RYDE/Reference_Implementation/ryde3f/src/seed_expand_functions_arm.h
  RYDE/Reference_Implementation/ryde3f/Makefile
  RYDE/Reference_Implementation/ryde5f/src/rijndael256_folded_arm.c
  RYDE/Reference_Implementation/ryde5f/src/rijndael256_folded_arm.h
  RYDE/Reference_Implementation/ryde5f/src/rijndael_arm.h
  RYDE/Reference_Implementation/ryde5f/src/seed_expand_functions_arm.h
  RYDE/Reference_Implementation/ryde5f/Makefile
  # SDitH
  SDitH/Reference_Implementation/sdith_cat3_fast/lib/aes/rijndael256_folded_arm.c
  SDitH/Reference_Implementation/sdith_cat3_fast/lib/aes/rijndael256_folded_arm.h
  SDitH/Reference_Implementation/sdith_cat3_fast/lib/aes/rijndael256_ctrle_special_arm.c
  SDitH/Reference_Implementation/sdith_cat3_fast/lib/aes/rijndael256_arm_wrapper.c
  SDitH/Reference_Implementation/sdith_cat3_fast/lib/aes/CMakeLists.txt
  SDitH/Reference_Implementation/sdith_cat3_fast/CMakeLists.txt
  SDitH/Reference_Implementation/sdith_cat5_fast/lib/aes/rijndael256_folded_arm.c
  SDitH/Reference_Implementation/sdith_cat5_fast/lib/aes/rijndael256_folded_arm.h
  SDitH/Reference_Implementation/sdith_cat5_fast/lib/aes/rijndael256_ctrle_special_arm.c
  SDitH/Reference_Implementation/sdith_cat5_fast/lib/aes/rijndael256_arm_wrapper.c
  SDitH/Reference_Implementation/sdith_cat5_fast/lib/aes/CMakeLists.txt
  SDitH/Reference_Implementation/sdith_cat5_fast/CMakeLists.txt
)

n=0
for f in "${FILES[@]}"; do
  mkdir -p "$DST/$(dirname "$f")"
  cp "$NIST/$f" "$DST/$f"
  n=$((n+1))
done
echo "snapshotted $n files into $DST"
