#!/bin/bash
# =============================================================================
# PQC folded-vs-EOR benchmark (Apple M2 / AArch64)
#
# For each NIST PQC signature scheme (SDitH, Mirath, RYDE, MQOM) at each level,
# builds BOTH Rijndael-256 ARM paths in the same run:
#   - arm_eor     : shipped EOR path (AESMC then separate EOR AddRoundKey)
#   - arm_folded  : AddRoundKey folded into AESE via per-key Kpre pre-shuffle
#
# The folded path computes Kpre once per key (rijndael256_folded_setup), and that
# cost is INSIDE the sign/verify timing (per-GGM-node key change), not hoisted.
#
# The schemes share a profiling harness that prints, per stage:
#   PROFILE <stage> avg_total_cycles=N avg_rijndael_cycles=M ratio=R avg_calls=K
# (cntvct_el0 cycles). We capture avg_total_cycles (whole sign/verify) and
# avg_rijndael_cycles (the Rijndael-256 portion) for keygen/sign/verify.
#
# Outputs (under results/):
#   benchmark_<ts>.csv          scheme,level,impl,stage,total_cycles,rijndael_cycles,rij_pct
#   folded_vs_eor_raw_<ts>.log  full build + bench stdout for every run
#
# Does NOT re-measure the §4 bulk/key-reuse throughput. PQC only.
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NIST_DIR="$(cd "$ROOT_DIR/../2nd-additional_signature" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

OPENSSL_PREFIX=$(brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl@3)
EXTRA="-I${OPENSSL_PREFIX}/include -L${OPENSSL_PREFIX}/lib"
NCPU=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Iterations averaged inside each bench, and number of repeat runs (median taken).
ITERS_FAST=${ITERS_FAST:-300}     # Mirath / RYDE / MQOM
ITERS_SDITH=${ITERS_SDITH:-60}    # SDitH sign/verify are ~ms each
REPEATS=${REPEATS:-3}

TS=$(date +%Y%m%d_%H%M%S)
CSV="$RESULTS_DIR/benchmark_${TS}.csv"
RAW="$RESULTS_DIR/folded_vs_eor_raw_${TS}.log"
echo "scheme,level,impl,stage,total_cycles,rijndael_cycles,rij_pct" > "$CSV"

log()  { echo "$@" | tee -a "$RAW"; }
rawc() { echo "$@" >> "$RAW"; }

log "============================================================"
log "PQC folded-vs-EOR benchmark  $(date)"
log "host    : $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
log "macos   : $(sw_vers -productVersion 2>/dev/null)  build $(sw_vers -buildVersion 2>/dev/null)"
log "clang   : $(clang --version | head -1)"
log "iters   : fast=$ITERS_FAST sdith=$ITERS_SDITH repeats=$REPEATS"
log "============================================================"

# median of stdin numbers (integer), empty -> NA
median() {
  local vals=($(sort -n)) n
  n=${#vals[@]}
  if [ "$n" -eq 0 ]; then echo "NA"; return; fi
  echo "${vals[$((n/2))]}"
}

# Parse one bench stdout (file $1) for stage $2 -> "total rij pct"
parse_stage() {
  awk -v st="$2" '$1=="PROFILE" && $2==st {
    t=""; r=""; p="";
    for(i=3;i<=NF;i++){
      if($i ~ /^avg_total_cycles=/){split($i,a,"="); t=a[2]}
      if($i ~ /^avg_rijndael_cycles=/){split($i,a,"="); r=a[2]}
      if($i ~ /^ratio=/){split($i,a,"="); p=a[2]}
    }
    print t" "r" "p
  }' "$1"
}

# Run a prebuilt bench binary REPEATS times, emit median CSV rows.
# $1 scheme $2 level $3 impl $4 bench-cmd...
bench_and_record() {
  local scheme="$1" level="$2" impl="$3"; shift 3
  local cmd=("$@")
  local tmpdir; tmpdir=$(mktemp -d)
  for rep in $(seq 1 "$REPEATS"); do
    rawc "---- $scheme $level $impl run $rep : ${cmd[*]} ----"
    "${cmd[@]}" > "$tmpdir/out_$rep.txt" 2>>"$RAW"
    cat "$tmpdir/out_$rep.txt" >> "$RAW"
  done
  for stage in keygen sign verify; do
    local tot rij pct
    tot=$(for rep in $(seq 1 "$REPEATS"); do parse_stage "$tmpdir/out_$rep.txt" "$stage" | awk '{print $1}'; done | median)
    rij=$(for rep in $(seq 1 "$REPEATS"); do parse_stage "$tmpdir/out_$rep.txt" "$stage" | awk '{print $2}'; done | median)
    pct=$(parse_stage "$tmpdir/out_1.txt" "$stage" | awk '{print $3}')
    [ -z "$tot" ] && tot=NA; [ -z "$rij" ] && rij=NA; [ -z "$pct" ] && pct=NA
    echo "$scheme,$level,$impl,$stage,$tot,$rij,$pct" >> "$CSV"
    log "  $scheme $level $impl $stage : total=$tot rij=$rij ($pct%)"
  done
  rm -rf "$tmpdir"
}

# ---------------------------------------------------------------- MQOM
run_mqom() {
  local lvl="$1"
  local dir="$NIST_DIR/MQOM/Reference_Implementation/mqom2_${lvl}_gf256_fast_r3"
  local levelnum; levelnum=$(echo "$lvl" | sed 's/cat//')
  cd "$dir" || return
  log ">>> MQOM $lvl"
  make clean >/dev/null 2>&1
  if make bench RIJNDAEL_ARM_CRYPTO=1 EXTRA_CFLAGS="$EXTRA" >>"$RAW" 2>&1; then
    bench_and_record MQOM "$levelnum" arm_eor ./bench "$ITERS_FAST"
  else log "  MQOM $lvl arm_eor BUILD FAILED"; fi
  make clean >/dev/null 2>&1
  if make bench RIJNDAEL_ARM_FOLDED=1 EXTRA_CFLAGS="$EXTRA" >>"$RAW" 2>&1; then
    bench_and_record MQOM "$levelnum" arm_folded ./bench "$ITERS_FAST"
  else log "  MQOM $lvl arm_folded BUILD FAILED"; fi
  make clean >/dev/null 2>&1
}

# ---------------------------------------------------------------- Mirath
run_mirath() {
  local m="$1"
  local dir="$NIST_DIR/Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_${m}_fast"
  local levelnum; levelnum=$(echo "$m" | sed 's/a//')
  local bin="mirath_${m}_f"
  cd "$dir" || return
  log ">>> Mirath $m"
  make clean >/dev/null 2>&1
  if make arm_crypto >>"$RAW" 2>&1 && [ -f "$bin" ]; then
    bench_and_record Mirath "$levelnum" arm_eor "./$bin" "$ITERS_FAST"
  else log "  Mirath $m arm_eor BUILD FAILED"; fi
  make clean >/dev/null 2>&1
  if make arm_folded >>"$RAW" 2>&1 && [ -f "$bin" ]; then
    bench_and_record Mirath "$levelnum" arm_folded "./$bin" "$ITERS_FAST"
  else log "  Mirath $m arm_folded BUILD FAILED"; fi
  make clean >/dev/null 2>&1
}

# ---------------------------------------------------------------- RYDE
run_ryde() {
  local r="$1"
  local dir="$NIST_DIR/RYDE/Reference_Implementation/ryde${r}"
  local levelnum; levelnum=$(echo "$r" | sed 's/f//')
  cd "$dir" || return
  log ">>> RYDE $r"
  make clean >/dev/null 2>&1
  if make "ryde${r}-arm-bench" >>"$RAW" 2>&1 && [ -f "bin/ryde${r}-arm-bench" ]; then
    bench_and_record RYDE "$levelnum" arm_eor "./bin/ryde${r}-arm-bench" "$ITERS_FAST"
  else log "  RYDE $r arm_eor BUILD FAILED"; fi
  make clean >/dev/null 2>&1
  if make "ryde${r}-arm-folded-bench" >>"$RAW" 2>&1 && [ -f "bin/ryde${r}-arm-folded-bench" ]; then
    bench_and_record RYDE "$levelnum" arm_folded "./bin/ryde${r}-arm-folded-bench" "$ITERS_FAST"
  else log "  RYDE $r arm_folded BUILD FAILED"; fi
  make clean >/dev/null 2>&1
}

# ---------------------------------------------------------------- SDitH
run_sdith() {
  local lvl="$1"
  local dir="$NIST_DIR/SDitH/Reference_Implementation/sdith_${lvl}_fast"
  local levelnum; levelnum=$(echo "$lvl" | sed 's/cat//')
  log ">>> SDitH $lvl"
  # EOR
  local bd="$dir/build_arm"
  rm -rf "$bd"; mkdir -p "$bd"; cd "$bd"
  if cmake .. -DCMAKE_BUILD_TYPE=Release -DUSE_ARM_CRYPTO=ON -DBUILD_KATS=OFF >>"$RAW" 2>&1 \
     && make -j"$NCPU" bench_sdith >>"$RAW" 2>&1 && [ -f bench_sdith ]; then
    bench_and_record SDitH "$levelnum" arm_eor ./bench_sdith "$ITERS_SDITH"
  else log "  SDitH $lvl arm_eor BUILD FAILED"; fi
  rm -rf "$bd"
  # folded
  bd="$dir/build_arm_folded"
  rm -rf "$bd"; mkdir -p "$bd"; cd "$bd"
  if cmake .. -DCMAKE_BUILD_TYPE=Release -DUSE_ARM_FOLDED=ON -DBUILD_KATS=OFF >>"$RAW" 2>&1 \
     && make -j"$NCPU" bench_sdith >>"$RAW" 2>&1 && [ -f bench_sdith ]; then
    bench_and_record SDitH "$levelnum" arm_folded ./bench_sdith "$ITERS_SDITH"
  else log "  SDitH $lvl arm_folded BUILD FAILED"; fi
  rm -rf "$bd"
}

run_mqom   cat3
run_mqom   cat5
run_mirath 3a
run_mirath 5a
run_ryde   3f
run_ryde   5f
run_sdith  cat3
run_sdith  cat5

log ""
log "CSV : $CSV"
log "RAW : $RAW"
log "done."
echo "CSV=$CSV"
