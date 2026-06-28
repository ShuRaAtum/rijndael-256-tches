#!/usr/bin/env bash
# Nsight Compute profiling script for Rijndael-256 ECB kernels
# Run from cuda/build/ after building profile_ecb
#
# Usage:
#   cd cuda/build && bash ../profile/run_ncu_profile.sh
#
# Requires: ncu (Nsight Compute CLI), sudo access for HW counters
set -euo pipefail

BINARY="./profile_ecb"
OUTDIR="../../paper/data/ncu"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: $BINARY not found. Build first:"
    echo "  cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_CUDA_ARCHITECTURES=89"
    echo "  make -j\$(nproc)"
    exit 1
fi

mkdir -p "$OUTDIR"

echo "============================================"
echo " Rijndael-256 Nsight Compute Profiling"
echo "============================================"
echo ""

# ------------------------------------------------------------------
# 1) Full metric collection (generates .ncu-rep for GUI analysis)
# ------------------------------------------------------------------
echo "[1/3] Full profiling (--set full) ..."
sudo ncu -f --set full \
    --target-processes all \
    --export "${OUTDIR}/ncu_rijndael256_full" \
    "$BINARY"
echo "  -> ${OUTDIR}/ncu_rijndael256_full.ncu-rep"
echo ""

# ------------------------------------------------------------------
# 2) Focused metrics (quick text summary)
# ------------------------------------------------------------------
METRICS="sm__warps_active.avg.pct_of_peak_sustained_active"
METRICS+=",l1tex__data_bank_conflicts_pipe_lsu_mem_shared.sum"
METRICS+=",l1tex__data_bank_conflicts_pipe_lsu_mem_shared_op_ld.sum"
METRICS+=",l1tex__t_sectors_pipe_lsu_mem_shared_op_ld.sum"
METRICS+=",sm__cycles_elapsed.avg"
METRICS+=",sm__inst_executed.sum"
METRICS+=",launch__occupancy"
METRICS+=",launch__waves_per_multiprocessor"
METRICS+=",smsp__warps_issue_stalled_long_scoreboard.avg"
METRICS+=",smsp__warps_issue_stalled_wait.avg"
METRICS+=",smsp__warps_issue_stalled_short_scoreboard.avg"
METRICS+=",smsp__warps_issue_stalled_mio_throttle.avg"

echo "[2/3] Focused metrics collection ..."
sudo ncu --metrics "$METRICS" "$BINARY" \
    | tee "${OUTDIR}/ncu_focused_metrics.txt"
echo ""

# ------------------------------------------------------------------
# 3) CSV export for paper tables
# ------------------------------------------------------------------
echo "[3/3] CSV export ..."
sudo ncu -f --set full --csv "$BINARY" > "${OUTDIR}/ncu_summary.csv"
echo "  -> ${OUTDIR}/ncu_summary.csv"
echo ""

echo "============================================"
echo " Profiling complete. Output in: ${OUTDIR}/"
echo "============================================"
ls -lh "${OUTDIR}/"
