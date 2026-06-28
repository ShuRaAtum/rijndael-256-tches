#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${1:-build}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${2:-benchmark-results/${TIMESTAMP}}"

mkdir -p "${OUT_DIR}"

echo "[1/4] Recording GPU metadata"
"${BUILD_DIR}/check_gpu" | tee "${OUT_DIR}/check_gpu.txt"

echo "[2/4] Running ECB benchmark"
"${BUILD_DIR}/benchmark_ecb" --csv "${OUT_DIR}/ecb.csv" \
  | tee "${OUT_DIR}/benchmark_ecb.txt"

echo "[3/4] Running CTR benchmark"
"${BUILD_DIR}/benchmark_ctr" --csv "${OUT_DIR}/ctr.csv" \
  | tee "${OUT_DIR}/benchmark_ctr.txt"

echo "[4/4] Running ES benchmark"
"${BUILD_DIR}/benchmark_es" --csv "${OUT_DIR}/es.csv" \
  | tee "${OUT_DIR}/benchmark_es.txt"

echo "Benchmark artifacts written to ${OUT_DIR}"
