#!/bin/bash
# Re-apply the folded-variant source/build snapshot (./tree/) onto the
# 2nd-additional_signature checkout. Run after a fresh upstream extraction.
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIST="$(cd "$HERE/../../../2nd-additional_signature" && pwd)"
SRC="$HERE/tree"
[ -d "$SRC" ] || { echo "no snapshot at $SRC; run pack_folded_integration.sh first"; exit 1; }
n=0
while IFS= read -r -d '' f; do
  rel="${f#"$SRC"/}"
  mkdir -p "$NIST/$(dirname "$rel")"
  cp "$f" "$NIST/$rel"
  n=$((n+1))
done < <(find "$SRC" -type f -print0)
echo "applied $n files into $NIST"
