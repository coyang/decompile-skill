#!/bin/bash
# Emit a C file with exactly 50 same-size function pairs to stdout.
# f_NN: 15-op arithmetic chain (%eax: add/shl/sub/sar).
# g_NN: 4 signed comparisons (%eax: cmpl/setcc/movzbl/xor/or).
# Every pair has an identical instruction count at -O0 but a nearly
# disjoint mnemonic multiset (measured mean Jaccard ~0.17), so any
# size-based or name-based decompile-similarity matcher must score
# them as different. Usage: gen_neg.sh a|b
set -euo pipefail
HALF="${1:?usage: gen_neg.sh a|b}"
for ((i = 0; i < 50; i++)); do
  A=$((i * 7 + 3)); B=$((i * 5 + 1)); C=$((i + 2)); D=$((i * 11 + 4))
  E=$((i * 3 + 9)); F=$((i + 17)); G=$((i % 4 + 2))
  if [[ "$HALF" == a ]]; then
    consts=("$A" "$C" "$E" "$B" "$D" "$F")
    e="x"; ci=0
    for ((j = 0; j < 15; j++)); do
      case $((j % 4)) in
        0) op="+"; k=${consts[ci]}; ci=$(((ci + 1) % 6));;
        1) op="<<"; k=$G;;
        2) op="-"; k=${consts[ci]}; ci=$(((ci + 1) % 6));;
        3) op=">>"; k=$G;;
      esac
      e="($e $op $k)"
    done
    printf 'int f_%02d(int x) { return %s; }\n' "$i" "$e"
  else
    printf 'int g_%02d(int x) { return ((x > %d) ^ (x < %d)) | ((x >= %d) ^ (x != %d)); }\n' \
      "$i" "$A" "$B" "$C" "$D"
  fi
done
