#!/bin/bash
# Emit a C file with exactly 2500 tiny exported functions to stdout.
for ((i = 0; i < 2500; i++)); do
  printf 'int big_fn_%04d(int x) { return x + %d; }\n' "$i" "$((i * 3 + 1))"
done
