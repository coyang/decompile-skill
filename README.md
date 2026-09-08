# decompile

Evidence-linked C/C++ source recovery from ELF binaries, with contract-bound
acceptance verification. An Agent Skill for reconstructing readable, recompilable
source from `.so` / `.a` / `.o` / executable targets.

## What it does

Two distinct outcomes:

- **quick** — an annotated per-function source report for a named scope.
- **deep** — a compilable reconstruction tree (`src/`, `include/`, `Makefile`,
  `NOTES.md`, `PROVENANCE.md`) with per-function evidence and explicit gaps.
- **accept** — evaluate a built shared library for cold-start replacement at a
  policy-declared target, under a pinned acceptance contract.

Equivalence is never inferred from compilation success, similarity scores, branch
counts or finite differential tests. The two supported correctness routes are
exact byte reproduction and a policy-approved independent certificate checker.

## Layout

```
SKILL.md                    workflow (freeze -> evidence -> reconstruct -> verify -> accept)
references/                 acceptance contract, evidence format, deep-mode, C++, cases
scripts/                    triage, Ghidra driver, differential sampler, verifier
ghidra_scripts/             Ghidra Java exports (functions, types)
evals/                      verification regression suite + fixture corpus
```

## Requirements

- binutils (`file`, `readelf`, `objdump`, `nm`)
- GCC family (or Clang) for rebuild checks
- Ghidra + JDK 17+ for decompiler evidence (reports can run without it)
- bubblewrap (`bwrap`) for the isolated differential sampler

## Quick start

```bash
# source report for a small named scope
bash "$SKILL_DIR/scripts/triage.sh" target.so --out /tmp/work

# deep reconstruction
bash "$SKILL_DIR/scripts/ghidra-decompile.sh" target.so --workdir /tmp/work

# acceptance verification of a rebuilt library
python3 "$SKILL_DIR/scripts/verify.py" ORIGINAL.so TREE \
  --candidate librebuilt.so --policy OWNER_POLICY.json \
  --policy-sha256 TRUSTED_SHA256 --json out/acceptance.json
```

## Tests

```bash
python3 -m unittest discover -s evals -p 'test_*.py' -v
```

`evals/` contains a fixture corpus (real GCC-built libraries, a stripped archive,
LTO/foreign/negative samples) and the regression suite for the verifier,
differential sampler and Ghidra type export.

## License

See [LICENSE](LICENSE).
