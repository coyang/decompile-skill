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

The skill is a skill for Claude Code (or compatible agent); no package install is
required. The scripts drive standard system tools, so the toolchain must be
present:

| Tool | Needed for | Notes |
|------|-----------|-------|
| `bash` | all scripts | |
| Python 3.8+ (`python3`) | triage, differential sampler, verifier | stdlib only, no third-party packages |
| `file`, `readelf`, `objdump`, `nm` | triage / ground truth | binutils |
| `gcc` (or `cc`/`clang`) | rebuild checks, acceptance build | |
| `ar` | archive (`*.a`) handling, evals | binutils |
| `timeout` | bounded external commands | coreutils |
| Ghidra `analyzeHeadless` + JDK 17+ | decompiler evidence (deep mode) | optional for quick reports; install from ghidra.org |
| `bwrap` (bubblewrap) | isolated differential sampler, verifier sandbox | optional but required for `accept`/sampling |

`SKILL_DIR` is the directory containing `SKILL.md`. The scripts never install
anything themselves.

Example install (Debian/Ubuntu):

```bash
sudo apt install binutils gcc python3 coreutils bubblewrap
```

### Feature matrix

| Tool set | quick report | deep reconstruction | differential sampling | acceptance (`accept`) |
|----------|-------------|--------------------|----------------------|------------------------|
| bash + binutils + python3 | yes | yes | no | no |
| + gcc + bubblewrap | yes | yes | yes | yes |
| + Ghidra/JDK | yes (disassembly only without) | full | yes | yes |

### Running the skill

In Claude Code, invoke it by name. From a shell, the entrypoints are:

```bash
SKILL_DIR=/path/to/decompile
bash "$SKILL_DIR/scripts/triage.sh" target.so --out /tmp/work     # quick: probe + report
bash "$SKILL_DIR/scripts/ghidra-decompile.sh" target.so --workdir /tmp/work  # deep: decompiler evidence
python3 "$SKILL_DIR/scripts/verify.py" ORIGINAL.so TREE \
  --candidate librebuilt.so --policy OWNER_POLICY.json \
  --policy-sha256 TRUSTED_SHA256 --json out/acceptance.json       # accept: verified replacement
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
