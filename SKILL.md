---
name: decompile
description: Reconstruct evidence-linked C/C++ from ELF binaries and verify exact artifacts under a pinned acceptance contract. Use for decompilation, source recovery, recompilable reconstruction, or evaluating a reconstructed library for replacement. General binary exploration belongs to ghidra. Never infer equivalence or replacement approval from compilation, similarity, or finite tests.
---

# ELF reconstruction and contract-bound acceptance

Resolve `SKILL_DIR` to this file's actual directory. Scripts and references below
are relative to it. This skill supports two separate outcomes: a useful source
reconstruction and an acceptance decision about one exact compiled artifact.

## Decision boundary

- `quick`: an annotated source report for requested functions.
- `deep`: a compilable reconstruction tree, evidence and explicit verification gaps.
- `accept`: evaluate a built shared library for **cold-start** replacement at one
  policy-declared target. This does not install it or hot-swap a running process.

Follow the user's requested outcome. Size and symbol availability affect cost
and uncertainty, not whether the user is entitled to request a deep reconstruction.
Do not silently downgrade or expand to the entire artifact. When no output is
specified, use a report for a small named scope; clarify only a material ambiguity.

No universal algorithm is provided for deciding equivalence of arbitrary C/C++
libraries. Supported automatic correctness routes are:

1. Direct byte comparison of the complete original and rebuilt ELF.
2. For nonidentical ELF, a policy-approved independent static certificate checker
   that verifies a formal/exhaustive proof under an explicit model. A general
   solver/checker is **not bundled**. Missing proof support means `UNKNOWN`.

Finite differential tests are `TESTED`, never proof. A negative result can reveal
a counterexample within the declared ABI and observations. No score, branch
count, function name, provenance marker or loader success can authorize replacement.

## 1. Freeze the target and define scope

Run `bash "$SKILL_DIR/scripts/triage.sh" ARTIFACT --out WORKDIR`, read its
`triage.json`, and record the full artifact SHA-256. Use a fresh work directory
for a new artifact; do not reuse cached triage as verification evidence.

Report ELF kind, architecture, per-member tier/language, known/estimated function
count and selected scope. A dynamic symbol table does not establish the presence
of internal symbols. DEBUG data is a source of names/types, not proof that every
function has complete debug information. Ghidra output is a tool interpretation,
not ground truth.
Read `fn_count_status`, `fn_count_basis` and `fn_count_complete` alongside the
legacy numeric count. A symbol census is not a total function inventory; language
`unknown` means no supported identification was established, not that the input is C.

Reject corrupt/non-ELF targets; request a final binary for standalone LTO IR.
For archives, preserve member identity and duplicate member names; refuse a
lossy expansion instead of silently overwriting members. This skill's generic
reconstruction recipes target C/C++ ELF; other languages and architectures need
explicitly supported analysis tools and ABI models.
The bundled archive drivers currently reject duplicate member names. For those
inputs obtain distinct members through an ordinal-aware extraction workflow first.

For replacement work read [acceptance.md](references/acceptance.md) first.
The deployment owner supplies the observation model, assumptions, target/runtime
pins and independently trusted checkers. Keep that policy outside the reconstruction
and obtain its digest from the owner/CI trust boundary. Do not write a permissive
policy, a checker that always passes, or a reduced domain to obtain approval.
Existing user authorization persists; do not add repeated approval questions.

## 2. Acquire immutable analysis evidence

Detect `file`, binutils, Python, compiler family, Ghidra/Java and required tools.
Do not silently install a latest toolchain during acceptance: tool/environment
changes invalidate pins. Explain actual missing prerequisites; continue static
analysis when execution tooling is unavailable.

For a few simple named functions, disassembly may suffice for a report. Otherwise:

```bash
bash "$SKILL_DIR/scripts/ghidra-decompile.sh" ARTIFACT --workdir WORKDIR
```

Announce scope and estimated cost before expensive analysis. Honor existing
budgets/authorization. A time estimate is an estimate, not a benchmark.
Keep Ghidra project/output hashes and analysis settings. Reuse a completed project
only for the same artifact/settings; partial analysis is not a complete evidence
inventory. Record failures, unsupported instructions and missing functions.

Read [evidence-format.md](references/evidence-format.md). Keep raw evidence apart
from editable reconstructed source. Evidence links describe origins; they do not
prove semantics. Address records include artifact/member, section and offset so
relocatable objects cannot pass by citing an arbitrary virtual address.

## 3. Reconstruct incrementally

For deep work read [deep-mode.md](references/deep-mode.md); also read
[cpp.md](references/cpp.md) for C++ targets. Create a new output directory or resume
known batches without overwriting unrelated work.
Use [reconstruction-cases.md](references/reconstruction-cases.md) for prototype
recovery, machine arithmetic/memory semantics, indirect calls and stateful harnesses.

Use `src/`, `include/`, `Makefile`, `NOTES.md` and `PROVENANCE.md`. Capture evidence
and uncertainty per function. Build headers first; preserve widths, signedness,
alignment, field offsets, calling convention, globals, initialization and error
behavior. Enforce recovered layout with `sizeof`/`offsetof` assertions. Exported
types are drafts: unsupported declarations/layouts must stop automatic use.

Unknown naming and unknown behavior are separate records. A descriptive local
name is not a fabricated semantic claim. Never hide a semantic stub behind a
renaming tag. Preserve the original machine behavior, including specified error
paths; do not force compiler-generated branch counts to match.

Compile and test one coherent component at a time. Use evidence and concrete
counterexamples to repair it. Record remaining uncertainty instead of iterating
until a score is green. Never run a target library or an untrusted Makefile in the
host process as a validation shortcut.

## 4. Diagnose behavior without upgrading evidence

The bounded sampler supports only a declared `int32_t f(int32_t)` interface:

```bash
python3 "$SKILL_DIR/scripts/differential.py" ORIGINAL.so CANDIDATE.so \
  --function classify --values '[-2147483648,-1,0,1,2147483647]'
```

It isolates each artifact with bubblewrap, compares return values and errno,
and never approves replacement. Only call it when this ABI is established.
Pointers, floats, callbacks, stateful sequences and external effects need a
purpose-built harness and a stated observation model. Sampling the whole integer
list is still not proof of hidden state, undefined behavior or all execution paths.

## 5. Run acceptance on the exact deliverable

Read [acceptance.md](references/acceptance.md) for the policy/checker protocol.
Run the script from the trusted skill installation:

```bash
python3 "$SKILL_DIR/scripts/verify.py" ORIGINAL.so TREE \
  --candidate librebuilt.so --policy OWNER_POLICY.json \
  --policy-sha256 TRUSTED_POLICY_SHA256 --json OUTSIDE_TREE/acceptance.json
```

The verifier snapshots artifacts, hashes source inputs, verifies ELF loader/symbol
contracts and environment pins, compiles all declared C/C++ translation units with a pinned compiler and restricted
flags in an isolated directory (the Makefile is hashed but never executed), and requires that build to reproduce the exact candidate.
It never guesses the output file or executes the original by default.

`verify.sh` is a compatibility entrypoint to this verifier. Old V1–V9 scores and
`--v6` no longer participate. `--workdir` is accepted but cached evidence is ignored.

- Exit **0**: `replacement.approved=true`, scoped to the exact policy, target,
  environment, source, tool and candidate digests.
- Exit **1**: a concrete loader/ABI/proof requirement was rejected.
- Exit **2**: unknown, unsupported, missing evidence, tool error or invalid input.

A successful source build alone is not an acceptance success. On failure, fix the
actual contract violation or report the missing checker; do not relax the policy.

## 6. Deliver the scope and evidence

For a report: paths, analyzed function inventory, source origins, unresolved
behavior and limitations. For a source tree: build procedure, artifact hash,
per-function recovery coverage, ABI/layout assumptions and diagnostic results.
For acceptance: copy the machine result, including **both** correctness and
replacement states, pins, observations, assumptions and blocking reason.

Report `UNKNOWN` plainly when a general nonidentical library lacks a supported
proof model. Never say the source is original, a finite test is proof, or a receipt
is a signed deployment credential. At actual deployment, the deployment system
must rerun acceptance, check all digests and filesystem metadata, perform its
atomic cold-start replacement, and retain the original for rollback.

Skill maintenance tests: `python3 -m unittest discover -s "$SKILL_DIR/evals" -p 'test_*.py'`.
