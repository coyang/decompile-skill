# Deep reconstruction procedure

## Inputs and workspace

Use a fresh triage result and full artifact SHA-256. Allocate a per-artifact work
directory and a separate output tree. Record the original archive/member/section
identity, architecture, compiler hints and analysis settings before extraction.
Keep raw Ghidra output and evidence hashes outside editable `src/`.

Ghidra's driver supports `--targets FILE`, `--program NAME`, `--processor ID`,
`--timeout SECONDS`, and persistent project reuse. Use target subsets after a
completed analysis; never treat the mere presence of a project file as proof that
an interrupted import completed. Recreate analysis in a new workspace if its
artifact/settings/completion state cannot be verified.

For archives, check `ar t` for duplicate basenames before extraction. Preserve
member ordinals; do not allow `ar x` overwrites to erase translation units. LTO
members require a final linked artifact or explicit unsupported status. Do not
pretend a missing member is an empty recovered source file.

## Recover interfaces before bodies

1. Inventory exported symbols with type, binding, visibility and symbol version.
2. Recover prototypes using DWARF, call sites, calling convention and dataflow.
   Demangled names alone do not establish a complete prototype or return type.
3. Recover data layout with byte width, signedness, alignment, field offset,
   padding, union semantics and array stride. Add `sizeof`, `_Alignof`/`alignof`
   and `offsetof` assertions against independently recovered facts.
4. Inventory globals/TLS, initial values, relocations, init/fini routines, indirect
   calls, error paths, external effects and exception/unwind behavior.

`ExportTypes.java` produces a draft and explicit diagnostics; inspect them before
using the result. Unsupported declarations must not be replaced with arbitrary
`int`/`char` just to compile. Build a byte-backed opaque layout when its accesses
can be reconstructed precisely, or report that type as unresolved. Do not assume
forward declarations make by-value recursive/dependent definitions compilable.

## Batch source reconstruction

For uncertain prototypes, integer/memory semantics, indirect control flow or
stateful tests, use [reconstruction-cases.md](reconstruction-cases.md). It supplies
evidence-to-counterexample repair procedures instead of treating decompiler
expressions as ready-to-compile source.

Create `include/`, `src/`, `Makefile`, `NOTES.md`, `PROVENANCE.md`. Group functions
by actual dependency and translation-unit evidence; use callee-first ordering
where it makes compilation easier. Preserve strongly connected call groups.
Keep batch status with artifact/member/function keys, source paths, evidence
hashes and unresolved issues. Resume only when those inputs still match.

After each coherent group, compile against the recovered headers and run known
functional tests. Treat compiler diagnostics as reconstruction evidence, not
permission to remove behavior. Fix a concrete error/counterexample at a time.
Track unresolved semantics and stop unproductive repair loops with an honest
partial delivery. Branch instructions, call counts and token similarities are
diagnostic observations; they are never correctness constraints.

A minimal Makefile should declare a single explicit deliverable and a clean/all
sequence. Acceptance copies and hashes only `src/`, `include/`, `Makefile`; it never runs
the Makefile. Its policy lists the compiler, all translation units and restricted
flags; a gate-owned command performs the build. Keep auxiliary C/C++ source and
headers under src/include. Prebuilt artifacts and arbitrary build commands are rejected. Reproducible flags and a fixed output
path simplify the exact-candidate rebuild check. Do not compare a different
optimization build to the deployed candidate and transfer its verdict.

## C++ and architecture

Read cpp.md for Itanium/x86-64 clues, then validate against the actual runtime.
Account for multiple/virtual inheritance, vptr adjustments, thunks, RTTI,
constructor/destructor variants, exception cleanup and template instantiations.
STL layout tables are identification hints, not portable ABI definitions. Debug
iterators, dual ABI, library vendor/version and compile flags change layouts.
If EH or a lifecycle path is not reconstructed, it remains an explicit semantic
gap; no banner can make that gap acceptable to a complete-equivalence checker.

Ghidra can analyze more architectures than the local compiler can build. Cross-
architecture reconstruction may be delivered as unverified source. Acceptance
must use a toolchain and proof/ABI/environment model for that actual architecture;
missing support means UNKNOWN, not zero similarity or accidental native PASS.

## Verification and delivery

Use the differential sampler only for its declared scalar ABI, otherwise supply
a dedicated isolated harness. Cover negative, boundary and state-dependent cases;
record return values, output memory, errors and side effects relevant to the user.
Finite success remains TESTED. Preserve discovered counterexamples as regression
fixtures; equivalent syntactic rewrites must not fail solely because code shape differs.

For a replacement decision read acceptance.md and run verify.py with an explicit
candidate and externally pinned policy. Only the exact rebuilt artifact and
approved observation/environment scope inherit the result. Keep diagnostic tests,
proof checking, ABI verification and deployment metadata as separate evidence.
An unsupported general C++ proof model is a blocker to approval, not a reason to
invent a weaker scorecard.
