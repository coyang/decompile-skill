# Evidence records: origin is separate from correctness

An evidence record makes a claim traceable. It does not make the claim true.
Ghidra output can contain analysis errors; symbols can be incomplete; compilation
can preserve the wrong behavior. Only acceptance.md defines correctness/approval.

## Function inventory

For each analyzed or reconstructed function retain:

- artifact SHA-256; for an archive, member ordinal/name and member SHA-256;
- section name/index, entry offset and address space (relocatable section offset,
  link-time VA or actual Ghidra image-base-relative address);
- original symbol when present, and a separate descriptive reconstructed name;
- raw evidence path and SHA-256, tool/version/options and analysis completion state;
- reconstructed source path and function identifier;
- `origin`: `debug-info`, `decompiler`, `disassembly`, `inference` or `placeholder`;
- recovered behavior, unresolved semantics, unsupported instructions and assumptions;
- prototype/layout origin and associated layout assertions.

A source comment can link to this record. Do not count the existence of one
`src:@0x...` string per file as per-function coverage. Do not validate a relocatable
object's address against nonexistent LOAD segments or assume an image-base delta.
For stripped functions, preserve the function-boundary evidence and its uncertainty.
If a member cannot be uniquely identified, its evidence is unresolved.

## Uncertainty has independent dimensions

1. **Naming**: a descriptive local/field name was assigned. This is normal and
   does not imply invented behavior. Preserve the original address/name mapping.
2. **Type/layout**: field width, signedness, offset, alignment, calling convention
   or prototype is uncertain. Add concrete assertions where evidence permits.
3. **Semantics**: an operation, branch, side effect or return behavior is unknown.
   Stubs belong here and block claims that their functions were fully recovered.
4. **Environment**: external functions, syscall behavior, initialization, threading
   or runtime ABI assumptions are incomplete.

Old (G)/(I)/(U) comments can remain as historical annotations, but they confer no
machine-verified confidence grade. Do not label semantic stubs as a naming issue.

## Raw evidence and literal handling

Keep raw dumps immutable relative to an analysis run and hash them. Record changes
as new evidence versions. String evidence refers to actual bytes, encoding, length
and location; escaped C syntax is not a literal byte search. Strings built at runtime
may be justified by instruction/dataflow evidence even when not contiguous in the
binary. Never skip format strings, paths or short strings merely to get a clean score.

The bundled driver writes each export to `ghidra/runs/<run-id>/`. Its
`run-manifest.json` records the analysis fingerprint, target coverage, program
statuses and file SHA-256 hashes. Failed runs retain their partial evidence and a
non-complete status. Select one explicit run when consuming an inventory; never
combine old function files with a newer subset's inventory implicitly.

Each program's `export-status.json` separates requested/matched/unmatched targets
from failed decompilations. A target may match only one program in an archive;
the driver checks coverage across the selected programs. A completed export means
the selected tool operations completed, not that Ghidra discovered every machine
function or that recovered semantics are correct. The JSON function inventory
also records `decompile_status` per exported function.

## Deliverables

`PROVENANCE.md` records artifact/source hashes and tool/settings history. `NOTES.md`
records uncertainty and repairs, with address/member references. These documents
are audit context. Neither a recorded original SHA-256 nor a well-formed comment
proves behavior. The independent acceptance gate reports its own artifact/source
hashes and has no path that turns prose or provenance into APPROVED.

Report function inventory coverage against the intended scope, including missing,
unsupported and failed functions. Never calculate success percentages only over
functions that happened to pair by name. Report diagnostic sample domains separately
from formally/exhaustively checked domains.
