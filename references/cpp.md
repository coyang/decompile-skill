# C++ reconstruction: establish the actual ABI

These are analysis procedures, not acceptance evidence. Read evidence-format.md
for origins and acceptance.md for the proof/ABI/replacement contract. Do not
infer complete semantics from a demangled signature or the presence of DWARF.

## Symbols and calling convention

Use `c++filt` on the original mangled symbols and retain both names. An unchanged
name can be unsupported, malformed or non-Itanium; it is not necessarily truncated.
Common Itanium clues are `_ZTV` (vtable), `_ZTI` (typeinfo), `_ZTS` (typeinfo name),
`_ZTT`/`_ZTC` (VTT/construction tables), C1/C2 constructor variants and D0/D1/D2
destructor variants. Recover relationships from call sites and relocations instead
of deriving class behavior from the prefix alone.

On SysV AMD64, account for the hidden `this` and possible return-object pointer,
integer versus floating/vector register classes, stack arguments and variadic
rules. A simple argument-count shift is insufficient for general prototypes.
The same symbol name does not establish return type, aggregate passing convention,
layout or compatible compiler flags. Confirm exported signatures with DWARF and
machine-level uses; missing prototype evidence is an ABI gap.

## Object and vtable layout

Map constructor/destructor stores and uses to object offsets. Record access width,
signedness, alignment, base subobjects and pointer adjustments. Cross-check virtual
slots using relocation records and the actual vptr address point. Do not assume
a vtable begins at the symbol address or that every slot is a direct function entry.
Resolve this-adjusting thunks, pure/deleted virtual entries and destructor variants.
Multiple/virtual inheritance and construction tables require their own model;
unknown handling must remain explicit.

Recover data layout using independent offsets and sizes, then compile static
assertions for sizeof/alignof/offsetof where legal. ExportTypes.java rejects
unsupported bitfields, packing and ambiguous type dependencies; its output is a
draft. A successful compile is not proof that a guessed class layout matches.

## Standard library and templates

First identify the library vendor/version and ABI options, including libstdc++
dual ABI, debug iterators, allocator/deleter representation and compiler settings.
Fixed string/vector/smart-pointer layout tables are not portable specifications.
Use the matching headers only after establishing compatibility, or preserve an
opaque representation with precisely reconstructed accesses and explicit gaps.
A custom deleter, alignment or library version can change an apparently familiar
layout. Do not silently substitute the host's current STL.

Recover the concrete instantiated behavior visible in the artifact. Factoring
several instantiations into a template is an optional readability transformation,
not evidence that the original generic source has been recovered. Clones and
inlining can merge/split functions; reconstructing one source function does not
permit dropping a clone's distinct behavior or error paths.

## Exceptions, lifetime and state

Inspect unwind tables, landing pads, personality routines, catch/throw calls,
cleanup paths, static-local guards and initialization/finalization. Presence of
an unwind table alone does not prove language-level throw/catch behavior, and
absence of familiar imports does not prove that no exception path exists.

Preserve RAII cleanup on normal and exceptional paths, destructor ordering,
allocation/deallocation pairing, TLS and thread-safe initialization. Rewriting an
unwind edge as an unconditional normal call is not generally equivalent. If these
paths cannot be modeled, deliver an incomplete reconstruction and keep acceptance
UNKNOWN. A limitations banner cannot waive a mandatory proof obligation.

## Acceptance handoff

For nonidentical C++ artifacts, the independent ABI checker must cover prototypes,
layouts, thunks, vtables/RTTI, symbol versions, TLS/IFUNC, exceptions and lifecycle
in addition to preliminary ELF export checks. The semantic certificate checker
must cover the same machine/runtime model and all required observable effects.
This skill does not bundle such a general C++ checker. Ordinary compilation,
`abidiff` without sufficient type evidence or sample tests do not authorize replacement.
