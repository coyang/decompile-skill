# Evidence-driven reconstruction cases

Use these procedures when a decompiler's prototype, expression or control flow
is uncertain. Examples are illustrative machine contracts, not evidence about a
new target. Keep instruction addresses and counterexamples for the actual input.

## Prototype recovery from callers and consumers

Start with the target calling convention, then record for each call site which
argument registers/stack slots are defined, their widths, and what memory they
reference. At the callee distinguish a value read before any local definition
from a scratch register. At return sites inspect how callers consume the result:
integer width, floating register, pointer dereference, or hidden result storage.
An unused result does not establish `void`. Register contents alone do not prove
that every apparent argument belongs to the prototype.

Example: a decompiler proposes `long lookup(long a, long b)`. Callers place an
object pointer in the first argument and a 32-bit index in the second; the callee
uses a four-byte load at `base + index * 4`, and callers consume only the low
32 bits of the result. Record a tentative `uint32_t lookup(const void *, uint32_t)`
with unresolved signedness and object layout. Inspect bounds comparisons and
all callers before refining it. Test index zero, the last valid index and the
observed error path. Do not invent behavior for invalid pointers/indices outside
the established machine contract.

## Integer wraparound: evidence, hypothesis, counterexample, repair

Suppose an instruction sequence computes a 32-bit increment and returns those
32 bits, with callers interpreting them as an unsigned value.

1. Evidence: operand width is 32 bits; overflow flags are not subsequently used.
2. Initial hypothesis: `int32_t increment(int32_t x) { return x + 1; }`.
3. Counterexample: input bits `0x7fffffff` produce `0x80000000` in the original;
   the C expression instead introduces signed-overflow undefined behavior.
4. Repair for this established unsigned interface:

   ```c
   uint32_t increment(uint32_t x) { return x + UINT32_C(1); }
   ```

5. Validate the actual candidate at `0`, `0x7fffffff`, `0x80000000`, `0xffffffff`
   with a harness for **this unsigned ABI**, then retain those as regression cases.
   These samples diagnose the repair; they are not a complete equivalence proof.

If callers interpret a signed result, recover that interpretation explicitly;
do not silently change the public declaration to simplify the example. Avoid
assuming signed casts, negative right shift or aliasing behave identically across
unestablished compiler/language settings.

For shifts, recover operand width and the machine's count treatment before
emitting C: a shift by the type width can be undefined in C even if the machine
masks the count. For flags used later, model carry/overflow separately from the
truncated result. For floating point record comparisons involving NaNs, signed
zero, rounding and exception effects before simplifying expressions.

## Layout and unaligned loads

Record accesses as `(base origin, offset, width, read/write, alignment evidence)`.
Cluster compatible accesses across callers, constructors and consumers; distinguish
overlapping fields from unions, reused storage and subobjects. Array stride is
evidence for element size, not automatically for the entire allocated object.

Example: byte evidence establishes a four-byte little-endian integer beginning
at offset one. Casting `buffer + 1` to `uint32_t *` introduces alignment and
aliasing assumptions. Under an established readable byte-buffer contract, use
byte assembly with unsigned casts before shifts, or `memcpy` into a local integer
plus an explicit target-endian conversion. This substitution does not apply to
MMIO, volatile/atomic accesses or concurrent memory without a matching model.
Check output bytes, boundary offsets and layout assertions, not only return values.

## Indirect control flow and optimization artifacts

For an indirect call/jump, trace the target-producing load and its index backward.
Combine relocations, table bytes, range guards and constructor vptr stores to
enumerate supported destinations. Record the default/out-of-range edge and any
unresolved destinations. A missing direct call-graph edge is not evidence that
the call cannot occur. Preserve strongly connected groups when selecting batches.

For a switch table, verify relative versus absolute entries, entry width, base
address and signed extension before turning it into a C switch. Exercise each
recovered case and the actual default path. For virtual calls, associate the
address point and `this` adjustment with the concrete subobject before choosing
a method prototype.

Identify compiler helpers, library routines, clones and inlined regions using
symbols/relocations, matching runtime evidence and call-site semantics. Reuse a
known routine only after establishing its ABI and behavior; similar bytes alone
do not justify dropping a function. Keep a mapping from machine regions to the
reconstructed component even when several regions share a readable helper.

## Stateful and pointer-based differential harnesses

The bundled scalar sampler does not support these interfaces. Build a dedicated
isolated harness only after the ABI is established; keep the original and
candidate in separate workers with equivalent initial state.

An operation sequence such as `create -> append -> read -> reset -> read -> destroy`
must compare outcomes after **each** operation. Capture return values, errno or
exceptions, defined output bytes, globals and relevant external events. Compare
pointer relationships/ownership when relevant, rather than unrelated process
addresses. Do not compare uninitialized padding as defined output.

Include zero-length and boundary buffers, supported aliasing, repeated calls,
failure cleanup and lifecycle operations. Record seeds and minimize failing
sequences into repeatable regression fixtures. Normalize nondeterminism only
where the observation contract permits it; otherwise report the mismatch or gap.
Run hostile targets in an appropriate isolated environment, never by loading
them into the analysis host process.

Deliver a matrix of recovered interface/layout, tested observations and unresolved
semantics per component. A real consumer's successful integration test improves
diagnostic evidence; `accept` still requires its independent acceptance contract.
