# Verification regression suite

Run from any directory:

```bash
python3 -m unittest discover -s /absolute/skill/evals -p 'test_*.py' -v
```

`test_acceptance.py` uses real GCC-built shared libraries and the installed
bubblewrap sandbox. It tests approved source-built byte identity plus rejected or
unknown arithmetic drift, partial evidence, policy/source/environment pins, ABI
changes, unsafe output paths, source blobs and symlinks. Both the successful and
blocked paths check that supplied constructors are not executed by acceptance.
The gate-owned compiler ignores Makefile commands. Tests never modify a production library.

`test_differential.py` verifies TESTED versus COUNTEREXAMPLE for scalar samples,
that neither authorizes replacement, and that constructor side effects remain
inside the diagnostic sandbox. This sampler is deliberately not a proof engine.

`test_checker_protocol.py` rejects stale requests, missing obligations/exports,
changed assumptions/models/certificates, sampled proof methods, invalid JSON,
timeouts, crashes and missing isolation. Synthetic protocol responses test rejection
only and are not evidence that a real semantic proof checker exists.

`test_type_export.py` compiles ExportTypes.java against locally installed Ghidra
and exercises width preservation, pointer-to-array declarations, by-value ordering
and unsupported layout rejection. It skips explicitly when Ghidra JARs are absent.
A skipped test is a validation gap, not a passing runtime integration.

The acceptance contract is in ../references/acceptance.md. External certificate
checkers are not supplied by the fixture corpus. Protocol tests must not use a
checker that always returns PASS as evidence of semantic correctness. Missing,
crashing, stale, malformed and incomplete proof results must remain blocked.

## Historical fixtures

`fixtures/` retains the original C/C++ binary sources, generated binaries and
handcraft reconstruction for analysis regressions. `make -C fixtures all` rebuilds
the corpus; `manifest` refreshes its source/binary hashes. `firewall` now runs the
current behavioral suite, replacing prose/keyword greps that did not validate
correctness. Existing V1–V9 results and negative-pair similarity tables are
historical diagnostics only and cannot be used as approval evidence.

The old verifier's measured false positive (x+1 changed to x+2 accepted), false
negative (equivalent condition inversion rejected), invalid-address acceptance
and V9 exception are recorded in test_acceptance.py. The new suite tests the
intended externally visible behavior instead of preserving those defects.

`evals.json` and ../test-prompts.json describe manual agent-level scenarios and
must agree on prompts. They complement executable tests; they are not a substitute
for an actual proof model or production deployment contract.
