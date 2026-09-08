# Acceptance contract and trust boundary

## Meaning of the decision

The two outputs answer different questions:

| Field | State | Meaning |
|---|---|---|
| correctness | UNKNOWN | No complete proof established; absence of a counterexample is insufficient. |
| correctness | PROVED_IDENTICAL | Complete original and candidate ELF bytes compare equal. This is about these artifacts, not every future compilation of the source. |
| correctness | PROVED_CONTRACT | An independently approved certificate checker validated the policy's formal/exhaustive model. Only that observation domain and its explicit assumptions are covered. |
| replacement | UNKNOWN | A required prerequisite/proof/tool is missing, invalid or failed. No approval. |
| replacement | REJECTED | A concrete loader/export requirement or independent verifier rejected this pair. This need not mean the mathematical functions differ. |
| replacement | APPROVED | Exact artifacts passed the pinned policy for the named cold-start target. No deployment was performed. |

Exit 0 is exclusive to APPROVED. Exit 1 is rejection. Exit 2 is unknown/error.
Never translate UNKNOWN into success, even when other checks passed.

General C/C++ equivalence is not automatically decidable. This installation
implements exact-byte verification and orchestration of independent certificate
checkers; it does **not** ship a general formal solver or C++ proof checker.
Most nonidentical real-world reconstructions will remain UNKNOWN until a checker
for their model is supplied. Do not claim those cases are now solved.

## Inputs and trusted policy

```
python3 scripts/verify.py ORIGINAL.so TREE --candidate librebuilt.so \
  --policy /owner/acceptance-policy.json --policy-sha256 <owner-published-sha256> \
  --json /outside-tree/acceptance.json
```

Without the policy, the command still records artifact/source hashes and identity
when possible; replacement remains UNKNOWN. Candidate is an explicit relative
path inside TREE. There is no output search or Makefile execution. Supplied libraries are not
loaded by the acceptance gate, including its positive identity path. The JSON report must be outside TREE.

Only `src/`, `include/`, and `Makefile` are copied into the isolated build. All
three are required. Symlinks and special files are rejected. The candidate cannot
already be part of those inputs. Only UTF-8 C/C++ translation units/headers (and .inc files) without embedded NUL
bytes are accepted under src/include; prebuilt ELF/archive/object blobs are rejected.
Makefile is hashed for provenance but **never executed** by acceptance. Other build
systems must be adapted explicitly; unsupported layouts do not borrow a prebuilt library. Source hashes are
SHA-256 of canonical JSON (`sort_keys=True,separators=(',',':'),ensure_ascii=True`)
mapping relative file paths in these roots to their SHA-256 hashes.

The policy is an **external trust input**. The reconstruction agent must not
approve its own policy/checker or invent assumptions to make the run pass. A CLI
hash computed by the same untrusted producer is not independent authorization.
The owner/CI must review and pin policy/checker/model and protect their distribution.
The verifier checks the supplied pin; it cannot establish who owns a file.

Policy schema 1 (JSON; substitute real reviewed values):

```json
{
  "schema_version": 1,
  "original_sha256": "<64 lowercase hex>",
  "source_sha256": "<sources.sha256 from the inspected tree>",
  "scope": {
    "id": "service-x-release-y",
    "observations": ["all externally observable behavior of the declared consumers"],
    "assumptions": ["same loader context and target runtime", "cold restart only"]
  },
  "environment": {
    "id": "target-image-and-toolchain-version",
    "system": "Linux",
    "machine": "x86_64",
    "release": "<exact platform.release()>",
    "files": {
      "/absolute/runtime-or-tool-file": "<64 lowercase hex>"
    }
  },
  "deployment": {
    "target": "/absolute/existing/original.so",
    "strategy": "cold-start",
    "rollback_sha256": "<same original SHA-256>",
    "loader_context_unchanged": true
  },
  "tools": {
    "<each absolute tool path from the inspected report.tools>": "<independently reviewed tool SHA-256>"
  },
  "build": {
    "compiler": "/usr/bin/gcc",
    "compiler_sha256": "<SHA-256 of resolved compiler executable>",
    "sources": ["src/library.c"],
    "flags": ["-O0"],
    "timeout_seconds": 60
  }
}
```

The tools map must exactly pin the trusted verifier, Python executable,
`/usr/bin/readelf` and `/usr/bin/bwrap`; PATH substitutions are ignored. The build
compiler is separately pinned. The gate constructs `compiler -shared -fPIC
-Iinclude SOURCES FLAGS -o CANDIDATE`, includes all source translation units and
allows a narrow set of optimization/standard/visibility flags, `-lm`, `-pthread`,
`-Wl,--build-id=none` and a simple SONAME. Arbitrary compiler plugins, linker scripts,
precompiled inputs and build commands are unsupported. The source_reconstruction
field records BUILT_EXACT_CANDIDATE only after this build reproduces the candidate.
This establishes which declared sources produced this artifact, not equivalence
under other compilation settings or that the source resembles the original.

The environment files map is nonempty and must pin the policy-relevant runtime,
loader, dependencies, compiler/toolchain and sandbox. The gate checks every declared
file and kernel/machine/system before and after verification, including symlink
resolution. **It does not discover a complete runtime closure or prove that the
owner's manifest/assumptions cover the deployment.** The policy owner must establish
that scope; target containers/VM image digests and consumer inventories belong in
the reviewed model and integration obligations. User-controlled environment pins
are not remote host attestation.

The target must still contain original bytes. The policy is outside TREE and
matches the independently supplied digest. Neither a hash nor a JSON receipt is
a signature. Do not use a receipt supplied by the reconstruction as a bearer token.

## Built-in identity route

The gate copies both artifacts to private snapshots, records SHA-256 and compares
the entire byte strings. It separately rebuilds source in bubblewrap and compares
the output bytes against that exact candidate. Headers, loader dependencies,
symbol metadata, source/target/policy/environment hashes are also checked.

Identity preserves existing behavior, including existing defects, under the same
loading/environment assumptions. It proves neither that the original was bug-free
nor that source would compile identically with other options. No supplied library constructor or
exported function is executed on this route. The isolated compiler processes source
as a build input; no build-provided command is run. No runtime smoke test is represented
as having run.

## Nonidentical route: independent checked certificates

Nonidentical artifacts require `scope.profile="elf-observational-equivalence-v1"`,
a nonempty unique `scope.consumers` inventory, and scope.observations containing
all of: `return-values`, `memory-and-global-state`, `errors-and-exceptions`,
`external-effects`, `initialization-and-finalization`, `termination-and-divergence`,
`concurrency-and-atomics`. The model must justify inapplicable obligations rather
than dropping them. Assumptions may describe the target environment/domain, never
assume candidate correctness/equivalence or the checker's intended conclusion.
A trusted checker must reject such circular/vacuous certificates; the orchestrator
does not solve natural-language assumption validity.

Add `verifiers` with `proof`, `abi` and `integration`. Each checker is an absolute
path outside TREE, a pinned SHA-256, an integer timeout 1..3600 seconds, and a
nonempty list of unique additional obligations. The gate always adds mandatory
profile obligations (all inputs/states, effects, errors/EH, lifecycle, termination,
concurrency, machine semantics; full ABI; all consumers/runtime/cold-start). They
cannot be removed by policy. The request contains their union. Checkers must be **self-contained statically
linked ELF executables**: no PT_INTERP or DT_NEEDED. They run in an empty namespace
without host `/usr`, libraries, home, environment credentials or network.
Scripts, dynamic binaries, solvers requiring undeclared external files and unavailable
sandboxing fail closed. A production checker must validate the certificate; a
program that echoes PASS is not a checker and must never be trusted.

The `proof` checker additionally requires:

```json
{
  "path": "/owner/checkers/equivalence-checker",
  "sha256": "<checker SHA-256>",
  "timeout_seconds": 300,
  "obligations": ["all exports and lifecycle effects under the approved model"],
  "method": "formal",
  "model": "<precise architecture, semantics, observations and solver/checker model version>",
  "certificate": "/absolute/path/to/untrusted-proof-certificate",
  "certificate_sha256": "<certificate SHA-256>"
}
```

`method` can be `formal` or `exhaustive`. Exhaustive means a checkable complete
finite-state/domain argument under the model, not testing a convenient list of
inputs. The certificate is untrusted even when hash-pinned. The pinned checker
must independently validate its relation to the exact binaries, assumptions,
all specified input/state domains and observations. No solver success string or
producer-supplied result JSON is accepted as a certificate check.

The `abi` and `integration` entries have `path`, `sha256`, `timeout_seconds` and
`obligations`. They must independently validate the declared contracts. No such
checker is bundled; ordinary `abidiff` success without complete debug/type coverage
is insufficient. Static export matching is only a preliminary check.

The process runs as `/checker /request.json`. Read-only paths are `/inputs/original`,
`/inputs/candidate`, `/request.json`, and for proof `/certificate`. `/work` and `/tmp`
are isolated scratch. Emit one JSON object to stdout. Tools have bounded wall time,
CPU, address space and output; any abnormal exit/timeout/invalid result blocks.

Request schema 1 includes:

- random `nonce`, `stage`, and `binding` (original/candidate/source/policy/environment SHA-256);
- `scope`, exact required `obligations`, complete dynamic `symbols` inventory;
- original/candidate paths; proof additionally contains `certificate_sha256`,
  `certificate`, `method`, `model`.

The response must include all of:

```json
{
  "schema_version": 1,
  "stage": "proof",
  "request_sha256": "<SHA-256 of the exact /request.json bytes>",
  "verdict": "PASS",
  "unknowns": [],
  "obligations": ["<exact obligations from request, no omissions or duplicates>"],
  "covered_exports": ["<all request symbol names, sorted>"],
  "assumptions": ["<exact request.scope.assumptions in order>"],
  "summary": "<what was independently checked>",
  "method": "formal",
  "model": "<exact model from request>",
  "checked_certificate_sha256": "<exact certificate SHA-256>"
}
```

The last three fields are proof-only. `FAIL` rejects the pair after request binding
is validated. Any other verdict or missing/partial coverage gives UNKNOWN. Results
are generated in this run, nonce-bound, and recorded with checker/request/response
hashes. There is no offline `--evidence-json` verdict import.

The gate enforces protocol integrity. Soundness of the trusted checker's proof
rules and completeness of the owner-approved model are part of the trusted computing
base; the gate cannot detect a malicious/no-op checker with an authorized hash.

ABI obligations should cover versions, visibility/binding, parameters/returns,
calling convention, data/TLS/IFUNC, struct layouts, C++ vtables/RTTI, unwind/EH and
lifecycle. Semantic obligations include initialization/finalization, indirect calls,
state, memory effects, errors, nondeterminism, concurrency and undefined behavior
where applicable. Integration obligations cover all policy-declared consumers and
loader/runtime assumptions. Missing models remain UNKNOWN rather than disappearing
from a denominator.

## Isolation and deployment limits

Bubblewrap is required for builds, checkers and the optional differential sampler.
The build sees read-only system tools plus writable scratch, no host home/network;
static checkers see no system runtime. This is namespace isolation, not a VM or
proof of resistance to kernel vulnerabilities. Use a dedicated VM for hostile
binaries. Resource bounds reduce accidental hangs; they are not complete cgroup
accounting of a malicious process tree. No dependency is installed automatically.

The receipt binds a cold-start candidate and target. Deployment is a separate
operation that must rerun the trusted gate on the target host and recheck digests
at installation, preserve ownership/mode/xattrs/capabilities/labels, switch atomically,
restart consumers and retain rollback bytes. File-content verification alone does
not prove those deployment actions correct. This skill contains no installer.

## Migration from V1–V9

`verify.sh` now delegates to `verify.py`; `--candidate` and an outside-tree `--json`
are required. Missing explicit policy means exit 2. `--v6` is accepted only for
migration and has no effect. Cached triage is never trusted. The old unguarded
Makefile/dlopen, branch-count hard gate, token similarity, regex naming gate and
negative-control verdict logic were removed. Historical fixture files are preserved,
but old V-score results are not acceptance evidence. Run current unittest regressions.
