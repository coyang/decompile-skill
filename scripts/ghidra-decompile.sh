#!/bin/bash
# ghidra-decompile.sh — Ghidra headless driver for the decompile skill.
#
# usage: ghidra-decompile.sh ARTIFACT --workdir DIR [--targets FILE]
#                            [--program NAME] [--timeout SEC] [--max-mem 4G]
#                            [--processor ID] [--no-analysis]

set -u
export LC_ALL=C

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_TOOL="$SKILL_DIR/scripts/ghidra_driver_manifest.py"

usage() { sed -nE 's/^#[[:space:]]+(usage:.*|\[.*)/\1/p' "$0" >&2; exit 2; }
fail() { echo "ghidra-decompile: $*" >&2; exit 2; }

ART="" WORK="" TARGETS="" PROGRAM="" TIMEOUT=300 MAXMEM=4G PROCESSOR="" NOANALYSIS=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --workdir) [[ $# -ge 2 ]] || usage; WORK="$2"; shift 2 ;;
    --targets) [[ $# -ge 2 ]] || usage; TARGETS="$2"; shift 2 ;;
    --program) [[ $# -ge 2 ]] || usage; PROGRAM="$2"; shift 2 ;;
    --timeout) [[ $# -ge 2 ]] || usage; TIMEOUT="$2"; shift 2 ;;
    --max-mem) [[ $# -ge 2 ]] || usage; MAXMEM="$2"; shift 2 ;;
    --processor) [[ $# -ge 2 ]] || usage; PROCESSOR="$2"; shift 2 ;;
    --no-analysis) NOANALYSIS=true; shift ;;
    -h|--help) usage ;;
    *) [[ -z "$ART" ]] && { ART="$1"; shift; } || usage ;;
  esac
done
[[ -n "$ART" && -n "$WORK" ]] || usage
[[ -f "$ART" ]] || { echo "ghidra-decompile: no such file: $ART" >&2; exit 1; }
[[ -f "$MANIFEST_TOOL" ]] || fail "missing manifest helper: $MANIFEST_TOOL"

if [[ -n "$TARGETS" ]]; then
  [[ -f "$TARGETS" ]] || fail "targets file not found: $TARGETS"
  awk 'BEGIN { found=0 } /^[[:space:]]*($|#)/ { next } { found=1 } END { exit !found }' "$TARGETS" \
    || fail "targets file contains no targets: $TARGETS"
  TARGETS=$(realpath "$TARGETS")
fi

mkdir -p "$WORK"
ABS_ART=$(realpath "$ART")
ABS_WORK=$(realpath "$WORK")

# Plain `ar x` overwrites earlier members with the same name. Refuse that lossy
# expansion until the driver can assign a stable identity to each occurrence.
IS_ARCHIVE=false
if file -b "$ABS_ART" | grep -qi 'ar archive'; then
  IS_ARCHIVE=true
  ARCHIVE_MEMBERS=$(ar t "$ABS_ART") || fail "cannot list archive members"
  DUPLICATES=$(printf '%s\n' "$ARCHIVE_MEMBERS" | sort | uniq -d)
  [[ -z "$DUPLICATES" ]] \
    || fail "duplicate archive member name(s) are unsupported: $(printf '%s' "$DUPLICATES" | tr '\n' ' ')"
  SANITIZED_COLLISIONS=$(printf '%s\n' "$ARCHIVE_MEMBERS" \
    | sed 's/[^a-zA-Z0-9._-]/_/g' | sort | uniq -d)
  [[ -z "$SANITIZED_COLLISIONS" ]] \
    || fail "archive member names collide after evidence-path sanitization: $(printf '%s' "$SANITIZED_COLLISIONS" | tr '\n' ' ')"
fi

AH=""
for c in ${GHIDRA_HOME:+"$GHIDRA_HOME/support/analyzeHeadless"} \
         "$(command -v analyzeHeadless 2>/dev/null || true)" \
         "$HOME/ghidra/support/analyzeHeadless" \
         "$HOME"/tools/ghidra_*/support/analyzeHeadless \
         "$HOME"/ghidra_*/support/analyzeHeadless \
         /opt/ghidra/support/analyzeHeadless /usr/share/ghidra/support/analyzeHeadless; do
  [[ -n "$c" && -x "$c" ]] && { AH="$c"; break; }
done
if [[ -z "$AH" ]]; then
  echo "ghidra-decompile: analyzeHeadless not found." >&2
  echo "  Install Ghidra and set GHIDRA_HOME, or use objdump-only degraded mode." >&2
  exit 3
fi
AH=$(realpath "$AH")

RUNS_DIR="$ABS_WORK/ghidra/runs"
mkdir -p "$RUNS_DIR"
RUN_DIR=$(mktemp -d "$RUNS_DIR/run-$(date -u +%Y%m%dT%H%M%S)-XXXXXX") \
  || fail "cannot create evidence run directory"
export GHIDRA_OUTPUT_DIR="$RUN_DIR"
FINGERPRINT="$RUN_DIR/analysis-fingerprint.json"
EXPECTED_PROGRAMS="$RUN_DIR/expected-programs.txt"
if [[ "$IS_ARCHIVE" == true ]]; then
  printf '%s\n' "$ARCHIVE_MEMBERS" > "$EXPECTED_PROGRAMS"
else
  basename "$ABS_ART" > "$EXPECTED_PROGRAMS"
fi
FP_ARGS=(fingerprint --artifact "$ABS_ART" --headless "$AH"
  --script "$SKILL_DIR/ghidra_scripts/DumpFunctions.java"
  --script "$SKILL_DIR/ghidra_scripts/ExportTypes.java"
  --processor "$PROCESSOR" --output "$FINGERPRINT")
[[ "$NOANALYSIS" == true ]] && FP_ARGS+=(--no-analysis)
FP_SHA=$(python3 "$MANIFEST_TOOL" "${FP_ARGS[@]}") \
  || fail "could not create analysis fingerprint"

# Ghidra rejects dot-prefixed path elements. Relocate only its project cache;
# immutable run evidence remains below the requested work directory.
PROJ_DIR="$ABS_WORK/ghproj"
if [[ "$ABS_WORK" =~ (^|/)\.[^/./] ]]; then
  PROJ_DIR="/tmp/decompile-gh-$(id -u)/$(printf '%s' "$ABS_WORK" | sha256sum | cut -c1-16)"
  echo "ghidra-decompile: NOTE project cache relocated to $PROJ_DIR for Ghidra path compatibility" >&2
fi
mkdir -p "$PROJ_DIR"

PROJ_NAME=$(python3 "$MANIFEST_TOOL" select-project \
  --project-dir "$PROJ_DIR" --fingerprint "$FINGERPRINT") \
  || fail "could not inspect cached project manifests"
MODE=import
if [[ -n "$PROJ_NAME" ]]; then
  MODE=reprocess
else
  PROJ_NAME="decompile_${FP_SHA:0:16}"
  if [[ -e "$PROJ_DIR/$PROJ_NAME.gpr" || -e "$PROJ_DIR/$PROJ_NAME.rep" ]]; then
    PROJ_NAME="${PROJ_NAME}_$(basename "$RUN_DIR" | tr -c 'A-Za-z0-9_-' '_')"
  fi
fi
PROJ="$PROJ_DIR/$PROJ_NAME.gpr"
ANALYSIS_MARKER="$PROJ_DIR/$PROJ_NAME.analysis-manifest.json"

TW=()
command -v timeout >/dev/null 2>&1 && TW=(timeout --preserve-status -k 10 "$TIMEOUT")

rc=0
if [[ "$MODE" == import ]]; then
  if [[ -n "$PROGRAM" ]]; then
    echo "ghidra-decompile: --program requires a completed reusable project; refusing unrestricted import" >&2
    rc=2
  fi
  echo "ghidra-decompile: IMPORT mode ($PROJ_NAME)"
  if [[ "$IS_ARCHIVE" == true && $rc -eq 0 ]]; then
    MEMBER_DIR="$RUN_DIR/archive-members"
    mkdir -p "$MEMBER_DIR"
    (cd "$MEMBER_DIR" && ar x "$ABS_ART") \
      || { echo "ghidra-decompile: archive extraction failed" >&2; rc=1; }
    if (( rc == 0 )); then
      while IFS= read -r member; do
        member_path="$MEMBER_DIR/$member"
        if [[ ! -f "$member_path" ]] || ! readelf -h "$member_path" >/dev/null 2>&1; then
          echo "ghidra-decompile: unsupported non-ELF archive member: $member" >&2
          rc=1
          break
        fi
        if readelf -SW "$member_path" 2>/dev/null | grep -q '\.gnu\.lto_'; then
          echo "ghidra-decompile: unsupported standalone LTO archive member: $member" >&2
          rc=1
          break
        fi
      done < "$EXPECTED_PROGRAMS"
    fi
    IMPORT_ARGS=(-import "$MEMBER_DIR" -recursive)
  else
    IMPORT_ARGS=(-import "$ABS_ART")
  fi
  [[ -n "$PROCESSOR" ]] && IMPORT_ARGS+=(-processor "$PROCESSOR" -loader ELF)
  [[ "$NOANALYSIS" == true ]] && IMPORT_ARGS+=(-noanalysis)
  if (( rc == 0 )); then
    POST_ARGS=(-postScript DumpFunctions.java)
    [[ -n "$TARGETS" ]] && POST_ARGS+=("$TARGETS")
    "${TW[@]}" env MAXMEM="$MAXMEM" "$AH" "$PROJ_DIR" "$PROJ_NAME" \
      "${IMPORT_ARGS[@]}" \
      -scriptPath "$SKILL_DIR/ghidra_scripts" \
      -postScript ExportTypes.java \
      "${POST_ARGS[@]}" 2>&1 | tee "$RUN_DIR/ghidra-output.log"
    rc=${PIPESTATUS[0]}
  fi
else
  echo "ghidra-decompile: REPROCESS mode ($PROJ_NAME, verified project reused)"
  PROG_ARGS=(-noanalysis)
  [[ -n "$PROGRAM" ]] && PROG_ARGS+=(-process "$PROGRAM") || PROG_ARGS+=(-process "*")
  POST_ARGS=(-scriptPath "$SKILL_DIR/ghidra_scripts" -postScript DumpFunctions.java)
  [[ -n "$TARGETS" ]] && POST_ARGS+=("$TARGETS")
  "${TW[@]}" env MAXMEM="$MAXMEM" "$AH" "$PROJ_DIR" "$PROJ_NAME" \
    "${PROG_ARGS[@]}" "${POST_ARGS[@]}" \
    2>&1 | tee "$RUN_DIR/ghidra-output.log"
  rc=${PIPESTATUS[0]}
fi

FINAL_ARGS=(finalize --run-dir "$RUN_DIR" --fingerprint "$FINGERPRINT"
  --mode "$MODE" --project-name "$PROJ_NAME" --headless-rc "$rc"
  --expected-programs "$EXPECTED_PROGRAMS")
[[ -n "$TARGETS" ]] && FINAL_ARGS+=(--targets "$TARGETS")
FINAL_ARGS+=(--analysis-marker "$ANALYSIS_MARKER" --project-dir "$PROJ_DIR")
final_rc=0
python3 "$MANIFEST_TOOL" "${FINAL_ARGS[@]}" || final_rc=$?

if (( rc )); then
  echo "ghidra-decompile: headless run failed (rc=$rc); incomplete evidence preserved at $RUN_DIR" >&2
  exit "$rc"
fi
if (( final_rc )); then
  echo "ghidra-decompile: export validation failed; evidence preserved at $RUN_DIR" >&2
  exit 1
fi
echo "ghidra-decompile: evidence exported under $RUN_DIR (project kept at $PROJ)"
find "$RUN_DIR" -mindepth 1 -maxdepth 1 -printf '  %f\n' | sort
