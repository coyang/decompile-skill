#!/bin/bash
# triage.sh — Phase 0 gate for the decompile skill.
# Probes an ELF artifact (or an archive, member by member) with binutils only
# and emits triage.json: kind, language, fidelity tier, cost numbers.
# Exit 1 = hard refusal (not ELF, LTO blob, unparseable). Exit 0 = proceed.
#
# Why a script instead of eyeballing readelf: the mode gate and every failure
# branch must be reproducible evidence, not a first-impression guess. Fidelity
# tier is computed from section booleans PER TU — `file`'s prose misleads about
# what names survive (a stripped .so keeps its .dynsym exports; a stripped .o
# keeps nothing; nm -D on an archive is always empty).

set -uo pipefail
export LC_ALL=C   # binutils output is localized on some boxes; we parse it.

usage() { echo "usage: triage.sh ARTIFACT [--out DIR]" >&2; exit 2; }
[[ $# -lt 1 ]] && usage
ART="$1"; shift
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -f "$ART" ]] || { echo "triage: not a readable file: $ART" >&2; exit 1; }
[[ -n "$OUT" ]] || OUT="$(dirname "$ART")/$(basename "$ART").decomp"
command -v python3 >/dev/null 2>&1 || { echo "triage: python3 is required to emit valid JSON" >&2; exit 1; }
mkdir -p "$OUT" || { echo "triage: cannot create output directory: $OUT" >&2; exit 1; }
JSON="$OUT/triage.json"
declare -a ARCHIVE_MEMBER_NAMES=()

emit_refuse() {
  local kind="$1" reason="$2" tmp="${JSON}.tmp.$$"
  if ! python3 - "$kind" "$reason" "${ARCHIVE_MEMBER_NAMES[@]}" > "$tmp" <<'PY'
import json
import sys

result = {"kind": sys.argv[1], "refuse_reason": sys.argv[2], "members": []}
if len(sys.argv) > 3:
    result["archive_member_names"] = sys.argv[3:]
json.dump(result, sys.stdout, ensure_ascii=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
  then
    rm -f "$tmp"
    echo "triage: failed to serialize refusal JSON" >&2
    exit 1
  fi
  if ! mv "$tmp" "$JSON"; then
    rm -f "$tmp"
    echo "triage: failed to write refusal report: $JSON" >&2
    exit 1
  fi
  echo "triage: REFUSED — $reason" >&2
  exit 1
}

MAGIC=$(file -b "$ART" 2>/dev/null || echo unreadable)
KIND=""
if printf '%s' "$MAGIC" | grep -qi 'ar archive'; then
  KIND=archive
elif printf '%s' "$MAGIC" | grep -q 'ELF '; then
  if   printf '%s' "$MAGIC" | grep -q 'shared object'; then KIND=so
  elif printf '%s' "$MAGIC" | grep -q 'executable';    then KIND=exe
  elif printf '%s' "$MAGIC" | grep -q 'relocatable';   then KIND=o
  else KIND=elf; fi
else
  emit_refuse not-elf "file magic is not ELF (.so/.a/.o/executable): $MAGIC"
fi

# probe_unit PATH LABEL KIND -> tab-separated: machine etype producer tier lang
# vtable eh funcs exported   (sets globals on failure via return 1)
probe_unit() {
  local U="$1" LABEL="$2" K="$3"
  local hdr machine etype producer secs tier lang mangled tv funcs exps
  local fsrc fn_status fn_basis e f
  if ! hdr=$(readelf -h "$U" 2>/dev/null) || [[ -z "$hdr" ]]; then
    return 1
  fi
  # Truncation: the ELF header can survive while sections lie past EOF.
  if readelf -SW "$U" 2>&1 >/dev/null | grep -qiE 'past end of file|exceeds the size|corrupt'; then
    return 1
  fi
  machine=$(awk -F: '/Machine:/{gsub(/^ +/,"",$2); print $2}' <<<"$hdr")
  etype=$(awk -F: '/Type:/{gsub(/^ +/,"",$2); print $2}' <<<"$hdr")
  producer=$(readelf -p .comment "$U" 2>/dev/null \
    | sed -n 's/^ *\[[^]]*\] *//p' | grep -m1 -iE 'gcc|clang|llvm' || true)
  [[ -z "$producer" ]] && producer=unknown
  secs=$(readelf -SW "$U" 2>/dev/null)
  if printf '%s' "$secs" | grep -q '\.gnu\.lto'; then
    printf 'LTO\n'; return 0
  fi
  if   printf '%s' "$secs" | grep -q '\.debug_info'; then tier=DEBUG
  elif printf '%s' "$secs" | grep -q '\.symtab';     then tier=SYMTAB
  elif printf '%s' "$secs" | grep -q '\.dynsym';     then tier=DYNSYM
  else tier=STRIPPED; fi
  # DW_AT_producer carries the full flag set; .comment only the version.
  # Flags matter upstream (V1 picks the compiler family, deep-mode rebuilds).
  if [[ "$tier" == DEBUG ]]; then
    producer=$(timeout 20 readelf --debug-dump=info "$U" 2>/dev/null \
      | sed -nE 's/.*DW_AT_producer *: //p' | head -1 \
      | sed -E 's/^\(indirect string, offset: 0x[0-9a-f]+\) *: //') || true
    [[ -n "$producer" ]] || producer=$(readelf -p .comment "$U" 2>/dev/null \
      | sed -n 's/^ *\[[^]]*\] *//p' | grep -m1 -iE 'gcc|clang|llvm' || true)
  fi
  [[ -z "$producer" ]] && producer=unknown
  mangled=$( { nm --defined-only "$U" 2>/dev/null || true
               nm -D --defined-only "$U" 2>/dev/null || true; } \
    | awk '{print $NF}' | grep -c '^_Z' || true)
  # has_vtables: .o/archive members have no .dynsym — nm -D alone missed every
  # vtable on them (iter-1 F14); plain nm is the right roster there.
  tv=$( { nm --defined-only "$U" 2>/dev/null || true
          nm -D --defined-only "$U" 2>/dev/null || true; } \
      | awk '{print $NF}' | grep -c '^_Z\(TV\|TI\|TC\|TH\|VN\)' || true)
  if [[ "$mangled" -gt 0 ]]; then lang=cpp
  # stripped C++ members keep mangled SECTION names (.text._ZN...) after symtab dies
  elif printf '%s' "$secs" | grep -qE '\.(text|rodata|data|eh_frame|gcc_except_table)\._Z|_ZTV'; then lang=cpp
  else lang=unknown; fi
  funcs=$( { nm --defined-only "$U" 2>/dev/null || true
             nm -D --defined-only "$U" 2>/dev/null || true; } \
    | awk '$2 ~ /[TtWw]/{print $NF}' | sort -u | wc -l)
  fsrc=nm
  fn_status=known
  fn_basis='visible defined text symbols from nm (lower bound; not a complete function inventory)'
  # STRIPPED .o: nm counts zero — that means "cannot count", not "no
  # functions" (iter-1 F1). Estimate via entry-instruction or FDE census.
  if (( funcs == 0 )) && [[ "$tier" == STRIPPED ]]; then
    e=$(objdump -d "$U" 2>/dev/null | grep -c endbr64 || true)
    if (( e > 0 )); then
      funcs=$e; fsrc=endbr64; fn_status=estimated
      fn_basis='endbr64 instruction census (heuristic estimate)'
    else f=$(timeout 20 readelf --debug-dump=frames "$U" 2>/dev/null | grep -c 'FDE cie' || true)
         if (( f > 0 )); then
           funcs=$f; fsrc=fde; fn_status=estimated
           fn_basis='frame description entry census (heuristic estimate)'
         else
           fsrc=unknown; fn_status=unknown
           fn_basis='no visible text symbols or supported function census'
         fi
    fi
  fi
  if [[ "$K" == archive ]]; then
    # exports of an object member = its global defined symbols (no .dynsym here)
    exps=$(nm --defined-only "$U" 2>/dev/null | awk '$2 ~ /[TtDdBbRrWw]/{print $NF}' | sort -u | wc -l)
  else
    exps=$(nm -D --defined-only "$U" 2>/dev/null | awk '$2 ~ /[TtDdBbRrWw]/{print $NF}' | sort -u | wc -l)
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$machine" "$etype" "$producer" "$tier" "$lang" \
    "$([[ "$tv" -gt 0 ]] && echo true || echo false)" \
    "$([[ "$(printf '%s' "$secs" | grep -c '\.gcc_except_table')" -gt 0 ]] && echo true || echo false)" \
    "$funcs" "$exps" "$fsrc" "$fn_status" "$fn_basis"
}

member_json() {
  local LABEL="$1" row="$2"
  local IFS=$'\t'; local -a f; read -ra f <<< "$row"
  python3 - "$LABEL" "${f[0]}" "${f[1]}" "${f[2]}" "${f[3]}" "${f[4]}" \
    "${f[5]}" "${f[6]}" "${f[7]:-0}" "${f[9]:-unknown}" "${f[8]:-0}" \
    "${f[10]:-unknown}" "${f[11]:-count basis unavailable}" <<'PY'
import json
import sys

value = {
    "name": sys.argv[1],
    "machine": sys.argv[2],
    "etype": sys.argv[3],
    "producer": sys.argv[4],
    "tier": sys.argv[5],
    "lang": sys.argv[6],
    "has_vtables": sys.argv[7] == "true",
    "has_eh": sys.argv[8] == "true",
    "funcs": int(sys.argv[9]),
    "fn_count_source": sys.argv[10],
    "exported": int(sys.argv[11]),
    "fn_count_status": sys.argv[12],
    "fn_count_basis": sys.argv[13],
    "fn_count_complete": False,
}
json.dump(value, sys.stdout, ensure_ascii=True, separators=(",", ":"))
PY
}

simple_member_json() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

json.dump(
    {"name": sys.argv[1], "kind": sys.argv[2], "funcs": 0, "exported": 0,
     "fn_count_status": "unknown", "fn_count_complete": False,
     "fn_count_basis": "unit was not analyzed as ELF code"},
    sys.stdout,
    ensure_ascii=True,
    separators=(",", ":"),
)
PY
}

# --- walk units -----------------------------------------------------------------
declare -a MJ=()
TOTAL_FUNCS=0 EXPS_TOP=0
LANGS=() TIERS=() PRODUCER=unknown MACHINE="" ETYPE="" ANY_VT=false ANY_EH=false
ANY_EST=false ANY_UNKNOWN=false CORRUPT=0

walk() { # PATH LABEL KIND
  local row
  if ! row=$(probe_unit "$1" "$2" "$3"); then
    CORRUPT=1
    local item
    if ! item=$(simple_member_json "$2" corrupt); then
      echo "triage: failed to serialize corrupt member: $2" >&2
      exit 1
    fi
    MJ+=("$item")
    return
  fi
  [[ "$row" == LTO ]] && {
    if [[ "$3" == archive ]]; then
      local item
      if ! item=$(simple_member_json "$2" lto); then
        echo "triage: failed to serialize LTO member: $2" >&2
        exit 1
      fi
      MJ+=("$item")
      return
    fi
    emit_refuse lto "LTO intermediate object (.gnu.lto_*): pass the final binary or rebuild with -fno-lto"
  }
  local IFS=$'\t'; local -a f; read -ra f <<< "$row"
  MACHINE="${f[0]}"; ETYPE="${f[1]}"; PRODUCER="${f[2]}"
  [[ "$3" != archive ]] && EXPS_TOP="${f[8]:-0}"
  LANGS+=("${f[4]}"); TIERS+=("${f[3]}")
  [[ "${f[5]}" == true ]] && ANY_VT=true
  [[ "${f[6]}" == true ]] && ANY_EH=true
  TOTAL_FUNCS=$((TOTAL_FUNCS + ${f[7]:-0}))
  [[ "${f[9]:-nm}" == nm ]] || ANY_EST=true
  [[ "${f[10]:-unknown}" == unknown ]] && ANY_UNKNOWN=true
  local item
  if ! item=$(member_json "$2" "$row"); then
    echo "triage: failed to serialize member: $2" >&2
    exit 1
  fi
  MJ+=("$item")
}

if [[ "$KIND" == archive ]]; then
  TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT
  cp "$ART" "$TMPD/a.ar" 2>/dev/null || emit_refuse corrupt "archive unreadable"
  archive_listing=""
  if ! archive_listing=$(ar t "$ART" 2>/dev/null); then
    emit_refuse corrupt "cannot read archive member table"
  fi
  mapfile -t ARCHIVE_MEMBER_NAMES <<< "$archive_listing"
  declare -A seen_members=()
  for m in "${ARCHIVE_MEMBER_NAMES[@]}"; do
    [[ -z "$m" ]] && continue
    if [[ -n "${seen_members[$m]+present}" ]]; then
      emit_refuse archive "duplicate archive member name would make extraction lossy: $m"
    fi
    seen_members["$m"]=1
  done
  for m in "${ARCHIVE_MEMBER_NAMES[@]}"; do
    [[ -z "$m" ]] && continue
    if ! ( cd "$TMPD" && ar x a.ar "$m" 2>/dev/null ); then
      emit_refuse corrupt "failed to extract archive member: $m"
    fi
    [[ -f "$TMPD/$m" ]] || emit_refuse corrupt "archive member was not extracted: $m"
    if ! member_magic=$(file -b "$TMPD/$m" 2>/dev/null); then
      emit_refuse corrupt "cannot identify archive member: $m"
    fi
    if ! printf '%s' "$member_magic" | grep -q 'ELF '; then
      if ! item=$(simple_member_json "$m" non-code); then
        echo "triage: failed to serialize non-code member: $m" >&2
        exit 1
      fi
      MJ+=("$item")
      continue
    fi
    walk "$TMPD/$m" "$m" archive
  done
  (( CORRUPT )) && emit_refuse corrupt "one or more archive members are not parseable ELF (see members[])"
else
  walk "$ART" "$(basename "$ART")" "$KIND"
  (( CORRUPT )) && emit_refuse corrupt "readelf failed — truncated or unparseable ELF"
fi

# --- aggregate ------------------------------------------------------------------
# `tier` is the WORST over units (safe ceiling), but on archives it lies by
# omission: a 25/26-DEBUG archive reports STRIPPED. tier_hist gives the truth.
worst=DEBUG HIST_D=0 HIST_S=0 HIST_Y=0 HIST_P=0
for t in "${TIERS[@]:-STRIPPED}"; do
  case "$t" in
    DEBUG) : ; HIST_D=$((HIST_D+1)) ;;
    SYMTAB) [[ "$worst" == DEBUG ]] && worst=SYMTAB ; HIST_S=$((HIST_S+1)) ;;
    DYNSYM) [[ "$worst" == DEBUG || "$worst" == SYMTAB ]] && worst=DYNSYM ; HIST_Y=$((HIST_Y+1)) ;;
    STRIPPED) worst=STRIPPED ; HIST_P=$((HIST_P+1)) ;;
  esac
done
TIER_HIST="DEBUG=$HIST_D SYMTAB=$HIST_S DYNSYM=$HIST_Y STRIPPED=$HIST_P"
lang=unknown
if [[ ${#LANGS[@]} -gt 0 ]]; then
  allsame=true
  for l in "${LANGS[@]}"; do [[ "$l" == "${LANGS[0]}" ]] || allsame=false; done
  $allsame && lang="${LANGS[0]}" || lang=mixed
fi
PIE=false
[[ "$KIND" == exe && "$ETYPE" == DYN* ]] && PIE=true
SZ=$(stat -c%s "$ART" 2>/dev/null || echo 0)
COST=false
(( SZ > 52428800 || TOTAL_FUNCS > 2000 )) && COST=true

FN_STATUS=known
FN_SOURCE=nm
FN_BASIS='sum of per-unit visible defined text symbols (lower bound; nm is not a complete function inventory)'
if $ANY_UNKNOWN; then
  FN_STATUS=unknown
  FN_SOURCE=unknown
  FN_BASIS='sum includes one or more units with no supported function census'
elif $ANY_EST; then
  FN_STATUS=estimated
  FN_SOURCE=estimated
  FN_BASIS='sum includes one or more heuristic per-unit function estimates'
fi

MEMBERS_JSON="$(IFS=,; echo "${MJ[*]:-}")"
tmp_json="${JSON}.tmp.$$"
if ! python3 - "$KIND" "${MACHINE:-unknown}" "$PIE" "$PRODUCER" "$lang" \
  "$ANY_VT" "$ANY_EH" "$worst" "$TIER_HIST" "$TOTAL_FUNCS" "$FN_SOURCE" \
  "$SZ" "$EXPS_TOP" "$COST" "$MAGIC" "$FN_STATUS" "$FN_BASIS" "$MEMBERS_JSON" \
  > "$tmp_json" <<'PY'
import json
import sys

members = json.loads("[" + sys.argv[18] + "]")
value = {
    "kind": sys.argv[1], "machine": sys.argv[2], "pie": sys.argv[3] == "true",
    "producer": sys.argv[4], "lang": sys.argv[5],
    "has_vtables": sys.argv[6] == "true", "has_eh": sys.argv[7] == "true",
    "tier": sys.argv[8], "tier_hist": sys.argv[9], "fn_count": int(sys.argv[10]),
    "fn_count_source": sys.argv[11], "size_bytes": int(sys.argv[12]),
    "exported_count": int(sys.argv[13]), "cost_warning": sys.argv[14] == "true",
    "refuse_reason": None, "magic": sys.argv[15], "members": members,
    "fn_count_status": sys.argv[16], "fn_count_basis": sys.argv[17],
    "fn_count_complete": False,
}
json.dump(value, sys.stdout, ensure_ascii=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
then
  rm -f "$tmp_json"
  echo "triage: failed to serialize triage report" >&2
  exit 1
fi
if ! mv "$tmp_json" "$JSON"; then
  rm -f "$tmp_json"
  echo "triage: failed to write triage report: $JSON" >&2
  exit 1
fi

echo "triage: $ART -> $JSON (kind=$KIND tier=$worst hist=\"$TIER_HIST\" lang=$lang fns=$TOTAL_FUNCS cost=$COST)"
