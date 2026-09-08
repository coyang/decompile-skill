# NOTES — reconstruction of libcutil.so

Artifact: evals/fixtures/build/libcutil.so, tier DEBUG (DWARF present),
producer gcc family, kind shared. Evidence: Ghidra exports under the run's
work dir, fn_<addr>_<name>.c per function; Ghidra-space addresses
(image base 0x100000 + ELF vaddr) are what the src:@ citations use.

## Inferences

AppConfig field order/name/magic (I) @0x10118e — because memset size 0x28
plus decompiler field offsets 0x0/0x8/0x24 agree with DWARF name strings
magic/name/flags in .debug_info.
enum LoadMode constants LOAD_RDONLY/LOAD_WRONLY/LOAD_RDWR (I) @0x1011f7 —
because the switch arms 1/2/3 return the rodata literals
read-only / write-only / read-write; names chosen to fit that pattern.
default_config initializer (I) @0x10118e — bytes taken from
readelf -x .data, not from any decompiler output.

## Structure

8 exported functions + 1 exported data symbol, 2 file-statics kept under
their symtab names (node_depth, fold_magic). node_sum is recursive over
Node::next; node_count delegates to node_depth after the null guard.

## Open questions

None blocking; the module is small and every function matched on first pass.
