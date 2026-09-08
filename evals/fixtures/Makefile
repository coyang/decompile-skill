# Fixture corpus for the decompile skill evals.
# bash + binutils + gcc/g++ only. `make all` is idempotent.
# Outputs: build/ (binaries), gt/ (ground-truth dumps), ../PROVENANCE.md.
#
# The JACCARD awk below is the single authority for the mnemonic-multiset
# (Tanimoto/Jaccard) metric used by gt/neg-pairs.tsv. scripts/verify.sh
# re-declares the identical one-liner (its V6 + negative-control recheck) —
# keep the two copies byte-identical when changing either.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
export LC_ALL := C
B := build
G := gt
SKILL_DIR := $(abspath $(CURDIR)/../..)

CC := gcc
CXX := g++

# Line 1 = function A mnemonics (space-separated), line 2 = function B's.
# Prints the multiset Jaccard (sum-of-min / sum-of-max) with 3 decimals.
JACCARD = awk 'NR==1{for(i=1;i<=NF;i++)a[$$i]++} NR==2{for(i=1;i<=NF;i++)b[$$i]++} END{inter=0;uni=0;for(k in a){inter+=(a[k]<b[k]?a[k]:b[k]); uni+=(a[k]>b[k]?a[k]:b[k])} for(k in b)if(!(k in a))uni+=b[k]; printf "%.3f\n", (uni?inter/uni:1)}'

# $(call MNEMS,binary,fn_name) -> one line: space-separated mnemonics.
MNEMS = objdump -d --no-show-raw-insn $(1) | awk -v fn="<$(2)>:" '/^[0-9a-f]+ <.*>:/{keep=$$0~fn} keep&&/^[ \t]+[0-9a-f]+:/{printf "%s ", $$2} END{print ""}'

BINS := $(B)/libcutil.so $(B)/libcutil_stripped.so $(B)/libcutil_O2.so \
        $(B)/libshapes.so $(B)/libshapes_stripped.so \
        $(B)/libmathkit.a $(B)/libmathkit_stripped.a $(B)/libmix.a \
        $(B)/c_util_stripped.o \
        $(B)/calc $(B)/calc_nopie $(B)/shapes_app.pie $(B)/shapes_app.nopie \
        $(B)/lto.o $(B)/foreign.so $(B)/big.so $(B)/truncated.so \
        $(B)/neg_a.so $(B)/neg_b.so

.PHONY: all gt manifest firewall clean
all: $(BINS) gt

# (build/ is a real directory target; gt/ is created by recipe mkdir,
# since `gt` is the phony ground-truth target itself.)
$(B):
	mkdir -p $@

### shared libraries / archives / objects ###############################

$(B)/libcutil.so: src/c_util.c | $(B)
	$(CC) -fPIC -O0 -g -shared -o $@ $<

$(B)/libcutil_stripped.so: $(B)/libcutil.so
	cp $< $@
	strip -s $@
	# .dynsym must survive: exported names still visible via nm -D
	@test $$(nm -D --defined-only $@ | grep -c 'config_init\|node_sum') -eq 2 \
	  || { echo "FAIL: stripped .so lost its exports"; exit 1; }

$(B)/libcutil_O2.so: src/c_util.c | $(B)
	$(CC) -fPIC -O2 -g -shared -o $@ $<

$(B)/libshapes.so: src/cpp_shapes.cpp src/cpp_shapes.h | $(B)
	$(CXX) -fPIC -O0 -g -shared -o $@ src/cpp_shapes.cpp

$(B)/libshapes_stripped.so: $(B)/libshapes.so
	cp $< $@
	strip -s $@
	@test $$(nm -D --defined-only $@ | grep -c 'total_area') -ge 1 \
	  || { echo "FAIL: stripped .so lost its exports"; exit 1; }

$(B)/mk_add.o: src/mathkit/mk_add.c | $(B)
	$(CC) -O0 -g -c $< -o $@
$(B)/mk_sub.o: src/mathkit/mk_sub.c | $(B)
	$(CC) -O0 -g -c $< -o $@
$(B)/mk_clamp.o: src/mathkit/mk_clamp.c | $(B)
	$(CC) -O0 -g -c $< -o $@
$(B)/mk_mul.o: src/mathkit/mk_mul.c | $(B)
	$(CC) -O0 -g -c $< -o $@

$(B)/libmathkit.a: $(B)/mk_add.o $(B)/mk_sub.o $(B)/mk_clamp.o $(B)/mk_mul.o
	ar rcs $@ $^

$(B)/libmathkit_stripped.a: $(B)/libmathkit.a
	cp $< $@
	strip --strip-unneeded $@

# Mixed archive for the T3 eval: 26 members — 6 renamed copies of each
# mathkit object (GNU ar rcs dedupes same basenames, hence the cp) plus two
# C++ members from cpp_shapes.cpp, one DEBUG (-O0 -g) and one stripped.
# Gives per-member tier/lang variety and >20 members.
$(B)/shapes_mix_dbg.o: src/cpp_shapes.cpp src/cpp_shapes.h | $(B)
	$(CXX) -fPIC -O0 -g -c src/cpp_shapes.cpp -o $@

$(B)/shapes_mix_str.o: $(B)/shapes_mix_dbg.o
	cp $< $@
	strip -s $@

$(B)/libmix.a: $(B)/mk_add.o $(B)/mk_sub.o $(B)/mk_clamp.o $(B)/mk_mul.o \
               $(B)/shapes_mix_dbg.o $(B)/shapes_mix_str.o
	@for m in mk_add mk_sub mk_clamp mk_mul; do \
	  for n in 1 2 3 4 5 6; do cp $(B)/$$m.o $(B)/mix_$${m}_$${n}.o; done; \
	done
	ar rcs $@ $(B)/mix_mk_*.o $(B)/shapes_mix_dbg.o $(B)/shapes_mix_str.o
	@test $$(ar t $@ | wc -l) -eq 26 \
	  || { echo "FAIL: libmix.a does not have 26 members"; exit 1; }

$(B)/c_util_stripped.o: src/c_util.c | $(B)
	$(CC) -fPIC -O0 -c $< -o $@
	strip -s $@
	# the nothing-survives case: a stripped .o has no symbols at all
	@test -z "$$(nm $@ 2>/dev/null || true)" \
	  || { echo "FAIL: c_util_stripped.o still has symbols"; exit 1; }

$(B)/lto.o: src/c_util.c | $(B)
	$(CC) -flto -O0 -g -c $< -o $@
	@readelf -SW $@ | grep -q '\.gnu\.lto_' \
	  || { echo "FAIL: lto.o has no .gnu.lto_* sections"; exit 1; }

### executables #########################################################

$(B)/calc: src/calc_main.c | $(B)
	$(CC) -O0 -g $< -o $@

$(B)/calc_nopie: src/calc_main.c | $(B)
	$(CC) -O0 -g -no-pie $< -o $@

$(B)/shapes_app.pie: src/cpp_shapes.cpp src/shapes_main.c src/cpp_shapes.h | $(B)
	$(CXX) -O0 -g src/cpp_shapes.cpp src/shapes_main.c -o $@

$(B)/shapes_app.nopie: src/cpp_shapes.cpp src/shapes_main.c src/cpp_shapes.h | $(B)
	$(CXX) -O0 -g -no-pie src/cpp_shapes.cpp src/shapes_main.c -o $@

### special fixtures ####################################################

# e_machine forgery: this binutils elfedit lacks -e and --output-mach only
# accepts x86 families, so patch the header byte directly (LE offset 18).
$(B)/foreign.so: $(B)/libcutil.so
	cp $< $@
	printf '\267' | dd of=$@ bs=1 seek=18 count=1 conv=notrunc
	@readelf -h $@ | grep -q 'Machine:.*AArch64' \
	  || { echo "FAIL: foreign.so header not AArch64"; exit 1; }

$(B)/big_src.c: tools/gen_big.sh | $(B)
	bash $< > $@

$(B)/big.so: $(B)/big_src.c
	$(CC) -fPIC -O2 -shared -o $@ $<
	@test $$(nm -D --defined-only $@ | grep -c 'big_fn_') -eq 2500 \
	  || { echo "FAIL: big.so does not export 2500 fns"; exit 1; }

$(B)/truncated.so: $(B)/libcutil.so
	head -c 3000 $< > $@

$(B)/neg_a.so: tools/gen_neg.sh | $(B)
	bash $< a > $(B)/neg_a.c
	$(CC) -O0 -fPIC -shared -w $(B)/neg_a.c -o $@

$(B)/neg_b.so: tools/gen_neg.sh | $(B)
	bash $< b > $(B)/neg_b.c
	$(CC) -O0 -fPIC -shared -w $(B)/neg_b.c -o $@

### ground truth ########################################################

# Negative control (V9): 50 same-instruction-count pairs must be scored
# as DISSIMILAR by the mnemonic-multiset Jaccard. Mean asserted < 0.4,
# per-pair values written to gt/neg-pairs.tsv (function_a, function_b,
# jaccard).
$(G)/neg-pairs.tsv: $(B)/neg_a.so $(B)/neg_b.so
	@mkdir -p $(G)
	@: > $@
	@for i in $$(seq -w 0 49); do \
	  ma=$$($(call MNEMS,$(B)/neg_a.so,f_$$i)); \
	  mb=$$($(call MNEMS,$(B)/neg_b.so,g_$$i)); \
	  j=$$(printf '%s\n%s\n' "$$ma" "$$mb" | $(JACCARD)); \
	  printf 'f_%s\tg_%s\t%s\n' "$$i" "$$i" "$$j" >> $@; \
	done
	@awk '!/^#/{s+=$$3;n++} END{printf "neg-pairs: %d pairs, mean Jaccard %.3f\n", n, s/n; exit !(n>=50 && s/n<0.4)}' $@

# nm dumps: -D for shared objects (dynsym), plain for static/artifacts.
# Archives: per-member union via `ar x` into a temp dir.
gt: $(BINS) $(G)/neg-pairs.tsv
	@mkdir -p $(G)
	@for b in libcutil.so libcutil_stripped.so libcutil_O2.so libshapes.so \
	           libshapes_stripped.so foreign.so big.so neg_a.so neg_b.so; do \
	  nm -D --defined-only $(B)/$$b | sort > $(G)/$$b.dynsyms.txt; \
	done
	@for b in calc calc_nopie shapes_app.pie shapes_app.nopie lto.o; do \
	  nm --defined-only $(B)/$$b | sort > $(G)/$$b.syms.txt; \
	done
	@: > $(G)/c_util_stripped.o.syms.txt
	@for a in libmathkit.a libmathkit_stripped.a libmix.a; do \
	  t=$$(mktemp -d); (cd $$t && ar x $(CURDIR)/$(B)/$$a && \
	    for m in *.o; do nm --defined-only $$m | awk 'NF>=2{print $$NF}'; done \
	    | sort -u) > $(G)/$$a.syms.txt; rm -rf $$t; \
	done

### provenance & firewall ###############################################

manifest: all
	@{ \
	  echo '# PROVENANCE — decompile skill eval fixtures'; \
	  echo ''; \
	  echo 'Generated by: make -C evals/fixtures manifest'; \
	  echo "Date: $$(date -u +%Y-%m-%dT%H:%MZ)"; \
	  echo ''; \
	  echo '## Tool versions'; \
	  echo ''; echo '```'; \
	  $(CC) --version | head -1; $(CXX) --version | head -1; \
	  clang --version | head -1 || true; \
	  readelf --version | head -1; \
	  java -version 2>&1 | head -1 || echo 'java: not found'; \
	  { ls $$HOME/ghidra/support/analyzeHeadless 2>/dev/null \
	    || ls $$HOME/tools/ghidra_*/support/analyzeHeadless 2>/dev/null \
	    || echo 'analyzeHeadless: not found'; } \
	    | sed "s|^$$HOME/|~/|"; \
	  echo '```'; \
	  echo ''; \
	  echo '## sha256: sources'; echo ''; echo '```'; \
	  find src tools Makefile -type f -print0 | sort -z | xargs -0 sha256sum; \
	  echo '```'; \
	  echo ''; \
	  echo '## sha256: built binaries'; echo ''; echo '```'; \
	  for b in $(sort $(BINS)); do sha256sum $$b; done; \
	  echo '```'; \
	} > ../PROVENANCE.md
	@echo "wrote ../PROVENANCE.md"

# Compatibility target: behavioral regressions replace keyword-based pseudo-validation.
firewall:
	python3 -m unittest discover -s $(SKILL_DIR)/evals -p 'test_*.py'

clean:
	rm -rf $(B) $(G) ../PROVENANCE.md
