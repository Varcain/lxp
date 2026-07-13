<!--
Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
SPDX-License-Identifier: GPL-3.0-or-later
-->
# lxp fuzz harnesses

Coverage-guided fuzzing for lxp's untrusted-input surfaces. Each harness is a standalone
executable exporting the engine-agnostic `LLVMFuzzerTestOneInput(const uint8_t*, size_t)`
entry, so the same code runs under **libFuzzer** (local, coverage-guided), **AFL++** (local,
CmpLog), and a **gcc replay `main()`** (CI corpus regression, no fuzzing engine). All builds
reuse the existing `-DLXP_SANITIZE=ON` ASan/UBSan flags.

## Targets

| Harness | Entry point | Notes |
|---|---|---|
| `fuzz_fdpic`   | `lxp_loader_load_fdpic` | FDPIC ELF loader (guest exec + netfs-exec path) |
| `fuzz_etrel`   | `lxp_loader_load`       | relocatable-object (ET_REL) loader |
| `fuzz_cpio`    | `lxp_cpio_to_rootfs`    | newc cpio initramfs parser |
| `fuzz_path`    | `resolve_path` + `lxp_rootfs_resolve` | path normalize + rootfs symlink follow |
| `fuzz_9p`      | `handle_reply` / `parse_getattr` | 9P2000.L reply parser (via the `LXP_FUZZ` shim) |
| `fuzz_syscall` | `lxp_syscall`           | syscall dispatcher — the `user_ok` pointer gate |

## Build & run

Everything is gated behind `-DLXP_BUILD_FUZZ=ON`; `LXP_FUZZ_ENGINE` picks the driver.

### libFuzzer (local, coverage-guided) — needs clang
```sh
cmake -S . -B build-fuzz -DLXP_BUILD_FUZZ=ON -DLXP_FUZZ_ENGINE=libfuzzer -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz -j"$(nproc)"
# fuzz one target; keep the committed corpus read-only by writing new units elsewhere:
mkdir -p work/fdpic
build-fuzz/fuzz/fuzz_fdpic -max_total_time=120 -dict=fuzz/dict/elf.dict work/fdpic fuzz/corpus/fdpic
```
Pass the *writable* work dir FIRST and the committed corpus as a later (seed) argument — libFuzzer
writes new units into the first dir only, so the curated `fuzz/corpus/**` stays clean.

### replay (CI regression) — gcc or clang, no fuzzing engine
```sh
cmake -S . -B build -DLXP_BUILD_FUZZ=ON -DLXP_FUZZ_ENGINE=replay -DLXP_SANITIZE=ON
cmake --build build -j"$(nproc)" --target fuzz_fdpic fuzz_etrel fuzz_cpio fuzz_path fuzz_9p fuzz_syscall
ctest --test-dir build -R _corpus --output-on-failure   # replays fuzz/corpus/** under ASan/UBSan
```
This is what the CI `fuzz` job runs (keeps CI clang-free).

### AFL++ (local, CmpLog) — for the stateful 9P/syscall targets
```sh
cmake -S . -B build-afl -DLXP_BUILD_FUZZ=ON -DLXP_FUZZ_ENGINE=afl \
      -DCMAKE_C_COMPILER=afl-clang-lto -DLXP_SANITIZE=ON
cmake --build build-afl -j"$(nproc)"
afl-fuzz -i fuzz/corpus/9p -o out -x fuzz/dict/9p.dict -- build-afl/fuzz/fuzz_9p @@   # + a `-c` CmpLog secondary
```

## Seeds

`fuzz/corpus/<target>/` holds a small **curated** seed set — do not commit evolved libFuzzer output
here. Regenerate the base seeds with `bash fuzz/tools/gen_seeds.sh`. `regress_*` seeds are minimized
reproducers for bugs the fuzzer found; they must stay green. `fuzz/dict/*.dict` are token
dictionaries (magic bytes) passed via `-dict=` / `-x`.

## Target-fidelity notes

lxp targets 32-bit ARMv7-M; fuzzing it as 64-bit host code needs a few adjustments so findings are
real target bugs, not host artifacts:

- **`fuzz_fdpic`** backs the image+region with **low-4-GiB (`MAP_32BIT`) guarded buffers**
  (`fuzz_lowbuf`): the FDPIC loadmap stores segment runtime addresses as `uint32`, so a truncated
  64-bit host pointer would be a spurious wild deref. A guard page one byte past
  `image_size`/`region_size` still faults a genuine OOB.
- **`fuzz_9p`** drives `handle_reply` through the `#ifdef LXP_FUZZ` shim in `src/netfs/lxp_netfs.c`
  (`lxp_netfs_fuzz_reset` + `lxp_netfs_fuzz_feed`) — the only gated hook in a shipping TU, inert in
  production (`LXP_FUZZ` is never defined outside this build).
- **`fuzz_syscall`** sets `region_lo/hi` to a real guest buffer so `user_ok` bounds derefs as
  on-target, and drops two UBSan sub-checks as target-benign C-standard pedantry: `alignment`
  (ARMv7-M does unaligned word LDR/STR in hardware) and `nonnull-attribute` (`memcpy(p,q,0)` is a
  no-op everywhere). ASan + the rest of UBSan still catch real corruption. It uses a
  non-terminating, non-blocking, per-proc-deterministic syscall allow-list.

## Findings (provenance)

The initial bring-up found and fixed **6 real bugs** (+ 2 target-benign UB classes handled), each
with a committed regression seed:

| Seed | Bug |
|---|---|
| `corpus/fdpic/regress_memset_underflow.elf` | `rw_span` uint32 overflow → ~4 GiB `memset` OOB write |
| `corpus/fdpic/regress_dynwalk_oob.elf`      | unbounded text `p_memsz` → OOB read in the dyn-table walk |
| `corpus/etrel/regress_symval_overflow.o`    | `lxp_loader_sym`: unbounded `st_value` → pointer-arith UB / wild address |
| `corpus/9p/regress_shortreply`              | `handle_reply`: truncated-reply reads past the declared body length |
| `corpus/syscall/regress_statx_path`         | `sys_statx`: `path[0]` dereferenced before `user_ok` |
| `corpus/syscall/regress_procfs_pidovf`      | `/proc/<pid>` decimal parse: signed int overflow |
