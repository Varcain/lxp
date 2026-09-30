# Extending lxp

Recipes for the four common extensions. Each lists the files to touch and the check that fails
if a step is missed. Read [architecture.md](architecture.md) first for the layers these fit
into. To support another RTOS, see [porting.md](porting.md).

## A syscall

1. **Number.** Add `#define LXP_NR_<name> <number>` to `src/lxp_linux_uapi.h`, using the ARM EABI
   number from `scripts/syscalls/arm-eabi.tbl`.
2. **Handler.** Write `long lxp_sys_<name>(lxp_proc_t *proc, const long a[6])` in the
   `src/sys/lxp_sys_<area>.c` it belongs to, and declare it in `src/sys/lxp_sys.h`. It returns
   the result or a negated errno. Reach guest memory only through the copy helpers
   (`lxp_copy_from_guest`, `lxp_copy_to_guest`, `lxp_guest_strnlen`).
3. **Table row.** Add `[LXP_NR_<name>] = {lxp_sys_<name>, flags}` to `g_lxp_sys_table` in
   `src/lxp_syscall.c`. Flags:
   - `LXP_SYS_FAST`: the trap may answer it inline. Only for calls that never block, never
     touch a provider and finish in bounded time.
   - `LXP_SYS_QUIET_ENOSYS`: an `-ENOSYS` result is expected (a program probing for a feature)
     and is not reported to the host's `on_enosys` hook.
   - `0` for everything else.
4. **Disposition.** Add a row to `scripts/syscalls/dispositions.tsv`: `implemented`,
   `benign-stub` (a fixed, inert answer on purpose), `refused-eopnotsupp`, `run-loop-handled`
   or `deliberately-enosys`. `docs/syscall-compat.md` is generated from this file.
5. **Test.** Cover it in `tests/suites/test_syscall_conformance.c` (or the suite of its area),
   including the error paths a guest can reach.

`scripts/syscalls/check-syscalls.sh` fails if a number has no disposition, or if a disposition
does not match the table. `scripts/check-guest-memory.sh` fails on a raw guest-pointer access.

A call that must wait for a provider parks the process with `lxp_wait_park()` and supplies a
retry that re-runs the same operation; see the pipe and socket handlers for the pattern.

## A file descriptor kind

1. **Kind.** Add `#define LXP_FD_<KIND> <n>` to `src/proc/lxp_proc.h`. If it becomes the highest
   kind, update `LXP_FD_KIND_COUNT` in `src/fs/lxp_vfs.h`.
2. **Operations.** In the subsystem that owns the kind, define
   `const lxp_file_ops_t lxp_<kind>_fops` (`src/fs/lxp_vfs.h`). Fill only the operations the
   kind supports; every `NULL` slot has a documented default (a stream has no `pread`, so it
   answers `-ESPIPE`; a non-directory has no `getdents`, so it answers `-ENOTDIR`; and so on).
3. **Table.** Point `g_lxp_file_ops[LXP_FD_<KIND>]` at it in `src/fs/lxp_vfs.c`, under the kind's
   feature gate if it has one.
4. **Opening.** Create descriptors with `lxp_fd_open()` / `lxp_fd_install()`, passing the open
   flags, so the access mode, `O_NONBLOCK` and `O_CLOEXEC` are recorded and enforced generically.
5. **Readiness.** If `poll(2)` must wait on the kind, give it a `poll` operation and a wait class
   the blocked-wait scan can retry.

## A device

1. **Driver.** Write a class driver in `src/dev/lxp_dev_<class>.c`: a `struct lxp_dev_ops`
   (`open`, `release`, `read`, `write`, `ioctl`, `poll`, each optional) and an
   `lxp_dev_autoreg_<class>()` that calls `lxp_dev_register()` with a `struct lxp_dev` (node
   path, operations, Linux major and minor, size if seekable). A read or write that cannot
   complete yet returns `-EAGAIN`; the device layer parks and retries it.
2. **Registration.** Call the autoreg from `lxp_dev_autoreg_all()` in `src/dev/lxp_dev.c`, under
   the device's feature gate. A driver that needs the host's hardware reaches it through a
   provider table (e.g. `lxp_display_ops_t`), never a native API.
3. **Gate.** For a new optional device:
   - add a row to `cmake/lxp_features.cmake` (name, owner `DEV`, description);
   - add its default and its `#error` owner rule to `include/lxp/lxp_config.h`;
   - add a source group `LXP_<GATE>_SOURCES` to `cmake/lxp_sources.cmake` and list it in
     `LXP_OPTIONAL_SOURCES`;
   - enable it in CI's `all` gate leg, and give it a leg of its own if it can be built alone.

   `scripts/check-features.sh` fails until the table, `lxp_config.h` and CI agree, and the
   source inventory fails configuration while the new file is unclassified.
4. **Guest ABI.** If guests call LXP-specific ioctls, put the command numbers and structures in
   `include/uapi/lxp/`, where `scripts/check-header-contract.sh` holds them to plain C99.

## A mount backend

1. **Operations.** Define a `const lxp_mount_ops_t` (`src/fs/lxp_mount.h`): `open` and `stat` at
   least, plus the name changes and lookups the namespace supports. For a `NULL` name change
   the caller still answers `EEXIST` or `ENOENT` from `stat`, accepts an attribute change as
   inert, and otherwise refuses with the mount's `name_errno` (`EPERM`, or `EROFS` for a
   read-only namespace). `readlink` and `access` have documented defaults too.
2. **Table entry.** Add `{<mountpoint function>, &<ops>}` to `g_mounts[]` in
   `src/fs/lxp_mount.c`, under its feature gate. The mountpoint function returns the current
   mountpoint, or `NULL` while the namespace is not mounted. A path belongs to the mount with
   the longest mountpoint above it.
3. **Descriptors.** Files the backend opens need a descriptor kind (see above).
4. **Tests.** Add the backend's rows to the golden routing matrix in
   `tests/suites/test_path_routing.c`, which checks every path syscall against every mount.
