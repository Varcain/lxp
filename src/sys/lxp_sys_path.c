/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Path-name syscalls: open, stat, statx and statfs, readlink, access, directory and
 * link creation and removal, rename, chmod, utimensat, mount, getcwd and chdir. Each
 * resolves the path and routes it to the namespace that owns it.
 */
#include "sys/lxp_sys.h"
#include "fs/lxp_fd_private.h"
#include "fs/lxp_mount.h"
#include "fs/lxp_path.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_tmpfs.h"
#include "fs/lxp_vfs.h"
#include "lxp_guest.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"
#if LXP_ENABLE_FS
#include "fs/lxp_hostfs.h"
#endif

#include <string.h>

/* Linux mount flags which have meaningful or intrinsically satisfied semantics
 * in the bounded hostfs namespace. Unsupported flags are rejected explicitly. */
#define LXP_MS_RDONLY 0x00000001ul
#define LXP_MS_NOSUID 0x00000002ul
#define LXP_MS_NODEV 0x00000004ul
#define LXP_MS_NOEXEC 0x00000008ul
#define LXP_MS_REMOUNT 0x00000020ul
#define LXP_MS_NOATIME 0x00000400ul
#define LXP_MS_NODIRATIME 0x00000800ul
#define LXP_MS_SILENT 0x00008000ul
#define LXP_MS_RELATIME 0x00200000ul
#define LXP_MS_MGC_MSK 0xffff0000ul
#define LXP_MS_MGC_VAL 0xc0ed0000ul

static long sys_openat(lxp_proc_t *p, int dirfd, const char *path, int flags)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path_at(p, dirfd, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	return lxp_mount_of(p, abspath)->open(p, abspath, flags);
}

static long mount_copy_string(lxp_proc_t *p, const char *guest, char *out, size_t capacity)
{
	if (!guest) {
		out[0] = '\0';
		return 0;
	}
	size_t length = 0;
	return lxp_copy_string_from_guest(p, out, capacity, (uintptr_t)guest, &length);
}

#if LXP_ENABLE_FS && LXP_ENABLE_BLOCK
static int mount_type_supported(const char *type)
{
	return type[0] == '\0' || strcmp(type, "auto") == 0 || strcmp(type, "vfat") == 0 ||
	       strcmp(type, "msdos") == 0 || strcmp(type, "fat") == 0;
}

static long mount_parse_options(char *options, unsigned long *flags)
{
	char *cursor = options;
	while (*cursor) {
		char *option = cursor;
		char *comma = strchr(cursor, ',');
		if (comma) {
			*comma = '\0';
			cursor = comma + 1;
		} else {
			cursor += strlen(cursor);
		}
		if (option[0] == '\0' || strcmp(option, "defaults") == 0 ||
		    strcmp(option, "rw") == 0) {
			if (strcmp(option, "rw") == 0)
				*flags &= ~LXP_MS_RDONLY;
		} else if (strcmp(option, "ro") == 0) {
			*flags |= LXP_MS_RDONLY;
		} else if (strcmp(option, "nosuid") == 0) {
			*flags |= LXP_MS_NOSUID;
		} else if (strcmp(option, "nodev") == 0) {
			*flags |= LXP_MS_NODEV;
		} else if (strcmp(option, "noexec") == 0) {
			*flags |= LXP_MS_NOEXEC;
		} else if (strcmp(option, "noatime") == 0) {
			*flags |= LXP_MS_NOATIME;
		} else if (strcmp(option, "nodiratime") == 0) {
			*flags |= LXP_MS_NODIRATIME;
		} else if (strcmp(option, "relatime") == 0) {
			*flags |= LXP_MS_RELATIME;
		} else if (strcmp(option, "remount") == 0) {
			*flags |= LXP_MS_REMOUNT;
		} else {
			return -LXP_EOPNOTSUPP;
		}
	}
	return 0;
}

static int mount_target_is_dir(lxp_proc_t *p, const char *target)
{
	if (strcmp(target, LXP_HOSTFS_DEFAULT_MOUNT) == 0)
		return 1;
	int wi = wfs_find(target);
	if (wi >= 0)
		return (wnode_at(wi)->mode & LXP_S_IFMT) == LXP_S_IFDIR;
	int fi = fs_follow(p, fs_lookup(p, target));
	return fi >= 0 && (file_mode(&p->fs[fi]) & LXP_S_IFMT) == LXP_S_IFDIR;
}
#endif

static long sys_mount(lxp_proc_t *p, const char *source, const char *target,
		      const char *filesystem_type, unsigned long flags, const char *data)
{
	if (!target)
		return -LXP_EFAULT;
	char target_path[LXP_PATH_MAX];
	long rc = resolve_path(p, target, target_path, sizeof(target_path));
	if (rc < 0)
		return rc;
	if (strcmp(target_path, "/proc") == 0) {
		char type[16];
		rc = mount_copy_string(p, filesystem_type, type, sizeof(type));
		return rc < 0 ? rc
			      : (type[0] == '\0' || strcmp(type, "proc") == 0 ? 0 : -LXP_ENODEV);
	}
#if LXP_ENABLE_FS && LXP_ENABLE_BLOCK
	char type[16];
	char options[128];
	rc = mount_copy_string(p, filesystem_type, type, sizeof(type));
	if (rc < 0)
		return rc;
	rc = mount_copy_string(p, data, options, sizeof(options));
	if (rc < 0)
		return rc;
	if ((flags & LXP_MS_MGC_MSK) == LXP_MS_MGC_VAL)
		flags &= ~LXP_MS_MGC_MSK;
	rc = mount_parse_options(options, &flags);
	if (rc < 0)
		return rc;
	const unsigned long supported = LXP_MS_RDONLY | LXP_MS_NOSUID | LXP_MS_NODEV |
					LXP_MS_NOEXEC | LXP_MS_REMOUNT | LXP_MS_NOATIME |
					LXP_MS_NODIRATIME | LXP_MS_SILENT | LXP_MS_RELATIME;
	if ((flags & ~supported) != 0u)
		return -LXP_EOPNOTSUPP;
	if (!mount_type_supported(type))
		return -LXP_ENODEV;
	if ((flags & LXP_MS_REMOUNT) != 0u) {
		if (strcmp(target_path, lxp_hostfs_mount_path()) != 0)
			return -LXP_EINVAL;
		return lxp_hostfs_remount(p, (flags & LXP_MS_RDONLY) != 0u);
	}
	if (!source)
		return -LXP_EINVAL;
	if (lxp_mount_occupied(target_path))
		return -LXP_EBUSY; /* /proc, /dev and the netfs mount cannot be covered */
	if (strcmp(target_path, "/") == 0 || !mount_target_is_dir(p, target_path))
		return -LXP_ENOTDIR;
	char source_path[LXP_PATH_MAX];
	rc = resolve_path(p, source, source_path, sizeof(source_path));
	if (rc < 0)
		return rc;
	return lxp_hostfs_mount(p, source_path, target_path, (flags & LXP_MS_RDONLY) != 0u);
#else
	(void)source;
	(void)filesystem_type;
	(void)flags;
	(void)data;
#endif
	return -LXP_ENODEV;
}

static long sys_umount(lxp_proc_t *p, const char *target, int flags)
{
	if (!target)
		return -LXP_EFAULT;
	if (flags != 0)
		return -LXP_EOPNOTSUPP;
	char target_path[LXP_PATH_MAX];
	long rc = resolve_path(p, target, target_path, sizeof(target_path));
	if (rc < 0)
		return rc;
	if (strcmp(target_path, "/proc") == 0)
		return 0;
#if LXP_ENABLE_FS
	if (strcmp(target_path, lxp_hostfs_mount_path()) == 0)
		return lxp_hostfs_unmount(p, target_path);
#endif
	return -LXP_EINVAL;
}

/* The stat record of an open descriptor, for fstat64 and statx(AT_EMPTY_PATH). */
static long fd_stat(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_stat *st)
{
	const lxp_file_ops_t *ops = lxp_vfs_ops(s);
	if (ops && ops->fstat)
		return ops->fstat(p, s, st);
	/* console/pipe/eventfd: a bare character device (S_IFCHR) so isatty()/stdio behaves. */
	lxp_stat_init(st, LXP_INO_DEV + (uint32_t)s->file_idx, LXP_S_IFCHR | 0620u, 0);
	return 0;
}

static long sys_fstat64(lxp_proc_t *p, int fd, void *statbuf)
{
	lxp_ofd_t *s = lxp_fd_description(p, fd);
	if (!s)
		return -LXP_EBADF;
	if (!lxp_guest_access_ok(p, statbuf, sizeof(struct lxp_kstat64), 1))
		return -LXP_EFAULT;
	struct lxp_stat st;
	long rc = fd_stat(p, s, &st);
	return rc < 0 ? rc : lxp_stat_copyout(p, (uintptr_t)statbuf, 0, &st);
}

/* stat a resolved path into the guest's kstat64 (statx layout when @p statx) at @p buf,
 * by the mount that answers it; a mount that answers later parks the caller instead. */
static long path_stat(lxp_proc_t *p, const char *abspath, int follow, uintptr_t buf, int statx)
{
	const lxp_mount_ops_t *mount = lxp_mount_of(p, abspath);
	if (mount->stat_park)
		return mount->stat_park(p, abspath, buf, statx);
	struct lxp_stat st;
	long rc = mount->stat(p, abspath, follow, &st);
	return rc < 0 ? rc : lxp_stat_copyout(p, buf, statx, &st);
}

/* path-based stat: resolve, optionally follow a trailing symlink, fill kstat64. */
static long sys_stat_path(lxp_proc_t *p, int dirfd, const char *path, int follow,
			  void *statbuf)
{
	if (!lxp_guest_access_ok(p, statbuf, sizeof(struct lxp_kstat64), 1))
		return -LXP_EFAULT; /* path is validated by resolve_path below */
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path_at(p, dirfd, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	return path_stat(p, abspath, follow, (uintptr_t)statbuf, 0);
}

/* What a name change on a mount without that operation means. */
enum name_change {
	NAME_CREATE, /* mkdir, symlink */
	NAME_REMOVE, /* unlink, rmdir, rename, link */
	NAME_ATTR,   /* chmod, utimensat */
};

/* Where the mount can say whether the name exists, creating an existing name is EEXIST,
 * touching a missing one ENOENT and an attribute change is accepted, inert; anything
 * else is the mount's refusal (EPERM, or EROFS for a read-only mount). */
static long name_unsupported(lxp_proc_t *p, const lxp_mount_ops_t *m, const char *path,
			     enum name_change change)
{
	if (!m->stat)
		return -(long)m->name_errno;
	struct lxp_stat st;
	int exists = m->stat(p, path, 0, &st) == 0;
	if (change == NAME_CREATE)
		return exists ? -LXP_EEXIST : -(long)m->name_errno;
	if (!exists)
		return -LXP_ENOENT;
	return change == NAME_ATTR ? 0 : -(long)m->name_errno;
}

/* Resolve a guest path (relative to @p dirfd) into abspath[LXP_PATH_MAX]; *mount
 * answers it. */
static long resolve_in_mount(lxp_proc_t *p, int dirfd, const char *path, char *abspath,
			     const lxp_mount_ops_t **mount)
{
	if (!path)
		return -LXP_EFAULT;
	long rr = resolve_path_at(p, dirfd, path, abspath, LXP_PATH_MAX);
	if (rr < 0)
		return rr;
	*mount = lxp_mount_of(p, abspath);
	return 0;
}

/* readlink: write the symlink target (not NUL-terminated) + return its length. */
static long sys_readlink(lxp_proc_t *p, int dirfd, const char *path, char *buf, size_t bufsiz)
{
	if (!lxp_guest_access_ok(p, buf, bufsiz, 1))
		return -LXP_EFAULT; /* path is validated by resolve_path below */
	char abspath[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = resolve_in_mount(p, dirfd, path, abspath, &m);
	if (rr < 0)
		return rr;
	char target[LXP_PATH_MAX];
	size_t cap = bufsiz < sizeof(target) ? bufsiz : sizeof(target);
	long n;
	if (m->readlink) {
		n = m->readlink(p, abspath, target, cap);
	} else {
		/* A mount without symlinks: EINVAL for a name that exists. */
		struct lxp_stat st;
		n = m->stat && m->stat(p, abspath, 0, &st) < 0 ? -LXP_ENOENT : -LXP_EINVAL;
	}
	if (n < 0)
		return n;
	return lxp_copy_to_guest(p, (uintptr_t)buf, target, (size_t)n) != 0 ? -LXP_EFAULT : n;
}

/* access/faccessat: permissions are synthetic, but each mount says what it cannot do. */
static long sys_access(lxp_proc_t *p, int dirfd, const char *path, int mode)
{
	if ((mode & ~7) != 0)
		return -LXP_EINVAL;
	char abspath[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = resolve_in_mount(p, dirfd, path, abspath, &m);
	if (rr < 0)
		return rr;
	if (m->access)
		return m->access(p, abspath, mode);
	struct lxp_stat st;
	return m->stat(p, abspath, 1, &st);
}

static long sys_mkdir(lxp_proc_t *p, int dirfd, const char *path, uint32_t mode)
{
	char abspath[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = resolve_in_mount(p, dirfd, path, abspath, &m);
	if (rr < 0)
		return rr;
	return m->mkdir ? m->mkdir(p, abspath, mode) : name_unsupported(p, m, abspath, NAME_CREATE);
}

/* unlink (is_rmdir = 0) or rmdir (is_rmdir = 1). */
static long sys_unlink(lxp_proc_t *p, int dirfd, const char *path, int is_rmdir)
{
	char abspath[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = resolve_in_mount(p, dirfd, path, abspath, &m);
	if (rr < 0)
		return rr;
	return m->remove ? m->remove(p, abspath, is_rmdir)
			 : name_unsupported(p, m, abspath, NAME_REMOVE);
}

/* rename and link: resolve both names; a pair that spans two mounts is EXDEV. */
static long two_names(lxp_proc_t *p, int olddirfd, const char *oldp, int newdirfd,
		      const char *newp, char *oldabs, char *newabs, const lxp_mount_ops_t **m)
{
	const lxp_mount_ops_t *to;
	long rr = resolve_in_mount(p, olddirfd, oldp, oldabs, m);
	if (rr < 0)
		return rr;
	rr = resolve_in_mount(p, newdirfd, newp, newabs, &to);
	if (rr < 0)
		return rr;
	return *m == to ? 0 : -LXP_EXDEV;
}

static long sys_rename(lxp_proc_t *p, int olddirfd, const char *oldp, int newdirfd,
		       const char *newp, unsigned flags)
{
	char oldabs[LXP_PATH_MAX], newabs[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = two_names(p, olddirfd, oldp, newdirfd, newp, oldabs, newabs, &m);
	if (rr == 0 && flags != 0)
		rr = -LXP_EINVAL;
	if (rr < 0)
		return rr;
	return m->rename ? m->rename(p, oldabs, newabs)
			 : name_unsupported(p, m, oldabs, NAME_REMOVE);
}

static long sys_symlink(lxp_proc_t *p, const char *target, int dirfd, const char *linkp)
{
	if (!target)
		return -LXP_EFAULT;
	char tbuf[LXP_PATH_MAX]; /* the target is stored verbatim */
	size_t tl;
	if (lxp_copy_string_from_guest(p, tbuf, sizeof(tbuf), (uintptr_t)target, &tl) != 0)
		return -LXP_EFAULT;
	char linkabs[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = resolve_in_mount(p, dirfd, linkp, linkabs, &m);
	if (rr < 0)
		return rr;
	return m->symlink ? m->symlink(p, tbuf, tl, linkabs)
			  : name_unsupported(p, m, linkabs, NAME_CREATE);
}

static long sys_link(lxp_proc_t *p, int olddirfd, const char *oldp, int newdirfd,
		     const char *newp)
{
	char oldabs[LXP_PATH_MAX], newabs[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = two_names(p, olddirfd, oldp, newdirfd, newp, oldabs, newabs, &m);
	if (rr < 0)
		return rr;
	return m->link ? m->link(p, oldabs, newabs) : name_unsupported(p, m, oldabs, NAME_REMOVE);
}

static long sys_chmod(lxp_proc_t *p, int dirfd, const char *path, uint32_t mode)
{
	char abspath[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = resolve_in_mount(p, dirfd, path, abspath, &m);
	if (rr < 0)
		return rr;
	return m->chmod ? m->chmod(p, abspath, mode) : name_unsupported(p, m, abspath, NAME_ATTR);
}

static long sys_utimensat(lxp_proc_t *p, int dirfd, const char *path)
{
	if (!path) /* futimens(fd): operate on the open fd — accept */
		return 0;
	char abspath[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = resolve_in_mount(p, dirfd, path, abspath, &m);
	if (rr < 0)
		return rr;
	return m->utimens ? m->utimens(p, abspath) : name_unsupported(p, m, abspath, NAME_ATTR);
}

static void statfs_synthetic(struct lxp_statfs64 *st, uint32_t magic)
{
	memset(st, 0, sizeof(*st));
	st->f_type = magic;
	st->f_bsize = 4096;
	st->f_frsize = 4096;
	st->f_blocks = 256;
	st->f_bfree = 192;
	st->f_bavail = 192;
	st->f_files = 64;
	st->f_ffree = 48;
	st->f_namelen = 255;
}

static long statfs_copy(lxp_proc_t *p, size_t size, void *buf, const struct lxp_statfs64 *st)
{
	if (size < sizeof(*st))
		return -LXP_EINVAL;
	if (!lxp_guest_access_ok(p, buf, sizeof(*st), 1))
		return -LXP_EFAULT;
	return lxp_copy_to_guest(p, (uintptr_t)buf, st, sizeof(*st));
}

static long sys_statfs_path(lxp_proc_t *p, const char *path, size_t size, void *buf)
{
	if (!lxp_guest_access_ok(p, buf, sizeof(struct lxp_statfs64), 1))
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rc = resolve_in_mount(p, LXP_AT_FDCWD, path, abspath, &m);
	if (rc < 0)
		return rc;
	struct lxp_statfs64 st;
	if (m->statfs) {
		rc = m->statfs(p, abspath, &st);
	} else {
		struct lxp_stat unused;
		rc = m->stat ? m->stat(p, abspath, 1, &unused) : 0; /* the name must exist */
		statfs_synthetic(&st, m->magic);
	}
	return rc < 0 ? rc : statfs_copy(p, size, buf, &st);
}

static long sys_fstatfs(lxp_proc_t *p, int fd, size_t size, void *buf)
{
	if (!lxp_guest_access_ok(p, buf, sizeof(struct lxp_statfs64), 1))
		return -LXP_EFAULT;
	lxp_ofd_t *slot = lxp_fd_description(p, fd);
	if (!slot)
		return -LXP_EBADF;
	struct lxp_statfs64 st;
	const lxp_file_ops_t *ops = lxp_vfs_ops(slot);
	if (ops && ops->fstatfs) {
		long rc = ops->fstatfs(p, slot, &st);
		return rc < 0 ? rc : statfs_copy(p, size, buf, &st);
	}
	statfs_synthetic(&st, LXP_TMPFS_MAGIC);
	return statfs_copy(p, size, buf, &st);
}

/*
 * statx: the stat() uClibc-ng actually issues. With AT_EMPTY_PATH (or an empty
 * path) it stats the open dirfd (fstat); otherwise it resolves a rootfs path.
 */
static long sys_statx(lxp_proc_t *p, int dirfd, const char *path, int flags, void *buf)
{
	if (!lxp_guest_access_ok(p, buf, sizeof(struct lxp_statx), 1))
		return -LXP_EFAULT;
	/* An empty path (or AT_EMPTY_PATH) stats dirfd itself. */
	long plen = path ? lxp_guest_strnlen(p, path, LXP_PATH_MAX) : 0;
	if (plen < 0)
		return -LXP_EFAULT;
	if (plen > 0 && !(flags & LXP_AT_EMPTY_PATH)) {
		char abspath[LXP_PATH_MAX];
		long rr = resolve_path_at(p, dirfd, path, abspath, sizeof(abspath));
		if (rr < 0)
			return rr;
		return path_stat(p, abspath, !(flags & LXP_AT_SYMLINK_NOFOLLOW), (uintptr_t)buf, 1);
	}
	lxp_ofd_t *s = lxp_fd_description(p, dirfd);
	if (!s)
		return -LXP_EBADF;
	struct lxp_stat st;
	long rc = fd_stat(p, s, &st);
	return rc < 0 ? rc : lxp_stat_copyout(p, (uintptr_t)buf, 1, &st);
}

/* legacy open(path, flags, mode): dirfd = cwd */
long lxp_sys_open(lxp_proc_t *proc, const long a[6])
{
	return sys_openat(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], (int)a[1]);
}

long lxp_sys_openat(lxp_proc_t *proc, const long a[6])
{
	return sys_openat(proc, (int)a[0], (const char *)(uintptr_t)a[1], (int)a[2]);
}

long lxp_sys_fstat64(lxp_proc_t *proc, const long a[6])
{
	return sys_fstat64(proc, (int)a[0], (void *)(uintptr_t)a[1]);
}

/* (path, statbuf) — follows symlinks */
long lxp_sys_stat64(lxp_proc_t *proc, const long a[6])
{
	return sys_stat_path(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], 1,
			     (void *)(uintptr_t)a[1]);
}

/* (path, statbuf) — does NOT follow */
long lxp_sys_lstat64(lxp_proc_t *proc, const long a[6])
{
	return sys_stat_path(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], 0,
			     (void *)(uintptr_t)a[1]);
}

/* (dirfd, path, statbuf, flags) */
long lxp_sys_fstatat64(lxp_proc_t *proc, const long a[6])
{
	return sys_stat_path(proc, (int)a[0], (const char *)(uintptr_t)a[1],
			     !((int)a[3] & LXP_AT_SYMLINK_NOFOLLOW), (void *)(uintptr_t)a[2]);
}

/* (dirfd, path, flags, mask, buf); mask ignored */
long lxp_sys_statx(lxp_proc_t *proc, const long a[6])
{
	return sys_statx(proc, (int)a[0], (const char *)(uintptr_t)a[1], (int)a[2],
			 (void *)(uintptr_t)a[4]);
}

/* (path, buf, bufsiz) */
long lxp_sys_readlink(lxp_proc_t *proc, const long a[6])
{
	return sys_readlink(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0],
			    (char *)(uintptr_t)a[1], (size_t)a[2]);
}

/* (dirfd, path, buf, bufsiz) */
long lxp_sys_readlinkat(lxp_proc_t *proc, const long a[6])
{
	return sys_readlink(proc, (int)a[0], (const char *)(uintptr_t)a[1], (char *)(uintptr_t)a[2],
			    (size_t)a[3]);
}

/* (path, mode) */
long lxp_sys_access(lxp_proc_t *proc, const long a[6])
{
	return sys_access(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], (int)a[1]);
}

/* (dirfd, path, mode, flags) */
long lxp_sys_faccessat(lxp_proc_t *proc, const long a[6])
{
	return sys_access(proc, (int)a[0], (const char *)(uintptr_t)a[1], (int)a[2]);
}

/* (path, mode) */
long lxp_sys_mkdir(lxp_proc_t *proc, const long a[6])
{
	return sys_mkdir(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], (uint32_t)a[1]);
}

/* (dirfd, path, mode) */
long lxp_sys_mkdirat(lxp_proc_t *proc, const long a[6])
{
	return sys_mkdir(proc, (int)a[0], (const char *)(uintptr_t)a[1], (uint32_t)a[2]);
}

/* (path) */
long lxp_sys_rmdir(lxp_proc_t *proc, const long a[6])
{
	return sys_unlink(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], 1);
}

/* (path) */
long lxp_sys_unlink(lxp_proc_t *proc, const long a[6])
{
	return sys_unlink(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], 0);
}

/* (dirfd, path, flags) */
long lxp_sys_unlinkat(lxp_proc_t *proc, const long a[6])
{
	if (((int)a[2] & ~LXP_AT_REMOVEDIR) != 0)
		return -LXP_EINVAL;
	return sys_unlink(proc, (int)a[0], (const char *)(uintptr_t)a[1],
			  ((int)a[2] & LXP_AT_REMOVEDIR) ? 1 : 0);
}

/* (oldpath, newpath) */
long lxp_sys_rename(lxp_proc_t *proc, const long a[6])
{
	return sys_rename(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], LXP_AT_FDCWD,
			  (const char *)(uintptr_t)a[1], 0);
}

/* (olddirfd, old, newdirfd, new) */
long lxp_sys_renameat(lxp_proc_t *proc, const long a[6])
{
	return sys_rename(proc, (int)a[0], (const char *)(uintptr_t)a[1], (int)a[2],
			  (const char *)(uintptr_t)a[3], 0);
}

/* (olddirfd, old, newdirfd, new, flags) */
long lxp_sys_renameat2(lxp_proc_t *proc, const long a[6])
{
	return sys_rename(proc, (int)a[0], (const char *)(uintptr_t)a[1], (int)a[2],
			  (const char *)(uintptr_t)a[3], (unsigned)a[4]);
}

/* (target, linkpath) */
long lxp_sys_symlink(lxp_proc_t *proc, const long a[6])
{
	return sys_symlink(proc, (const char *)(uintptr_t)a[0], LXP_AT_FDCWD,
			   (const char *)(uintptr_t)a[1]);
}

/* (target, newdirfd, linkpath) */
long lxp_sys_symlinkat(lxp_proc_t *proc, const long a[6])
{
	return sys_symlink(proc, (const char *)(uintptr_t)a[0], (int)a[1],
			   (const char *)(uintptr_t)a[2]);
}

/* (oldpath, newpath) */
long lxp_sys_link(lxp_proc_t *proc, const long a[6])
{
	return sys_link(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], LXP_AT_FDCWD,
			(const char *)(uintptr_t)a[1]);
}

/* (olddirfd, oldpath, newdirfd, newpath, flags) */
long lxp_sys_linkat(lxp_proc_t *proc, const long a[6])
{
	return sys_link(proc, (int)a[0], (const char *)(uintptr_t)a[1], (int)a[2],
			(const char *)(uintptr_t)a[3]);
}

/* (path, mode) */
long lxp_sys_chmod(lxp_proc_t *proc, const long a[6])
{
	return sys_chmod(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], (uint32_t)a[1]);
}

/* (dirfd, path, mode) */
long lxp_sys_fchmodat(lxp_proc_t *proc, const long a[6])
{
	return sys_chmod(proc, (int)a[0], (const char *)(uintptr_t)a[1], (uint32_t)a[2]);
}

/* (dirfd, path, times, flags) — times not tracked; the time64 variant uClibc-ng issues
 * for touch */
long lxp_sys_utimensat(lxp_proc_t *proc, const long a[6])
{
	return sys_utimensat(proc, (int)a[0], (const char *)(uintptr_t)a[1]);
}

long lxp_sys_mount(lxp_proc_t *proc, const long a[6])
{
	return sys_mount(proc, (const char *)(uintptr_t)a[0], (const char *)(uintptr_t)a[1],
			 (const char *)(uintptr_t)a[2], (unsigned long)a[3],
			 (const char *)(uintptr_t)a[4]);
}

long lxp_sys_umount2(lxp_proc_t *proc, const long a[6])
{
	return sys_umount(proc, (const char *)(uintptr_t)a[0], (int)a[1]);
}

/* (path, sz, buf) */
long lxp_sys_statfs64(lxp_proc_t *proc, const long a[6])
{
	return sys_statfs_path(proc, (const char *)(uintptr_t)a[0], (size_t)a[1],
			       (void *)(uintptr_t)a[2]);
}

/* (fd, sz, buf) */
long lxp_sys_fstatfs64(lxp_proc_t *proc, const long a[6])
{
	return sys_fstatfs(proc, (int)a[0], (size_t)a[1], (void *)(uintptr_t)a[2]);
}

long lxp_sys_getcwd(lxp_proc_t *proc, const long a[6])
{
	/* getcwd(buf, size): write the cwd; the raw syscall returns the length
	 * including the NUL terminator. */
	char *buf = (char *)(uintptr_t)a[0];
	if (!buf)
		return -LXP_EFAULT;
	size_t len = strlen(proc->fs_context->cwd) + 1;
	if ((size_t)a[1] < len)
		return -LXP_ERANGE;
	if (lxp_copy_to_guest(proc, (uintptr_t)buf, proc->fs_context->cwd, len) != 0)
		return -LXP_EFAULT;
	return (long)len;
}

long lxp_sys_chdir(lxp_proc_t *proc, const long a[6])
{
	char abspath[LXP_PATH_MAX];
	const lxp_mount_ops_t *m;
	long rr = resolve_in_mount(proc, LXP_AT_FDCWD, (const char *)(uintptr_t)a[0], abspath, &m);
	if (rr < 0)
		return rr;
	if (m->chdir)
		return m->chdir(proc, abspath);
	struct lxp_stat st;
	long rc = m->stat(proc, abspath, 1, &st);
	if (rc < 0)
		return rc;
	if ((st.mode & LXP_S_IFMT) != LXP_S_IFDIR)
		return -LXP_ENOTDIR;
	strcpy(proc->fs_context->cwd, abspath);
	return 0;
}
