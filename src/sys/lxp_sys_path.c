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
#include "fs/lxp_path.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_tmpfs.h"
#include "fs/lxp_vfs.h"
#include "lxp_guest.h"
#include "lxp_internal.h"
#include "lxp_linux_uapi.h"
#include "lxp_text.h"
#include "proc/lxp_procfs.h"
#if LXP_ENABLE_DEV
#include "dev/lxp_dev.h"
#endif
#if LXP_ENABLE_FS
#include "fs/lxp_hostfs.h"
#endif
#if LXP_ENABLE_NETFS
#include "netfs/lxp_netfs.h"
#endif
#if LXP_ENABLE_PTY
#include "pty/lxp_pty.h"
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

enum lxp_path_stat_result {
	LXP_PATH_STAT_LOCAL,
	LXP_PATH_STAT_NETFS,
};


static long sys_openat(lxp_proc_t *p, int dirfd, const char *path, int flags)
{
	(void)dirfd; /* dirfd is AT_FDCWD; relative paths resolve against p->fs_context->cwd */
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	path = abspath;
	if (proc_is(path)) /* synthetic /proc shadows everything */
		return lxp_procfs_open(p, path, flags);
#if LXP_ENABLE_FS
	/* The mount boundary is exact: /data and descendants route to the host
	 * provider, while /database remains part of the ordinary rootfs/tmpfs. */
	if (lxp_hostfs_match(path)) {
		long hi = lxp_hostfs_open(p, path, flags);
		if (hi < 0)
			return hi;
		int fd = lxp_sys_fd_alloc(p, LXP_FD_HOSTFS, (int)hi, 0, flags);
		if (fd < 0)
			lxp_hostfs_close((int)hi);
		return fd;
	}
#endif
	/* The synthetic console/null/random nodes all open as an FD_CONSOLE; file_idx selects
	 * the behaviour (2 = r/w console, 3 = /dev/null → EOF/discard, 4 = host entropy,
	 * 5 = /dev/zero → zero-fill/discard). A small name→idx table instead of a strcmp chain
	 * (smaller .text). getty opens /dev/console + dups it to fds 0/1/2; dropbear/mbedTLS open
	 * /dev/urandom for entropy. */
	static const struct {
		const char *path;
		uint8_t idx;
	} console_dev[] = {
		{"/dev/console", 2}, {"/dev/tty", 2},	  {"/dev/tty0", 2},   {"/dev/ttyS0", 2},
		{"/dev/null", 3},    {"/dev/urandom", 4}, {"/dev/random", 4}, {"/dev/zero", 5},
	};
	for (size_t k = 0; k < sizeof(console_dev) / sizeof(console_dev[0]); k++)
		if (strcmp(path, console_dev[k].path) == 0)
			return lxp_sys_fd_alloc(p, LXP_FD_CONSOLE, console_dev[k].idx, 0, flags);
#if LXP_ENABLE_PTY
	/* Unix98 pty: each open of /dev/ptmx mints a fresh pair (the master, rw=1); the
	 * slave is /dev/pts/N (rw=0), N = the pool index from TIOCGPTN/ptsname. */
	if (strcmp(path, "/dev/ptmx") == 0) {
		long idx = lxp_pty_open_master(flags);
		if (idx < 0)
			return idx;
		int fd = lxp_sys_fd_alloc(p, LXP_FD_PTY, (int)idx, 0, flags);
		if (fd >= 0) {
			(void)lxp_fd_set_end(p, fd, 1); /* master end */
			lxp_pty_end_open((int)idx, 1);
		} else {
			lxp_pty_discard((int)idx);
		}
		return fd;
	}
	if (strncmp(path, "/dev/pts/", 9) == 0) {
		int num = 0;
		const char *d = path + 9;
		if (*d < '0' || *d > '9')
			return -LXP_ENOENT;
		for (; *d >= '0' && *d <= '9'; d++)
			num = num * 10 + (*d - '0');
		if (*d != '\0')
			return -LXP_ENOENT;
		long idx = lxp_pty_open_slave(num, flags);
		if (idx < 0)
			return idx;
		int fd = lxp_sys_fd_alloc(p, LXP_FD_PTY, (int)idx, 0, flags); /* slave end (rw=0) */
		if (fd >= 0)
			lxp_pty_end_open((int)idx, 0);
		return fd;
	}
#endif
#if LXP_ENABLE_DEV
	/* Registered character devices (/dev/fb0, /dev/input/event0, ...). A hit opens
	 * an FD_DEV whose file_idx is the device open-pool index; a miss falls through. */
	{
		int di = lxp_dev_lookup(path);
		if (di >= 0) {
			long oi = lxp_dev_open_new(p, di, flags);
			if (oi < 0)
				return oi;
			int fd = lxp_sys_fd_alloc(p, LXP_FD_DEV, (int)oi, 0, flags);
			if (fd < 0)
				lxp_dev_close((int)oi);
			return fd;
		}
	}
#endif
#if LXP_ENABLE_NETFS
	/* Remote 9P mount (/mnt/pi): read-only browse. Shadows the RO rootfs; the open
	 * parks (walk+getattr+lopen round-trips) and the coordinator installs the fd. */
	if (lxp_netfs_lookup(path) >= 0)
		return lxp_netfs_open(p, path, flags);
#endif
	int wr = (flags & LXP_O_ACCMODE) != LXP_O_RDONLY;
	int wi = wfs_find(path);

	/* A writable open (or O_CREAT) goes to the writable VFS overlay. */
	if (wr || (flags & LXP_O_CREAT)) {
		if (wi < 0) {
			if (!(flags & LXP_O_CREAT)) {
				if (fs_lookup(p, path) >= 0)
					return -LXP_EROFS; /* RO rootfs file */
				return -LXP_ENOENT;
			}
			wi = wfs_create(path, LXP_S_IFREG | 0644u);
			if (wi < 0)
				return -LXP_EMFILE;
		} else {
			if ((wnode_at(wi)->mode & LXP_S_IFMT) == LXP_S_IFDIR)
				return -LXP_EISDIR;
			if (flags & LXP_O_TRUNC)
				wnode_at(wi)->size = 0;
		}
		return lxp_sys_fd_alloc(p, LXP_FD_TMPFS, wi, (flags & LXP_O_APPEND) ? wnode_at(wi)->size : 0,
				flags);
	}

	/* Read: a writable node shadows the rootfs; else the read-only rootfs. */
	if (wi >= 0)
		return lxp_sys_fd_alloc(p, LXP_FD_TMPFS, wi, 0, flags);
	/* Follow symlinks so a read open of e.g. /lib/libc.so.0 -> libuClibc.so returns the
	 * target ELF (ld.so opens its .so deps by their symlinked SONAMEs). */
	int idx = fs_follow(p, fs_lookup(p, path));
	if (idx >= 0)
		return lxp_sys_fd_alloc(p, LXP_FD_FILE, idx, 0, flags);
	return -LXP_ENOENT;
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

/* Resolve all local pathname namespaces in their authoritative precedence.
 * Remote 9P metadata retains its asynchronous guest-buffer path, so identify
 * that boundary without duplicating the rest of the lookup ladder. */
static long path_stat_lookup(lxp_proc_t *p, const char *abspath, int follow,
			     struct lxp_stat *out)
{
	lxp_stat_init(out, 0, 0, 0);
	if (proc_is(abspath)) {
		out->mode = proc_mode(abspath, p);
		if (out->mode == 0)
			return -LXP_ENOENT;
		out->ino = lxp_procfs_inode(abspath);
		return LXP_PATH_STAT_LOCAL;
	}
#if LXP_ENABLE_DEV
	int di = lxp_dev_stat_path(abspath, &out->mode, &out->rdev);
	if (di >= 0) {
		out->ino = LXP_INO_DEV + (uint32_t)di;
		return LXP_PATH_STAT_LOCAL;
	}
#endif
#if LXP_ENABLE_NETFS
	if (lxp_netfs_lookup(abspath) >= 0)
		return LXP_PATH_STAT_NETFS;
#endif
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		lxp_fs_stat_t stat;
		long rc = lxp_hostfs_path_stat(p, abspath, &stat);
		if (rc < 0)
			return rc;
		lxp_hostfs_stat_record(out, lxp_hostfs_path_inode(abspath), &stat);
		return LXP_PATH_STAT_LOCAL;
	}
#endif
	int index = wfs_find(abspath);
	if (index >= 0) {
		lxp_stat_init(out, LXP_INO_TMPFS + (uint32_t)index, wnode_at(index)->mode,
			      wnode_at(index)->size);
		return LXP_PATH_STAT_LOCAL;
	}
	index = fs_lookup(p, abspath);
	if (index < 0)
		return -LXP_ENOENT;
	if (follow) {
		index = fs_follow(p, index);
		if (index < 0)
			return -LXP_ENOENT;
	}
	lxp_stat_init(out, LXP_INO_ROOTFS + (uint32_t)index, file_mode(&p->fs[index]),
		      p->fs[index].size);
	return LXP_PATH_STAT_LOCAL;
}

/* path-based stat: resolve, optionally follow a trailing symlink, fill kstat64. */
static long sys_stat_path(lxp_proc_t *p, const char *path, int follow, void *statbuf)
{
	if (!lxp_guest_access_ok(p, statbuf, sizeof(struct lxp_kstat64), 1))
		return -LXP_EFAULT; /* path is validated by resolve_path below */
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	struct lxp_stat stat;
	long source = path_stat_lookup(p, abspath, follow, &stat);
#if LXP_ENABLE_NETFS
	if (source == LXP_PATH_STAT_NETFS)
		return lxp_netfs_stat(p, abspath, (uintptr_t)statbuf, 0); /* parks */
#endif
	if (source < 0)
		return source;
	return lxp_stat_copyout(p, (uintptr_t)statbuf, 0, &stat);
}

/* readlink: write the symlink target (not NUL-terminated) + return its length. */
static long sys_readlink(lxp_proc_t *p, const char *path, char *buf, size_t bufsiz)
{
	if (!lxp_guest_access_ok(p, buf, bufsiz, 1))
		return -LXP_EFAULT; /* path is validated by resolve_path below */
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if (strcmp(abspath, "/proc/self") == 0) { /* -> the running process's pid */
		char tmp[12];
		lxp_text_t pid_text = lxp_text_make(tmp, sizeof(tmp));
		lxp_text_u64(&pid_text, (uint64_t)p->pid);
		size_t n = pid_text.length;
		if (n > bufsiz)
			n = bufsiz;
		if (lxp_copy_to_guest(p, (uintptr_t)buf, tmp, n) != 0)
			return -LXP_EFAULT;
		return (long)n;
	}
	if (strcmp(abspath, "/proc/self/exe") == 0) { /* -> the running program's path */
		/* Same running image execve re-runs for "/proc/self/exe" (exec_file_idx). Programs
		 * readlink() this to learn where they were launched from; without it they got ENOENT. */
		int ei = p->exec_file_idx;
		if (ei < 0 || ei >= p->fs_count)
			return -LXP_ENOENT;
		const char *exe = p->fs[ei].path;
		size_t n = strlen(exe);
		if (n > bufsiz)
			n = bufsiz;
		if (lxp_copy_to_guest(p, (uintptr_t)buf, exe, n) != 0)
			return -LXP_EFAULT;
		return (long)n;
	}
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath))
		return -LXP_EINVAL; /* The FAT-backed provider cannot contain symlinks. */
#endif
	int wi = wfs_find(abspath); /* a writable symlink (ln -s) shadows the rootfs */
	if (wi >= 0) {
		lxp_wnode_t *w = wnode_at(wi);
		if ((w->mode & LXP_S_IFMT) != LXP_S_IFLNK || !w->data)
			return -LXP_EINVAL;
		size_t n = w->size > bufsiz ? bufsiz : w->size;
		if (lxp_copy_to_guest(p, (uintptr_t)buf, w->data, n) != 0)
			return -LXP_EFAULT;
		return (long)n;
	}
	int idx = fs_lookup(p, abspath);
	if (idx < 0)
		return -LXP_ENOENT;
	const lxp_file_t *lnk = &p->fs[idx];
	if ((file_mode(lnk) & LXP_S_IFMT) != LXP_S_IFLNK || !lnk->data)
		return -LXP_EINVAL;
	size_t n = lnk->size > bufsiz ? bufsiz : lnk->size;
	if (lxp_copy_to_guest(p, (uintptr_t)buf, lnk->data, n) != 0)
		return -LXP_EFAULT;
	return (long)n;
}

/* access/faccessat: permissions are synthetic, but read-only/noexec hostfs
 * policy must not claim that an operation can succeed when it cannot. */
static long sys_access(lxp_proc_t *p, const char *path, int mode)
{
	if (!path)
		return -LXP_EFAULT;
	if ((mode & ~7) != 0)
		return -LXP_EINVAL;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
	if (abspath[0] == '/' && abspath[1] == '\0')
		return 0; /* root */
	if (proc_is(abspath))
		return proc_mode(abspath, p) ? 0 : -LXP_ENOENT;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		lxp_fs_stat_t stat;
		long result = lxp_hostfs_path_stat(p, abspath, &stat);
		if (result < 0)
			return result;
		if ((mode & 2) != 0 && lxp_hostfs_is_read_only())
			return -LXP_EROFS;
		if ((mode & 1) != 0 && stat.type != LXP_FS_TYPE_DIR)
			return -LXP_EACCES;
		return 0;
	}
#endif
	if (wfs_find(abspath) >= 0 || fs_lookup(p, abspath) >= 0)
		return 0;
	return -LXP_ENOENT;
}

static long sys_mkdir(lxp_proc_t *p, const char *path, uint32_t mode)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath))
		return lxp_hostfs_mkdir(p, abspath);
#endif
	if (wfs_find(abspath) >= 0 || fs_lookup(p, abspath) >= 0)
		return -LXP_EEXIST;
	if (wfs_create(abspath, LXP_S_IFDIR | (mode & 0777u)) < 0)
		return -LXP_ENOSPC;
	return 0;
}

/* unlink (is_rmdir=0) / rmdir (is_rmdir=1) on a writable node. */
static long sys_unlink(lxp_proc_t *p, const char *path, int is_rmdir)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath))
		return is_rmdir ? lxp_hostfs_rmdir(p, abspath) : lxp_hostfs_unlink(p, abspath);
#endif
	int wi = wfs_find(abspath);
	if (wi < 0)
		return (fs_lookup(p, abspath) >= 0) ? -LXP_EROFS : -LXP_ENOENT;
	int isdir = (wnode_at(wi)->mode & LXP_S_IFMT) == LXP_S_IFDIR;
	if (is_rmdir && !isdir)
		return -LXP_ENOTDIR;
	if (!is_rmdir && isdir)
		return -LXP_EISDIR;
	if (isdir) {
		for (int j = 0; j < LXP_NWNODE; j++)
			if (wnode_at(j)->used && lxp_path_child_name(abspath, wnode_at(j)->path))
				return -LXP_ENOTEMPTY;
	}
	wfs_free(wi); /* reclaim the node + its pool bytes */
	return 0;
}

static long sys_rename(lxp_proc_t *p, const char *oldp, const char *newp, unsigned flags)
{
	if (!oldp || !newp)
		return -LXP_EFAULT;
	char oldabs[LXP_PATH_MAX], newabs[LXP_PATH_MAX];
	long r1 = resolve_path(p, oldp, oldabs, sizeof(oldabs));
	if (r1 < 0)
		return r1;
	long r2 = resolve_path(p, newp, newabs, sizeof(newabs));
	if (r2 < 0)
		return r2;
	if (flags != 0)
		return -LXP_EINVAL;
#if LXP_ENABLE_FS
	int old_host = lxp_hostfs_match(oldabs);
	int new_host = lxp_hostfs_match(newabs);
	if (old_host != new_host)
		return -LXP_EXDEV;
	if (old_host)
		return lxp_hostfs_rename(p, oldabs, newabs);
#endif
	int wi = wfs_find(oldabs);
	if (wi < 0)
		return (fs_lookup(p, oldabs) >= 0) ? -LXP_EROFS : -LXP_ENOENT;
	if (strlen(newabs) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	int di = wfs_find(newabs); /* replace an existing destination node */
	if (di >= 0 && di != wi)
		wfs_free(di); /* reclaim the replaced destination's bytes */
	strcpy(wnode_at(wi)->path, newabs);
	return 0;
}

static long sys_symlink(lxp_proc_t *p, const char *target, const char *linkp)
{
	if (!target || !linkp)
		return -LXP_EFAULT;
	char tbuf[LXP_PATH_MAX]; /* the target is stored verbatim */
	size_t tl;
	if (lxp_copy_string_from_guest(p, tbuf, sizeof(tbuf), (uintptr_t)target, &tl) != 0)
		return -LXP_EFAULT;
	char linkabs[LXP_PATH_MAX];
	long rr = resolve_path(p, linkp, linkabs, sizeof(linkabs));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(linkabs))
		return -LXP_EOPNOTSUPP; /* FAT provider contract has no symlink primitive. */
#endif
	if (wfs_find(linkabs) >= 0 || fs_lookup(p, linkabs) >= 0)
		return -LXP_EEXIST;
	int wi = wfs_create(linkabs, LXP_S_IFLNK | 0777u);
	if (wi < 0)
		return -LXP_ENOSPC;
	if (wfs_reserve(wi, tl) < 0) {
		wfs_free(wi); /* roll back the just-created node (its data is still NULL) */
		return -LXP_ENOSPC;
	}
	memcpy(wnode_at(wi)->data, tbuf, tl);
	wnode_at(wi)->size = tl;
	return 0;
}

/*
 * link(oldpath, newpath): make newpath name oldpath's file.
 *
 * The writable overlay has no shared-inode / link-count model (st_nlink is always
 * reported as 1), so a true hard link is not representable. We satisfy the call by
 * creating newpath as an independent writable copy of oldpath's current bytes — enough
 * for the only realistic uses on this read-only-rootfs target: `ln a b`, and the
 * write-temp / link / unlink-temp atomic-replace idiom (dropbear host-key generation,
 * mkstemp-based writers, editors). oldpath may live in the RO rootfs or the overlay;
 * directories are rejected with EPERM, matching Linux. The final path component is not
 * dereferenced — link() does not follow a symlink at oldpath.
 */
static long sys_link(lxp_proc_t *p, const char *oldp, const char *newp)
{
	if (!oldp || !newp)
		return -LXP_EFAULT;
	char oldabs[LXP_PATH_MAX], newabs[LXP_PATH_MAX];
	long r1 = resolve_path(p, oldp, oldabs, sizeof(oldabs));
	if (r1 < 0)
		return r1;
	long r2 = resolve_path(p, newp, newabs, sizeof(newabs));
	if (r2 < 0)
		return r2;
#if LXP_ENABLE_FS
	int old_host = lxp_hostfs_match(oldabs);
	int new_host = lxp_hostfs_match(newabs);
	if (old_host != new_host)
		return -LXP_EXDEV;
	if (old_host)
		return -LXP_EOPNOTSUPP; /* Host provider intentionally exposes no hard links. */
#endif
	if (strlen(newabs) >= LXP_PATH_MAX)
		return -LXP_ENAMETOOLONG;
	if (wfs_find(newabs) >= 0 || fs_lookup(p, newabs) >= 0)
		return -LXP_EEXIST;

	/* Source bytes: writable overlay first, then the RO rootfs. */
	const uint8_t *src;
	size_t srclen;
	uint32_t srcmode;
	int wi = wfs_find(oldabs);
	if (wi >= 0) {
		src = wnode_at(wi)->data;
		srclen = wnode_at(wi)->size;
		srcmode = wnode_at(wi)->mode;
	} else {
		int idx = fs_lookup(p, oldabs);
		if (idx < 0)
			return -LXP_ENOENT;
		src = p->fs[idx].data;
		srclen = p->fs[idx].size;
		srcmode = file_mode(&p->fs[idx]);
	}
	if ((srcmode & LXP_S_IFMT) == LXP_S_IFDIR)
		return -LXP_EPERM; /* hard links to directories are not permitted */

	int ni = wfs_create(newabs, LXP_S_IFREG | (srcmode & 0777u));
	if (ni < 0)
		return -LXP_ENOSPC;
	if (srclen > 0) {
		if (wfs_reserve(ni, srclen) < 0) {
			wfs_free(ni); /* roll back the just-created node (its data is still NULL) */
			return -LXP_ENOSPC;
		}
		memcpy(wnode_at(ni)->data, src,
		       srclen); /* the arena never moves the source block */
		wnode_at(ni)->size = srclen;
	}
	return 0;
}

static long sys_chmod(lxp_proc_t *p, const char *path, uint32_t mode)
{
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		lxp_fs_stat_t stat;
		if (lxp_hostfs_is_read_only())
			return -LXP_EROFS;
		return lxp_hostfs_path_stat(p, abspath, &stat); /* FAT mode bits are inert. */
	}
#endif
	int wi = wfs_find(abspath);
	if (wi >= 0) {
		wnode_at(wi)->mode = (wnode_at(wi)->mode & LXP_S_IFMT) | (mode & 0777u);
		return 0;
	}
	return (fs_lookup(p, abspath) >= 0) ? 0 : -LXP_ENOENT; /* rootfs: accept, inert */
}

/* utimensat: times are not tracked, but the existence check must be honest —
 * `touch` probes with utimensat first and only creates the file on -ENOENT. */
static long sys_utimensat(lxp_proc_t *p, const char *path)
{
	if (!path) /* futimens(fd): operate on the open fd — accept */
		return 0;
	char abspath[LXP_PATH_MAX];
	long rr = resolve_path(p, path, abspath, sizeof(abspath));
	if (rr < 0)
		return rr;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		lxp_fs_stat_t stat;
		if (lxp_hostfs_is_read_only())
			return -LXP_EROFS;
		return lxp_hostfs_path_stat(p, abspath,
					    &stat); /* Provider does not expose timestamps. */
	}
#endif
	if ((abspath[0] == '/' && abspath[1] == '\0') || wfs_find(abspath) >= 0 ||
	    fs_lookup(p, abspath) >= 0)
		return 0;
	return -LXP_ENOENT;
}

static void statfs_synthetic(struct lxp_statfs64 *st)
{
	memset(st, 0, sizeof(*st));
	st->f_type = LXP_TMPFS_MAGIC;
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
	long rc = resolve_path(p, path, abspath, sizeof(abspath));
	if (rc < 0)
		return rc;
	struct lxp_statfs64 st;
#if LXP_ENABLE_FS
	if (lxp_hostfs_match(abspath)) {
		rc = lxp_hostfs_statfs(p, &st);
		return rc < 0 ? rc : statfs_copy(p, size, buf, &st);
	}
#endif
	statfs_synthetic(&st);
	return statfs_copy(p, size, buf, &st);
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
	statfs_synthetic(&st);
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
	struct lxp_stat st;
	if (plen > 0 && !(flags & LXP_AT_EMPTY_PATH)) {
		char abspath[LXP_PATH_MAX];
		long rr = resolve_path(p, path, abspath, sizeof(abspath));
		if (rr < 0)
			return rr;
		long source =
			path_stat_lookup(p, abspath, !(flags & LXP_AT_SYMLINK_NOFOLLOW), &st);
#if LXP_ENABLE_NETFS
		if (source == LXP_PATH_STAT_NETFS)
			return lxp_netfs_stat(p, abspath, (uintptr_t)buf, 1); /* parks */
#endif
		if (source < 0)
			return source;
	} else {
		lxp_ofd_t *s = lxp_fd_description(p, dirfd);
		if (!s)
			return -LXP_EBADF;
		long rc = fd_stat(p, s, &st);
		if (rc < 0)
			return rc;
	}
	return lxp_stat_copyout(p, (uintptr_t)buf, 1, &st);
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
	return sys_stat_path(proc, (const char *)(uintptr_t)a[0], 1, (void *)(uintptr_t)a[1]);
}

/* (path, statbuf) — does NOT follow */
long lxp_sys_lstat64(lxp_proc_t *proc, const long a[6])
{
	return sys_stat_path(proc, (const char *)(uintptr_t)a[0], 0, (void *)(uintptr_t)a[1]);
}

/* (dirfd, path, statbuf, flags) */
long lxp_sys_fstatat64(lxp_proc_t *proc, const long a[6])
{
	return sys_stat_path(proc, (const char *)(uintptr_t)a[1],
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
	return sys_readlink(proc, (const char *)(uintptr_t)a[0], (char *)(uintptr_t)a[1],
			    (size_t)a[2]);
}

/* (dirfd, path, buf, bufsiz) */
long lxp_sys_readlinkat(lxp_proc_t *proc, const long a[6])
{
	return sys_readlink(proc, (const char *)(uintptr_t)a[1], (char *)(uintptr_t)a[2],
			    (size_t)a[3]);
}

/* (path, mode) */
long lxp_sys_access(lxp_proc_t *proc, const long a[6])
{
	return sys_access(proc, (const char *)(uintptr_t)a[0], (int)a[1]);
}

/* (dirfd, path, mode) */
/* (dirfd, path, mode, flags) */
long lxp_sys_faccessat(lxp_proc_t *proc, const long a[6])
{
	return sys_access(proc, (const char *)(uintptr_t)a[1], (int)a[2]);
}

/* (path, mode) */
long lxp_sys_mkdir(lxp_proc_t *proc, const long a[6])
{
	return sys_mkdir(proc, (const char *)(uintptr_t)a[0], (uint32_t)a[1]);
}

/* (dirfd, path, mode) */
long lxp_sys_mkdirat(lxp_proc_t *proc, const long a[6])
{
	return sys_mkdir(proc, (const char *)(uintptr_t)a[1], (uint32_t)a[2]);
}

/* (path) */
long lxp_sys_rmdir(lxp_proc_t *proc, const long a[6])
{
	return sys_unlink(proc, (const char *)(uintptr_t)a[0], 1);
}

/* (path) */
long lxp_sys_unlink(lxp_proc_t *proc, const long a[6])
{
	return sys_unlink(proc, (const char *)(uintptr_t)a[0], 0);
}

/* (dirfd, path, flags) */
long lxp_sys_unlinkat(lxp_proc_t *proc, const long a[6])
{
	if (((int)a[2] & ~LXP_AT_REMOVEDIR) != 0)
		return -LXP_EINVAL;
	return sys_unlink(proc, (const char *)(uintptr_t)a[1],
			  ((int)a[2] & LXP_AT_REMOVEDIR) ? 1 : 0);
}

/* (oldpath, newpath) */
long lxp_sys_rename(lxp_proc_t *proc, const long a[6])
{
	return sys_rename(proc, (const char *)(uintptr_t)a[0], (const char *)(uintptr_t)a[1],
			  0);
}

/* (olddirfd, old, newdirfd, new) */
long lxp_sys_renameat(lxp_proc_t *proc, const long a[6])
{
	return sys_rename(proc, (const char *)(uintptr_t)a[1], (const char *)(uintptr_t)a[3],
			  0);
}

/* (olddirfd, old, newdirfd, new, flags) */
long lxp_sys_renameat2(lxp_proc_t *proc, const long a[6])
{
	return sys_rename(proc, (const char *)(uintptr_t)a[1], (const char *)(uintptr_t)a[3],
			  (unsigned)a[4]);
}

/* (target, linkpath) */
long lxp_sys_symlink(lxp_proc_t *proc, const long a[6])
{
	return sys_symlink(proc, (const char *)(uintptr_t)a[0], (const char *)(uintptr_t)a[1]);
}

/* (target, newdirfd, linkpath) */
long lxp_sys_symlinkat(lxp_proc_t *proc, const long a[6])
{
	return sys_symlink(proc, (const char *)(uintptr_t)a[0], (const char *)(uintptr_t)a[2]);
}

/* (oldpath, newpath) */
long lxp_sys_link(lxp_proc_t *proc, const long a[6])
{
	return sys_link(proc, (const char *)(uintptr_t)a[0], (const char *)(uintptr_t)a[1]);
}

/* (olddirfd, oldpath, newdirfd, newpath, flags) */
long lxp_sys_linkat(lxp_proc_t *proc, const long a[6])
{
	return sys_link(proc, (const char *)(uintptr_t)a[1], (const char *)(uintptr_t)a[3]);
}

/* (path, mode) */
long lxp_sys_chmod(lxp_proc_t *proc, const long a[6])
{
	return sys_chmod(proc, (const char *)(uintptr_t)a[0], (uint32_t)a[1]);
}

/* (dirfd, path, mode) */
long lxp_sys_fchmodat(lxp_proc_t *proc, const long a[6])
{
	return sys_chmod(proc, (const char *)(uintptr_t)a[1], (uint32_t)a[2]);
}

/* (dirfd, path, times, flags) — times not tracked */
/* time64 variant uClibc-ng issues for touch */
long lxp_sys_utimensat(lxp_proc_t *proc, const long a[6])
{
	return sys_utimensat(proc, (const char *)(uintptr_t)a[1]);
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
	const char *path = (const char *)(uintptr_t)a[0];
	if (!path)
		return -LXP_EFAULT;
	char abspath[LXP_PATH_MAX];
	long r = resolve_path(proc, path, abspath, sizeof(abspath));
	if (r < 0)
		return r;
	/* "/" is always valid; else require an existing directory in either the
	 * writable overlay or the read-only rootfs. */
	if (!(abspath[0] == '/' && abspath[1] == '\0')) {
#if LXP_ENABLE_FS
		if (lxp_hostfs_match(abspath)) {
			lxp_fs_stat_t stat;
			long sr = lxp_hostfs_path_stat(proc, abspath, &stat);
			if (sr < 0)
				return sr;
			if (stat.type != LXP_FS_TYPE_DIR)
				return -LXP_ENOTDIR;
			strcpy(proc->fs_context->cwd, abspath);
			return 0;
		}
#endif
		int wi = wfs_find(abspath);
		if (wi >= 0) {
			if ((wnode_at(wi)->mode & LXP_S_IFMT) != LXP_S_IFDIR)
				return -LXP_ENOTDIR;
		} else {
			int idx = fs_lookup(proc, abspath);
			if (idx < 0)
				return -LXP_ENOENT;
			if ((file_mode(&proc->fs[idx]) & LXP_S_IFMT) != LXP_S_IFDIR)
				return -LXP_ENOTDIR;
		}
	}
	strcpy(proc->fs_context->cwd, abspath);
	return 0;
}
