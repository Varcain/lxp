/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Golden path routing: which namespace answers each path-name syscall, pinned per path
 * so a change to the routing shows up as a changed cell. Every cell runs one syscall
 * against a fresh world:
 *   rootfs  /, /bin, /bin/busybox, /bin/sh -> busybox, /etc, /etc/hosts, /etclink -> etc,
 *           and the empty mount-point directories /dev, /proc, /tmp, /data, /mnt, /mnt/pi
 *   tmpfs   /tmp/w (file) and /tmp/wd (directory)
 *   hostfs  a fake provider at /data holding the file /f and the directory /d
 *   netfs   configured at /mnt/pi with no server, so a call that reaches it parks
 *   /dev    the built-in console and pty nodes plus a registered /dev/rtest
 * A cell is 0 or the negated errno the call returned, or the namespace that served it
 * (for open, stat and the calls that create or remove a name).
 */
#include "../framework/lxp_test.h"
#include "../framework/lxp_mock_fdpic.h"
#include "../framework/lxp_proc_fixture.h"
#include "../framework/lxp_stat_view.h"

#include "dev/lxp_dev.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_tmpfs.h"
#include "lxp/lxp_fs_ops.h"
#include "lxp_guest.h"
#include "lxp_provider.h"
#include "netfs/lxp_netfs.h"
#include "proc/lxp_exec_stage.h"
#include "pty/lxp_pty.h"

#include <stdio.h>
#include <string.h>

enum {
	ROOT = 1000, /* read-only rootfs */
	TMP,	     /* writable tmpfs overlay */
	PROC,	     /* synthetic /proc */
	CONS,	     /* console, null and random nodes */
	PTY,	     /* pseudo-terminal nodes */
	DEV,	     /* registered character device */
	HOST,	     /* hostfs provider at /data */
	NET,	     /* netfs at /mnt/pi: the call parked on a 9P request */
	SKIP,	     /* not exercised here */
};
#define E(name) (-LXP_E##name)

/* ---- fake hostfs volume ----------------------------------------------------- */

static char g_host_op[96]; /* the last mutation the provider performed */
static int g_host_handle;

static uint8_t host_type(const char *path)
{
	if (strcmp(path, "/") == 0 || strcmp(path, "/d") == 0)
		return LXP_FS_TYPE_DIR;
	if (strcmp(path, "/f") == 0)
		return LXP_FS_TYPE_FILE;
	return LXP_FS_TYPE_UNKNOWN;
}

static void host_record(const char *op, const char *path)
{
	snprintf(g_host_op, sizeof(g_host_op), "%s %s", op, path);
}

static void host_request_owner(uint64_t owner)
{
	(void)owner;
}

static int host_is_mounted(void)
{
	return 1;
}

static int host_volume_stat(lxp_fs_volume_stat_t *out)
{
	memset(out, 0, sizeof(*out));
	out->blocks = 64u;
	out->block_size = 512u;
	out->fragment_size = 512u;
	out->name_max = 255u;
	return LXP_OK;
}

static int host_object_open(const char *path, unsigned flags, int require_dir,
			    lxp_fs_open_result_t *out)
{
	memset(out, 0, sizeof(*out));
	uint8_t type = host_type(path);
	if (type == LXP_FS_TYPE_UNKNOWN) {
		if (!(flags & LXP_FS_O_CREATE))
			return LXP_ERR_NOT_FOUND;
		type = LXP_FS_TYPE_FILE;
	}
	if (type == LXP_FS_TYPE_DIR) {
		if (!require_dir && (flags & (LXP_FS_O_WRITE | LXP_FS_O_CREATE | LXP_FS_O_TRUNC)))
			return LXP_ERR_IS_DIR;
		out->handle.dir = (lxp_fs_dir_t)&g_host_handle;
	} else {
		if (require_dir)
			return LXP_ERR_NOT_DIR;
		out->handle.file = (lxp_fs_file_t)&g_host_handle;
	}
	out->type = type;
	return LXP_OK;
}

static int host_file_close(lxp_fs_file_t file)
{
	(void)file;
	return LXP_OK;
}

static int host_dir_close(lxp_fs_dir_t dir)
{
	(void)dir;
	return LXP_OK;
}

static int host_path_stat(const char *path, lxp_fs_stat_t *out)
{
	memset(out, 0, sizeof(*out));
	out->type = host_type(path);
	return out->type == LXP_FS_TYPE_UNKNOWN ? LXP_ERR_NOT_FOUND : LXP_OK;
}

static int host_mkdir(const char *path)
{
	if (host_type(path) != LXP_FS_TYPE_UNKNOWN)
		return LXP_ERR_ALREADY_EXISTS;
	host_record("mkdir", path);
	return LXP_OK;
}

static int host_rmdir(const char *path)
{
	uint8_t type = host_type(path);
	if (type == LXP_FS_TYPE_UNKNOWN)
		return LXP_ERR_NOT_FOUND;
	if (type != LXP_FS_TYPE_DIR)
		return LXP_ERR_NOT_DIR;
	host_record("rmdir", path);
	return LXP_OK;
}

static int host_unlink(const char *path)
{
	uint8_t type = host_type(path);
	if (type == LXP_FS_TYPE_UNKNOWN)
		return LXP_ERR_NOT_FOUND;
	if (type == LXP_FS_TYPE_DIR)
		return LXP_ERR_IS_DIR;
	host_record("unlink", path);
	return LXP_OK;
}

static int host_rename(const char *old_path, const char *new_path)
{
	(void)new_path;
	if (host_type(old_path) == LXP_FS_TYPE_UNKNOWN)
		return LXP_ERR_NOT_FOUND;
	host_record("rename", old_path);
	return LXP_OK;
}

static const lxp_fs_ops_t g_host_ops = {
	.abi_version = LXP_FS_OPS_ABI_VERSION,
	.struct_size = sizeof(lxp_fs_ops_t),
	.request_owner = host_request_owner,
	.is_mounted = host_is_mounted,
	.volume_stat = host_volume_stat,
	.object_open = host_object_open,
	.file_close = host_file_close,
	.dir_close = host_dir_close,
	.path_stat = host_path_stat,
	.path_mkdir = host_mkdir,
	.path_rmdir = host_rmdir,
	.path_unlink = host_unlink,
	.path_rename = host_rename,
};

/* ---- the world -------------------------------------------------------------- */

static const struct lxp_dev_ops g_rtest_ops = {0};
static const struct lxp_dev g_rtest = {.path = "/dev/rtest", .ops = &g_rtest_ops, .major = 10};

static const uint8_t g_busybox[] = "BB";
static const uint8_t g_hosts[] = "127.0.0.1 localhost\n";

#define ROOTFS_FILE(p, d, m) {.path = (p), .data = (d), .size = sizeof(d) - 1u, .mode = (m)}
#define ROOTFS_DIR(p) {.path = (p), .mode = LXP_S_IFDIR | 0755u}
#define ROOTFS_LINK(p, t)                                                                          \
	{.path = (p), .data = (const uint8_t *)(t), .size = sizeof(t) - 1u,                        \
	 .mode = LXP_S_IFLNK | 0777u}

static const lxp_file_t g_rootfs[] = {
	ROOTFS_DIR("/"),
	ROOTFS_DIR("/bin"),
	ROOTFS_FILE("/bin/busybox", g_busybox, LXP_S_IFREG | 0755u),
	ROOTFS_LINK("/bin/sh", "busybox"),
	ROOTFS_DIR("/data"),
	ROOTFS_DIR("/dev"),
	ROOTFS_DIR("/etc"),
	ROOTFS_FILE("/etc/hosts", g_hosts, LXP_S_IFREG | 0644u),
	ROOTFS_LINK("/etclink", "etc"),
	ROOTFS_DIR("/mnt"),
	ROOTFS_DIR("/mnt/pi"),
	ROOTFS_DIR("/proc"),
	ROOTFS_DIR("/tmp"),
};

/* One process for every cell: the fixture keys its exec capture by the proc's address. */
static lxp_proc_t g_proc;
static const lxp_net_ops_t *g_saved_net;
static const lxp_display_ops_t *g_saved_display;
static const lxp_block_ops_t *g_saved_block;

static long call(lxp_proc_t *p, long nr, long a0, long a1, long a2, long a3)
{
	uint32_t generation = 1;
	lxp_guest_view_t view;
	lxp_slot_ref_t owner = {.index = 0, .generation = 1};
	assert_int_equal(lxp_guest_view_begin(p, owner, &generation, LXP_GUEST_READ_WRITE, &view),
			 LXP_OK);
	long result = lxp_syscall(p, nr, a0, a1, a2, a3, 0, 0);
	lxp_guest_view_end(&view);
	return result;
}

static lxp_conf_t *world_begin(lxp_proc_t *p)
{
	lxp_proc_runtime_reset();
	lxp_fd_runtime_reset();
	lxp_pty_runtime_reset();
	lxp_conf_t *fx = lxp_conf_begin(p, g_rootfs, (int)(sizeof(g_rootfs) / sizeof(g_rootfs[0])));
	if (!fx)
		return NULL;
	p->mm->region = (lxp_region_ref_t){.index = 0, .generation = 1};
	for (int i = 0; i < LXP_NWNODE; i++)
		if (lxp_wnode_at(i)->used)
			lxp_wfs_free(i);
	assert_true(lxp_wfs_create("/tmp/w", LXP_S_IFREG | 0644u) >= 0);
	assert_true(lxp_wfs_create("/tmp/wd", LXP_S_IFDIR | 0755u) >= 0);
	g_host_op[0] = '\0';
	return fx;
}

static void world_end(lxp_proc_t *p)
{
	if (p->wait.kind == LXP_WAIT_NETFS) {
		uint32_t generation = 1;
		lxp_guest_view_t view;
		lxp_slot_ref_t owner = {.index = 0, .generation = 1};
		assert_int_equal(lxp_guest_view_begin(p, owner, &generation, LXP_GUEST_READ_WRITE,
						      &view),
				 LXP_OK);
		lxp_netfs_cancel(p);
		lxp_guest_view_end(&view);
		(void)lxp_wait_cancel(p);
	}
}

/* ---- outcomes --------------------------------------------------------------- */

static long open_outcome(lxp_proc_t *p, long fd)
{
	if (p->wait.kind == LXP_WAIT_NETFS)
		return NET;
	if (fd < 0)
		return fd;
	long route;
	switch (lxp_fd_kind(p, (int)fd)) {
	case LXP_FD_FILE:
		route = ROOT;
		break;
	case LXP_FD_TMPFS:
		route = TMP;
		break;
	case LXP_FD_PROC:
		route = PROC;
		break;
	case LXP_FD_CONSOLE:
		route = CONS;
		break;
	case LXP_FD_PTY:
		route = PTY;
		break;
	case LXP_FD_DEV:
		route = DEV;
		break;
	case LXP_FD_HOSTFS:
		route = HOST;
		break;
	default:
		route = 0;
		break;
	}
	assert_int_equal(call(p, LXP_NR_close, fd, 0, 0, 0), 0);
	return route;
}

static long stat_outcome(lxp_proc_t *p, long rc, const uint8_t *statbuf)
{
	if (p->wait.kind == LXP_WAIT_NETFS)
		return NET;
	if (rc < 0)
		return rc;
	uint64_t ino = lxp_view_kstat64(statbuf).ino;
	if (ino >= LXP_INO_HOSTFS)
		return HOST;
	if (ino >= LXP_INO_DEV)
		return DEV;
	if (ino >= LXP_INO_PROC)
		return PROC;
	if (ino >= LXP_INO_TMPFS)
		return TMP;
	return ROOT;
}

/* A create or remove that succeeded: the host provider logged it, or it was tmpfs. */
static long name_outcome(long rc)
{
	if (rc < 0)
		return rc;
	return g_host_op[0] ? HOST : TMP;
}

enum op {
	OP_OPEN,
	OP_CREAT,
	OP_STAT,
	OP_LSTAT,
	OP_MKDIR,
	OP_UNLINK,
	OP_RMDIR,
	OP_SYMLINK,
	OP_CHMOD,
	OP_UTIMENS,
	OP_STATFS,
	OP_READLINK,
	OP_ACCESS,
	OP_ACCESS_W,
	OP_ACCESS_X,
	OP_CHDIR,
	OP_EXEC,
	OP_RENAME,
	OP_LINK,
};

static const char *const g_op_name[] = {
	"open",    "creat",  "stat",     "lstat",  "mkdir", "unlink", "rmdir",  "symlink", "chmod",
	"utimens", "statfs", "readlink", "access", "w_ok",  "x_ok",   "chdir",  "exec",
	"rename",  "link",
};

static long run_op(lxp_proc_t *p, lxp_conf_t *fx, enum op op, const char *path, const char *path2)
{
	long gp = (long)(uintptr_t)lxp_conf_str(fx, path);
	long gp2 = path2 ? (long)(uintptr_t)lxp_conf_str(fx, path2) : 0;
	uint8_t *buf = lxp_conf_alloc(fx, 256);
	long b = (long)(uintptr_t)buf;
	long rc;
	switch (op) {
	case OP_OPEN:
		return open_outcome(p, call(p, LXP_NR_openat, LXP_AT_FDCWD, gp, LXP_O_RDONLY, 0));
	case OP_CREAT:
		return open_outcome(p, call(p, LXP_NR_openat, LXP_AT_FDCWD, gp,
					    LXP_O_WRONLY | LXP_O_CREAT, 0644));
	case OP_STAT:
		return stat_outcome(p, call(p, LXP_NR_stat64, gp, b, 0, 0), buf);
	case OP_LSTAT:
		return stat_outcome(p, call(p, LXP_NR_lstat64, gp, b, 0, 0), buf);
	case OP_MKDIR:
		return name_outcome(call(p, LXP_NR_mkdir, gp, 0755, 0, 0));
	case OP_UNLINK:
		return name_outcome(call(p, LXP_NR_unlink, gp, 0, 0, 0));
	case OP_RMDIR:
		return name_outcome(call(p, LXP_NR_rmdir, gp, 0, 0, 0));
	case OP_SYMLINK:
		return name_outcome(
			call(p, LXP_NR_symlink, (long)(uintptr_t)lxp_conf_str(fx, "x"), gp, 0, 0));
	case OP_CHMOD:
		return call(p, LXP_NR_chmod, gp, 0600, 0, 0);
	case OP_UTIMENS:
		return call(p, LXP_NR_utimensat, LXP_AT_FDCWD, gp, 0, 0);
	case OP_STATFS:
		rc = call(p, LXP_NR_statfs64, gp, (long)sizeof(struct lxp_statfs64), b, 0);
		if (rc < 0)
			return rc;
		switch (lxp_view_u32(buf, 0)) {
		case LXP_MSDOS_SUPER_MAGIC:
			return HOST;
		case LXP_PROC_SUPER_MAGIC:
			return PROC;
		case LXP_V9FS_MAGIC:
			return NET;
		case LXP_TMPFS_MAGIC:
			return TMP;
		default:
			return 0;
		}
	case OP_READLINK:
		return call(p, LXP_NR_readlink, gp, b, 64, 0);
	case OP_ACCESS:
	case OP_ACCESS_W:
	case OP_ACCESS_X:
		rc = op == OP_ACCESS_W ? 2 : op == OP_ACCESS_X ? 1 : 0; /* W_OK, X_OK, F_OK */
		rc = call(p, LXP_NR_access, gp, rc, 0, 0);
		return p->wait.kind == LXP_WAIT_NETFS ? NET : rc;
	case OP_CHDIR:
		rc = call(p, LXP_NR_chdir, gp, 0, 0, 0);
		return p->wait.kind == LXP_WAIT_NETFS ? NET : rc;
	case OP_EXEC:
		rc = call(p, LXP_NR_execve, gp, 0, 0, 0);
		return p->wait.kind == LXP_WAIT_NETFS ? NET : rc;
	case OP_RENAME:
		rc = name_outcome(call(p, LXP_NR_rename, gp, gp2, 0, 0));
		if (rc == TMP)
			assert_true(lxp_wfs_find(path2) >= 0);
		return rc;
	case OP_LINK:
		rc = name_outcome(call(p, LXP_NR_link, gp, gp2, 0, 0));
		if (rc == TMP)
			assert_true(lxp_wfs_find(path2) >= 0);
		return rc;
	}
	return 0;
}

static void outcome_text(long v, char *out, size_t n)
{
	static const char *const route[] = {"ROOT", "TMP",  "PROC", "CONS", "PTY",
					    "DEV",  "HOST", "NET",  "SKIP"};
	if (v >= ROOT && v <= SKIP)
		snprintf(out, n, "%s", route[v - ROOT]);
	else
		snprintf(out, n, "%ld", v);
}

/* Run one cell on a fresh world; report a mismatch without stopping the table. */
static int check(enum op op, const char *path, const char *path2, long expect)
{
	if (expect == SKIP)
		return 0;
	lxp_conf_t *fx = world_begin(&g_proc);
	assert_non_null(fx);
	long got = run_op(&g_proc, fx, op, path, path2);
	world_end(&g_proc);
	if (got == expect)
		return 0;
	char want_text[16], got_text[16];
	outcome_text(expect, want_text, sizeof(want_text));
	outcome_text(got, got_text, sizeof(got_text));
	print_message("  %s %s%s%s: expected %s, got %s\n", g_op_name[op], path, path2 ? " " : "",
		      path2 ? path2 : "", want_text, got_text);
	return 1;
}

/* ---- the tables ------------------------------------------------------------- */

struct row4 {
	const char *path;
	long cell[4];
};

struct row6 {
	const char *path;
	long cell[6];
};

struct row7 {
	const char *path;
	long cell[7];
};

struct pair {
	const char *from;
	const char *to;
	long expect;
};

/* open(O_RDONLY), open(O_WRONLY | O_CREAT), stat, lstat. */
static const struct row4 g_open_stat[] = {
	/* path         open      creat     stat      lstat */
	{"/",          {ROOT,     E(ISDIR), ROOT,     ROOT}},
	{"/proc",      {PROC,     E(ISDIR), PROC,     PROC}},
	{"/proc/self", {E(NOENT), E(ACCES), PROC,     PROC}},
	{"/proc/stat", {PROC,     E(ACCES), PROC,     PROC}},
	{"/proc/nope", {E(NOENT), E(ACCES), E(NOENT), E(NOENT)}},
	{"/data",      {HOST,     E(ISDIR), HOST,     HOST}},
	{"/data/f",    {HOST,     HOST,     HOST,     HOST}},
	{"/data/nope", {E(NOENT), HOST,     E(NOENT), E(NOENT)}},
	{"/dev",       {ROOT,     E(ISDIR), ROOT,     ROOT}},
	{"/dev/null",  {CONS,     CONS,     DEV,      DEV}},
	{"/dev/ptmx",  {PTY,      PTY,      DEV,      DEV}},
	{"/dev/rtest", {DEV,      DEV,      DEV,      DEV}},
	{"/mnt/pi",    {NET,      E(ROFS),  NET,      NET}},
	{"/mnt/pi/f",  {NET,      E(ROFS),  NET,      NET}},
	{"/tmp/w",     {TMP,      TMP,      TMP,      TMP}},
	{"/tmp/wd",    {TMP,      E(ISDIR), TMP,      TMP}},
	{"/etc/hosts", {ROOT,     E(ROFS),  ROOT,     ROOT}},
	{"/bin/sh",    {ROOT,     E(ROFS),  ROOT,     ROOT}},
	{"/etclink",   {ROOT,     E(ISDIR), ROOT,     ROOT}},
	{"/nope",      {E(NOENT), TMP,      E(NOENT), E(NOENT)}},
};

/* mkdir, unlink, rmdir, symlink (as the link name), chmod, utimensat, statfs. */
static const struct row7 g_names[] = {
	/* path         mkdir     unlink    rmdir      symlink       chmod     utimens   statfs */
	{"/",          {E(EXIST), E(ROFS),  E(ROFS),   E(EXIST),     0,        0,        TMP}},
	{"/proc",      {E(EXIST), E(PERM),  E(PERM),   E(EXIST),     0,        0,        PROC}},
	{"/proc/self", {E(EXIST), E(PERM),  E(PERM),   E(EXIST),     0,        0,        PROC}},
	{"/proc/stat", {E(EXIST), E(PERM),  E(PERM),   E(EXIST),     0,        0,        PROC}},
	{"/proc/nope", {E(PERM),  E(NOENT), E(NOENT),  E(PERM),      E(NOENT), E(NOENT), E(NOENT)}},
	{"/data",      {E(EXIST), E(BUSY),  E(BUSY),   E(OPNOTSUPP), 0,        0,        HOST}},
	{"/data/f",    {E(EXIST), HOST,     E(NOTDIR), E(OPNOTSUPP), 0,        0,        HOST}},
	{"/data/nope", {HOST,     E(NOENT), E(NOENT),  E(OPNOTSUPP), E(NOENT), E(NOENT), HOST}},
	{"/dev",       {E(EXIST), E(ROFS),  E(ROFS),   E(EXIST),     0,        0,        TMP}},
	{"/dev/null",  {E(EXIST), E(PERM),  E(PERM),   E(EXIST),     0,        0,        TMP}},
	{"/dev/ptmx",  {E(EXIST), E(PERM),  E(PERM),   E(EXIST),     0,        0,        TMP}},
	{"/dev/rtest", {E(EXIST), E(PERM),  E(PERM),   E(EXIST),     0,        0,        TMP}},
	{"/mnt/pi",    {E(ROFS),  E(ROFS),  E(ROFS),   E(ROFS),      E(ROFS),  E(ROFS),  NET}},
	{"/mnt/pi/f",  {E(ROFS),  E(ROFS),  E(ROFS),   E(ROFS),      E(ROFS),  E(ROFS),  NET}},
	{"/tmp/w",     {E(EXIST), TMP,      E(NOTDIR), E(EXIST),     0,        0,        TMP}},
	{"/tmp/wd",    {E(EXIST), E(ISDIR), TMP,       E(EXIST),     0,        0,        TMP}},
	{"/etc/hosts", {E(EXIST), E(ROFS),  E(ROFS),   E(EXIST),     0,        0,        TMP}},
	{"/bin/sh",    {E(EXIST), E(ROFS),  E(ROFS),   E(EXIST),     0,        0,        TMP}},
	{"/etclink",   {E(EXIST), E(ROFS),  E(ROFS),   E(EXIST),     0,        0,        TMP}},
	{"/nope",      {TMP,      E(NOENT), E(NOENT),  TMP,          E(NOENT), E(NOENT), E(NOENT)}},
};

/* readlink (the returned length), access (F_OK, W_OK, X_OK), chdir, execve. */
static const struct row6 g_lookup[] = {
	/* path         readlink  access    w_ok      x_ok      chdir      exec */
	{"/",          {E(INVAL), 0,        0,        0,        0,         E(ACCES)}},
	{"/proc",      {E(INVAL), 0,        E(ACCES), 0,        0,         E(ACCES)}},
	{"/proc/self", {1,        0,        E(ACCES), 0,        0,         E(ACCES)}},
	{"/proc/stat", {E(INVAL), 0,        E(ACCES), E(ACCES), E(NOTDIR), E(ACCES)}},
	{"/proc/nope", {E(NOENT), E(NOENT), E(NOENT), E(NOENT), E(NOENT),  E(NOENT)}},
	{"/data",      {E(INVAL), 0,        0,        0,        0,         E(ACCES)}},
	{"/data/f",    {E(INVAL), 0,        0,        E(ACCES), E(NOTDIR), E(ACCES)}},
	{"/data/nope", {E(NOENT), E(NOENT), E(NOENT), E(NOENT), E(NOENT),  E(NOENT)}},
	{"/dev",       {E(INVAL), 0,        0,        0,        0,         E(ACCES)}},
	{"/dev/null",  {E(INVAL), 0,        0,        E(ACCES), E(NOTDIR), E(ACCES)}},
	{"/dev/ptmx",  {E(INVAL), 0,        0,        E(ACCES), E(NOTDIR), E(ACCES)}},
	{"/dev/rtest", {E(INVAL), 0,        0,        E(ACCES), E(NOTDIR), E(ACCES)}},
	{"/mnt/pi",    {E(INVAL), NET,      E(ROFS),  NET,      NET,       NET}},
	{"/mnt/pi/f",  {E(INVAL), NET,      E(ROFS),  NET,      NET,       NET}},
	{"/tmp/w",     {E(INVAL), 0,        0,        0,        E(NOTDIR), E(NOEXEC)}},
	{"/tmp/wd",    {E(INVAL), 0,        0,        0,        0,         E(ACCES)}},
	{"/etc/hosts", {E(INVAL), 0,        E(ROFS),  0,        E(NOTDIR), SKIP}},
	{"/bin/sh",    {7,        0,        E(ROFS),  0,        E(NOTDIR), SKIP}},
	{"/etclink",   {3,        0,        E(ROFS),  0,        0,         E(ACCES)}},
	{"/nope",      {E(NOENT), E(NOENT), E(NOENT), E(NOENT), E(NOENT),  E(NOENT)}},
};

static const struct pair g_renames[] = {
	{"/tmp/w", "/tmp/w2", TMP},
	{"/tmp/w", "/data/x", E(XDEV)},
	{"/data/f", "/data/g", HOST},
	{"/data/f", "/tmp/x", E(XDEV)},
	{"/etc/hosts", "/tmp/x", E(ROFS)},
	{"/nope", "/tmp/x", E(NOENT)},
	{"/proc/stat", "/tmp/x", E(XDEV)},
	{"/mnt/pi/f", "/tmp/x", E(XDEV)},
	{"/tmp/w", "/proc/x", E(XDEV)},
	{"/tmp/w", "/mnt/pi/x", E(XDEV)},
	{"/tmp/w", "/dev/null", E(XDEV)},
	{"/tmp/w", "/etc/hosts", E(ROFS)},
};

static const struct pair g_links[] = {
	{"/tmp/w", "/tmp/w2", TMP},
	{"/etc/hosts", "/tmp/p", TMP},
	{"/data/f", "/data/g", E(OPNOTSUPP)},
	{"/data/f", "/tmp/x", E(XDEV)},
	{"/tmp/wd", "/tmp/x", E(PERM)},
	{"/tmp/w", "/etc/hosts", E(EXIST)},
	{"/mnt/pi/f", "/tmp/x", E(XDEV)},
	{"/tmp/w", "/proc/x", E(XDEV)},
	{"/tmp/w", "/mnt/pi/x", E(XDEV)},
};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static void test_route_open_and_stat(void **state)
{
	(void)state;
	static const enum op ops[] = {OP_OPEN, OP_CREAT, OP_STAT, OP_LSTAT};
	int bad = 0;
	for (size_t r = 0; r < COUNT(g_open_stat); r++)
		for (size_t c = 0; c < COUNT(ops); c++)
			bad += check(ops[c], g_open_stat[r].path, NULL, g_open_stat[r].cell[c]);
	assert_int_equal(bad, 0);
}

static void test_route_namespace_operations(void **state)
{
	(void)state;
	static const enum op ops[] = {OP_MKDIR, OP_UNLINK,  OP_RMDIR, OP_SYMLINK,
				      OP_CHMOD, OP_UTIMENS, OP_STATFS};
	int bad = 0;
	for (size_t r = 0; r < COUNT(g_names); r++)
		for (size_t c = 0; c < COUNT(ops); c++)
			bad += check(ops[c], g_names[r].path, NULL, g_names[r].cell[c]);
	for (size_t i = 0; i < COUNT(g_renames); i++)
		bad += check(OP_RENAME, g_renames[i].from, g_renames[i].to, g_renames[i].expect);
	for (size_t i = 0; i < COUNT(g_links); i++)
		bad += check(OP_LINK, g_links[i].from, g_links[i].to, g_links[i].expect);
	assert_int_equal(bad, 0);
}

static void test_route_lookups(void **state)
{
	(void)state;
	static const enum op ops[] = {OP_READLINK, OP_ACCESS, OP_ACCESS_W,
				      OP_ACCESS_X, OP_CHDIR,  OP_EXEC};
	int bad = 0;
	for (size_t r = 0; r < COUNT(g_lookup); r++)
		for (size_t c = 0; c < COUNT(ops); c++)
			bad += check(ops[c], g_lookup[r].path, NULL, g_lookup[r].cell[c]);
	assert_int_equal(bad, 0);
}

/* The built-in /dev nodes stat as character devices with Linux's numbers, and a pts
 * node reports the inode its open slave descriptor does. */
static void test_dev_nodes_stat_as_devices(void **state)
{
	(void)state;
	lxp_conf_t *fx = world_begin(&g_proc);
	assert_non_null(fx);
	uint8_t *buf = lxp_conf_alloc(fx, 128);
	uint32_t *ptn = lxp_conf_alloc(fx, sizeof(*ptn));
	long b = (long)(uintptr_t)buf;

	long null_path = (long)(uintptr_t)lxp_conf_str(fx, "/dev/null");
	assert_int_equal(call(&g_proc, LXP_NR_stat64, null_path, b, 0, 0), 0);
	lxp_stat_view_t null_node = lxp_view_kstat64(buf);
	assert_int_equal(null_node.mode, LXP_S_IFCHR | 0666u);
	assert_int_equal(null_node.rdev, (1u << 8) | 3u);

	long master = call(&g_proc, LXP_NR_openat, LXP_AT_FDCWD,
			   (long)(uintptr_t)lxp_conf_str(fx, "/dev/ptmx"), LXP_O_RDWR, 0);
	assert_true(master >= 0);
	long ptn_arg = (long)(uintptr_t)ptn;
	assert_int_equal(call(&g_proc, LXP_NR_ioctl, master, (long)LXP_TIOCGPTN, ptn_arg, 0), 0);
	char name[24];
	snprintf(name, sizeof(name), "/dev/pts/%u", *ptn);
	long pts = (long)(uintptr_t)lxp_conf_str(fx, name);
	assert_int_equal(call(&g_proc, LXP_NR_stat64, pts, b, 0, 0), 0);
	lxp_stat_view_t by_path = lxp_view_kstat64(buf);
	assert_int_equal(by_path.rdev, (136u << 8) | *ptn);
	long slave = call(&g_proc, LXP_NR_openat, LXP_AT_FDCWD, pts, LXP_O_RDWR, 0);
	assert_true(slave >= 0);
	assert_int_equal(call(&g_proc, LXP_NR_fstat64, slave, b, 0, 0), 0);
	lxp_stat_view_t by_fd = lxp_view_kstat64(buf);
	assert_int_equal(by_fd.ino, by_path.ino);
	assert_int_equal(by_fd.mode, by_path.mode);

	assert_int_equal(call(&g_proc, LXP_NR_close, slave, 0, 0, 0), 0);
	assert_int_equal(call(&g_proc, LXP_NR_close, master, 0, 0, 0), 0);
	world_end(&g_proc);
}

/* chdir through a rootfs symlink lands where it leads, so relative paths resolve from the
 * real directory. */
static void test_chdir_follows_symlinks(void **state)
{
	(void)state;
	lxp_conf_t *fx = world_begin(&g_proc);
	assert_non_null(fx);
	long link = (long)(uintptr_t)lxp_conf_str(fx, "/etclink");
	assert_int_equal(call(&g_proc, LXP_NR_chdir, link, 0, 0, 0), 0);
	assert_string_equal(g_proc.fs_context->cwd, "/etc");
	long hosts = (long)(uintptr_t)lxp_conf_str(fx, "hosts");
	long fd = call(&g_proc, LXP_NR_openat, LXP_AT_FDCWD, hosts, LXP_O_RDONLY, 0);
	assert_true(fd >= 0);
	assert_int_equal(call(&g_proc, LXP_NR_close, fd, 0, 0, 0), 0);
	world_end(&g_proc);
}

/* A program stored in tmpfs is checked and copied into the exec staging buffer by execve.
 * The buffer then belongs to that exec until the coordinator's commit takes the image, so
 * another staged exec meanwhile is EAGAIN. */
static void test_exec_from_tmpfs(void **state)
{
	(void)state;
	lxp_conf_t *fx = world_begin(&g_proc);
	assert_non_null(fx);
	g_proc.alive = 1; /* a process calling execve is running */
	uint8_t prog[LXP_MOCK_FDPIC_SIZE];
	lxp_mock_fdpic(prog);
	int wi = lxp_wfs_create("/tmp/prog", LXP_S_IFREG | 0755u);
	assert_true(wi >= 0);
	assert_int_equal(lxp_wfs_reserve(wi, sizeof(prog)), 0);
	memcpy(lxp_wnode_at(wi)->data, prog, sizeof(prog));
	lxp_wnode_at(wi)->size = sizeof(prog);

	long path = (long)(uintptr_t)lxp_conf_str(fx, "/tmp/prog");
	assert_int_equal(call(&g_proc, LXP_NR_execve, path, 0, 0, 0), 0);
	assert_int_equal(g_proc.intent.kind, LXP_INTENT_EXEC);
	assert_int_equal(g_proc.exec_file_idx, LXP_EXEC_STAGED);
	size_t size = 0;
	const uint8_t *image = lxp_exec_stage_image(&size);
	assert_int_equal(size, sizeof(prog));
	assert_memory_equal(image, prog, sizeof(prog));

	lxp_proc_t other;
	memset(&other, 0, sizeof(other));
	uint8_t *stage;
	size_t cap;
	assert_int_equal(lxp_exec_stage_claim(&other, &stage, &cap), -LXP_EAGAIN);
	assert_int_equal(lxp_intent_complete(&g_proc, LXP_INTENT_EXEC), 0); /* the commit */
	assert_int_equal(lxp_exec_stage_claim(&other, &stage, &cap), 0);
	g_proc.alive = 0;
	world_end(&g_proc);
}

static long open_path(lxp_conf_t *fx, const char *path, int flags)
{
	return call(&g_proc, LXP_NR_openat, LXP_AT_FDCWD, (long)(uintptr_t)lxp_conf_str(fx, path),
		    flags, 0);
}

static long str(lxp_conf_t *fx, const char *text)
{
	return (long)(uintptr_t)lxp_conf_str(fx, text);
}

/* The *at() calls resolve a relative path from the directory open on dirfd: a rootfs,
 * tmpfs or /proc directory. An absolute path ignores dirfd; a file is ENOTDIR, a closed
 * descriptor EBADF, a hostfs directory EOPNOTSUPP and an unlinked one ENOENT. */
static void test_at_calls_resolve_from_dirfd(void **state)
{
	(void)state;
	lxp_conf_t *fx = world_begin(&g_proc);
	assert_non_null(fx);
	uint8_t *buf = lxp_conf_alloc(fx, 128);
	long b = (long)(uintptr_t)buf;
	long etc = open_path(fx, "/etc", LXP_O_RDONLY);
	long bin = open_path(fx, "/bin", LXP_O_RDONLY);
	long proc = open_path(fx, "/proc", LXP_O_RDONLY);
	long tmp = open_path(fx, "/tmp", LXP_O_RDONLY);
	long wd = open_path(fx, "/tmp/wd", LXP_O_RDONLY);
	assert_true(etc >= 0 && bin >= 0 && proc >= 0 && tmp >= 0 && wd >= 0);

	long fd = call(&g_proc, LXP_NR_openat, etc, str(fx, "hosts"), LXP_O_RDONLY, 0);
	assert_true(fd >= 0);
	assert_int_equal(lxp_fd_kind(&g_proc, (int)fd), LXP_FD_FILE);
	assert_int_equal(call(&g_proc, LXP_NR_fstatat64, etc, str(fx, "hosts"), b, 0), 0);
	assert_int_equal(call(&g_proc, LXP_NR_readlinkat, bin, str(fx, "sh"), b, 64), 7);
	assert_int_equal(call(&g_proc, LXP_NR_faccessat, proc, str(fx, "stat"), 0, 0), 0);
	assert_int_equal(call(&g_proc, LXP_NR_mkdirat, wd, str(fx, "x"), 0755, 0), 0);
	assert_true(lxp_wfs_find("/tmp/wd/x") >= 0);
	assert_int_equal(call(&g_proc, LXP_NR_unlinkat, wd, str(fx, "x"), LXP_AT_REMOVEDIR, 0), 0);
	assert_int_equal(call(&g_proc, LXP_NR_renameat, tmp, str(fx, "w"), wd, str(fx, "moved")),
			 0);
	assert_true(lxp_wfs_find("/tmp/wd/moved") >= 0);
	assert_int_equal(call(&g_proc, LXP_NR_symlinkat, str(fx, "t"), wd, str(fx, "l"), 0), 0);
	assert_true(lxp_wfs_find("/tmp/wd/l") >= 0);

	assert_int_equal(call(&g_proc, LXP_NR_openat, fd, str(fx, "x"), LXP_O_RDONLY, 0),
			 -LXP_ENOTDIR);
	assert_int_equal(call(&g_proc, LXP_NR_openat, 29, str(fx, "hosts"), LXP_O_RDONLY, 0),
			 -LXP_EBADF);
	long abs_fd = call(&g_proc, LXP_NR_openat, 29, str(fx, "/etc/hosts"), LXP_O_RDONLY, 0);
	assert_true(abs_fd >= 0);
	long data = open_path(fx, "/data", LXP_O_RDONLY);
	assert_true(data >= 0);
	assert_int_equal(call(&g_proc, LXP_NR_openat, data, str(fx, "f"), LXP_O_RDONLY, 0),
			 -LXP_EOPNOTSUPP);
	assert_int_equal(call(&g_proc, LXP_NR_mkdir, str(fx, "/tmp/gone"), 0755, 0, 0), 0);
	long gone = open_path(fx, "/tmp/gone", LXP_O_RDONLY);
	assert_true(gone >= 0);
	assert_int_equal(call(&g_proc, LXP_NR_rmdir, str(fx, "/tmp/gone"), 0, 0, 0), 0);
	long create = LXP_O_WRONLY | LXP_O_CREAT;
	assert_int_equal(call(&g_proc, LXP_NR_openat, gone, str(fx, "x"), create, 0644),
			 -LXP_ENOENT);

	const long fds[] = {etc, bin, proc, tmp, wd, fd, abs_fd, data, gone};
	for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
		assert_int_equal(call(&g_proc, LXP_NR_close, fds[i], 0, 0, 0), 0);
	world_end(&g_proc);
}

static int group_setup(void **state)
{
	(void)state;
	g_saved_net = g_lxp_net_ops;
	g_saved_display = g_lxp_display_ops;
	g_saved_block = g_lxp_block_ops;
	lxp_providers_publish(g_saved_net, g_saved_display, &g_host_ops, g_saved_block);
	if (lxp_dev_register(&g_rtest) != 0)
		return -1;
	const lxp_netfs_config_t netfs = {
		.mountpoint = "/mnt/pi",
		.server_ip = {127, 0, 0, 1},
		.port = 9,
		.aname = "/",
		.uname = "root",
	};
	return lxp_netfs_init(&netfs) == LXP_OK ? 0 : -1;
}

static int group_teardown(void **state)
{
	(void)state;
	lxp_netfs_shutdown();
	lxp_conf_release(&g_conf);
	lxp_fd_runtime_reset();
	lxp_providers_publish(g_saved_net, g_saved_display, NULL, g_saved_block);
	return 0;
}

int test_path_routing_run(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_route_open_and_stat),
		cmocka_unit_test(test_route_namespace_operations),
		cmocka_unit_test(test_route_lookups),
		cmocka_unit_test(test_dev_nodes_stat_as_devices),
		cmocka_unit_test(test_chdir_follows_symlinks),
		cmocka_unit_test(test_exec_from_tmpfs),
		cmocka_unit_test(test_at_calls_resolve_from_dirfd),
	};
	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
