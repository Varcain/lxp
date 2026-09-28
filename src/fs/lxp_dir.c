/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Directory listings of the local namespace. A rootfs, tmpfs or /proc directory
 * lists the union of everything below its path: rootfs entries, writable-overlay
 * nodes (which shadow rootfs entries of the same path), the host mount point,
 * registered devices and synthetic /proc entries.
 */
#include "fs/lxp_dir.h"

#include "fs/lxp_path.h"
#include "fs/lxp_tmpfs.h"
#include "lxp/lxp_config.h"
#include "lxp/lxp_stats.h"
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

#include <string.h>

/* Emit one entry of a merged directory listing into @p sink, skipping the entries an
 * earlier call already returned (index < s->offset); the resume cookie is the entry's
 * index + 1. Returns 0 once the buffer is full, else 1 (and advances). */
static int dirent_emit(lxp_dirent_sink_t *sink, long *pos, lxp_ofd_t *s, uint64_t ino,
		       const char *name, uint32_t mode)
{
	if (*pos < (long)s->offset) {
		(*pos)++;
		return 1; /* already returned by an earlier getdents call */
	}
	if (!lxp_dirent_put(sink, ino, (uint64_t)(*pos + 1), lxp_dirent_type(mode), name,
			    strlen(name)))
		return 0;
	(*pos)++;
	s->offset++;
	return 1;
}

long lxp_dir_list(lxp_proc_t *p, lxp_ofd_t *s, const char *dirpath, lxp_dirent_sink_t *sink)
{
	long pos = 0; /* running child index across both sources; s->offset = emitted */
	int full = 0;
	/* rootfs children (a writable node of the same path shadows the rootfs one) */
#if LXP_ENABLE_FS
	const char *host_mount = lxp_hostfs_mount_path();
#endif
	for (int i = 0; i < p->fs_count && !full; i++) {
		const char *name = lxp_path_child_name(dirpath, p->fs[i].path);
		if (!name || wfs_find(p->fs[i].path) >= 0
#if LXP_ENABLE_FS
		    || strcmp(p->fs[i].path, host_mount) == 0
#endif
		)
			continue;
		if (!dirent_emit(sink, &pos, s, (uint64_t)(i + 1), name, file_mode(&p->fs[i])))
			full = 1;
	}
	/* writable-overlay children */
	for (int i = 0; i < LXP_NWNODE && !full; i++) {
		if (!wnode_at(i)->used)
			continue;
#if LXP_ENABLE_FS
		if (strcmp(wnode_at(i)->path, host_mount) == 0)
			continue;
#endif
		const char *name = lxp_path_child_name(dirpath, wnode_at(i)->path);
		if (!name)
			continue;
		if (!dirent_emit(sink, &pos, s, (uint64_t)(100000 + i), name, wnode_at(i)->mode))
			full = 1;
	}
#if LXP_ENABLE_FS
	/* The mounted namespace shadows an underlying placeholder, or supplies the
	 * synthetic default /data directory when the rootfs has none. */
	const char *mount_name = lxp_path_child_name(dirpath, host_mount);
	if (!full && mount_name &&
	    !dirent_emit(sink, &pos, s, lxp_hostfs_path_inode(host_mount), mount_name, LXP_S_IFDIR))
		full = 1;
#endif
#if LXP_ENABLE_DEV
	/* registered character devices whose node sits directly under this dir (/dev/fb0). */
	for (int i = 0; i < lxp_dev_count() && !full; i++) {
		uint32_t dmode = LXP_S_IFCHR | 0666u;
		const char *dp = lxp_dev_path(i, &dmode);
		const char *name = dp ? lxp_path_child_name(dirpath, dp) : NULL;
		if (!name)
			continue;
		if (!dirent_emit(sink, &pos, s, (uint64_t)(0x300000 + i), name, dmode))
			full = 1;
	}
#endif
	/* synthetic /proc children */
	if (!full && proc_is(dirpath)) {
		const char *file;
		int dpid = proc_pid(dirpath, p, &file);
		if (strcmp(dirpath, "/proc") == 0) {
			uint64_t ino = 200000;
			for (int i = 0; g_proc_files[i] && !full; i++)
				if (!dirent_emit(sink, &pos, s, ino++,
						 g_proc_files[i], LXP_S_IFREG))
					full = 1;
			if (!full &&
			    !dirent_emit(sink, &pos, s, ino++, "self", LXP_S_IFLNK))
				full = 1;
			/* every live process + kernel thread from the ps/top snapshot */
			int np = lxp_pent_count(), seen1 = 0, seenself = 0;
			for (int i = 0; i < np && !full; i++) {
				const struct lxp_pentry *e = lxp_pent_at(i);
				if (!e)
					break;
				char pidstr[12];
				lxp_text_t pid_text = lxp_text_make(pidstr, sizeof(pidstr) - 1);
				lxp_text_u64(&pid_text, (uint64_t)e->pid);
				size_t k = pid_text.length;
				pidstr[k] = '\0';
				seen1 |= (e->pid == 1);
				seenself |= (e->pid == p->pid);
				if (!dirent_emit(sink, &pos, s, ino++, pidstr, LXP_S_IFDIR))
					full = 1;
			}
			/* fallbacks before the first snapshot refresh populates the table */
			if (!full && !seen1 &&
			    !dirent_emit(sink, &pos, s, ino++, "1", LXP_S_IFDIR))
				full = 1;
			if (!full && !seenself && p->pid != 1) {
				char pidstr[12];
				lxp_text_t pid_text = lxp_text_make(pidstr, sizeof(pidstr) - 1);
				lxp_text_u64(&pid_text, (uint64_t)p->pid);
				size_t k = pid_text.length;
				pidstr[k] = '\0';
				if (!dirent_emit(sink, &pos, s, ino++, pidstr, LXP_S_IFDIR))
					full = 1;
			}
		} else if (dpid > 0 && !file && proc_pid_known(p, dpid)) {
			static const char *const pf[] = {"stat", "cmdline", "status", "comm", NULL};
			uint64_t ino = 300000;
			for (int i = 0; pf[i] && !full; i++)
				if (!dirent_emit(sink, &pos, s, ino++, pf[i], LXP_S_IFREG))
					full = 1;
		}
	}
	if (sink->error)
		return sink->error;
	if (full && sink->filled == 0)
		return -LXP_EINVAL; /* buffer too small for even one entry */
	return (long)sink->filled;
}
