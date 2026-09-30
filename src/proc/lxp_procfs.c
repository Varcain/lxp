/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Synthetic /proc content generation: builds the read-only text of /proc/<file> and
 * /proc/<pid>/...  on open (version, uptime, meminfo, cpuinfo, mounts, stat, self/exe,
 * ...), and the FD_PROC descriptors that hold it.
 */
#include "proc/lxp_procfs.h"

#include "fs/lxp_dir.h"
#include "fs/lxp_mount.h"
#include "fs/lxp_path.h"
#include "fs/lxp_stat.h"
#include "fs/lxp_vfs.h"
#include "lxp/lxp_config.h"
#include "proc/lxp_proc.h"
#include "lxp/lxp_stats.h"
#include "lxp_internal.h"
#include "lxp_text.h"
#if LXP_ENABLE_BLOCK
#include "dev/lxp_dev_block.h"
#endif
#if LXP_ENABLE_FS
#include "fs/lxp_hostfs.h"
#include "lxp_provider.h"
#endif
#if LXP_ENABLE_NET
#include "net/lxp_net.h"
#endif

#include <string.h>

/* ---- synthetic /proc (read-only, generated on open) ----------------------- */
#if LXP_ENABLE_FS
/* /proc/mounts uses the fstab escaping convention for whitespace and '\\'. */
static void p_mount_field(lxp_text_t *text, const char *s)
{
	while (*s) {
		const char *escape = NULL;
		switch (*s) {
		case ' ':
			escape = "\\040";
			break;
		case '\t':
			escape = "\\011";
			break;
		case '\n':
			escape = "\\012";
			break;
		case '\\':
			escape = "\\134";
			break;
		default:
			lxp_text_putc(text, *s);
			break;
		}
		if (escape)
			lxp_text_puts(text, escape);
		s++;
	}
}
#endif
#if LXP_ENABLE_NET
/* Format a 4-byte IPv4 address as the 8 upper-hex digits the kernel writes in
 * /proc/net/route: the __be32 value read in the host's (little-endian) order. */
static void p_hexle(lxp_text_t *text, const uint8_t a[4])
{
	static const char h[] = "0123456789ABCDEF";
	for (int i = 3; i >= 0; i--) {
		lxp_text_putc(text, h[a[i] >> 4]);
		lxp_text_putc(text, h[a[i] & 0xf]);
	}
}
#endif

/* True for any path inside the synthetic /proc tree. */
int lxp_proc_is(const char *abs)
{
	return strcmp(abs, "/proc") == 0 || strncmp(abs, "/proc/", 6) == 0;
}

/* Parse "/proc/<pid|self>[/file]": returns the pid (>0) + sets *file to the
 * trailing component (NULL if the path is the /proc/<pid> dir itself), or 0. */
int lxp_proc_pid(const char *abs, const lxp_proc_t *p, const char **file)
{
	*file = NULL;
	if (strncmp(abs, "/proc/", 6) != 0)
		return 0;
	const char *s = abs + 6;
	int pid = 0;
	if (strncmp(s, "self", 4) == 0 && (s[4] == '\0' || s[4] == '/')) {
		pid = p->pid;
		s += 4;
	} else if (*s >= '0' && *s <= '9') {
		while (*s >= '0' && *s <= '9') {
			if (pid <
			    1000000) /* clamp: no real pid is this large; guards int overflow (UB) */
				pid = pid * 10 + (*s - '0');
			s++;
		}
	} else {
		return 0;
	}
	if (*s == '/')
		*file = s + 1;
	else if (*s != '\0')
		return 0;
	return pid;
}

int lxp_proc_pid_known(const lxp_proc_t *p, int pid)
{
	/* pid 1 + the running process are always valid; every other live Linux slot
	 * and RTOS kernel thread comes from the ps/top snapshot. */
	return pid == 1 || pid == p->pid || lxp_pent_find(pid) != NULL;
}

const char *const g_lxp_proc_files[] = {"version",	  "uptime",	 "meminfo", "lxp_resources",
#if LXP_ENABLE_FS
				    "lxp_fs",
#endif
#if LXP_ENABLE_BLOCK
				    "partitions",
#endif
				    "rt_scope",	  "cpuinfo",	 "mounts",  "stat",
				    "loadavg",	  "filesystems", NULL};

/* st_mode for a /proc node, or 0 if the path is not a synthetic /proc node. */
uint32_t lxp_proc_mode(const char *abs, const lxp_proc_t *p)
{
	if (strcmp(abs, "/proc") == 0)
		return LXP_S_IFDIR | 0555u;
	if (strcmp(abs, "/proc/self") == 0)
		return LXP_S_IFLNK | 0777u;
	const char *file;
	int pid = lxp_proc_pid(abs, p, &file);
	if (pid > 0)
		return !lxp_proc_pid_known(p, pid) ? 0u
		       : file		       ? (LXP_S_IFREG | 0444u)
					       : (LXP_S_IFDIR | 0555u);
#if LXP_ENABLE_NET
	if (strcmp(abs, "/proc/net") == 0)
		return LXP_S_IFDIR | 0555u;
	if (strcmp(abs, "/proc/net/dev") == 0 || strcmp(abs, "/proc/net/route") == 0)
		return LXP_S_IFREG | 0444u;
#endif
	for (int i = 0; g_lxp_proc_files[i]; i++)
		if (strcmp(abs + 6, g_lxp_proc_files[i]) == 0)
			return LXP_S_IFREG | 0444u;
	return 0;
}

/* Generate the content of a /proc FILE into buf[cap]; returns length, or -1. */
long lxp_proc_gen(const char *abs, const lxp_proc_t *p, char *buf, size_t cap)
{
	lxp_text_t text = lxp_text_make(buf, cap);
	const char *file;
	int pid = lxp_proc_pid(abs, p, &file);
	if (pid > 0 && file) {
		if (!lxp_proc_pid_known(p, pid))
			return -1;
		/* Metadata from the ps/top snapshot; fall back to pid 1 / the current
		 * process before the first snapshot refresh. comm is the bare name —
		 * kernel threads get an empty cmdline so ps/top bracket them as [name]. */
		const struct lxp_pentry *e = lxp_pent_find(pid);
		char comm[20];
		int ppid, nice, is_kernel;
		char state;
		uint64_t cpu_us;
		size_t ci = 0;
		if (e) {
			for (const char *s = e->comm; *s && ci < sizeof(comm) - 1; s++)
				comm[ci++] = *s;
			ppid = e->ppid;
			state = e->state;
			cpu_us = e->cpu_us;
			nice = e->nice;
			is_kernel = e->is_kernel;
		} else {
			const char *c = (pid == 1)			? "init"
					: (pid == p->pid && p->comm[0]) ? p->comm
									: "busybox";
			for (const char *s = c; *s && ci < sizeof(comm) - 1; s++)
				comm[ci++] = *s;
			ppid = (pid == 1) ? 0 : (pid == p->pid) ? p->group->ppid : 1;
			state = (pid == p->pid) ? 'R' : 'S';
			cpu_us = lxp_proc_cpu_us(pid);
			nice = pid == p->pid ? lxp_proc_nice_get(p) : 0;
			is_kernel = 0;
		}
		comm[ci] = '\0';
		uint64_t utime = cpu_us / 10000ull; /* USER_HZ = 100 → jiffies */
		if (strcmp(file, "stat") == 0) {
			lxp_text_u64(&text, (uint64_t)pid);
			lxp_text_puts(&text, " (");
			lxp_text_puts(&text, comm);
			lxp_text_puts(&text, ") ");
			lxp_text_putc(&text, state);
			lxp_text_puts(&text, " ");
			lxp_text_u64(&text, (uint64_t)ppid);
			/* fields 5..13 (pgrp..cmajflt), then field 14 utime, then 15..24. */
			lxp_text_puts(&text, " 0 0 0 0 0 0 0 0 0 ");
			lxp_text_u64(&text, utime);
			lxp_text_puts(&text, " 0 0 0 ");
			lxp_text_s64(&text, 20 + nice);
			lxp_text_puts(&text, " ");
			lxp_text_s64(&text, nice);
			lxp_text_puts(&text, " 0 0 0 0 0\n");
		} else if (strcmp(file, "cmdline") == 0) {
			/* kernel threads have a 0-byte cmdline so ps/top bracket them. */
			if (!is_kernel) {
				lxp_text_puts(&text, comm);
				lxp_text_putc(&text, '\0');
			}
		} else if (strcmp(file, "comm") == 0) {
			lxp_text_puts(&text, comm);
			lxp_text_puts(&text, "\n");
		} else if (strcmp(file, "status") == 0) {
			lxp_text_puts(&text, "Name:\t");
			lxp_text_puts(&text, comm);
			lxp_text_puts(&text, "\nState:\t");
			lxp_text_putc(&text, state);
			lxp_text_puts(&text, (state == 'R') ? " (running)\nPid:\t"
							    : " (sleeping)\nPid:\t");
			lxp_text_u64(&text, (uint64_t)pid);
			lxp_text_puts(&text, "\nPPid:\t");
			lxp_text_u64(&text, (uint64_t)ppid);
			lxp_text_puts(&text, "\nNice:\t");
			lxp_text_s64(&text, nice);
			lxp_text_puts(&text, "\n");
		} else {
			return -1;
		}
		return (long)text.length;
	}
	if (strcmp(abs, "/proc/version") == 0) {
		lxp_text_puts(&text, "Linux version 6.1.0 (");
		lxp_text_puts(&text, lxp_system_version());
		lxp_text_puts(&text, ") (uClibc)\n");
	} else if (strcmp(abs, "/proc/uptime") == 0) {
		uint64_t ns = 0;
		lxp_time_ns(&ns);
		lxp_text_u64(&text, ns / 1000000000ull);
		lxp_text_puts(&text, ".00 ");
		lxp_text_u64(&text, ns / 1000000000ull);
		lxp_text_puts(&text, ".00\n");
	} else if (strcmp(abs, "/proc/meminfo") == 0) {
		struct lxp_resource_stats resources;
		struct lxp_mem_stats heap;
		lxp_get_resource_stats(&resources);
		(void)lxp_mem_stats(&heap);
		lxp_text_puts(&text, "MemTotal:       ");
		lxp_text_u64(&text, resources.total_bytes / 1024u);
		lxp_text_puts(&text, " kB\nMemFree:        ");
		lxp_text_u64(&text, resources.free_bytes / 1024u);
		lxp_text_puts(&text, " kB\nMemAvailable:   ");
		lxp_text_u64(&text, resources.available_bytes / 1024u);
		lxp_text_puts(&text, " kB\nBuffers:           0 kB\nCached:            0 kB\n"
				     "SReclaimable:      0 kB\n");
		lxp_text_puts(&text, "LxpSlotsTotal:  ");
		lxp_text_u64(&text, resources.slots_total);
		lxp_text_puts(&text, "\nLxpSlotsFree:   ");
		lxp_text_u64(&text, resources.slots_free);
		lxp_text_puts(&text, "\nLxpRegionsTotal: ");
		lxp_text_u64(&text, resources.regions_total);
		lxp_text_puts(&text, "\nLxpRegionsFree: ");
		lxp_text_u64(&text, resources.regions_free);
		lxp_text_puts(&text, "\nHostHeapTotal:  ");
		lxp_text_u64(&text, heap.total / 1024u);
		lxp_text_puts(&text, " kB\nHostHeapFree:   ");
		lxp_text_u64(&text, heap.free / 1024u);
		lxp_text_puts(&text, " kB\n");
	} else if (strcmp(abs, "/proc/partitions") == 0) {
#if LXP_ENABLE_BLOCK
		return lxp_block_proc_partitions(buf, cap);
#else
		return -1;
#endif
	} else if (strcmp(abs, "/proc/lxp_resources") == 0) {
		struct lxp_resource_stats resources;
		struct lxp_mem_stats heap;
		lxp_get_resource_stats(&resources);
		(void)lxp_mem_stats(&heap);
#define RESOURCE_LINE(name, value)                      \
	do {                                            \
		lxp_text_puts(&text, name " ");         \
		lxp_text_u64(&text, (uint64_t)(value)); \
		lxp_text_puts(&text, "\n");             \
	} while (0)
		RESOURCE_LINE("slots_total", resources.slots_total);
		RESOURCE_LINE("slots_free", resources.slots_free);
		RESOURCE_LINE("regions_total", resources.regions_total);
		RESOURCE_LINE("regions_free", resources.regions_free);
		RESOURCE_LINE("program_region_bytes", resources.program_region_bytes);
		RESOURCE_LINE("dynamic_pool_bytes", resources.dynamic_pool_bytes);
		RESOURCE_LINE("guest_bytes_total", resources.total_bytes);
		RESOURCE_LINE("guest_bytes_free", resources.free_bytes);
		RESOURCE_LINE("guest_bytes_available", resources.available_bytes);
		RESOURCE_LINE("host_heap_total", heap.total);
		RESOURCE_LINE("host_heap_free", heap.free);
#undef RESOURCE_LINE
#if LXP_ENABLE_FS
	} else if (strcmp(abs, "/proc/lxp_fs") == 0) {
		lxp_fs_metrics_t metrics;
		memset(&metrics, 0, sizeof(metrics));
		int available = g_lxp_fs_ops != NULL && g_lxp_fs_ops->metrics != NULL &&
				g_lxp_fs_ops->metrics(&metrics) == LXP_OK;
#define FS_METRIC_LINE(name, value)                     \
	do {                                            \
		lxp_text_puts(&text, name " ");         \
		lxp_text_u64(&text, (uint64_t)(value)); \
		lxp_text_puts(&text, "\n");             \
	} while (0)
		FS_METRIC_LINE("provider_available", available);
		FS_METRIC_LINE("requests_submitted", metrics.requests_submitted);
		FS_METRIC_LINE("requests_completed", metrics.requests_completed);
		FS_METRIC_LINE("requests_failed", metrics.requests_failed);
		FS_METRIC_LINE("pending", metrics.pending);
		FS_METRIC_LINE("queue_depth_max", metrics.queue_depth_max);
		FS_METRIC_LINE("bytes_read", metrics.bytes_read);
		FS_METRIC_LINE("bytes_written", metrics.bytes_written);
		FS_METRIC_LINE("queue_wait_us_total", metrics.queue_wait_us_total);
		FS_METRIC_LINE("queue_wait_us_max", metrics.queue_wait_us_max);
		FS_METRIC_LINE("service_us_total", metrics.service_us_total);
		FS_METRIC_LINE("service_us_max", metrics.service_us_max);
		FS_METRIC_LINE("completion_wait_us_total", metrics.completion_wait_us_total);
		FS_METRIC_LINE("completion_wait_us_max", metrics.completion_wait_us_max);
		FS_METRIC_LINE("budget_overruns", metrics.budget_overruns);
		FS_METRIC_LINE("media_available", metrics.media_available);
		FS_METRIC_LINE("media_read_commands", metrics.media_read_commands);
		FS_METRIC_LINE("media_write_commands", metrics.media_write_commands);
		FS_METRIC_LINE("media_read_blocks", metrics.media_read_blocks);
		FS_METRIC_LINE("media_write_blocks", metrics.media_write_blocks);
		FS_METRIC_LINE("media_multiblock_commands", metrics.media_multiblock_commands);
		FS_METRIC_LINE("media_completion_wait_us_total",
			       metrics.media_completion_wait_us_total);
		FS_METRIC_LINE("media_completion_wait_us_max",
			       metrics.media_completion_wait_us_max);
		FS_METRIC_LINE("media_ready_wait_us_total", metrics.media_ready_wait_us_total);
		FS_METRIC_LINE("media_ready_wait_us_max", metrics.media_ready_wait_us_max);
		FS_METRIC_LINE("media_errors", metrics.media_errors);
		FS_METRIC_LINE("media_recoveries", metrics.media_recoveries);
#undef FS_METRIC_LINE
#endif
	} else if (strcmp(abs, "/proc/rt_scope") == 0) {
		long length = lxp_rt_scope_read(buf, cap);
		if (length < 0) {
			lxp_text_puts(&text, "available 0\n");
		} else {
			return length;
		}
	} else if (strcmp(abs, "/proc/cpuinfo") == 0) {
		lxp_text_puts(&text,
			      "processor\t: 0\nmodel name\t: ARM Cortex-M\nFeatures\t: thumb\n\n");
	} else if (strcmp(abs, "/proc/mounts") == 0) {
		lxp_text_puts(&text, "rootfs / rootfs ro 0 0\nproc /proc proc rw 0 0\n"
				     "tmpfs /tmp tmpfs rw 0 0\n");
#if LXP_ENABLE_FS
		if (lxp_hostfs_is_mounted()) {
			p_mount_field(&text, lxp_hostfs_mount_source());
			lxp_text_puts(&text, " ");
			p_mount_field(&text, lxp_hostfs_mount_path());
			lxp_text_puts(&text, " vfat ");
			lxp_text_puts(&text, lxp_hostfs_is_read_only() ? "ro" : "rw");
			lxp_text_puts(&text, ",nosuid,nodev,noexec 0 0\n");
		}
#endif
	} else if (strcmp(abs, "/proc/stat") == 0) {
		/* All busy time is reported as "user"; top derives %CPU from the
		 * user-vs-idle delta between two reads (USER_HZ = 100 → jiffies). */
		uint64_t idle_us = 0, busy_us = 0;
		lxp_cpu_totals(&idle_us, &busy_us);
		uint64_t user = busy_us / 10000ull, idle = idle_us / 10000ull;
		lxp_text_puts(&text, "cpu  ");
		lxp_text_u64(&text, user);
		lxp_text_puts(&text, " 0 0 ");
		lxp_text_u64(&text, idle);
		lxp_text_puts(&text, " 0 0 0 0 0 0\ncpu0 ");
		lxp_text_u64(&text, user);
		lxp_text_puts(&text, " 0 0 ");
		lxp_text_u64(&text, idle);
		lxp_text_puts(&text, " 0 0 0 0 0 0\nctxt 0\nbtime 0\n");
	} else if (strcmp(abs, "/proc/loadavg") == 0) {
		int nproc = lxp_pent_count();
		lxp_text_puts(&text, "0.00 0.00 0.00 1/");
		lxp_text_u64(&text, (uint64_t)(nproc > 0 ? nproc : 1));
		lxp_text_puts(&text, " ");
		lxp_text_u64(&text, (uint64_t)p->pid);
		lxp_text_puts(&text, "\n");
	} else if (strcmp(abs, "/proc/filesystems") == 0) {
		lxp_text_puts(&text, "nodev\tproc\nnodev\ttmpfs\n");
#if LXP_ENABLE_FS
		lxp_text_puts(&text, "\tvfat\n");
#endif
#if LXP_ENABLE_NET
	} else if (strcmp(abs, "/proc/net/dev") == 0) {
		/* busybox ifconfig reads this to enumerate interfaces + show RX/TX stats.
		 * The network-provider contract has no traffic counters, so report zeros. */
		lxp_text_puts(
			&text,
			"Inter-|   Receive                                                |  Transmit\n"
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    "
			"packets errs drop fifo colls carrier compressed\n");
		/* One interface (eth0). The SIOC* ioctls ignore ifr_name, so listing a
		 * loopback here would make busybox print it with eth0's data — omit it. */
		if (lxp_sock_ifsnapshot(NULL, NULL, NULL, NULL, NULL) == 0)
			lxp_text_puts(
				&text,
				"  eth0:       0       0    0    0    0     0          0         0"
				"        0       0    0    0    0     0       0          0\n");
	} else if (strcmp(abs, "/proc/net/route") == 0) {
		uint8_t ip[4] = {0}, gw[4] = {0}, nm[4] = {0};
		lxp_text_puts(
			&text,
			"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU"
			"\tWindow\tIRTT\n");
		if (lxp_sock_ifsnapshot(ip, gw, nm, NULL, NULL) == 0) {
			uint8_t net[4];
			for (int i = 0; i < 4; i++)
				net[i] = (uint8_t)(ip[i] & nm[i]);
			/* local subnet: dest = ip & mask, no gateway, flags = UP */
			lxp_text_puts(&text, "eth0\t");
			p_hexle(&text, net);
			lxp_text_puts(&text, "\t00000000\t0001\t0\t0\t0\t");
			p_hexle(&text, nm);
			lxp_text_puts(&text, "\t0\t0\t0\n");
			/* default route: dest = 0, gateway = gw, flags = UP|GATEWAY */
			if (gw[0] | gw[1] | gw[2] | gw[3]) {
				lxp_text_puts(&text, "eth0\t00000000\t");
				p_hexle(&text, gw);
				lxp_text_puts(&text, "\t0003\t0\t0\t0\t00000000\t0\t0\t0\n");
			}
		}
#endif
	} else {
		return -1;
	}
	return (long)text.length;
}

static uint32_t procfs_inode_of(uint32_t path_hash)
{
	return LXP_INO_PROC + (path_hash & 0xfffffu);
}

uint32_t lxp_procfs_inode(const char *abs)
{
	return procfs_inode_of(lxp_path_hash(LXP_PATH_HASH_INIT, abs));
}

uint32_t lxp_procfs_child_inode(const char *dir, const char *name)
{
	uint32_t hash = lxp_path_hash(lxp_path_hash(LXP_PATH_HASH_INIT, dir), "/");
	return procfs_inode_of(lxp_path_hash(hash, name));
}

/* ---- /proc descriptors (content generated on open) ------------------------ */
#define LXP_NPROCF 12
#define LXP_PROCBUF 1024
#define LXP_PROCPATH 64 /* /proc paths are short ("/proc/<pid>/status"); not LXP_PATH_MAX */
static struct {
	char path[LXP_PROCPATH];
	char buf[LXP_PROCBUF];
	size_t len;
	int is_dir;
	int used;
} g_procf[LXP_NPROCF];

void lxp_procfs_runtime_reset(void)
{
	memset(g_procf, 0, sizeof(g_procf));
}

long lxp_procfs_open(lxp_proc_t *p, const char *abs, int flags)
{
	uint32_t m = lxp_proc_mode(abs, p);
	if (m == 0 || (m & LXP_S_IFMT) == LXP_S_IFLNK)
		return -LXP_ENOENT;	 /* /proc/self resolves via readlink, not open */
	if (strlen(abs) >= LXP_PROCPATH) /* the cached path buffer is /proc-sized, not PATH_MAX */
		return -LXP_ENOENT;
	int dir = (m & LXP_S_IFMT) == LXP_S_IFDIR;
	for (int i = 0; i < LXP_NPROCF; i++) {
		if (g_procf[i].used)
			continue;
		long n = dir ? 0 : lxp_proc_gen(abs, p, g_procf[i].buf, LXP_PROCBUF);
		if (n < 0)
			return -LXP_ENOENT;
		strcpy(g_procf[i].path, abs);
		g_procf[i].len = (size_t)n;
		g_procf[i].is_dir = dir;
		g_procf[i].used = 1;
		int fd = lxp_fd_install(p, LXP_FD_PROC, i, flags);
		if (fd < 0)
			g_procf[i].used = 0; /* no fd installed → release the content slot */
		return fd;
	}
	return -LXP_EMFILE;
}

/* A /proc file read returns bytes from the content generated at open. */
static long fop_pread_proc(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len, uint64_t off)
{
	if (g_procf[s->file_idx].is_dir)
		return -LXP_EISDIR;
	return lxp_vfs_read_mem(p, g_procf[s->file_idx].buf, g_procf[s->file_idx].len, buf, len,
				off);
}

static long fop_read_proc(lxp_proc_t *p, lxp_ofd_t *s, void *buf, size_t len)
{
	long n = fop_pread_proc(p, s, buf, len, s->offset);
	if (n > 0)
		s->offset += (size_t)n;
	return n;
}

static long fop_getdents_proc(lxp_proc_t *p, lxp_ofd_t *s, lxp_dirent_sink_t *sink)
{
	if (!g_procf[s->file_idx].is_dir)
		return -LXP_ENOTDIR;
	return lxp_dir_list(p, s, g_procf[s->file_idx].path, sink);
}

/* /proc content is generated at open, so a file seeks within that snapshot and a
 * directory rewinds its listing (rewinddir). */
static int64_t fop_lseek_proc(lxp_proc_t *p, lxp_ofd_t *s, int64_t off, int whence)
{
	(void)p;
	return lxp_vfs_seek(s, (int64_t)g_procf[s->file_idx].len, off, whence);
}

static long fop_fstat_proc(lxp_proc_t *p, lxp_ofd_t *s, struct lxp_stat *st)
{
	(void)p;
	lxp_stat_init(st, lxp_procfs_inode(g_procf[s->file_idx].path),
		      g_procf[s->file_idx].is_dir ? (LXP_S_IFDIR | 0555u) : (LXP_S_IFREG | 0444u),
		      g_procf[s->file_idx].len);
	return 0;
}

static void fop_close_proc(lxp_proc_t *p, lxp_ofd_t *s)
{
	(void)p;
	g_procf[s->file_idx].used = 0; /* release the generated-content slot */
}

static long fop_dir_path_proc(lxp_proc_t *p, lxp_ofd_t *s, char *out, size_t cap)
{
	(void)p;
	if (!g_procf[s->file_idx].is_dir)
		return -LXP_ENOTDIR;
	return lxp_vfs_copy_path(g_procf[s->file_idx].path, out, cap);
}

const lxp_file_ops_t lxp_procfs_fops = {
	.read = fop_read_proc,
	.pread = fop_pread_proc,
	.lseek = fop_lseek_proc,
	.getdents = fop_getdents_proc,
	.dir_path = fop_dir_path_proc,
	.fstat = fop_fstat_proc,
	.close = fop_close_proc,
};

/* Every /proc file is read-only and /proc takes no new names, so a write open fails
 * as it does on Linux: EISDIR for a directory, else EACCES (ENOENT for a missing
 * name opened without O_CREAT). */
static long procfs_mount_open(lxp_proc_t *p, const char *path, int flags)
{
	if ((flags & LXP_O_ACCMODE) != LXP_O_RDONLY || (flags & (LXP_O_CREAT | LXP_O_TRUNC))) {
		uint32_t mode = lxp_proc_mode(path, p);
		if ((mode & LXP_S_IFMT) == LXP_S_IFDIR)
			return -LXP_EISDIR;
		return mode == 0 && !(flags & LXP_O_CREAT) ? -LXP_ENOENT : -LXP_EACCES;
	}
	return lxp_procfs_open(p, path, flags);
}

static long procfs_mount_stat(lxp_proc_t *p, const char *path, int follow, struct lxp_stat *st)
{
	uint32_t mode = lxp_proc_mode(path, p);
	if (mode == 0)
		return -LXP_ENOENT;
	if (follow && (mode & LXP_S_IFMT) == LXP_S_IFLNK) /* /proc/self: the caller's pid dir */
		mode = LXP_S_IFDIR | 0555u;
	lxp_stat_init(st, lxp_procfs_inode(path), mode, 0);
	return 0;
}

/* /proc/self names the caller's pid and /proc/self/exe its program; nothing else in /proc
 * is a symlink. */
static long procfs_mount_readlink(lxp_proc_t *p, const char *path, char *out, size_t cap)
{
	char pid[12];
	const char *target;
	size_t n;
	if (strcmp(path, "/proc/self") == 0) {
		lxp_text_t pid_text = lxp_text_make(pid, sizeof(pid));
		lxp_text_u64(&pid_text, (uint64_t)p->pid);
		target = pid;
		n = pid_text.length;
	} else if (strcmp(path, "/proc/self/exe") == 0) {
		/* The image execve re-runs for "/proc/self/exe" (exec_file_idx): programs
		 * readlink() it to learn where they were launched from. */
		int ei = p->exec_file_idx;
		if (ei < 0 || ei >= p->fs_count)
			return -LXP_ENOENT;
		target = p->fs[ei].path;
		n = strlen(target);
	} else {
		return lxp_proc_mode(path, p) ? -LXP_EINVAL : -LXP_ENOENT;
	}
	if (n > cap)
		n = cap;
	memcpy(out, target, n);
	return (long)n;
}

/* Every /proc file is read-only; only its directories are searchable. */
static long procfs_mount_access(lxp_proc_t *p, const char *path, int mode)
{
	struct lxp_stat st;
	long rc = procfs_mount_stat(p, path, 1, &st);
	if (rc < 0)
		return rc;
	if ((mode & 2) || ((mode & 1) && (st.mode & LXP_S_IFMT) != LXP_S_IFDIR))
		return -LXP_EACCES;
	return 0;
}

const lxp_mount_ops_t lxp_procfs_mount_ops = {
	.open = procfs_mount_open,
	.stat = procfs_mount_stat,
	.readlink = procfs_mount_readlink,
	.access = procfs_mount_access,
	.magic = LXP_PROC_SUPER_MAGIC,
	.name_errno = LXP_EPERM,
};
