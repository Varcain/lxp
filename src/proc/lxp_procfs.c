/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * Synthetic /proc content generation: builds the read-only text of /proc/<file> and
 * /proc/<pid>/...  on open (version, uptime, meminfo, cpuinfo, mounts, stat, self/exe,
 * ...). The syscall dispatcher owns the /proc fd backing (g_procf) + open glue and
 * calls proc_is / proc_mode / proc_gen here (see proc/lxp_procfs.h).
 */
#include "proc/lxp_procfs.h"

#include "lxp/lxp_config.h"
#include "lxp/lxp_stats.h"
#include "lxp/lxp_syscall.h"
#include "lxp_internal.h"
#if LXP_ENABLE_NET
#include "lxp/lxp_net.h"
#endif

#include <string.h>

/* ---- synthetic /proc (read-only, generated on open) ----------------------- */
static size_t p_str(char *o, size_t off, size_t cap, const char *s)
{
	while (*s && off < cap)
		o[off++] = *s++;
	return off;
}
size_t p_dec(char *o, size_t off, size_t cap, uint64_t v)
{
	char t[20];
	int n = 0;
	if (!v)
		t[n++] = '0';
	while (v) {
		t[n++] = (char)('0' + v % 10u);
		v /= 10u;
	}
	while (n && off < cap)
		o[off++] = t[--n];
	return off;
}
#if LXP_ENABLE_NET
/* Format a 4-byte IPv4 address as the 8 upper-hex digits the kernel writes in
 * /proc/net/route: the __be32 value read in the host's (little-endian) order. */
static size_t p_hexle(char *o, size_t off, size_t cap, const uint8_t a[4])
{
	static const char h[] = "0123456789ABCDEF";
	for (int i = 3; i >= 0; i--) {
		if (off < cap)
			o[off++] = h[a[i] >> 4];
		if (off < cap)
			o[off++] = h[a[i] & 0xf];
	}
	return off;
}
#endif

/* True for any path inside the synthetic /proc tree. */
int proc_is(const char *abs)
{
	return strcmp(abs, "/proc") == 0 || strncmp(abs, "/proc/", 6) == 0;
}

/* Parse "/proc/<pid|self>[/file]": returns the pid (>0) + sets *file to the
 * trailing component (NULL if the path is the /proc/<pid> dir itself), or 0. */
int proc_pid(const char *abs, const lxp_proc_t *p, const char **file)
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
			if (pid < 1000000) /* clamp: no real pid is this large; guards int overflow (UB) */
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

int proc_pid_known(const lxp_proc_t *p, int pid)
{
	/* pid 1 + the running process are always valid; every other live Linux slot
	 * and RTOS kernel thread comes from the ps/top snapshot. */
	return pid == 1 || pid == p->pid || lxp_pent_find(pid) != NULL;
}

const char *const g_proc_files[] = {"version", "uptime",	 "meminfo",	"cpuinfo", "mounts",
					   "stat",    "loadavg", "filesystems", NULL};

/* st_mode for a /proc node, or 0 if the path is not a synthetic /proc node. */
uint32_t proc_mode(const char *abs, const lxp_proc_t *p)
{
	if (strcmp(abs, "/proc") == 0)
		return LXP_S_IFDIR | 0555u;
	if (strcmp(abs, "/proc/self") == 0)
		return LXP_S_IFLNK | 0777u;
	const char *file;
	int pid = proc_pid(abs, p, &file);
	if (pid > 0)
		return !proc_pid_known(p, pid) ? 0u
		       : file		       ? (LXP_S_IFREG | 0444u)
					       : (LXP_S_IFDIR | 0555u);
#if LXP_ENABLE_NET
	if (strcmp(abs, "/proc/net") == 0)
		return LXP_S_IFDIR | 0555u;
	if (strcmp(abs, "/proc/net/dev") == 0 || strcmp(abs, "/proc/net/route") == 0)
		return LXP_S_IFREG | 0444u;
#endif
	for (int i = 0; g_proc_files[i]; i++)
		if (strcmp(abs + 6, g_proc_files[i]) == 0)
			return LXP_S_IFREG | 0444u;
	return 0;
}

/* Generate the content of a /proc FILE into buf[cap]; returns length, or -1. */
long proc_gen(const char *abs, const lxp_proc_t *p, char *buf, size_t cap)
{
	size_t o = 0;
	const char *file;
	int pid = proc_pid(abs, p, &file);
	if (pid > 0 && file) {
		if (!proc_pid_known(p, pid))
			return -1;
		/* Metadata from the ps/top snapshot; fall back to pid 1 / the current
		 * process before the first snapshot refresh. comm is the bare name —
		 * kernel threads get an empty cmdline so ps/top bracket them as [name]. */
		const struct lxp_pentry *e = lxp_pent_find(pid);
		char comm[20];
		int ppid, is_kernel;
		char state;
		uint64_t cpu_us;
		size_t ci = 0;
		if (e) {
			for (const char *s = e->comm; *s && ci < sizeof(comm) - 1; s++)
				comm[ci++] = *s;
			ppid = e->ppid;
			state = e->state;
			cpu_us = e->cpu_us;
			is_kernel = e->is_kernel;
		} else {
			const char *c = (pid == 1)			? "init"
					: (pid == p->pid && p->comm[0]) ? p->comm
									: "busybox";
			for (const char *s = c; *s && ci < sizeof(comm) - 1; s++)
				comm[ci++] = *s;
			ppid = (pid == 1) ? 0 : (pid == p->pid) ? p->ppid : 1;
			state = (pid == p->pid) ? 'R' : 'S';
			cpu_us = lxp_proc_cpu_us(pid);
			is_kernel = 0;
		}
		comm[ci] = '\0';
		uint64_t utime = cpu_us / 10000ull; /* USER_HZ = 100 → jiffies */
		if (strcmp(file, "stat") == 0) {
			o = p_dec(buf, o, cap, (uint64_t)pid);
			o = p_str(buf, o, cap, " (");
			o = p_str(buf, o, cap, comm);
			o = p_str(buf, o, cap, ") ");
			if (o < cap)
				buf[o++] = state;
			o = p_str(buf, o, cap, " ");
			o = p_dec(buf, o, cap, (uint64_t)ppid);
			/* fields 5..13 (pgrp..cmajflt), then field 14 utime, then 15..24. */
			o = p_str(buf, o, cap, " 0 0 0 0 0 0 0 0 0 ");
			o = p_dec(buf, o, cap, utime);
			o = p_str(buf, o, cap, " 0 0 0 0 0 0 0 0 0 0\n");
		} else if (strcmp(file, "cmdline") == 0) {
			/* kernel threads have a 0-byte cmdline so ps/top bracket them. */
			if (!is_kernel) {
				o = p_str(buf, o, cap, comm);
				if (o < cap)
					buf[o++] = '\0';
			}
		} else if (strcmp(file, "comm") == 0) {
			o = p_str(buf, o, cap, comm);
			o = p_str(buf, o, cap, "\n");
		} else if (strcmp(file, "status") == 0) {
			o = p_str(buf, o, cap, "Name:\t");
			o = p_str(buf, o, cap, comm);
			o = p_str(buf, o, cap, "\nState:\t");
			if (o < cap)
				buf[o++] = state;
			o = p_str(buf, o, cap,
				  (state == 'R') ? " (running)\nPid:\t" : " (sleeping)\nPid:\t");
			o = p_dec(buf, o, cap, (uint64_t)pid);
			o = p_str(buf, o, cap, "\nPPid:\t");
			o = p_dec(buf, o, cap, (uint64_t)ppid);
			o = p_str(buf, o, cap, "\n");
		} else {
			return -1;
		}
		return (long)o;
	}
	if (strcmp(abs, "/proc/version") == 0) {
		o = p_str(buf, o, cap, "Linux version 6.1.0 (overtos) (uClibc) #1 oveRTOS\n");
	} else if (strcmp(abs, "/proc/uptime") == 0) {
		uint64_t ns = 0;
		lxp_time_ns(&ns);
		o = p_dec(buf, o, cap, ns / 1000000000ull);
		o = p_str(buf, o, cap, ".00 ");
		o = p_dec(buf, o, cap, ns / 1000000000ull);
		o = p_str(buf, o, cap, ".00\n");
	} else if (strcmp(abs, "/proc/meminfo") == 0) {
		struct lxp_mem_stats m;
		(void)lxp_mem_stats(&m);
		o = p_str(buf, o, cap, "MemTotal:       ");
		o = p_dec(buf, o, cap, m.total / 1024u);
		o = p_str(buf, o, cap, " kB\nMemFree:        ");
		o = p_dec(buf, o, cap, m.free / 1024u);
		o = p_str(buf, o, cap, " kB\nMemAvailable:   ");
		o = p_dec(buf, o, cap, m.free / 1024u);
		o = p_str(buf, o, cap,
			  " kB\nBuffers:           0 kB\nCached:            0 kB\n"
			  "SReclaimable:      0 kB\n");
	} else if (strcmp(abs, "/proc/cpuinfo") == 0) {
		o = p_str(buf, o, cap,
			  "processor\t: 0\nmodel name\t: ARM Cortex-M\nFeatures\t: thumb\n\n");
	} else if (strcmp(abs, "/proc/mounts") == 0) {
		o = p_str(buf, o, cap,
			  "rootfs / rootfs ro 0 0\nproc /proc proc rw 0 0\n"
			  "tmpfs /tmp tmpfs rw 0 0\n");
	} else if (strcmp(abs, "/proc/stat") == 0) {
		/* All busy time is reported as "user"; top derives %CPU from the
		 * user-vs-idle delta between two reads (USER_HZ = 100 → jiffies). */
		uint64_t idle_us = 0, busy_us = 0;
		lxp_cpu_totals(&idle_us, &busy_us);
		uint64_t user = busy_us / 10000ull, idle = idle_us / 10000ull;
		o = p_str(buf, o, cap, "cpu  ");
		o = p_dec(buf, o, cap, user);
		o = p_str(buf, o, cap, " 0 0 ");
		o = p_dec(buf, o, cap, idle);
		o = p_str(buf, o, cap, " 0 0 0 0 0 0\ncpu0 ");
		o = p_dec(buf, o, cap, user);
		o = p_str(buf, o, cap, " 0 0 ");
		o = p_dec(buf, o, cap, idle);
		o = p_str(buf, o, cap, " 0 0 0 0 0 0\nctxt 0\nbtime 0\n");
	} else if (strcmp(abs, "/proc/loadavg") == 0) {
		int nproc = lxp_pent_count();
		o = p_str(buf, o, cap, "0.00 0.00 0.00 1/");
		o = p_dec(buf, o, cap, (uint64_t)(nproc > 0 ? nproc : 1));
		o = p_str(buf, o, cap, " ");
		o = p_dec(buf, o, cap, (uint64_t)p->pid);
		o = p_str(buf, o, cap, "\n");
	} else if (strcmp(abs, "/proc/filesystems") == 0) {
		o = p_str(buf, o, cap, "nodev\tproc\nnodev\ttmpfs\n");
#if LXP_ENABLE_NET
	} else if (strcmp(abs, "/proc/net/dev") == 0) {
		/* busybox ifconfig reads this to enumerate interfaces + show RX/TX stats.
		 * ove_net has no per-interface counters, so report zeros. */
		o = p_str(buf, o, cap,
			  "Inter-|   Receive                                                |  Transmit\n"
			  " face |bytes    packets errs drop fifo frame compressed multicast|bytes    "
			  "packets errs drop fifo colls carrier compressed\n");
		/* One interface (eth0). The SIOC* ioctls ignore ifr_name, so listing a
		 * loopback here would make busybox print it with eth0's data — omit it. */
		if (lxp_sock_ifsnapshot(NULL, NULL, NULL, NULL, NULL) == 0)
			o = p_str(buf, o, cap,
				  "  eth0:       0       0    0    0    0     0          0         0"
				  "        0       0    0    0    0     0       0          0\n");
	} else if (strcmp(abs, "/proc/net/route") == 0) {
		uint8_t ip[4] = {0}, gw[4] = {0}, nm[4] = {0};
		o = p_str(buf, o, cap,
			  "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU"
			  "\tWindow\tIRTT\n");
		if (lxp_sock_ifsnapshot(ip, gw, nm, NULL, NULL) == 0) {
			uint8_t net[4];
			for (int i = 0; i < 4; i++)
				net[i] = (uint8_t)(ip[i] & nm[i]);
			/* local subnet: dest = ip & mask, no gateway, flags = UP */
			o = p_str(buf, o, cap, "eth0\t");
			o = p_hexle(buf, o, cap, net);
			o = p_str(buf, o, cap, "\t00000000\t0001\t0\t0\t0\t");
			o = p_hexle(buf, o, cap, nm);
			o = p_str(buf, o, cap, "\t0\t0\t0\n");
			/* default route: dest = 0, gateway = gw, flags = UP|GATEWAY */
			if (gw[0] | gw[1] | gw[2] | gw[3]) {
				o = p_str(buf, o, cap, "eth0\t00000000\t");
				o = p_hexle(buf, o, cap, gw);
				o = p_str(buf, o, cap, "\t0003\t0\t0\t0\t00000000\t0\t0\t0\n");
			}
		}
#endif
	} else {
		return -1;
	}
	return (long)o;
}
