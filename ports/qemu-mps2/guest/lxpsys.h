/* Minimal FDPIC guest syscall shims for the lxp QEMU harness. ARM EABI numbers,
 * matching the module's impersonation (write=4, read=3, ...). No libc, no globals:
 * everything is inline svc + PC-relative string literals, so the guests carry no
 * GOT dependency (r9 is preserved but unused). */
#ifndef LXP_GUEST_LXPSYS_H
#define LXP_GUEST_LXPSYS_H

static inline long lxp_svc0(long nr, long a0)
{
	register long r0 __asm__("r0") = a0;
	register long r7 __asm__("r7") = nr;
	__asm__ volatile("svc 0" : "+r"(r0) : "r"(r7) : "memory");
	return r0;
}
static inline long lxp_svc1(long nr, long a0, long a1)
{
	register long r0 __asm__("r0") = a0;
	register long r1 __asm__("r1") = a1;
	register long r7 __asm__("r7") = nr;
	__asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r7) : "memory");
	return r0;
}
static inline long lxp_svc3(long nr, long a0, long a1, long a2)
{
	register long r0 __asm__("r0") = a0;
	register long r1 __asm__("r1") = a1;
	register long r2 __asm__("r2") = a2;
	register long r7 __asm__("r7") = nr;
	__asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
	return r0;
}
static inline long lxp_svc4(long nr, long a0, long a1, long a2, long a3)
{
	register long r0 __asm__("r0") = a0;
	register long r1 __asm__("r1") = a1;
	register long r2 __asm__("r2") = a2;
	register long r3 __asm__("r3") = a3;
	register long r7 __asm__("r7") = nr;
	__asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r7) : "memory");
	return r0;
}

/* Six-argument form (r0-r5 + nr in r7). lxp_syscall/lxp_dispatch already accept a0-a5; this
 * lets a guest issue statx (buf in a4), mmap2 (a4/a5), pread64 (a4) etc. r4/r5 are callee-saved,
 * so the compiler spills them around the trap. */
static inline long lxp_svc6(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
	register long r0 __asm__("r0") = a0;
	register long r1 __asm__("r1") = a1;
	register long r2 __asm__("r2") = a2;
	register long r3 __asm__("r3") = a3;
	register long r4 __asm__("r4") = a4;
	register long r5 __asm__("r5") = a5;
	register long r7 __asm__("r7") = nr;
	__asm__ volatile("svc 0"
			 : "+r"(r0)
			 : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7)
			 : "memory");
	return r0;
}

static inline long sys_getpid(void)
{
	return lxp_svc0(20, 0);
}
static inline long sys_brk(unsigned long addr)
{
	return lxp_svc0(45, (long)addr);
}
static inline long sys_kill(int pid, int sig)
{
	return lxp_svc1(37, pid, sig);
}
static inline long sys_mmap2(unsigned long addr, unsigned long len, long prot, long flags, long fd,
			     long off)
{
	return lxp_svc6(192, (long)addr, (long)len, prot, flags, fd, off);
}
static inline long sys_statx(int dirfd, const char *path, int flags, unsigned mask, void *buf)
{
	return lxp_svc6(397, dirfd, (long)path, flags, (long)mask, (long)buf, 0);
}

static inline long sys_read(int fd, void *buf, unsigned long n)
{
	return lxp_svc3(3, fd, (long)buf, (long)n);
}
static inline long sys_write(int fd, const void *buf, unsigned long n)
{
	return lxp_svc3(4, fd, (long)buf, (long)n);
}
static inline long sys_close(int fd)
{
	return lxp_svc0(6, fd);
}
static inline long sys_execve(const char *path, char *const argv[], char *const envp[])
{
	return lxp_svc3(11, (long)path, (long)argv, (long)envp);
}
static inline long sys_wait4(int pid, int *status, int opts, void *rusage)
{
	return lxp_svc4(114, pid, (long)status, opts, (long)rusage);
}
static inline long sys_pipe(int fds[2])
{
	return lxp_svc0(42, (long)fds);
}
static inline long sys_vfork(void)
{
	register long r0 __asm__("r0");
	register long r7 __asm__("r7") = 190; /* ARM EABI NR_vfork */
	__asm__ volatile("svc 0" : "=r"(r0) : "r"(r7) : "memory");
	return r0;
}
static inline void sys_exit(int code)
{
	lxp_svc0(248, code); /* NR_exit_group */
	for (;;) {
	}
}

#endif /* LXP_GUEST_LXPSYS_H */
