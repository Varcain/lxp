/* M4 syscall-conformance guest: drive the paths host cmocka CANNOT reach — the SVC decode +
 * lxp_dispatch resume-register ABI, the 32-bit-r0 truncation, the -errno sign through the real
 * exception frame, the >4-arg (svc6) struct-returning marshalling (statx), and the run-loop-
 * intercepted fork/kill/wait4 machinery. Prints "lxp-m4-ok" only if every check passes; any
 * miss prints "lxp-m4-FAIL". Built static-FDPIC. See ports/qemu-mps2/README.md.
 *
 * Host cmocka calls lxp_syscall() directly, so it never exercises the r7 nr-decode, the
 * arg-register marshalling, the (uint32_t)r return truncation, or the capture/prog_tramp resume
 * ABI (the class of the earlier M2 wait4 r1-r3 bug). Those live only on this path. */
#include "lxpsys.h"

/* Issue a benign trap (getpid) with sentinels in r1-r3 and read them back within the same asm
 * block, so the compiler cannot reload them from memory — a direct observation that the SVC
 * round-trip preserves the caller's r1-r3 (only r0 is the return). */
static int regs_preserved(void)
{
	long o0, o1, o2, o3;
	__asm__ volatile("mov r1, %[s1]\n\t"
			 "mov r2, %[s2]\n\t"
			 "mov r3, %[s3]\n\t"
			 "mov r7, #20\n\t" /* __NR_getpid: ignores r1-r3 */
			 "svc 0\n\t"
			 "mov %[o0], r0\n\t"
			 "mov %[o1], r1\n\t"
			 "mov %[o2], r2\n\t"
			 "mov %[o3], r3\n\t"
			 : [o0] "=&r"(o0), [o1] "=&r"(o1), [o2] "=&r"(o2), [o3] "=&r"(o3)
			 : [s1] "r"(0x11111111L), [s2] "r"(0x22222222L), [s3] "r"(0x33333333L)
			 : "r0", "r1", "r2", "r3", "r7", "memory");
	return o0 >= 1 /* a valid pid in r0 */
	       && o1 == 0x11111111L && o2 == 0x22222222L && o3 == 0x33333333L;
}

void _start(void)
{
	int ok = 1;

	/* 1. resume-register ABI: r1-r3 survive the trap (no exception frame exists host-side). */
	ok &= regs_preserved();

	/* 2. -errno sign through the real frame: write(badfd) -> -EBADF, seen as 0xFFFFFFF7. */
	ok &= ((int)sys_write(99, "x", 1) == -9);

	/* 3. 32-bit r0 address width: brk + anonymous mmap return usable low memory, and it is
	 *    genuinely writable (the value survives the (uint32_t)r0 truncation exactly). */
	ok &= (sys_brk(0) > 0x1000);
	long m = sys_mmap2(0, 4096, 3 /*PROT_R|W*/, 0x20 /*MAP_ANONYMOUS*/, -1, 0);
	ok &= (m > 0x1000);
	*(volatile unsigned char *)m = 0xa5;
	ok &= (*(volatile unsigned char *)m == 0xa5);

	/* 4. real-frame statx via the 6-arg shim (buf in a4): a rootfs file is a regular file with
	 *    a non-zero size — proves >4-arg register marshalling + struct fill on the SVC path. */
	unsigned char sx[256];
	long sr = sys_statx(-100 /*AT_FDCWD*/, "/child", 0, 0, sx);
	unsigned short stx_mode;
	unsigned int stx_size;
	__builtin_memcpy(&stx_mode, sx + 28, 2); /* stx_mode @ offset 28 */
	__builtin_memcpy(&stx_size, sx + 40, 4); /* stx_size @ offset 40 */
	ok &= (sr == 0 && (stx_mode & 0xf000) == 0x8000 /*S_IFREG*/ && stx_size > 0);

	/* 5. kill dispatch validation: an out-of-range signal is rejected with -EINVAL (kill,
	 *    tkill and tgkill are intercepted in lxp_dispatch, sharing this check). */
	ok &= ((int)sys_kill(1, 999) == -22 /*EINVAL*/);

	/* 6. run-loop-intercepted process + signal delivery: vfork a child that execs /spin (which
	 *    parks in a console read), signal it with SIGTERM, and reap it. wait4 must report
	 *    WIFSIGNALED with the signal in the low 7 bits (lxp_encode_wstatus). This is the only
	 *    exercise of cross-process kill delivery + a signal-terminated reap. */
	long pid = sys_vfork();
	if (pid == 0) {
		char *const av[] = {"spin", 0};
		sys_execve("/spin", av, 0);
		sys_exit(127); /* execve returned -> failure */
	}
	if (pid > 0) {
		sys_kill((int)pid, 15 /*SIGTERM*/);
		int status = 0;
		long w = sys_wait4((int)pid, &status, 0, 0);
		ok &= (w == pid && (status & 0x7f) == 15 && (status & 0xff00) == 0);
	} else {
		ok = 0; /* vfork failed */
	}

	sys_write(1, ok ? "lxp-m4-ok\n" : "lxp-m4-FAIL\n", ok ? 10 : 12);
	sys_exit(ok ? 0 : 1);
}
