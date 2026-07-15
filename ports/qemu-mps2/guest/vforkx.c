/* M8 parent guest: vfork + a deliberately FAILING execve + wait4 — the busybox
 * command-not-found path, end to end under the real engine seam. The child's exec
 * cannot succeed, so it _exits 127; the parent must resume from the vfork and reap
 * exactly that (region snapshot/restore intact, no fault, correct wait status).
 *
 * This complements init.c (M2 = SUCCESSFUL exec) with the failed-exec case, and is an
 * integration smoke test: the bug it was born from — a SIGCHLD interrupting the parent's
 * wait4 (the -EINTR reap) and the FDPIC-r9 restore across that signal — needs a parent
 * that PARKS in wait4 (vfork's child-exits-first timing precludes it) and a multi-module
 * FDPIC image (these guests are single-module + GOT-free). Those are guarded by the host
 * coordinator suite (reap_to_parent SIGCHLD suppression) and the on-target busybox rootfs;
 * here we lock down that the failed-exec vfork path itself reaps 127 without faulting. */
#include "lxpsys.h"

void _start(void)
{
	long pid = sys_vfork();
	if (pid == 0) {
		char *const cargv[] = {"x", 0};
		sys_execve("/no/such/program", cargv, 0);
		sys_exit(127); /* execve failed → exit like a shell's command-not-found */
	}
	if (pid < 0)
		sys_exit(102);

	int status = 0;
	long w = sys_wait4((int)pid, &status, 0, 0);

	int ok = (w == pid) && ((status & 0x7f) == 0) && (((status >> 8) & 0xff) == 127);
	sys_write(1, ok ? "lxp-m8-ok\n" : "lxp-m8-FAIL\n", ok ? 10 : 12);
	sys_exit(ok ? 0 : 1);
}
