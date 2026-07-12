/* M2 parent guest: pipe + vfork + execve(/child) + wait4, verifying the child's
 * pipe byte and exit status. Exercises the multi-slot process model end-to-end:
 * spawn_launch (the vfork child + the exec'd image) and spawn_resume (the vfork
 * parent resuming, and wait4 delivering the reaped status). Built static-FDPIC. */
#include "lxpsys.h"

void _start(void)
{
	int p[2];
	if (sys_pipe(p) != 0)
		sys_exit(101);

	long pid = sys_vfork();
	if (pid == 0) {
		/* child: replace this image with /child. It inherits the pipe write end
		 * (fd p[1]==4) across execve. argv proves argument plumbing survives exec. */
		char *const cargv[] = {"child", 0};
		sys_execve("/child", cargv, 0);
		sys_exit(127); /* execve returned → failure */
	}
	if (pid < 0)
		sys_exit(102);

	/* parent (resumed the instant the child exec'd into its own image). */
	char c = 0;
	long n = sys_read(p[0], &c, 1); /* blocks until /child writes 'K' */
	int status = 0;
	long w = sys_wait4(pid, &status, 0, 0);

	int ok = (n == 1) && (c == 'K') && (w == pid) && (((status >> 8) & 0xff) == 7);
	if (ok)
		sys_write(1, "lxp-m2-ok\n", 10);
	else
		sys_write(1, "lxp-m2-FAIL\n", 12);
	sys_exit(ok ? 0 : 1);
}
