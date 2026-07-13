/* M4 helper: block forever on a console read so the parent can deliver a signal to a live,
 * co-running process. SIGTERM (default action: terminate) reaps it; the parent's wait4 then
 * observes WIFSIGNALED. Built static-FDPIC. */
#include "lxpsys.h"

void _start(void)
{
	char c;
	for (;;)
		sys_read(0, &c, 1); /* no console input under QEMU -> parks until a signal arrives */
}
