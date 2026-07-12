/* M2 exec'd child: write a byte to the inherited pipe write end, then exit with a
 * distinct code the parent verifies via wait4. fd 4 is the parent's pipe write end
 * (fds 0/1/2 = console, pipe() returned 3/4), inherited across execve. */
#include "lxpsys.h"

void _start(void)
{
	sys_write(4, "K", 1);
	sys_exit(7);
}
