/* M1 smoke guest: write a marker and exit. Built static-FDPIC; the lxp module's
 * FDPIC loader XIPs its text in place and runs it under the QEMU harness.
 * Uses the ARM EABI syscall numbers the module impersonates (write=4, exit_group=248). */
static long sys_write(int fd, const void *buf, unsigned long n)
{
	register long r0 __asm__("r0") = fd;
	register long r1 __asm__("r1") = (long)buf;
	register long r2 __asm__("r2") = (long)n;
	register long r7 __asm__("r7") = 4; /* ARM EABI NR_write */
	__asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
	return r0;
}
static void sys_exit(int code)
{
	register long r0 __asm__("r0") = code;
	register long r7 __asm__("r7") = 248; /* ARM EABI NR_exit_group */
	__asm__ volatile("svc 0" : "+r"(r0) : "r"(r7) : "memory");
	for (;;) {
	}
}
void _start(void)
{
	sys_write(1, "lxp-m1-ok\n", 10);
	sys_exit(0);
}
