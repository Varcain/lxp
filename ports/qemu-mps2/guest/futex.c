/* M5 guest: exercise the real uaddr-keyed futex between two co-running CLONE_VM threads.
 *
 * The main thread spawns a second thread (clone(CLONE_VM)) that blocks in FUTEX_WAIT on a
 * word shared through the common region. The main thread sleeps (letting the child reach the
 * wait and park), changes the word, and FUTEX_WAKEs it. A FUTEX_WAIT that genuinely parked
 * and was woken returns 0 — the old stub returned -EAGAIN immediately without blocking — so
 * the child encodes that distinction in its exit code and the parent asserts it. Built
 * static-FDPIC. Prints "lxp-m5-ok" only if the block-and-wake actually happened. */
#include "lxpsys.h"

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

/* futex(uaddr, op, val, timeout, uaddr2, val3) — NR 240. `timeout` is a relative timespec
 * for FUTEX_WAIT, or NULL to wait forever. */
static inline long sys_futex(volatile int *uaddr, int op, int val, void *timeout)
{
	return lxp_svc6(240, (long)uaddr, op, val, (long)timeout, 0, 0);
}

/* nanosleep(req, rem) — NR 162. 32-bit timespec {tv_sec, tv_nsec}. */
static void sleep_ms(long ms)
{
	long ts[2] = {ms / 1000, (ms % 1000) * 1000000L};
	lxp_svc1(162, (long)ts, 0);
}

/* The second thread's body: block until the main thread wakes us. A real futex parks and
 * returns 0 on wake (the stub returned -EAGAIN at once, never blocking). Exit 42 iff woken.
 * Marked `used` — it is only reached from the clone trampoline's asm. */
__attribute__((used)) static void thread_body(volatile int *word)
{
	long r = sys_futex(word, FUTEX_WAIT, 0, (void *)0); /* *word still 0 -> park; woken -> 0 */
	sys_exit(r == 0 ? 42 : 1);
}

/* clone(CLONE_VM) trampoline: spawn thread_body on `stack_top` with `word` as its argument;
 * return the child tid to the caller. The child runs on the new stack and never returns here.
 * r0-r3 are NOT preserved into the child (only r4-r11/sp/lr/pc are), so `word` is carried
 * across the clone svc in r4. */
__attribute__((naked)) static long thread_spawn(void *stack_top, volatile int *word)
{
	__asm__ volatile("push {r4, lr}\n"
			 "mov r4, r1\n"	     /* r4 = word (survives clone into the child) */
			 "mov r1, r0\n"	     /* clone arg1 = child stack top */
			 "movw r0, #0x100\n" /* clone arg0 = CLONE_VM */
			 "movs r7, #120\n"   /* NR_clone */
			 "svc 0\n"
			 "cmp r0, #0\n"
			 "bne 1f\n"	  /* parent: r0 = tid */
			 "mov r0, r4\n"	  /* child: first C arg = word */
			 "bl thread_body\n" /* runs on the child stack; never returns */
			 "1:\n"
			 "pop {r4, pc}\n"); /* parent: restore r4, return tid */
}

void _start(void)
{
	volatile int word = 0;
	/* The child thread's stack: a local (parent-stack) buffer, so its address is a plain
	 * runtime RAM address needing no FDPIC data relocation. The child runs within [buf,
	 * buf+sizeof) which is disjoint from the parent's stack that grows below _start's sp. */
	unsigned char child_stack[512] __attribute__((aligned(8)));

	long tid = thread_spawn(child_stack + sizeof(child_stack), &word);
	if (tid <= 0) {
		sys_write(1, "lxp-m5-FAIL\n", 12);
		sys_exit(1);
	}

	sleep_ms(50);					       /* let the child reach FUTEX_WAIT and park */
	word = 1;					       /* change the value the child waited on... */
	long woke = sys_futex(&word, FUTEX_WAKE, 1, (void *)0); /* ...and wake it */

	int status = 0;
	long w = sys_wait4((int)tid, &status, 0, 0);
	/* Pass iff the child reaped as tid, exited 42 (real block+wake), and WAKE reported 1. */
	int ok = (w == tid) && (((status >> 8) & 0xff) == 42) && (woke == 1);
	sys_write(1, ok ? "lxp-m5-ok\n" : "lxp-m5-FAIL\n", ok ? 10 : 12);
	sys_exit(ok ? 0 : 1);
}
