/* M9 guest: prove proportional Linux nice scheduling survives frequent native
 * preemption. Two CLONE_VM workers share only a stop flag and result counters,
 * run the same integer workload, and select opposite nice endpoints. The parent
 * sleeps while they compete, then stops and reaps both workers. The host harness
 * independently proves that its higher-priority 1 kHz task actually ran.
 *
 * Keeping the timing syscall in the sleeping parent is deliberate: the measured
 * worker counts represent guest CPU service rather than coordinator/SVC traffic.
 */
#include "lxpsys.h"

#include <stdint.h>

struct worker_ctx {
	volatile uint32_t *stop;
	volatile uint32_t blocks;
	int nice;
};

__attribute__((used)) static void worker_body(struct worker_ctx *ctx)
{
	if (sys_nice(ctx->nice) != 0)
		sys_exit(2);

	uint32_t state = ctx->nice < 0 ? 0x51f15e5du : 0xa341316cu;
	uint32_t blocks = 0;
	while (!*ctx->stop) {
		/* Identical, register-resident work. Check the shared stop flag only
		 * once per block so the loop measures scheduled execution, not loads. */
		for (unsigned i = 0; i < 256u; i++) {
			state ^= state << 13;
			state ^= state >> 17;
			state ^= state << 5;
		}
		blocks++;
	}
	/* Make the arithmetic observable and prevent whole-loop elimination. */
	ctx->blocks = blocks ^ (state & 1u);
	sys_exit(0);
}

/* clone(CLONE_VM) with a per-worker stack. r0-r3 are not preserved into the
 * child, so carry the context pointer in callee-saved r4 across the trap. */
__attribute__((naked)) static long worker_spawn(void *stack_top, struct worker_ctx *ctx)
{
	__asm__ volatile("push {r4, lr}\n"
			 "mov r4, r1\n"
			 "mov r1, r0\n"
			 "movw r0, #0x100\n" /* CLONE_VM */
			 "movs r7, #120\n"   /* NR_clone */
			 "svc 0\n"
			 "cmp r0, #0\n"
			 "bne 1f\n"
			 "mov r0, r4\n"
			 "bl worker_body\n"
			 "1:\n"
			 "pop {r4, pc}\n");
}

static void put_u32(uint32_t value)
{
	char digits[10];
	unsigned n = 0;
	do {
		digits[n++] = (char)('0' + value % 10u);
		value /= 10u;
	} while (value != 0u);
	while (n != 0u)
		sys_write(1, &digits[--n], 1);
}

void _start(void)
{
	volatile uint32_t stop = 0;
	struct worker_ctx high = {&stop, 0, -20};
	struct worker_ctx low = {&stop, 0, 19};
	unsigned char high_stack[768] __attribute__((aligned(8)));
	unsigned char low_stack[768] __attribute__((aligned(8)));

	long high_tid = worker_spawn(high_stack + sizeof(high_stack), &high);
	long low_tid = worker_spawn(low_stack + sizeof(low_stack), &low);
	if (high_tid <= 0 || low_tid <= 0)
		sys_exit(101);

	long duration[2] = {2, 0};
	if (sys_nanosleep(duration) != 0)
		sys_exit(102);
	stop = 1;

	int high_status = 0;
	int low_status = 0;
	long high_wait = sys_wait4((int)high_tid, &high_status, 0, 0);
	long low_wait = sys_wait4((int)low_tid, &low_status, 0, 0);
	uint32_t ratio = low.blocks ? high.blocks / low.blocks : 0u;
	int ok = high_wait == high_tid && low_wait == low_tid &&
		 ((high_status >> 8) & 0xff) == 0 && ((low_status >> 8) & 0xff) == 0 &&
		 high.blocks != 0u && low.blocks != 0u && ratio >= 8u && ratio <= 40u;

	sys_write(1, ok ? "lxp-m9-share-ok high=" : "lxp-m9-share-FAIL high=",
		  ok ? 21 : 23);
	put_u32(high.blocks);
	sys_write(1, " low=", 5);
	put_u32(low.blocks);
	sys_write(1, " ratio=", 7);
	put_u32(ratio);
	sys_write(1, "\n", 1);
	sys_exit(ok ? 0 : 1);
}
