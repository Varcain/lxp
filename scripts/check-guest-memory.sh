#!/bin/sh
# Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Keep privileged guest access behind lxp_guest.c. This is a source gate rather
# than a compiler analysis, so it relies on a naming rule: a guest pointer is a
# raw syscall register (a[N], aN) or a local named u<name> (ubuf, uaddr, umsg;
# a bare u is not one). It flags the ways such a pointer is read or written in
# place:
#   - the retired user_ok/user_strnlen helpers;
#   - a mem*() or str*() call that takes a guest pointer argument;
#   - a cast-and-dereference, *(T *)ubuf or ((T *)a[1])->field;
#   - a member access, umsg->msg_iov (taking its address, &umsg->x, is fine).
# A buffer validated with lxp_guest_access_ok() and handed on as a pointer (the
# read/write data path, a DMA2D source) is not a dereference and passes.
#
# --self-test runs the patterns over known-bad and known-good lines.
set -eu
cd "$(dirname "$0")/.."

G='(u[a-z][a-z0-9_]*|a\[[0-5]\]|a[0-5])'
CASTS='(\([^()]*\)[[:space:]]*)*'
LEGACY='(^|[^A-Za-z0-9_])(user_ok|user_strnlen)([^A-Za-z0-9_]|$)'
MEMFN="(^|[^A-Za-z0-9_])(mem(cpy|move|cmp|chr|set)|str(n?cpy|n?len|n?cmp|chr))\(([^;]*,)?[[:space:]]*$CASTS$G[[:space:]]*[,)]"
DEREF="\*[[:space:]]*\([^()]*\*[[:space:]]*\)[[:space:]]*$CASTS$G([^A-Za-z0-9_]|$)"
DEREF_PAREN="\([[:space:]]*\([^()]*\*[[:space:]]*\)[[:space:]]*$CASTS$G[[:space:]]*\)[[:space:]]*(->|\[)"
MEMBER='(^|[^A-Za-z0-9_&.>])u[a-z][a-z0-9_]*[[:space:]]*->'

# Drop comment lines, then hide the type names and sizeof() operands that would
# otherwise read as u-named identifiers (uint32_t, unsigned, sizeof(ubuf)).
normalize()
{
	grep -vE '^([^:]+:[0-9]+:)?[[:space:]]*(\*([[:space:]/]|$)|/\*|//)' |
		sed -E 's/(^|[^A-Za-z0-9_])(uint[0-9a-z]*_t|unsigned)([^A-Za-z0-9_]|$)/\1T\3/g
			s/sizeof[[:space:]]*\([^()]*\)/N/g'
}

matches()
{
	grep -E "$LEGACY|$MEMFN|$DEREF|$DEREF_PAREN|$MEMBER" || true
}

if [ "${1:-}" = "--self-test" ]; then
	bad=$(cat <<'EOF'
	if (!user_ok(p, buf, n, 0))
	memcpy(&t, ut, sizeof(t));
	memcpy(ubuf, &st, sizeof(st));
	memmove(dst, (const void *)(uintptr_t)a[1], len);
	long n = strnlen((const char *)a2, max);
	uint32_t v = *(const uint32_t *)uaddr;
	*(int *)(uintptr_t)a[1] = status;
	int fl = ((const struct lxp_msghdr *)a[1])->msg_flags;
	size_t n = umsg->msg_iovlen;
EOF
)
	good=$(cat <<'EOF'
	if (lxp_copy_from_guest(proc, &t, (uintptr_t)(uint32_t)a2, sizeof(t)) == 0) {
	if (a[1] && !lxp_guest_access_ok(proc, (void *)(uintptr_t)a[1], sizeof(int), 1))
	void *srclen = src ? &umsg->msg_namelen : NULL;
	memcpy(dst, src, sizeof(uint32_t));
	memset(&st, 0, sizeof(ust));
	uint32_t *used = &st.used;
	long r = sys_write(p, fd, ubuf, len);
	return lxp_sys_pipe_flags(p, (int *)a[0], (int)a[1]);
EOF
)
	status=0
	missed=$(printf '%s\n' "$bad" | while IFS= read -r l; do
		printf '%s\n' "$l" | normalize | matches | grep -q . || printf '%s\n' "$l"
	done)
	flagged=$(printf '%s\n' "$good" | normalize | matches)
	if [ -n "$missed" ]; then
		echo "FAIL: self-test missed raw guest access:"
		echo "$missed"
		status=1
	fi
	if [ -n "$flagged" ]; then
		echo "FAIL: self-test flagged boundary-safe code:"
		echo "$flagged"
		status=1
	fi
	[ "$status" -eq 0 ] && echo "OK: guest-memory patterns pass their self-test."
	exit "$status"
fi

found=$(grep -rn '' src include --include='*.c' --include='*.h' --exclude=lxp_guest.c | normalize | matches)
if [ -n "$found" ]; then
	echo "FAIL: raw privileged guest-memory access escaped the common boundary:"
	echo "$found"
	exit 1
fi

echo "OK: guest pointer validation/copies use the common lxp_guest boundary."
