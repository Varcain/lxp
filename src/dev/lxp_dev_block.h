/* Internal block-class namespace helpers shared with the /data mount router. */
#ifndef LXP_DEV_BLOCK_H
#define LXP_DEV_BLOCK_H

#include <stddef.h>
#include <stdint.h>

typedef struct lxp_block_view_info {
	uint64_t first_block;
	uint64_t block_count;
	uint32_t logical_block_size;
	uint8_t partition;
} lxp_block_view_info_t;

/** Resolve /dev/mmcblk0[p1..p4] against the last validated MBR scan. */
int lxp_block_resolve(const char *path, lxp_block_view_info_t *out);

/** Generate Linux-compatible /proc/partitions content for present block views. */
long lxp_block_proc_partitions(char *buffer, size_t capacity);

#endif /* LXP_DEV_BLOCK_H */
