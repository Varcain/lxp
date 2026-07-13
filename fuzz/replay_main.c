/*
 * Copyright (C) 2026 Kamil Lulko <kamil.lulko@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of the lxp module (the OS-agnostic Linux personality).
 *
 * A gcc-buildable standalone driver over the engine-agnostic
 * LLVMFuzzerTestOneInput() contract (the classic libFuzzer StandaloneFuzzTargetMain).
 * It replays each file named on argv through the harness once. Under -DLXP_SANITIZE
 * this turns a corpus directory into an ASan/UBSan regression test that needs no
 * fuzzing engine — the form CI runs (keeps CI gcc-only). AFL++ can also drive this
 * binary with `-- ./fuzz_x @@`.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

static int run_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f) {
		perror(path);
		return 1;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return 1;
	}
	long n = ftell(f);
	if (n < 0) {
		fclose(f);
		return 1;
	}
	rewind(f);
	uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
	if (!buf) {
		fclose(f);
		return 1;
	}
	size_t got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	LLVMFuzzerTestOneInput(buf, got);
	free(buf);
	return 0;
}

int main(int argc, char **argv)
{
	if (LLVMFuzzerInitialize)
		LLVMFuzzerInitialize(&argc, &argv);
	int rc = 0;
	for (int i = 1; i < argc; i++)
		rc |= run_file(argv[i]);
	return rc;
}
