#!/bin/bash
# Vendor the FreeRTOS kernel for the standalone QEMU harness (NOT committed; see
# .gitignore). Pinned to the same release the oveRTOS consumer uses.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
VENDOR="$HERE/vendor"
FREERTOS_TAG="V11.1.0"
mkdir -p "$VENDOR"
if [ ! -d "$VENDOR/FreeRTOS-Kernel/include" ]; then
    echo "Fetching FreeRTOS-Kernel $FREERTOS_TAG ..."
    git clone --depth 1 --branch "$FREERTOS_TAG" \
        https://github.com/FreeRTOS/FreeRTOS-Kernel.git "$VENDOR/FreeRTOS-Kernel"
fi
echo "deps ready in $VENDOR"
