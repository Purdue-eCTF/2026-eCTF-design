#!/bin/sh
set -eu

# Erases the device before flashing. Pass its serial port as the first argument.
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <serial-device> [firmware-name]" >&2
    exit 2
fi

device=$1
name=${2:-testing}
cd "$(dirname "$0")"
elf="${CARGO_TARGET_DIR:-target}/thumbv6m-none-eabi/release/design"
bin="${elf}.bin"

if [ ! -f "$elf" ]; then
    echo "Firmware not found: $elf (run ./build.sh first)" >&2
    exit 1
fi

arm-none-eabi-objcopy -O binary "$elf" "$bin"
uvx ectf hw "$device" erase
uvx ectf hw "$device" flash "$bin" -n "$name"
uvx ectf hw "$device" start
