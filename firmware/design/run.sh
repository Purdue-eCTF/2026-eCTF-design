#!/bin/sh

binary="$1"
device="/dev/cu.usbmodemM43210051"


arm-none-eabi-objcopy -O binary "$binary" "$binary.bin"

uvx ectf hw $device erase
uvx ectf hw $device flash "$binary.bin" -n testing
uvx ectf hw $device start
