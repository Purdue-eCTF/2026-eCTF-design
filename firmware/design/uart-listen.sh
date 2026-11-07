#!/bin/sh
set -eu

# Usage: ./uart-listen.sh [serial-device] [baud-rate]
device=${1:-/dev/ttyACM0}
baud=${2:-115200}

stty -F "$device" "$baud" raw -echo -ixon -ixoff -crtscts
printf 'Listening on %s at %s baud (Ctrl-C to stop)\n' "$device" "$baud" >&2
exec cat "$device"
