#!/bin/sh
set -eu

# Usage: ./build.sh [--debug] [extra cargo build args...]
#   --debug   enable the `debug-isr` feature (UART echo on the S2 button). Never use for a final build.
cd "$(dirname "$0")"
LOCAL_SECRETS_FILE="${LOCAL_SECRETS_FILE:-$(pwd)/../../ectf26_design/secrets.json}"
BUILD_SEED="67"
PERMISSIONS="0001=RWC"
HSM_PIN="676767"
export HSM_PIN PERMISSIONS LOCAL_SECRETS_FILE BUILD_SEED

debug=0
for arg in "$@"; do
    shift
    if [ "$arg" = "--debug" ]; then
        debug=1
    else
        set -- "$@" "$arg"
    fi
done

if [ "$debug" = 1 ]; then
    set -- --features debug-isr "$@"
    echo "build.sh: DEBUG build, debug-isr feature enabled" >&2
fi

exec cargo build --release "$@"
