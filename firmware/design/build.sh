#!/bin/sh
set -eu

# Usage: ./build.sh [extra cargo build args...]
cd "$(dirname "$0")"
LOCAL_SECRETS_FILE="${LOCAL_SECRETS_FILE:-$(pwd)/../../ectf26_design/secrets.json}"
BUILD_SEED="67"
PERMISSIONS="0001=RWC"
HSM_PIN="676767"
export HSM_PIN PERMISSIONS LOCAL_SECRETS_FILE BUILD_SEED

exec cargo build --release "$@"
