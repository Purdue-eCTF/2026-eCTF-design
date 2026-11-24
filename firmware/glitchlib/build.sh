#!/bin/sh
# Usage: ./build.sh [extra cargo args]   (env PAC_PATH=<local mspm0l222x-pac checkout> to build against it)
# Output: target/thumbv6m-none-eabi/release/libglitchlib.a  -> copied to ./libglitchlib.a
set -eu
cd "$(dirname "$0")"
if [ -n "${PAC_PATH:-}" ]; then
    set -- --config "patch.\"https://github.com/Purdue-eCTF/mspm0l222x-pac.git\".mspm0l222x-pac.path=\"$PAC_PATH\"" "$@"
fi
cargo build --release "$@"
cp target/thumbv6m-none-eabi/release/libglitchlib.a libglitchlib.a
echo "built $(pwd)/libglitchlib.a"

# Keep the integrate-glitchlib skill self-contained: ship the fresh library with the header and linker fragment.
SKILL_ASSETS=".agents/integrate-glitchlib/assets"
mkdir -p "$SKILL_ASSETS"
cp libglitchlib.a include/glitchlib.h glitchlib.ld "$SKILL_ASSETS/"
echo "copied library, header and linker fragment to $(pwd)/$SKILL_ASSETS"
