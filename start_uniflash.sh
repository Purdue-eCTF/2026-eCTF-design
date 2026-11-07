#!/usr/bin/env bash
set -euo pipefail

# This uses the UniFlash installation and Docker image prepared for this board.
# The container needs USB access and the X11 socket used by KDE's XWayland.
install_dir="${UNIFLASH_DIR:-/tmp/ectf-bootloader}"
image="${UNIFLASH_IMAGE:-ectf-uniflash-gui:latest}"
name="ectf-uniflash"
xauthority="${XAUTHORITY:-$HOME/.Xauthority}"

if ! command -v docker >/dev/null; then
    echo "Error: docker is not installed or not in PATH." >&2
    exit 1
fi
if [[ ! -x "$install_dir/ti/node-webkit/nw" ]]; then
    echo "Error: UniFlash not found at $install_dir/ti." >&2
    echo "Set UNIFLASH_DIR to the directory containing the ti installation." >&2
    exit 1
fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "Error: Docker image $image not found." >&2
    exit 1
fi
if [[ -z "${DISPLAY:-}" || ! -r "$xauthority" ]]; then
    echo "Error: DISPLAY or readable Xauthority file is missing." >&2
    exit 1
fi
if docker ps --format '{{.Names}}' | grep -Fxq "$name"; then
    echo "UniFlash is already running in container $name."
    exit 0
fi
if docker ps -a --format '{{.Names}}' | grep -Fxq "$name"; then
    echo "Error: stopped container $name already exists; remove or rename it first." >&2
    exit 1
fi

docker run -d --rm --name "$name" --privileged \
    --hostname "$(hostname)" \
    -e DISPLAY="$DISPLAY" -e XAUTHORITY=/tmp/xauth -e QT_X11_NO_MITSHM=1 \
    -v "$xauthority:/tmp/xauth:ro" \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v /dev/bus/usb:/dev/bus/usb \
    -v "$install_dir:/work" \
    -v "$install_dir:$install_dir" \
    --entrypoint /work/ti/node-webkit/nw "$image" \
    --no-sandbox --disable-gpu /work/ti >/dev/null

echo "UniFlash started in container $name. Close its window to stop it."
