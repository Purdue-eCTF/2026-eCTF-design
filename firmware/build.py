#!/usr/bin/env python3

import os
import secrets
import subprocess
import sys


DESIGN_DIR = "/hsm/design"
TARGET_DIR = "/tmp/target"
MAX_RETRIES = 5


def run_build() -> int:
    os.chdir(DESIGN_DIR)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = TARGET_DIR

    for attempt in range(1, MAX_RETRIES + 1):
        build_seed = secrets.token_hex(16)
        env["BUILD_SEED"] = build_seed
        print(f"[build] attempt {attempt}/{MAX_RETRIES} BUILD_SEED={build_seed}", flush=True)

        result = subprocess.run(
            ["cargo", "build", "--release"],
            env=env,
            check=False,
        )
        if result.returncode == 0:
            break

        print(
            f"[build] cargo failed on attempt {attempt} with code {result.returncode}",
            flush=True,
        )
    else:
        return 1

    objcopy = subprocess.run(
        [
            "arm-none-eabi-objcopy",
            "-O",
            "binary",
            f"{TARGET_DIR}/thumbv6m-none-eabi/release/design",
            "/out/hsm.bin",
        ],
        check=False,
    )
    return objcopy.returncode


if __name__ == "__main__":
    sys.exit(run_build())
