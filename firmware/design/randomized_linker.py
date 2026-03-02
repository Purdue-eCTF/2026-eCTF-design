#!/usr/bin/env python3

import contextlib
import os
import random
import re
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path


def run_linker(args: list[str]):
    # trying to use lld breaks arm-none-eabi-gcc
    args = [arg for arg in args if arg != "-fuse-ld=lld"]
    subprocess.run(["arm-none-eabi-gcc", *args], check=True)  # noqa: S603, S607


def get_text(path: str):
    map_text = Path(path).read_text()
    candidates = re.findall(r"^\s*(\.text\.[^\s]+)", map_text, flags=re.MULTILINE)
    # Filter wildcard/script artifacts like ".text.*)" and keep deterministic ordering.
    filtered = {s for s in candidates if "*" not in s and ")" not in s}
    return sorted(filtered)


def main():
    linker_args = sys.argv[1:]
    template = Path(next(arg for arg in linker_args if arg.startswith("-T"))[2:])
    if not template.is_absolute():
        template = Path.cwd() / template
    assert Path(template).exists()

    with (
        tempfile.NamedTemporaryFile(prefix="rand_link_", suffix=".map") as mapfile,
        tempfile.NamedTemporaryFile(prefix="rand_link_", suffix=".x") as outfile,
    ):
        first_args = [*linker_args, f"-Wl,-Map={mapfile.name}"]

        # ignore stdout from initial linker pass
        with contextlib.redirect_stdout(open(os.devnull, "w")):
            run_linker(first_args)
        sections = get_text(mapfile.name)
        assert sections, "no sections found"

        hasher = sha256()
        hasher.update(
            os.environ.get("BUILD_SEED", "default build seed").encode(),
        )
        seed = hasher.digest()

        rng = random.Random(seed)
        shuffled = sections[:]
        rng.shuffle(shuffled)

        old = template.read_bytes()
        randomized_text = (
            b"/* BEGIN generated randomized .text.* order */\n"
            + b"        *(.text);\n        "
            + b"\n        ".join([f"*({section});".encode() for section in shuffled])
            # fallback
            + b"\n        *(.text.*);"
        )
        new = old.replace(b"*(.text .text.*);", randomized_text)
        if len(old) == len(new):
            print("Error: failed to find a *(.text.*); in original linker script to replace")
            sys.exit(1)


        outfile.write(new)
        outfile.flush()

        new_args = [arg for arg in linker_args if not arg.startswith("-T")] + [
            f"-T{outfile.name}",
        ]
        run_linker(new_args)


if __name__ == "__main__":
    main()
