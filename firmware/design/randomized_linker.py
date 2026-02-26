#!/usr/bin/env python3
"""
Linker wrapper that randomizes .text.* input section order.

Behavior:
1) Forward original args to the real linker with an added temp map file.
2) Parse .text.* sections from that map file.
3) Build a randomized temp linker script by replacing *(.text .text.*) in link.x.
4) Forward args again to the real linker, replacing -T<linker_script> with -T<temp>.

Deterministic shuffle seed:
  sha256(f"{BUILD_SEED}:{MAGIC_CONSTANT}")
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import random
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from typing import Sequence


DEFAULT_REAL_LINKER = "arm-none-eabi-gcc"
DEFAULT_SEED_ENV = "BUILD_SEED"
DEFAULT_MAGIC_CONSTANT = "ectf26-randomize-text-order-v1"


def is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.lower() in {"1", "true", "yes", "on"}


def log(msg: str, *, verbose: bool) -> None:
    if verbose:
        print(f"[randomized_linker] {msg}", file=sys.stderr)


def run_linker(real_linker: str, args: Sequence[str], *, verbose: bool) -> int:
    sanitized_args = sanitize_args_for_real_linker(args, real_linker=real_linker)
    log(f"exec: {real_linker} {' '.join(sanitized_args)}", verbose=verbose)
    proc = subprocess.run([real_linker, *sanitized_args], check=False)
    return proc.returncode


def sanitize_args_for_real_linker(args: Sequence[str], *, real_linker: str) -> list[str]:
    out: list[str] = []
    base = pathlib.Path(real_linker).name
    is_arm_gcc = "arm-none-eabi-gcc" in base or base == "gcc"

    i = 0
    while i < len(args):
        arg = args[i]
        # rustc may pass this for gcc-flavor links; embedded gcc toolchains often fail on it.
        if is_arm_gcc and arg == "-fuse-ld=lld":
            i += 1
            continue
        out.append(arg)
        i += 1

    return out


def get_or_generate_seed(seed_env: str, *, verbose: bool) -> str:
    seed = os.environ.get(seed_env)
    if seed:
        return seed

    seed = secrets.token_hex(32)
    os.environ[seed_env] = seed
    log(f"{seed_env} not set; generated {seed}", verbose=verbose)
    return seed


def extract_text_sections_from_map(map_path: pathlib.Path) -> list[str]:
    map_text = map_path.read_text()
    candidates = re.findall(r"^\s*(\.text\.[^\s]+)", map_text, flags=re.MULTILINE)
    # Filter wildcard/script artifacts like ".text.*)" and keep deterministic ordering.
    filtered = {s for s in candidates if "*" not in s and ")" not in s}
    return sorted(filtered)


def find_linker_script_arg(args: Sequence[str]) -> str | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-T" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("-T") and len(arg) > 2:
            return arg[2:]
        if arg.startswith("-Wl,"):
            parts = arg[4:].split(",")
            for j, part in enumerate(parts):
                if part == "-T" and j + 1 < len(parts):
                    return parts[j + 1]
                if part.startswith("-T") and len(part) > 2:
                    return part[2:]
        i += 1
    return None


def replace_linker_script_arg(args: Sequence[str], new_script: str) -> tuple[list[str], bool]:
    out: list[str] = []
    replaced = False
    i = 0

    while i < len(args):
        arg = args[i]
        if arg == "-T" and i + 1 < len(args):
            out.extend(["-T", new_script])
            replaced = True
            i += 2
            continue
        if arg.startswith("-T") and len(arg) > 2:
            out.append(f"-T{new_script}")
            replaced = True
            i += 1
            continue
        if arg.startswith("-Wl,"):
            parts = arg[4:].split(",")
            changed = False
            for j, part in enumerate(parts):
                if part == "-T" and j + 1 < len(parts):
                    parts[j + 1] = new_script
                    replaced = True
                    changed = True
                elif part.startswith("-T") and len(part) > 2:
                    parts[j] = f"-T{new_script}"
                    replaced = True
                    changed = True
            if changed:
                out.append("-Wl," + ",".join(parts))
            else:
                out.append(arg)
            i += 1
            continue
        out.append(arg)
        i += 1

    return out, replaced


def resolve_linker_template(path_from_arg: str) -> pathlib.Path:
    candidate = pathlib.Path(path_from_arg)
    if candidate.is_absolute():
        return candidate
    return pathlib.Path.cwd() / candidate


def generate_randomized_linker(
    linker_template_path: pathlib.Path,
    output_linker_path: pathlib.Path,
    shuffled_sections: Sequence[str],
) -> None:
    linker_text = linker_template_path.read_text()
    pattern = re.compile(r"^(\s*)\*\(\.text \.text\.\*\);\s*$", flags=re.MULTILINE)
    match = pattern.search(linker_text)
    if match is None:
        raise RuntimeError(
            f"Could not find wildcard '*(.text .text.*);' in {linker_template_path}"
        )

    indent = match.group(1)
    replacement_lines = [
        f"{indent}/* BEGIN randomized .text.* order (generated by randomized_linker.py) */",
        f"{indent}*(.text);",
    ]
    replacement_lines.extend(f"{indent}*({section});" for section in shuffled_sections)
    replacement_lines.extend(
        [
            f"{indent}*(.text.*);",
            f"{indent}/* END randomized .text.* order */",
        ]
    )
    replacement_block = "\n".join(replacement_lines)
    randomized_text = (
        linker_text[: match.start()] + replacement_block + linker_text[match.end() :]
    )
    output_linker_path.write_text(randomized_text)


def cleanup_temp(path: pathlib.Path, *, keep_temps: bool, verbose: bool) -> None:
    if keep_temps:
        log(f"keeping temp file: {path}", verbose=verbose)
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # Best-effort cleanup only.
        pass


def main() -> int:
    verbose = is_truthy(os.environ.get("RANDOMIZED_LINKER_VERBOSE"))
    keep_temps = is_truthy(os.environ.get("RANDOMIZED_LINKER_KEEP_TEMPS"))

    real_linker = os.environ.get("RANDOMIZED_LINKER_REAL", DEFAULT_REAL_LINKER)
    magic_constant = os.environ.get("RANDOMIZED_LINKER_MAGIC", DEFAULT_MAGIC_CONSTANT)
    seed_env = os.environ.get("RANDOMIZED_LINKER_SEED_ENV", DEFAULT_SEED_ENV)
    linker_args = sys.argv[1:]

    if not linker_args:
        print("randomized_linker.py: no linker arguments provided", file=sys.stderr)
        return 2

    resolved_real = shutil.which(real_linker) or real_linker
    wrapper_path = pathlib.Path(sys.argv[0]).resolve()
    try:
        if pathlib.Path(resolved_real).resolve() == wrapper_path:
            print(
                "randomized_linker.py: real linker resolves to wrapper itself; "
                "set RANDOMIZED_LINKER_REAL to arm-none-eabi-gcc",
                file=sys.stderr,
            )
            return 2
    except OSError:
        pass

    template_from_args = find_linker_script_arg(linker_args)
    if template_from_args is None:
        log("no -T linker script arg found; pass-through mode", verbose=verbose)
        return run_linker(real_linker, linker_args, verbose=verbose)

    template_path = resolve_linker_template(template_from_args)
    if not template_path.exists():
        print(
            f"randomized_linker.py: linker template not found: {template_path}",
            file=sys.stderr,
        )
        return 2

    map_fd, map_name = tempfile.mkstemp(prefix="rand_link_", suffix=".map")
    os.close(map_fd)
    map_path = pathlib.Path(map_name)

    first_args = [*linker_args, f"-Wl,-Map={map_path}"]
    log(f"pass1 map file: {map_path}", verbose=verbose)
    first_rc = run_linker(real_linker, first_args, verbose=verbose)
    if first_rc != 0:
        cleanup_temp(map_path, keep_temps=keep_temps, verbose=verbose)
        return first_rc

    sections = extract_text_sections_from_map(map_path)
    if not sections:
        log("no .text.* sections found; skipping randomization pass", verbose=verbose)
        cleanup_temp(map_path, keep_temps=keep_temps, verbose=verbose)
        return 0

    seed = get_or_generate_seed(seed_env, verbose=verbose)
    digest = hashlib.sha256(f"{seed}:{magic_constant}".encode("utf-8")).hexdigest()
    rng = random.Random(int(digest[:16], 16))
    shuffled = sections[:]
    rng.shuffle(shuffled)
    log(
        f"seed_env={seed_env} seed={seed} digest={digest} sections={len(shuffled)}",
        verbose=verbose,
    )

    link_fd, link_name = tempfile.mkstemp(prefix="rand_link_", suffix=".x")
    os.close(link_fd)
    randomized_linker_path = pathlib.Path(link_name)
    generate_randomized_linker(template_path, randomized_linker_path, shuffled)
    log(f"pass2 linker script: {randomized_linker_path}", verbose=verbose)

    second_args, replaced = replace_linker_script_arg(linker_args, str(randomized_linker_path))
    if not replaced:
        second_args.append(f"-T{randomized_linker_path}")

    second_rc = run_linker(real_linker, second_args, verbose=verbose)

    cleanup_temp(map_path, keep_temps=keep_temps, verbose=verbose)
    cleanup_temp(randomized_linker_path, keep_temps=keep_temps, verbose=verbose)
    return second_rc


if __name__ == "__main__":
    raise SystemExit(main())
