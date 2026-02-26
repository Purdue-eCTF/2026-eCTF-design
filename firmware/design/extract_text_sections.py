#!/usr/bin/env python3
"""
Compile-time function order randomization helper.

Flow:
1) Build once with map+gc diagnostics to gather .text.* and GC-removed .text.*.
2) Deterministically shuffle .text.* using sha256(BUILD_SEED + magic constant).
3) Emit a randomized temp linker script (unique filename for parallel runs).
4) Rebuild using that randomized linker script (without editing .cargo/config.toml).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import random
import re
import shlex
import subprocess
import sys
import tempfile


DEFAULT_MAGIC_CONSTANT = "ectf26-randomize-text-order-v1"
DEFAULT_LINKER_TEMPLATE = "link.x"
DEFAULT_RANDOMIZED_BUILD_CMD = "cargo build --release --target thumbv6m-none-eabi"


def run_build(command: str, env: dict[str, str] | None = None) -> tuple[int, str]:
    proc = subprocess.run(
        command,
        shell=True,
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )
    build_output = f"{proc.stdout}\n{proc.stderr}"
    return proc.returncode, build_output


def extract_all_text_sections(map_text: str) -> list[str]:
    # Keep only map lines that define concrete .text.<name> input sections.
    sections = set(re.findall(r"^\s*(\.text\.[^\s]+)", map_text, flags=re.MULTILINE))
    return sorted(sections)


def extract_gc_removed_sections(build_output: str) -> list[str]:
    removed = set(
        re.findall(r"removing unused section '(\.text\.[^']+)'", build_output)
    )
    return sorted(removed)


def deterministic_shuffle(items: list[str], build_seed: str, magic: str) -> tuple[list[str], str]:
    seed_material = f"{build_seed}:{magic}".encode("utf-8")
    seed_digest = hashlib.sha256(seed_material).hexdigest()
    rng_seed = int(seed_digest[:16], 16)
    rng = random.Random(rng_seed)
    shuffled = items[:]
    rng.shuffle(shuffled)
    return shuffled, seed_digest


def generate_randomized_linker(
    linker_template_path: pathlib.Path,
    output_linker_path: pathlib.Path,
    shuffled_sections: list[str],
) -> None:
    linker_text = linker_template_path.read_text()
    pattern = re.compile(r"^(\s*)\*\(\.text \.text\.\*\);\s*$", flags=re.MULTILINE)
    match = pattern.search(linker_text)
    if match is None:
        raise RuntimeError(
            f"Could not find expected wildcard line '*(.text .text.*);' in {linker_template_path}"
        )

    indent = match.group(1)
    replacement_lines = [
        f"{indent}/* BEGIN randomized .text.* order (generated) */",
        f"{indent}*(.text);",
    ]
    replacement_lines.extend(f"{indent}*({section});" for section in shuffled_sections)
    replacement_lines.extend(
        [
            f"{indent}*(.text.*);",
            f"{indent}/* END randomized .text.* order (generated) */",
        ]
    )
    replacement_block = "\n".join(replacement_lines)

    randomized_text = (
        linker_text[: match.start()] + replacement_block + linker_text[match.end() :]
    )
    output_linker_path.write_text(randomized_text)


def make_encoded_rustflags_for_randomized_linker(linker_path: pathlib.Path) -> str:
    # This replaces target rustflags from .cargo/config for this build invocation.
    tokens = [
        "-C",
        "linker=arm-none-eabi-gcc",
        "-Z",
        "stack-protector=strong",
        "-C",
        "link-arg=-nostartfiles",
        "-C",
        f"link-arg=-T{linker_path}",
        "-Wlinker-messages",
    ]
    return "\x1f".join(tokens)


def print_section_list(title: str, sections: list[str]) -> None:
    print(f"{title} ({len(sections)}):")
    for section in sections:
        print(section)
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract sections, randomize .text.* order, emit temp linker script, rebuild."
    )
    parser.add_argument(
        "--randomized-build-cmd",
        default=DEFAULT_RANDOMIZED_BUILD_CMD,
        help="Build command to run with the randomized linker script.",
    )
    parser.add_argument(
        "--seed-env",
        default="BUILD_SEED",
        help="Environment variable name that contains the build seed.",
    )
    parser.add_argument(
        "--magic-constant",
        default=DEFAULT_MAGIC_CONSTANT,
        help="Magic constant combined with build seed for deterministic shuffle.",
    )
    parser.add_argument(
        "--linker-template",
        default=DEFAULT_LINKER_TEMPLATE,
        help="Path to base linker script template.",
    )
    args = parser.parse_args()

    build_seed = os.environ.get(args.seed_env)
    if build_seed is None:
        print(
            f"Missing required env var '{args.seed_env}'.",
            file=sys.stderr,
        )
        return 2

    temp_map_path = pathlib.Path(
        tempfile.NamedTemporaryFile(
            prefix="design_sections_",
            suffix=".map",
            delete=False,
        ).name
    )
    extraction_build_cmd = (
        "cargo rustc --release --target thumbv6m-none-eabi -- "
        f"-C link-arg=-Wl,-Map={temp_map_path} "
        "-C link-arg=-Wl,--print-gc-sections"
    )

    print(f"Running extraction build:\n  {extraction_build_cmd}\n")
    extract_rc, extract_output = run_build(extraction_build_cmd)
    extract_log_path = pathlib.Path(
        tempfile.NamedTemporaryFile(
            prefix="design_sections_extract_",
            suffix=".log",
            delete=False,
        ).name
    )
    extract_log_path.write_text(extract_output)
    print(f"Saved extraction build output to: {extract_log_path}")
    print(f"Map file path: {temp_map_path}\n")

    if extract_rc != 0:
        print(f"Extraction build failed with exit code {extract_rc}.", file=sys.stderr)
        print("First 200 lines of captured output:", file=sys.stderr)
        for line in extract_output.splitlines()[:200]:
            print(line, file=sys.stderr)
        return extract_rc

    if not temp_map_path.exists():
        print(f"Expected map file was not produced: {temp_map_path}", file=sys.stderr)
        return 3

    all_sections = extract_all_text_sections(temp_map_path.read_text())
    gc_removed_sections = extract_gc_removed_sections(extract_output)
    gc_kept_estimate = sorted(set(all_sections) - set(gc_removed_sections))

    shuffled_sections, seed_digest = deterministic_shuffle(
        all_sections, build_seed=build_seed, magic=args.magic_constant
    )

    randomized_linker_path = pathlib.Path(
        tempfile.NamedTemporaryFile(
            prefix="design_randomized_link_",
            suffix=".x",
            delete=False,
        ).name
    )
    generate_randomized_linker(
        linker_template_path=pathlib.Path(args.linker_template),
        output_linker_path=randomized_linker_path,
        shuffled_sections=shuffled_sections,
    )

    randomized_env = dict(os.environ)
    randomized_env.pop("RUSTFLAGS", None)
    randomized_env["CARGO_ENCODED_RUSTFLAGS"] = make_encoded_rustflags_for_randomized_linker(
        randomized_linker_path
    )

    print(f"Running randomized build:\n  {args.randomized_build_cmd}\n")
    random_rc, random_output = run_build(args.randomized_build_cmd, env=randomized_env)
    random_log_path = pathlib.Path(
        tempfile.NamedTemporaryFile(
            prefix="design_sections_randomized_",
            suffix=".log",
            delete=False,
        ).name
    )
    random_log_path.write_text(random_output)
    print(f"Saved randomized build output to: {random_log_path}\n")

    print_section_list("All .text.* sections from map", all_sections)
    print_section_list("GC removed .text.* sections", gc_removed_sections)
    print_section_list("Estimated kept .text.* sections", gc_kept_estimate)
    print_section_list("Shuffled .text.* order used in randomized linker", shuffled_sections)

    print("Summary:")
    print(f"- build_seed_env: {args.seed_env}")
    print(f"- build_seed_value: {build_seed}")
    print(f"- magic_constant: {args.magic_constant}")
    print(f"- seed_digest_sha256: {seed_digest}")
    print(f"- extraction_build_cmd: {shlex.quote(extraction_build_cmd)}")
    print(f"- extraction_log: {extract_log_path}")
    print(f"- map_file: {temp_map_path}")
    print(f"- randomized_linker_file: {randomized_linker_path}")
    print(f"- randomized_build_cmd: {shlex.quote(args.randomized_build_cmd)}")
    print(f"- randomized_build_log: {random_log_path}")
    print(f"- all_sections: {len(all_sections)}")
    print(f"- gc_removed_sections: {len(gc_removed_sections)}")
    print(f"- kept_estimate: {len(gc_kept_estimate)}")
    print(f"- randomized_build_exit_code: {random_rc}")

    if random_rc != 0:
        print("\nRandomized build failed. First 200 lines of output:", file=sys.stderr)
        for line in random_output.splitlines()[:200]:
            print(line, file=sys.stderr)
        return random_rc

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
