#!/usr/bin/env python3
"""Generate a GNU ld --section-ordering-file with randomized .text.* order.

Usage (two-pass with Cargo):
  1) Build once to populate target artifacts.
  2) Run this script to generate an ordering script.
  3) Rebuild with the generated file passed to the linker.

Example:
  python firmware/tools/randomize_function_order.py \
    --input-root /tmp/target/thumbv6m-none-eabi/release \
    --seed 12345 \
    --output /tmp/function-order.ld

  RUSTFLAGS="-C link-arg=-Xlinker -C link-arg=--section-ordering-file=/tmp/function-order.ld" \
    CARGO_TARGET_DIR=/tmp/target cargo build --release
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
import subprocess
from pathlib import Path

SECTION_RE = re.compile(r"^\s*\d+\s+([^\s]+)\s+[0-9a-fA-F]+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Randomize .text.* function section order for GNU ld"
    )
    parser.add_argument(
        "--input-root",
        action="append",
        type=Path,
        default=[],
        help="Directory to scan recursively for .o/.a/.rlib artifacts (repeatable)",
    )
    parser.add_argument(
        "--input-file",
        action="append",
        type=Path,
        default=[],
        help="Specific .o/.a/.rlib file to scan (repeatable)",
    )
    parser.add_argument(
        "--objdump",
        default="arm-none-eabi-objdump",
        help="Objdump binary to use",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="PRNG seed (default: derive from discovered section set)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to emit linker section-ordering file",
    )
    parser.add_argument(
        "--metadata-out",
        type=Path,
        default=None,
        help="Optional JSON metadata output (seed, section count, inputs)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Regex for section names to exclude (repeatable)",
    )
    parser.add_argument(
        "--keep-front",
        action="append",
        default=[".Reset", ".HardFaultTrampoline"],
        help="Section name to keep first in fixed order (repeatable)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and print stats only, do not write files",
    )
    return parser.parse_args()


def find_inputs(input_roots: list[Path], input_files: list[Path]) -> list[Path]:
    files: set[Path] = set()
    for root in input_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix in {".o", ".a", ".rlib"} and path.is_file():
                files.add(path)
    for path in input_files:
        if path.exists() and path.is_file():
            files.add(path)
    return sorted(files)


def section_names_from_file(objdump: str, path: Path) -> set[str]:
    try:
        result = subprocess.run(
            [objdump, "-h", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(f"failed running {objdump}: {exc}") from exc

    if result.returncode != 0:
        return set()

    sections: set[str] = set()
    for line in result.stdout.splitlines():
        m = SECTION_RE.match(line)
        if not m:
            continue
        section = m.group(1)
        if section.startswith(".text."):
            sections.add(section)
    return sections


def derive_seed(sections: list[str]) -> int:
    digest = hashlib.sha256("\n".join(sections).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "little")


def main() -> int:
    args = parse_args()

    if shutil.which(args.objdump) is None:
        raise SystemExit(f"objdump not found in PATH: {args.objdump}")

    if not args.input_root and not args.input_file:
        # Cargo default for this repo.
        args.input_root = [Path("/tmp/target/thumbv6m-none-eabi/release")]

    input_files = find_inputs(args.input_root, args.input_file)
    if not input_files:
        raise SystemExit("no input files found (.o/.a/.rlib)")

    exclude_patterns = [re.compile(p) for p in args.exclude]

    sections: set[str] = set()
    for path in input_files:
        sections |= section_names_from_file(args.objdump, path)

    if not sections:
        raise SystemExit("no .text.* sections found in provided inputs")

    front_sections = [s for s in args.keep_front if s in sections]
    sections -= set(front_sections)

    filtered_sections = []
    for section in sorted(sections):
        if any(p.search(section) for p in exclude_patterns):
            continue
        filtered_sections.append(section)

    seed = args.seed if args.seed is not None else derive_seed(filtered_sections)
    rng = random.Random(seed)
    rng.shuffle(filtered_sections)

    ordered_sections = front_sections + filtered_sections

    metadata = {
        "seed": seed,
        "input_files": [str(p) for p in input_files],
        "section_count": len(ordered_sections),
        "fixed_front_count": len(front_sections),
        "output": str(args.output),
    }

    print(
        f"inputs={len(input_files)} sections={len(ordered_sections)} seed={seed} output={args.output}"
    )

    if args.dry_run:
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="ascii") as f:
        f.write("/* Auto-generated by randomize_function_order.py */\n")
        f.write("SECTIONS\n")
        f.write("{\n")
        f.write("  .text :\n")
        f.write("  {\n")
        f.write("    *(.Reset)\n")
        f.write("    *(.HardFaultTrampoline)\n")
        f.write("    *(.HardFault.*)\n")
        for section in ordered_sections:
            f.write(f"    *({section})\n")
        f.write("  }\n")
        f.write("}\n")

    if args.metadata_out is not None:
        args.metadata_out.parent.mkdir(parents=True, exist_ok=True)
        with args.metadata_out.open("w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, sort_keys=True)
            f.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
