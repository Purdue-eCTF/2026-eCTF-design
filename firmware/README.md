# Firmware Build Notes

## Randomized Function Order (Draft)

GNU `arm-none-eabi-ld` supports section ordering via `--section-ordering-file`.
This repo now includes a helper script to randomize `.text.*` section order:
`firmware/tools/randomize_function_order.py`.

### Two-pass workflow (with `randomized` profile)

1. Build once to produce object/archive inputs:

```bash
cd firmware/design
CARGO_TARGET_DIR=/tmp/target \
RUSTFLAGS="-Z function-settings=yes" \
cargo build --profile randomized
```

2. Generate randomized section ordering file:

```bash
cd /home/jack/projects/ctf/ectf_2026/dev/2026-eCTF-design
python firmware/tools/randomize_function_order.py \
  --input-root /tmp/target/thumbv6m-none-eabi/randomized \
  --seed 12345 \
  --output /tmp/function-order.ld \
  --metadata-out /tmp/function-order.json
```

3. Re-link with ordering file enabled:

```bash
cd firmware/design
RUSTFLAGS="-C function-sections=yes -C data-sections=yes -C link-arg=-Xlinker -C link-arg=--section-ordering-file=/tmp/function-order.ld" \
CARGO_TARGET_DIR=/tmp/target cargo build --profile randomized
```

### Notes

- Keep the seed for reproducible builds.
- Layout changes may affect size and veneers/branch stubs.
- The script keeps `.Reset` and `.HardFaultTrampoline` at the front by default.
- `randomized` disables LTO so more per-function `.text.*` sections survive to link time.
