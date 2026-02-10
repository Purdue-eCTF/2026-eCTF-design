cd /hsm/design

CARGO_TARGET_DIR="/tmp/target" cargo build --release

arm-none-eabi-objcopy -O binary "/tmp/target/thumbv6m-none-eabi/release/design" "/out/hsm.bin"
