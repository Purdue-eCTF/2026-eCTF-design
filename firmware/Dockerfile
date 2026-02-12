FROM rust:slim-trixie

# what will be run:
# docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='1a2b3c' -e PERMISSIONS='1234=R--:4321=RWC' build-hsm

RUN <<EOF
apt update && apt install -y gcc-arm-none-eabi
rustup +nightly toolchain update
rustup +nightly target install thumbv6m-none-eabi
EOF

WORKDIR /hsm
ENTRYPOINT ["/bin/sh", "/hsm/build.sh"]
