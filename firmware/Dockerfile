FROM rust:slim-trixie

# what will be run:
# docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='1a2b3c' -e PERMISSIONS='1234=R--:4321=RWC' build-hsm

ARG DEBIAN_FRONTEND=noninteractive
RUN <<EOF
apt-get update && apt-get install -y gcc-arm-none-eabi
rustup toolchain update nightly
rustup target install --toolchain nightly thumbv6m-none-eabi
rustup component add --toolchain nightly rustc-dev rustfmt
EOF

WORKDIR /hsm
ENTRYPOINT ["/bin/sh", "/hsm/build.sh"]
