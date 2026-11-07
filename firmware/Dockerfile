FROM rust:slim-trixie

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && \
apt install --no-install-recommends -y gcc-arm-none-eabi python3 && \
rm -rf /var/lib/apt/lists/* && \
rustup toolchain install nightly-2026-03-08 --profile minimal && \
rustup target install --toolchain nightly-2026-03-08 thumbv6m-none-eabi && \
rustup component add --toolchain nightly-2026-03-08 rustc-dev rustfmt

WORKDIR /hsm
ENTRYPOINT ["python3", "/hsm/build.py"]
