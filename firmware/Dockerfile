FROM rust:slim-trixie

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && \
apt install --no-install-recommends -y gcc-arm-none-eabi python3 && \
rm -rf /var/lib/apt/lists/* && \
rustup toolchain update nightly && \
rustup target install --toolchain nightly thumbv6m-none-eabi && \
rustup component add --toolchain nightly rustc-dev rustfmt

WORKDIR /hsm
ENTRYPOINT ["python3", "/hsm/build.py"]
