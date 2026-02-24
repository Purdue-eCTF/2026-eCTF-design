FROM rust:slim-trixie

# what will be run:
# docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='1a2b3c' -e PERMISSIONS='1234=R--:4321=RWC' build-hsm
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update
RUN apt install --no-install-recommends -y gcc-arm-none-eabi
RUN rm -rf /var/lib/apt/lists/*
RUN rustup toolchain update nightly
RUN rustup target install --toolchain nightly thumbv6m-none-eabi
RUN rustup component add --toolchain nightly rustc-dev rustfmt

WORKDIR /hsm
ENTRYPOINT ["/bin/sh", "/hsm/build.sh"]
