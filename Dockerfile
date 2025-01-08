FROM ubuntu:22.04

LABEL version="4.21.0"
LABEL name="Cosmian KMS docker container"

ENV DEBIAN_FRONTEND=noninteractive
ENV OPENSSL_DIR=/usr/local/openssl

WORKDIR /root

RUN apt-get update \
    && apt-get install --no-install-recommends -qq -y \
    curl \
    build-essential \
    libssl-dev \
    ca-certificates \
    libclang-dev \
    pkg-config \
    git \
    wget \
    && apt-get -y -q upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "nightly-x86_64-unknown-linux-gnu"

COPY . /root/kms

WORKDIR /root/kms

ARG TARGETPLATFORM
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then export ARCHITECTURE=x86_64; elif [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then export ARCHITECTURE=arm; elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then export ARCHITECTURE=arm64; else export ARCHITECTURE=x86_64; fi \
    && bash /root/kms/.github/scripts/get_openssl_binaries.sh

RUN /root/.cargo/bin/cargo build -p cosmian_kms_cli -p cosmian_kms_server --release --no-default-features \
    && cp /root/kms/target/release/cosmian_kms_server /usr/bin/cosmian_kms_server \
    && cp /root/kms/target/release/ckms               /usr/bin/ckms

#
# Create working directory
#
WORKDIR /data

EXPOSE 9998

ENTRYPOINT ["cosmian_kms_server"]
