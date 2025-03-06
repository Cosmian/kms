# FROM ubuntu:22.04

# LABEL version="4.21.2"
# LABEL name="Cosmian KMS docker container"

# ENV DEBIAN_FRONTEND=noninteractive
# ENV OPENSSL_DIR=/usr/local/openssl

# WORKDIR /root

# RUN apt-get update \
#     && apt-get install --no-install-recommends -qq -y \
#     curl \
#     build-essential \
#     libssl-dev \
#     ca-certificates \
#     libclang-dev \
#     pkg-config \
#     git \
#     wget \
#     && apt-get -y -q upgrade \
#     && apt-get clean \
#     && rm -rf /var/lib/apt/lists/*

# RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "nightly-x86_64-unknown-linux-gnu"

# COPY . /root/kms

# WORKDIR /root/kms

# ARG TARGETPLATFORM
# RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then export ARCHITECTURE=x86_64; elif [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then export ARCHITECTURE=arm; elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then export ARCHITECTURE=arm64; else export ARCHITECTURE=x86_64; fi \
#     && bash /root/kms/.github/scripts/get_openssl_binaries.sh

# RUN /root/.cargo/bin/cargo build -p cosmian_kms_server --release --no-default-features \
#     && cp /root/kms/target/release/cosmian_kms_server /usr/bin/cosmian_kms_server
#     # && cp /root/kms/target/release/ckms               /usr/bin/ckms

# #
# # Create working directory
# #
# WORKDIR /data

# RUN  mkdir /data/ui && cp -R /root/kms/ui/dist /data/ui

# EXPOSE 9998

# ENTRYPOINT ["cosmian_kms_server"]


FROM rust:1.85.0-bullseye AS builder

LABEL version="4.22.1"
LABEL name="Cosmian KMS docker container"

ENV OPENSSL_DIR=/usr/local/openssl

# Add build argument for FIPS mode
ARG FIPS=false

WORKDIR /root

COPY . /root/kms

WORKDIR /root/kms

ARG TARGETPLATFORM
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then export ARCHITECTURE=x86_64; elif [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then export ARCHITECTURE=arm; elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then export ARCHITECTURE=arm64; else export ARCHITECTURE=x86_64; fi \
    && bash /root/kms/.github/scripts/get_openssl_binaries.sh

# Conditional cargo build based on FIPS argument
RUN if [ "$FIPS" = "true" ]; then \
    cargo build -p cosmian_kms_cli -p cosmian_kms_server --release --no-default-features --features="fips"; \
    else \
    cargo build -p cosmian_kms_cli -p cosmian_kms_server --release --no-default-features; \
    fi

#
# KMS server
#
FROM debian:bullseye-slim AS kms-server

COPY --from=builder /root/kms/target/release/cosmian_kms        /usr/bin/cosmian_kms
COPY --from=builder /root/kms/target/release/ckms               /usr/bin/ckms
COPY --from=builder /usr/local/openssl                          /usr/local/openssl

#
# Create working directory
#
WORKDIR /data

RUN  mkdir /data/ui
COPY --from=builder /root/kms/ui/dist /data/ui

EXPOSE 9998

ENTRYPOINT ["cosmian_kms"]
