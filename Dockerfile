#
# KMS server
#
FROM rust:1.86.0-bookworm AS builder

LABEL version="5.1.1"
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
    cargo build -p cosmian_cli -p cosmian_kms_server --release --no-default-features --features="fips"; \
    else \
    cargo build -p cosmian_cli -p cosmian_kms_server --release --no-default-features; \
    fi

#
# KMS server
#
FROM debian:bookworm-20250428-slim AS kms-server

COPY --from=builder /root/kms/crate/server/ui                   /usr/local/cosmian/ui
COPY --from=builder /root/kms/target/release/cosmian_kms        /usr/bin/cosmian_kms
COPY --from=builder /root/kms/target/release/cosmian            /usr/bin/cosmian
COPY --from=builder /usr/local/openssl                          /usr/local/openssl

EXPOSE 9998

ENTRYPOINT ["cosmian_kms"]
