#
# KMS server
#
FROM rust:1.86.0-bookworm AS builder

LABEL version="5.8.0"
LABEL name="Cosmian KMS docker container"
LABEL org.opencontainers.image.description="Cosmian KMS docker container"
LABEL org.opencontainers.image.title="Cosmian KMS"
LABEL org.opencontainers.image.vendor="Cosmian"
LABEL org.opencontainers.image.source="https://github.com/Cosmian/kms"
LABEL org.opencontainers.image.documentation="https://docs.cosmian.com/key_management_system/"
LABEL org.opencontainers.image.licenses="BUSL-1.1"

ENV OPENSSL_DIR=/usr/local/openssl

# Add build argument for FIPS mode
ARG FIPS=false

WORKDIR /root

COPY . /root/kms

WORKDIR /root/kms

ARG TARGETPLATFORM
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then export ARCHITECTURE=x86_64; elif [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then export ARCHITECTURE=arm; elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then export ARCHITECTURE=arm64; else export ARCHITECTURE=x86_64; fi \
    && bash /root/kms/.github/reusable_scripts/get_openssl_binaries.sh

# Conditional cargo build based on FIPS argument
RUN if [ "$FIPS" = "true" ]; then \
    cargo build -p cosmian_kms_server --release --no-default-features; \
    else \
    cargo build -p cosmian_kms_server --release --no-default-features --features="non-fips"; \
    fi

# Create UI directory structure based on FIPS mode
RUN if [ "$FIPS" = "true" ]; then \
    cp -r crate/server/ui /tmp/ui_to_copy; \
    else \
    cp -r crate/server/ui_non_fips /tmp/ui_to_copy; \
    fi

#
# KMS server
#
FROM debian:bookworm-20250428-slim AS kms-server

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --no-install-recommends -qq -y ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/local/cosmian

COPY --from=builder /tmp/ui_to_copy                             /usr/local/cosmian/ui
COPY --from=builder /root/kms/target/release/cosmian_kms        /usr/bin/cosmian_kms
COPY --from=builder /usr/local/openssl                          /usr/local/openssl

EXPOSE 9998

ENTRYPOINT ["cosmian_kms"]
