#
# KMS server
#
FROM rust:1.90.0-bullseye AS builder

LABEL version="5.11.0"
LABEL name="Cosmian KMS docker container"
LABEL org.opencontainers.image.description="Cosmian KMS docker container"
LABEL org.opencontainers.image.title="Cosmian KMS"
LABEL org.opencontainers.image.vendor="Cosmian"
LABEL org.opencontainers.image.source="https://github.com/Cosmian/kms"
LABEL org.opencontainers.image.documentation="https://docs.cosmian.com/key_management_system/"
LABEL org.opencontainers.image.licenses="BUSL-1.1"

# Add build argument for FIPS mode
ARG FIPS=false

# OpenSSL version to build against (must be 3.1.2 per project requirements)
ENV OPENSSL_VERSION=3.1.2 \
    OPENSSL_URL=https://www.openssl.org/source/old/3.1/openssl-3.1.2.tar.gz \
    OPENSSL_SHA256=a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539

WORKDIR /root

# System deps required to build OpenSSL and Rust crates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    build-essential \
    perl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build OpenSSL 3.1.2 with or without FIPS provider depending on ARG FIPS
RUN set -eux; \
    mkdir -p /tmp/openssl && cd /tmp/openssl; \
    curl -fsSL "$OPENSSL_URL" -o openssl.tar.gz; \
    echo "$OPENSSL_SHA256  openssl.tar.gz" | sha256sum -c -; \
    tar -xzf openssl.tar.gz --strip-components=1; \
    if [ "$FIPS" = "true" ]; then \
    CONF_OPTS="no-shared enable-fips"; \
    else \
    CONF_OPTS="no-shared no-fips"; \
    fi; \
    perl ./Configure $CONF_OPTS --prefix=/opt/openssl --openssldir=/opt/openssl/ssl linux-x86_64; \
    make -j$(nproc); \
    make install_sw; \
    if [ "$FIPS" = "true" ]; then \
    soext=so; [ "$(uname -s)" = "Darwin" ] && soext=dylib || true; \
    moddir=/opt/openssl/lib/ossl-modules; \
    /opt/openssl/bin/openssl fipsinstall -module "$moddir/fips.$soext" -out /opt/openssl/ssl/fipsmodule.cnf; \
    fi; \
    rm -rf /tmp/openssl

# Make OpenSSL discoverable to build scripts and prefer static linking
ENV OPENSSL_DIR=/opt/openssl \
    OPENSSL_STATIC=1 \
    OPENSSL_NO_VENDOR=1 \
    PKG_CONFIG_ALL_STATIC=1 \
    PKG_CONFIG_PATH=/opt/openssl/lib/pkgconfig

COPY . /root/kms

WORKDIR /root/kms

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

RUN mkdir -p /usr/local/cosmian /usr/local/openssl

COPY --from=builder /tmp/ui_to_copy                             /usr/local/cosmian/ui
COPY --from=builder /root/kms/target/release/cosmian_kms        /usr/bin/cosmian_kms
COPY --from=builder /opt/openssl                                 /usr/local/openssl

# Ensure provider modules can be discovered at runtime
ENV OPENSSL_MODULES=/usr/local/openssl/lib/ossl-modules \
    OPENSSL_CONF=/usr/local/openssl/ssl/openssl.cnf

EXPOSE 9998

ENTRYPOINT ["cosmian_kms"]
