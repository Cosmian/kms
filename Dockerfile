FROM ubuntu:22.04 as builder

LABEL version="4.11.0"
LABEL name="Cosmian KMS docker container"

ARG FEATURES

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /root

RUN apt-get update \
    && apt-get install --no-install-recommends -qq -y \
    curl \
    build-essential \
    libssl-dev \
    ca-certificates \
    libclang-dev \
    libsodium-dev \
    pkg-config \
    git \
    && apt-get -y -q upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "nightly-x86_64-unknown-linux-gnu"

COPY . /root/kms

WORKDIR /root/kms
RUN /root/.cargo/bin/cargo build --release --no-default-features ${FEATURES}

#
# KMS Server
#
FROM ubuntu:22.04 as kms

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --no-install-recommends -qq -y \
    ca-certificates \
    libssl-dev \
    libsodium-dev \
    && apt-get -y -q upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/kms/target/release/cosmian_kms_server /usr/bin/cosmian_kms_server
COPY --from=builder /root/kms/target/release/ckms               /usr/bin/ckms

#
# Create working directory
#
WORKDIR /data

EXPOSE 9998

ENTRYPOINT ["cosmian_kms_server"]
