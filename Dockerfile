FROM ubuntu:22.04 AS builder

LABEL version="4.19.3"
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
    libsodium-dev \
    pkg-config \
    git \
    wget \
    && apt-get -y -q upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "nightly-x86_64-unknown-linux-gnu"

COPY . /root/kms

WORKDIR /root/kms

RUN mkdir -p $OPENSSL_DIR \
    && bash /root/kms/.github/scripts/local_ossl_instl.sh $OPENSSL_DIR

RUN /root/.cargo/bin/cargo build --release --no-default-features

#
# KMS Server
#
FROM ubuntu:22.04 AS kms

ENV DEBIAN_FRONTEND=noninteractive
ENV OPENSSL_DIR=/usr/local/openssl

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
COPY --from=builder $OPENSSL_DIR/lib64/ossl-modules/legacy.so $OPENSSL_DIR/lib64/ossl-modules/legacy.so

#
# Create working directory
#
WORKDIR /data

EXPOSE 9998

ENTRYPOINT ["cosmian_kms_server"]
