############################################################
# Cosmian KMS - Docker image built from local Debian package
#
# This Dockerfile installs the prebuilt KMS server Debian package
# (FIPS by default) directly into a minimal Debian runtime image.
# Use DEB_FILE build-arg to select the exact .deb to install:
#   --build-arg DEB_FILE=result-deb-fips/cosmian-kms-server-fips_X.Y.Z-1_amd64.deb     (default)
#   --build-arg DEB_FILE=result-deb-non-fips/cosmian-kms-server_X.Y.Z-1_amd64.deb
############################################################

FROM debian:bookworm-20250428-slim AS kms-server

LABEL version="5.12.1"
LABEL name="Cosmian KMS docker container"
LABEL org.opencontainers.image.description="Cosmian KMS docker container"
LABEL org.opencontainers.image.title="Cosmian KMS"
LABEL org.opencontainers.image.vendor="Cosmian"
LABEL org.opencontainers.image.source="https://github.com/Cosmian/kms"
LABEL org.opencontainers.image.documentation="https://docs.cosmian.com/key_management_system/"
LABEL org.opencontainers.image.licenses="BUSL-1.1"

###
# Provide the Debian package file directly.
# Default to the FIPS variant produced by packaging.
# Override to non-FIPS with:
#   --build-arg DEB_FILE=result-deb-non-fips/cosmian-kms-server_X.Y.Z-1_amd64.deb
###
ARG DEB_FILE=result-deb-fips/cosmian-kms-server-fips_X.Y.Z-1_amd64.deb

ENV DEBIAN_FRONTEND=noninteractive

# Install ca-certificates and the locally provided Debian package
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the Debian package produced by the repository into the image
# Default file is the FIPS .deb; override with --build-arg DEB_FILE=...
COPY ${DEB_FILE} /tmp/kms.deb

# Install the package; apt can install a local .deb directly
# Provide a stub systemctl so postinst scripts that try to touch systemd succeed
RUN printf '#!/bin/sh\nexit 0\n' > /bin/systemctl \
    && chmod +x /bin/systemctl \
    && apt-get update \
    && apt-get install -y /tmp/kms.deb \
    && ln -s /usr/sbin/cosmian_kms /usr/bin/cosmian_kms \
    && rm -f /tmp/kms.deb \
    && rm -f /etc/cosmian/kms.toml \
    && rm -f /bin/systemctl \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 9998

# Default entrypoint; pass args at docker run time if desired
ENTRYPOINT ["cosmian_kms"]
