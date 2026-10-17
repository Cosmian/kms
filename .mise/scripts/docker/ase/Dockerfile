# SAP ASE 16.x image built from the Developer Edition installer.
#
# Build context must contain ASE_Suite.linuxamd64.tgz (not in repo — download
# from SAP Software Center: me.sap.com/softwarecenter, search "Adaptive Server
# Enterprise Developer Edition").
#
# Build: docker build -t cosmian-ase-kmip .mise/scripts/docker/ase/
#        (run from repo root so docker-compose can use it)

# Stay on 22.04: from 24.04 on, libaio1 is renamed libaio1t64 (soname libaio.so.1t64), which SAP ASE binaries do not load.
FROM ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401

# SAP ASE runtime deps
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libaio1 libstdc++6 libgcc-s1 libpam0g bc hostname procps psmisc \
        openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /install

COPY ASE_Suite.linuxamd64.tgz response.txt ./

# Silent install — takes ~3-5 min; clean up installer after
# pipefail so a nonzero setup.bin exit fails the RUN even though tee succeeds
RUN /bin/bash -o pipefail -c 'tar xzf ASE_Suite.linuxamd64.tgz && \
    ./setup.bin -f response.txt -DAGREE_TO_SAP_LICENSE=true -i silent \
        -DRUN_SILENT=true 2>&1 | tee /tmp/ase_install.log && \
    rm -rf /install && \
    # Verify key binary exists
    test -f /opt/sap/ASE-16_1/bin/dataserver'

# Files copied before the entrypoint starts ASE are deployed into this directory.
RUN mkdir -p /root/.cosmian /opt/sap/ASE-16_1/ssl

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ASE listener + backup server + XP server
EXPOSE 5000 5001 5002

ENTRYPOINT ["/entrypoint.sh"]
