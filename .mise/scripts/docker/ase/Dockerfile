# SAP ASE 16.x image built from the Developer Edition installer.
#
# Build context must contain ASE_Suite.linuxamd64.tgz (not in repo — download
# from SAP Software Center: me.sap.com/softwarecenter, search "Adaptive Server
# Enterprise Developer Edition").
#
# Build: docker build -t cosmian-ase-kmip .mise/scripts/docker/ase/
#        (run from repo root so docker-compose can use it)

FROM ubuntu:22.04

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

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ASE listener + backup server + XP server
EXPOSE 5000 5001 5002

ENTRYPOINT ["/entrypoint.sh"]
