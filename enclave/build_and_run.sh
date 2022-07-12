#!/bin/bash

# We need to force the hosts and resolve which were modified by docker when starting
# Doing that, we are sure that the hashes (and the `MR_ENCLAVE``) will be the same on every dockers instance for a given docker 
cp etc/hosts /etc/hosts
cp etc/resolv.conf /etc/resolv.conf

if [ $# -eq 0 ]; then
    make SGX=1 && gramine-sgx ./kms
elif [ $# -eq 1 -a $1 = "--emulation" ]
    mkdir /opt/cosmian-internal
    # Generate a dummy key. `MR_ENCLAVE`` does not depend to it.
    openssl genrsa -3 -out /opt/cosmian-internal/cosmian-signer-key.pem 3072
    # Compile but don't start
    make SGX=1  
    # Note: if `public_data` is mounted inside the docker, the user can read `kms.manifest.kms` from outside the docker
else
    echo "Usage: $0 [--emulation]"
    echo "Using --emulation enables you to get the mr_enclave of the enclave server"
    echo "You don't need to use an SGX machine to use --emulation param"
fi
