#!/bin/bash

guix time-machine -C channels.scm -- \
    shell --container --network --emulate-fhs \
    -m .guix/packages/openssl.scm \
    -m manifest.scm -- \
    bash -lc 'bash .guix/kms.sh'
