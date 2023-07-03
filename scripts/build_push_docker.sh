#!/bin/sh

set -x

# requires a `docker login ghcr.io -u <USER>` before running
docker rmi -f "$(docker images | grep "ghcr.io/cosmian/kms")"
docker build . -f delivery/Dockerfile.standalone -t ghcr.io/cosmian/kms:4.4.2
docker push ghcr.io/cosmian/kms:4.4.2
