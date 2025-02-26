#!/bin/bash

env | sort

set -ex

DEBUG_OR_RELEASE="$1"

find . # List artifacts

apt update -y
apt-get install -y zip

for archive_name in $ARCHIVE_NAMES; do
  zip -r "$archive_name".zip "$archive_name"
done

# Warning, no windows binaries in debug
if [ "${DEBUG_OR_RELEASE}" = "release" ]; then
  zip -r "$archive_name".zip windows-release
fi

find . # List zip files

if [[ "${GITHUB_REF}" =~ 'refs/tags/' ]]; then
  BRANCH="${GITHUB_REF_NAME}"
else
  BRANCH="last_build/${GITHUB_HEAD_REF:-${GITHUB_REF#refs/heads/}}"
fi

DESTINATION_DIR=/mnt/package/cli/$BRANCH

ssh -o 'StrictHostKeyChecking no' -i /root/.ssh/id_rsa cosmian@package.cosmian.com mkdir -p "$DESTINATION_DIR"
scp -o 'StrictHostKeyChecking no' -i /root/.ssh/id_rsa ./*.zip cosmian@package.cosmian.com:"$DESTINATION_DIR"/

# Push the packages to the package.cosmian.com server
if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  KMS_DESTINATION_DIR=/mnt/package/kms/4.22.1
  FINDEX_SERVER_DESTINATION_DIR=/mnt/package/findex-server/0.2.0

  for dir in "$DESTINATION_DIR" "$KMS_DESTINATION_DIR" "$FINDEX_SERVER_DESTINATION_DIR"; do
    ssh -o 'StrictHostKeyChecking no' -i /root/.ssh/id_rsa cosmian@package.cosmian.com mkdir -p "$dir"/{rhel9,ubuntu-22.04,ubuntu-24.04}
  done

  # RedHat 9 package
  for dir in "$DESTINATION_DIR/rhel9" "$KMS_DESTINATION_DIR/rhel9" "$FINDEX_SERVER_DESTINATION_DIR/rhel9"; do
    scp -o 'StrictHostKeyChecking no' \
      -i /root/.ssh/id_rsa rhel9-"$DEBUG_OR_RELEASE"/generate-rpm/*.rpm \
      cosmian@package.cosmian.com:"$dir"/
    # Remove the old packages
    ssh -o 'StrictHostKeyChecking no' -i /root/.ssh/id_rsa cosmian@package.cosmian.com rm -f "$dir"/rhel9/cosmian_cli*.rpm
    for version in 22.04 24.04; do
      ssh -o 'StrictHostKeyChecking no' -i /root/.ssh/id_rsa cosmian@package.cosmian.com rm -f "$dir"/ubuntu-"$version"/cosmian-cli*.deb
    done
  done

  # Ubuntu packages
  for version in 22.04 24.04; do
    for dir in "$DESTINATION_DIR/ubuntu-$version" "$KMS_DESTINATION_DIR/ubuntu-$version" "$FINDEX_SERVER_DESTINATION_DIR/ubuntu-$version"; do
      scp -o 'StrictHostKeyChecking no' \
        -i /root/.ssh/id_rsa ubuntu_${version//./_}-"$DEBUG_OR_RELEASE"/debian/*.deb \
        cosmian@package.cosmian.com:"$dir"/
    done
  done
fi # end
