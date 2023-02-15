#!/bin/sh

ssh $SGX_REMOTE docker pull $IMAGE_TAG
ssh $SGX_REMOTE docker stop $SHORT_IMAGE_NAME || true
ssh $SGX_REMOTE docker rm $SHORT_IMAGE_NAME || true
ssh $SGX_REMOTE sudo rm -rf /tmp/private_data /tmp/public_data /tmp/shared_data
ssh $SGX_REMOTE mkdir -p /tmp/private_data /tmp/public_data /tmp/shared_data
ssh $SGX_REMOTE docker run -d \
    --pull=always \
    --device /dev/sgx_enclave \
    --device /dev/sgx_provision \
    --name $SHORT_IMAGE_NAME \
    -v /var/run/aesmd:/var/run/aesmd/ \
    -v /opt/cosmian-internal:/opt/cosmian-internal \
    -v /tmp/public_data:/root/public_data \
    -v /tmp/private_data:/root/private_data \
    -v /tmp/shared_data:/root/shared_data \
    -p80:80 \
    -p443:443 \
    -it $IMAGE_TAG
ssh $SGX_REMOTE docker system prune --all -f
