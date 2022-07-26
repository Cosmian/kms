#!/bin/sh

export KMS_DELEGATED_AUTHORITY_DOMAIN="dev-1mbsbmin.us.auth0.com"
export KMS_PUBLIC_PATH="data/public"
export KMS_SHARED_PATH="data/shared"
export KMS_PRIVATE_PATH="data/private"

mkdir -p ${KMS_PUBLIC_PATH} ${KMS_SHARED_PATH} ${KMS_PRIVATE_PATH} 

cargo run --bin cosmian_kms_server --features dev --no-default-features
