#!/usr/bin/env bash
set -euo pipefail
set -x

# Secret backend integration test — AWS Systems Manager Parameter Store
#
# Creates a SecureString parameter in SSM, runs the Rust #[ignore] integration
# test, then deletes the parameter.
#
# Required env vars (from GitHub secrets):
#   AWS_ACCESS_KEY_ID      — IAM credentials with ssm:GetParameter / ssm:PutParameter
#   AWS_SECRET_ACCESS_KEY  — (or AWS_PROFILE / instance role)
#   AWS_REGION             — region where the parameter is created (e.g. eu-west-1)
#   KMS_TEST_AWS_KMS_KEY_ID — (optional) KMS key ID for SecureString encryption;
#                             defaults to "alias/aws/ssm"
#
# Feature flag: secret-aws

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

require_cmd cargo "Cargo is required."
require_cmd aws "AWS CLI v2 is required."

echo "========================================="
echo "Running secret backend test: AWS SSM Parameter Store"
echo "Variant: ${VARIANT_NAME}"
echo "========================================="

AWS_REGION="${AWS_REGION:-eu-west-1}"
PARAM_NAME="/kms/ci/secret-backend-test"
SECRET_VALUE="ci-secret-value"
KMS_KEY="${KMS_TEST_AWS_KMS_KEY_ID:-alias/aws/ssm}"

cleanup() {
  echo "Deleting SSM parameter ${PARAM_NAME}..."
  aws ssm delete-parameter \
    --name "${PARAM_NAME}" \
    --region "${AWS_REGION}" 2>/dev/null || true
}
trap cleanup EXIT

echo "Creating SSM SecureString parameter ${PARAM_NAME} in ${AWS_REGION}..."
aws ssm put-parameter \
  --name "${PARAM_NAME}" \
  --value "${SECRET_VALUE}" \
  --type SecureString \
  --key-id "${KMS_KEY}" \
  --region "${AWS_REGION}" \
  --overwrite

echo "Building cosmian_kms_server with secret-aws feature..."
cargo build -p cosmian_kms_server --features secret-aws

echo "Running AWS SSM integration test..."
AWS_REGION="${AWS_REGION}" \
KMS_TEST_AWS_SSM_URI="aws-ssm://${AWS_REGION}${PARAM_NAME}" \
KMS_TEST_AWS_SSM_EXPECTED="${SECRET_VALUE}" \
cargo test -p cosmian_kms_server --features secret-aws --lib -- \
  --ignored --nocapture test_secret_aws_ssm

echo "AWS SSM secret backend test completed successfully."
