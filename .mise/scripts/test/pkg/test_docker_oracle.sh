#!/bin/bash
# Oracle TDE remote upgrade and smoke test.
# Requires: DOCKER_IMAGE_NAME, ORACLE_KMS_DEMO_USER_PASS, COSMIAN_HSM_PIN env vars.
# Runs only on non-fips amd64 — the CI workflow enforces this via step conditions.

set -exuo pipefail

echo "Running Oracle TDE remote upgrade and smoke test"
TAG_ONLY="${DOCKER_IMAGE_NAME##*:}"

echo "Copy upgrade script to oracle"
ssh -o StrictHostKeyChecking=accept-new ec2-user@oracle.netbird.selfhosted \
  'cat > /tmp/upgrade-kms.sh' \
  <.mise/scripts/oracle/upgrade-kms.sh

echo "Run KMS upgrade on oracle"
ssh -o StrictHostKeyChecking=accept-new ec2-user@oracle.netbird.selfhosted \
  bash /tmp/upgrade-kms.sh "${TAG_ONLY}"

echo "Copy smoke test script to oracle"
ssh -o StrictHostKeyChecking=accept-new ec2-user@oracle.netbird.selfhosted \
  'cat > /tmp/smoke-test-tde.sh' \
  <.mise/scripts/oracle/smoke-test-tde.sh

echo "Run TDE smoke test on oracle"
ssh -o StrictHostKeyChecking=accept-new ec2-user@oracle.netbird.selfhosted \
  bash /tmp/smoke-test-tde.sh \
  "${ORACLE_KMS_DEMO_USER_PASS}" "${TAG_ONLY}" "${COSMIAN_HSM_PIN}"

echo "Cleanup smoke test scripts on oracle"
ssh -o StrictHostKeyChecking=accept-new ec2-user@oracle.netbird.selfhosted \
  rm -f /tmp/smoke-test-tde.sh /tmp/upgrade-kms.sh

echo "Oracle TDE remote upgrade and smoke test completed successfully"
