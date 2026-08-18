#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -m)" in
  arm64|aarch64) ARCH_TAG="add_role_to_user-arm64" ;;
  *)             ARCH_TAG="add_role_to_user-amd64" ;;
esac
echo "AUTH_SERVER_IMAGE=ghcr.io/cosmian/auth-server:${ARCH_TAG}" > .env
echo "==> Using auth-server image tag: ${ARCH_TAG}"

echo "==> Generating TLS certificate for auth-server..."
mkdir -p tls jwt
openssl ecparam -genkey -name prime256v1 -noout -out tls/tls.key.ec 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in tls/tls.key.ec -out tls/tls.key 2>/dev/null
openssl req -x509 -new -key tls/tls.key.ec -out tls/tls.crt \
  -days 3650 -nodes -subj "/CN=auth-server" \
  -addext "subjectAltName=DNS:auth-server,DNS:localhost" 2>/dev/null
rm -f tls/tls.key.ec

echo "==> Generating JWT signing key (EC P-256, PKCS8)..."
openssl ecparam -genkey -name prime256v1 -noout -out jwt/jwt_ec_private.pem 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in jwt/jwt_ec_private.pem -out jwt/jwt_ec_private_pkcs8.pem 2>/dev/null
openssl ec -in jwt/jwt_ec_private.pem -pubout -out jwt/jwt_ec_public.pem 2>/dev/null
rm -f jwt/jwt_ec_private.pem

echo "==> Starting stack (etcd, apisix, postgres, redis, auth-server)..."
docker compose up -d

echo "==> Waiting for auth-server to accept connections..."
for i in $(seq 1 30); do
  curl -sk -o /dev/null "https://localhost:18443/" 2>/dev/null && break
  sleep 2
done

echo "==> Waiting for APISIX admin API..."
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:9180/apisix/admin/routes" \
    -H "X-API-KEY: repro-admin-key-12345" && break
  sleep 2
done

echo ""
echo "Stack is up."
echo "  APISIX gateway : http://localhost:9080"
echo "  APISIX admin   : http://localhost:9180 (key: repro-admin-key-12345)"
echo "  auth-server    : direct access via 'docker compose exec auth-server' or port-forward"
echo ""
echo "Next: ./test-scripts/reproduce.sh"
