# AWS XKS

Specs: <https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md>

Code loosely inspired from <https://github.com/aws-samples/aws-kms-xks-proxy/> (License Apache 2.0)

## Authorization model

The `Sigv4MWare` middleware authenticates every request from AWS KMS using the shared
SigV4 secret. That signature is the trust boundary — it matches AWS's model in which the
AWS key policy / IAM is the source of truth for which principals may use a key.

Every XKS operation (`encrypt`, `decrypt`, `metadata`) runs under a single reserved KMS
identity, `AWS_XKS_SERVICE_USER` (`[aws-xks-service]`, defined in `mod.rs`), so any
correctly-signed request works regardless of the caller ARN. The `awsPrincipalArn` in the
request body is used for audit logging only, never for authorization.

Keys are **owned by `default_username`**, exactly as before, so operators keep full
administrative control (list, revoke, destroy, export) and key creation still satisfies the
`privileged_users` policy. `CreateKey` grants the reserved identity exactly `Encrypt`,
`Decrypt`, and `GetAttributes` — it is a least-privilege delegate that can neither revoke,
destroy, nor export key material (`Get` is deliberately not granted).

Two consequences follow from the grant-based model:

- The XKS endpoints can only reach objects that carry this grant, i.e. XKS keys — never any
  other object owned by `default_username`.
- Because the identity is wrapped in square brackets, it cannot collide with any identity a
  client can authenticate as (JWT `email`/subject, TLS certificate CN, AWS principal ARN,
  API-token user), so it cannot be impersonated over the normal interfaces.

Keys created by earlier KMS versions carried a grant bound to the creating ARN instead. On
startup, `migrate_aws_xks_key_access` (in `start_kms_server.rs`) grants those
`aws-xks`-tagged keys to the reserved identity. It is idempotent and performs no writes once
every key is up to date.

## Testing

Follow the instructions in `test_data/aws_xks/README.md` to run the AWS XKS tests.
