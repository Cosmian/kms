## Bug fixes

- **AWS XKS — key usage no longer restricted to the creator principal**
  ([#1093](https://github.com/Cosmian/kms/issues/1093)): the XKS proxy previously
  authorized each `Encrypt`/`Decrypt`/`GetKeyMetadata` request using the caller's
  `awsPrincipalArn`, and `CreateKey` granted usage only to the ARN that first created the
  key. As a result only that single principal could use the key, which broke AWS's model
  where the AWS key policy / IAM is the source of truth and made numerous or dynamic IAM
  roles (CI/CD, Lambda, EC2, SSO/Control Tower) unusable without a manual per-ARN entry.

  XKS requests are trusted on the basis of their SigV4 signature (the shared XKS credential
  authenticated by `Sigv4MWare`). XKS operations now run under a stable, reserved KMS
  service identity instead of the transient caller ARN, so any correctly-signed request may
  use the key regardless of which IAM role AWS used. The `awsPrincipalArn` is retained for
  audit logging only.

  Keys stay owned by `default_username`, so operators keep full administrative control
  (list, revoke, destroy, export) and key creation continues to honour `privileged_users`.
  The reserved identity is only granted `Encrypt`, `Decrypt` and `GetAttributes`: it is a
  least-privilege delegate that cannot revoke, destroy or export key material, and the XKS
  endpoints can therefore only reach XKS keys — no other object.

  XKS keys created by earlier versions are granted to the reserved identity at server
  startup; the migration is idempotent and requires no operator action.
