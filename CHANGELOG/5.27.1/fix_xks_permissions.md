## Bug Fixes

### AWS XKS

- Reject `ReKey` (manual or via the auto-rotation scheduler) on `aws-xks`-tagged keys.
  Rotating one in place would assign a new internal unique identifier, but AWS KMS always
  calls the XKS proxy back with the original external key id and has no way to learn about
  a new one — silently breaking the key without any visible error on the AWS side. To
  rotate the material behind an external key, create a new external key (new CMK) in AWS
  KMS and destroy the old one via `ckms`/the Web UI once traffic has moved.
- Warn at startup when AWS XKS is enabled and `crypto_officer.users` is empty: since AWS
  never calls back to list, rotate, revoke, or destroy key material, a Crypto Officer must
  be configured (a real TLS certificate CN / OIDC subject matching `default_username`) so
  that XKS keys remain monitorable and manageable through the normal `ckms`/Web UI surface.

## Documentation

### AWS XKS

- Document that lifecycle management of XKS keys (monitoring, revocation, destruction) is
  entirely an operator responsibility exercised by a designated Crypto Officer, since AWS
  never triggers these operations itself. Explicitly warn against ever granting the
  reserved `AWS_XKS_SERVICE_USER` identity a real credential, as that would let any holder
  bypass AWS's SigV4 trust boundary.

## Testing

### AWS XKS

- Add regression coverage proving the real-credentialed key owner can monitor (`Locate`,
  `GetAttributes`) and administer (`Revoke`, `Destroy`) XKS keys end to end, that the
  reserved `AWS_XKS_SERVICE_USER` identity stays unreachable for this purpose, and that
  `ReKey` on an `aws-xks`-tagged key is rejected.
