## Bug fixes

- **PKCS#11 provider — OpenSSH signing (`CKR_KEY_HANDLE_INVALID`)**: fix
  `C_SignInit` failing with error 96 (`CKR_KEY_HANDLE_INVALID`) during OpenSSH
  public-key authentication ([#1076](https://github.com/Cosmian/kms/issues/1076)).

  Standard PKCS#11 clients (e.g. OpenSSH) read a public key's `CKA_ID` and reuse
  it to locate the paired **private** key before signing. The KMS stores a key
  pair under two distinct UIDs — `<base>` (private key) and `<base>_pk` (public
  key) — so the two keys do not share a `CKA_ID`. A `CKO_PRIVATE_KEY` search by
  the public key's id previously returned the **public key** object (the id
  lookup had no class filter), and `C_SignInit` then rejected its handle.

  The module's `CKA_ID` object lookup is now class-aware: a `CKO_PRIVATE_KEY`
  search resolves only to a private key — matching the exact id, or, when given
  the paired public key's id, stripping the `_pk` suffix to reach the private
  key. Class-scoped searches for other object classes also enforce the requested
  class, so a search never returns a wrong-class object; a search that matches
  nothing now returns zero objects instead of an error.
