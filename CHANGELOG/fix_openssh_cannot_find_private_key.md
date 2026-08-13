## Bug fixes

- **PKCS#11 provider — OpenSSH "cannot find private key"**: add backend fallback
  when the private key listed by `CKA_ID` is not found in the in-memory object
  store ([#1111](https://github.com/Cosmian/kms/issues/1111)).

  The fix for [#1076] made the `CKA_ID` object lookup class-aware, correctly
  resolving the private key from the public key's id by stripping the `_pk`
  suffix. However, this depended on the private key being present in the
  `OBJECTS_STORE`, which is populated at the start of every `C_FindObjectsInit`
  call by `find_all_objects`. That function uses single system tags (e.g.
  `["_sk"]`) to locate objects, and if the backend silently failed to return
  private keys (e.g. because the tag-based locate returned no results), the
  private key was absent from the store and the subsequent `CKO_PRIVATE_KEY`
  lookup by `CKA_ID` returned zero objects.

  The `CKO_PRIVATE_KEY` search by `CKA_ID` now falls back to the backend's
  `find_all_private_keys` (which uses user-scoped combined tags like
  `["ssh-auth", "_sk"]`) when the initial in-memory store lookup fails.

[#1076]: https://github.com/Cosmian/kms/issues/1076
