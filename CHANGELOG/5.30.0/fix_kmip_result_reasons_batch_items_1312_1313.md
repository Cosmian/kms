# KMIP response compliance corrections

## Bug Fixes

- KMIP 2.1 RNG Seed responses now encode `DataLength`, malformed Request Message responses echo their batch-item `Operation` and `UniqueBatchItemID`, and failed operations return their applicable result reason instead of `Operation_Not_Supported` ([#1312](https://github.com/Cosmian/kms/issues/1312), [#1313](https://github.com/Cosmian/kms/issues/1313)).

---

Closes #1312, #1313
