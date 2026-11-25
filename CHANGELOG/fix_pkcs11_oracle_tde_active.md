## Bug Fixes

### PKCS#11
- Keys and data objects created through `C_GenerateKey` / `C_CreateObject` (`ORACLE.TDE.HSM.MK.*`, `ORACLE.SECURITY.KM.ENCRYPTION.*`, `DATA_OBJECT_SUPPORTED_IDEN`) are now `Active` on import instead of `PreActive`, fixing `ORA-28353` when opening the Oracle TDE keystore. Objects created by earlier versions must be activated once with `ckms … activate`.
