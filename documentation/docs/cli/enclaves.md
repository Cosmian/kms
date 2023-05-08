# Enclaves Management

Commands specific to a KMS running in an enclave.

### new-database

Initialize a new database on the KMS [enclave mode only]

**Usage:**
```
ckms configure 
```

### trust

Query the enclave to check its trustworthiness

**Usage:**
```
ckms trust --mr-enclave <MR_ENCLAVE> <EXPORT_PATH>
```

**Arguments:**
```
<EXPORT_PATH>  The path to store exported files (quote, manifest, certificate, remote attestation, ...)
```

**Options:**
```
--mr-enclave <MR_ENCLAVE>  The value of the MR_ENCLAVE obtained by running the KMS docker on your local machine
-h, --help                 Print help
```