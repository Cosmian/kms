# Manual Setup for MongoDB Client-Side Field Level Encryption (CSFLE) with KMIP

This guide walks through the manual setup process for enabling Client-Side Field Level Encryption in MongoDB using a KMIP-compatible Key Management System (KMS).

---

## Prerequisites

### Packages
- **MongoDB Enterprise** ≥ `6.0`
- **Python** ≥ `3.8`
- **Python packages**:
  - `pymongo`
  - `dnspython`
- **MongoDB Crypt Shared Library**:
  - Download from the MongoDB Enterprise downloads section (e.g., `mongo_crypt_v1.so`)
  - Install to: `/opt/mongo_crypt_shared/mongo_crypt_v1.so`
- **Cosmian KMS**:
  - Cosmian KMS endpoint: `your-cosmian_kms-server:port`
  - TLS certs:
    - Client cert: `/opt/kms-certs/client.pem`
    - CA cert: `/opt/kms-certs/ca.pem`
- **Key Vault Namespace**:
  - Database: `encryption`
  - Collection: `__keyVault`
- **Schema Target Collection (example)**:
  - Database: `medical`
  - Collection: `patients`
- **Alternative Key Name** (for the DEK): `yourSecretKeyAlias`

---

## Step-by-Step Guide
⚠️ This tutorial was done in a DB test environment with an external cosmian kms.

### 1. Define environment variable

Ensure that the path to the crypt shared library is defined:

```bash
export CRYPT_SHARED_LIB_PATH=/opt/mongo_crypt_shared/mongo_crypt_v1.so
```

---

### 2. Clean up existing DEKs (optional)

```python
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")
client["encryption"]["__keyVault"].delete_many({"keyAltNames": ["yourSecretKeyAlias"]})
```

---

### 3. Generate a new DEK manually

```python
from pymongo.encryption import ClientEncryption
from pymongo import MongoClient
from bson.codec_options import CodecOptions

kms_providers = {
    "kmip": {
        "endpoint": "your-cosmian_kms-server:port"
    }
}

tls_options = {
    "kmip": {
        "tlsCertificateKeyFile": "/opt/kms-certs/client.pem",
        "tlsCAFile": "/opt/kms-certs/ca.pem"
    }
}

client = MongoClient("mongodb://localhost:27017")
client_encryption = ClientEncryption(
    kms_providers=kms_providers,
    key_vault_namespace="encryption.__keyVault",
    key_vault_client=client,
    codec_options=CodecOptions(),
    kms_tls_options=tls_options
)

data_key_id = client_encryption.create_data_key("kmip", key_alt_names=["yourSecretKeyAlias"])
print(f"Created DEK with ID: {data_key_id}")
```

---

### 4. Define your encryption schema

```python
schema_map = {
    "medical.patients": {
        "bsonType": "object",
        "properties": {
            "ssn": {
                "encrypt": {
                    "keyId": [data_key_id],
                    "bsonType": "string",
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                }
            }
        }
    }
}
```

---

### 5. Create the encrypted MongoClient

```python
from pymongo.encryption_options import AutoEncryptionOpts

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers=kms_providers,
    key_vault_namespace="encryption.__keyVault",
    schema_map=schema_map,
    kms_tls_options=tls_options,
    crypt_shared_lib_path=CRYPT_SHARED_LIB_PATH
)

secure_client = MongoClient("mongodb://localhost:27017", auto_encryption_opts=auto_encryption_opts)
```

---

### 6. Insert encrypted data

```python
db = secure_client["medical"]
collection = db["patients"]
collection.drop()

collection.insert_one({
    "nom": "Doe",
    "ssn": "123-45-6789"
})

print("Encrypted document inserted.")
```

---

## Notes

- Replace `your-cosmian_kms-server:port` with your KMIP endpoint (e.g. `cosmian-kms.example.com:5696`).
- Replace certificate paths if different.
- The `ssn` field will be transparently encrypted on insert, and decrypted on read.
- This setup requires MongoDB Enterprise, as CSFLE is not supported in the Community Edition.


---
<br>
<br>
<br>
<br>


# Reading Encrypted Data with MongoDB CSFLE (Client-Side Field Level Encryption)

## Step-by-Step Guide
This guide walks you through reading encrypted documents stored in MongoDB using automatic decryption with the CSFLE feature.

---

### 1. Set the Shared Crypt Library Path

Make sure the environment variable is set to the location of your shared crypt library:

```bash
export CRYPT_SHARED_LIB_PATH=/opt/mongo_crypt_shared/mongo_crypt_v1.so
```

---

### 2. (Optional) Read Raw Encrypted Documents

You can view the encrypted form of the documents using a regular (non-CSFLE-enabled) MongoDB client:

```python
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")

print("🔒 Raw encrypted documents:")
for doc in client.medical.patients.find():
    print(doc)
```

---

### 3. Define KMS Provider Configuration


```python
kms_providers = {
    "kmip": {
        "endpoint": "your-cosmian_kms-server:port"
    }
}

tls_options = {
    "kmip": {
        "tlsCertificateKeyFile": "/opt/kms-certs/client.pem",
        "tlsCAFile": "/opt/kms-certs/ca.pem"
    }
}
```

---

### 4. Configure AutoEncryptionOpts

This will enable automatic decryption using the shared library:

```python
import os
from pymongo.encryption_options import AutoEncryptionOpts

CRYPT_SHARED_LIB_PATH = os.getenv("CRYPT_SHARED_LIB_PATH", "/opt/mongo_crypt_shared/mongo_crypt_v1.so")

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers=kms_providers,
    key_vault_namespace="encryption.__keyVault",
    kms_tls_options=tls_options,
    crypt_shared_lib_path=CRYPT_SHARED_LIB_PATH
)
```

---

### 5. Create a Secure Client with CSFLE Enabled

```python
from pymongo import MongoClient

secure_client = MongoClient(
    "mongodb://localhost:27017",
    auto_encryption_opts=auto_encryption_opts
)
```

---

### 6. Read Decrypted Documents

```python
secure_db = secure_client["medical"]
secure_coll = secure_db["patients"]

print("🔓 Automatically decrypted documents:")
for doc in secure_coll.find():
    print(doc)
```

---

## Result

Encrypted fields will be automatically decrypted in the returned documents, provided the proper key is stored in your key vault and accessible via the configured Cosmian KMS.

---

## Notes

- Make sure the key vault namespace (`encryption.__keyVault`) matches the namespace used during encryption.
- This method works only with MongoDB Enterprise or MongoDB Atlas with CSFLE support.
