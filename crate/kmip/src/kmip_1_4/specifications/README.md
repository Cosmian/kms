# KMIP 1.4 XML Specifications – Test Flow Overview

This directory contains the KMIP 1.4 conformance test vectors (XML) organized per profile:

- `XML/mandatory/` – Mandatory profile test cases
- `XML/optional/` – Optional profile test cases

They originate from the OASIS KMIP Profiles repository of test cases. Our test harness parses each XML into structured KMIP requests/responses and executes them against the KMS, validating both behavior and payloads.

## How the XML runner works

High-level loop per XML file:

1. Parse the XML into a `KmipXmlDoc` with RequestMessage(s)
   and expected ResponseMessage(s).
2. For each request in order:
   - Apply placeholder substitutions (e.g., `$UNIQUE_IDENTIFIER_0`, `$NOW`).
   - Inject cached values as required by later operations:
     - UID (ID Placeholder) from prior responses
     - AEAD artifacts (IV/Nonce, Tag, AAD) and correlation values
     - Sign/MAC outputs for verification requests
   - Send the request and capture the actual response.
   - Compare with expected response, allowing tolerated flexibilities
     (timestamps, RandomIV, allowed orderings, etc.).
   - Update caches (last UID, AEAD artifacts by AAD, correlation,
     last Signature/MAC).
3. Ensure request and response counts match and finalize invariants.

## End-to-end flow steps (what we validate)

|    # | Operation                             | Relevant request fields we track                                                        | Response validation focus                                                                | Cache and side-effects                    |
| ---: | ------------------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------- |
|    1 | Interop (Begin/End)                   | InteropIdentifier                                                                       | ResultStatus=Success                                                                     | None                                      |
|    2 | Log                                   | LogMessage                                                                              | ResultStatus=Success                                                                     | None                                      |
|    3 | Register                              | ObjectType; Object (KeyBlock/KeyValue); Attributes (Algorithm, Length, UsageMask, Name) | UniqueIdentifier returned; ObjectType and key material/attributes echoed when applicable | Set ID Placeholder (last UID)             |
|    4 | Create                                | ObjectType; Attributes (Algorithm, Length, UsageMask)                                   | UniqueIdentifier; created attributes                                                     | Set ID Placeholder                        |
|    5 | CreateKeyPair                         | Common/Private/Public Attributes                                                        | Private/Public Key UIDs                                                                  | Set ID Placeholder to Private Key UID     |
|    6 | Get                                   | UniqueIdentifier; KeyFormatType/Wrap params (optional)                                  | ObjectType; object payload (KeyBlock); echoed UID                                        | None                                      |
|    7 | Export                                | UniqueIdentifier; KeyFormatType/Wrap params                                             | ObjectType; Attributes; Object                                                           | None                                      |
|    8 | Import                                | Object (e.g., key/cert); Attributes (optional)                                          | UniqueIdentifier                                                                         | Set ID Placeholder                        |
|    9 | Locate                                | Attributes or Names used to search                                                      | One or more UniqueIdentifier values                                                      | Update last UID (when single result)      |
|   10 | SetAttribute                          | UniqueIdentifier; Attribute                                                             | UniqueIdentifier                                                                         | None                                      |
|   11 | Add/Modify/DeleteAttribute            | UniqueIdentifier; Attribute/Reference                                                   | UniqueIdentifier                                                                         | None                                      |
|   12 | GetAttributes                         | UniqueIdentifier; AttributeReference (optional)                                         | Attributes/values present                                                                | None                                      |
|   13 | Activate                              | UniqueIdentifier                                                                        | UniqueIdentifier                                                                         | None                                      |
|   14 | Revoke                                | UniqueIdentifier; RevocationReason                                                      | UniqueIdentifier                                                                         | None                                      |
|   15 | Validate                              | UniqueIdentifier(s) or Certificate; ValidityTime                                        | ValidateResponse payload                                                                 | None                                      |
|   16 | Encrypt                               | UID; CryptoParams; Data; IV?; AAD?; init/final?; corr?                                  | Ciphertext; IV (RandomIV); Tag; Corr                                                     | Cache AAD→(IV,Tag,CV); last enc artifacts |
|   17 | Decrypt                               | UID; CryptoParams; Data; IV; Tag; AAD; init/final; corr                                 | Plaintext; Corr (multipart)                                                              | Clear enc artifacts on completion         |
|   18 | MAC / MACVerify                       | UniqueIdentifier; Data; AAD; init/final; correlation                                    | MAC value (for MAC); verification result for MACVerify                                   | Cache last MAC for MACVerify              |
|   19 | Sign / SignatureVerify                | UniqueIdentifier; Data/Hash; Algorithm params                                           | Signature (for Sign); verification result for SignatureVerify                            | Cache last Signature for SignatureVerify  |
|   20 | PKCS11/PKCS11Response                 | Function; InputParameters; CorrelationValue                                             | ReturnCode; OutputParameters; CorrelationValue                                           | Cache last PKCS#11 correlation value      |
|   21 | DiscoverVersions/Query/Hash/DeriveKey | Operation-specific inputs                                                               | Response payload structure                                                               | None                                      |
|   22 | Destroy                               | UniqueIdentifier; extensions (remove/cascade when supported)                            | UniqueIdentifier                                                                         | None                                      |

---

## Per-file summaries

Each table lists the RequestMessage operations in order. Details are best-effort and include common inputs like UID, ObjectType/Alg/Len, or flags (AAD/IV/Tag/Init/Final/Corr). Additional columns include the expected ResultStatus from the corresponding ResponseMessage and the ClientCorrelationValue from the RequestHeader when present.

### mandatory/AKLC-M-1-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | CreateKeyPair | -                        | Success         | -                  |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    4 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Destroy       | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |

### mandatory/AKLC-M-2-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | CreateKeyPair | -                        | Success         | -                  |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Activate      | -                        | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    6 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    7 | Destroy       | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    8 | Revoke        | -                        | Success         | -                  |
|    9 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   10 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/AKLC-M-3-14.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | CreateKeyPair   | -                        | Success         | -                  |
|    2 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Activate        | -                        | Success         | -                  |
|    4 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | ModifyAttribute | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    6 | Revoke          | -                        | Success         | -                  |
|    7 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    8 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    9 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   10 | Destroy         | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |

### mandatory/AX-M-1-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | AddAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | Revoke        | -                        | Success         | -                  |
|    5 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/AX-M-2-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Create        | ObjectType=SymmetricKey  | Success         | -                  |
|    3 | AddAttribute  | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    5 | Revoke        | -                        | Success         | -                  |
|    6 | Destroy       | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    7 | Revoke        | -                        | Success         | -                  |
|    8 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-1-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | -                  |
|    2 | Sign      | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-2-14.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | Register        | ObjectType=PublicKey     | Success         | -                  |
|    2 | SignatureVerify | -                        | Success         | -                  |
|    3 | SignatureVerify | -                        | Success         | -                  |
|    4 | SignatureVerify | -                        | Success         | -                  |
|    5 | Revoke          | -                        | Success         | -                  |
|    6 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-3-14.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | Register        | ObjectType=PrivateKey    | Success         | -                  |
|    2 | Register        | ObjectType=PublicKey     | Success         | -                  |
|    3 | Sign            | -                        | Success         | -                  |
|    4 | SignatureVerify | -                        | Success         | -                  |
|    5 | SignatureVerify | -                        | Success         | -                  |
|    6 | Revoke          | -                        | Success         | -                  |
|    7 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    8 | Revoke          | -                        | Success         | -                  |
|    9 | Destroy         | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |

### mandatory/CS-AC-M-4-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | MAC       | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-5-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | MACVerify | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-6-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | MAC       | -                        | Success         | -                  |
|    3 | MACVerify | -                        | Success         | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-7-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Hash      | -       | Success         | -                  |
|    2 | Hash      | -       | Success         | -                  |

### mandatory/CS-AC-M-8-14.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | Register        | ObjectType=PrivateKey    | Success         | -                  |
|    2 | Register        | ObjectType=PublicKey     | Success         | -                  |
|    3 | Sign            | -                        | OperationFailed | -                  |
|    4 | SignatureVerify | -                        | OperationFailed | -                  |
|    5 | Revoke          | -                        | Success         | -                  |
|    6 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    7 | Revoke          | -                        | Success         | -                  |
|    8 | Destroy         | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-1-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-10-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | -                  |
|    2 | Decrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-2-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | -                  |
|    2 | Decrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-3-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-4-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | -                  |
|    2 | Decrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-5-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-6-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | -                  |
|    2 | Decrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-7-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-8-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | -                  |
|    2 | Decrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-AC-M-OAEP-9-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-1-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-10-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | IV                       | Success         | -                  |
|    3 | Decrypt   | IV                       | Success         | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-11-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | IV                       | Success         | -                  |
|    3 | Decrypt   | IV                       | Success         | -                  |
|    4 | Decrypt   | -                        | OperationFailed | -                  |
|    5 | Decrypt   | IV                       | Success         | -                  |
|    6 | Revoke    | -                        | Success         | -                  |
|    7 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-12-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | IV                       | Success         | -                  |
|    3 | Decrypt   | -                        | OperationFailed | -                  |
|    4 | Decrypt   | IV                       | Success         | -                  |
|    5 | Revoke    | -                        | Success         | -                  |
|    6 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-13-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Decrypt   | -                        | OperationFailed | -                  |
|    4 | Decrypt   | IV                       | Success         | -                  |
|    5 | Revoke    | -                        | Success         | -                  |
|    6 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-14-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | OperationFailed | -                  |
|    3 | Decrypt   | -                        | OperationFailed | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-2-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Decrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-3-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Decrypt   | -                        | Success         | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-4-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-5-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Decrypt   | -                        | Success         | -                  |
|    3 | Revoke    | -                        | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-6-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Decrypt   | -                        | Success         | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-7-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Encrypt   | -                        | OperationFailed | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-8-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Decrypt   | -                        | Success         | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-9-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | -                        | Success         | -                  |
|    3 | Decrypt   | -                        | Success         | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-GCM-1-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | IV                       | Success         | -                  |
|    3 | Decrypt   | IV                       | Success         | -                  |
|    4 | Decrypt   | IV                       | OperationFailed | -                  |
|    5 | Decrypt   | IV                       | OperationFailed | -                  |
|    6 | Decrypt   | IV                       | OperationFailed | -                  |
|    7 | Decrypt   | IV                       | Success         | -                  |
|    8 | Encrypt   | IV                       | OperationFailed | -                  |
|    9 | Encrypt   | IV                       | OperationFailed | -                  |
|   10 | Revoke    | -                        | Success         | -                  |
|   11 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-BC-M-GCM-2-14.xml

| Step | Operation | Details                   | Expected Status | Client Correlation |
| ---: | --------- | ------------------------- | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|    2 | Encrypt   | AAD, IV                   | Success         | -                  |
|    3 | Decrypt   | AAD, IV                   | Success         | -                  |
|    4 | Revoke    | -                         | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0  | Success         | -                  |
|    6 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|    7 | Encrypt   | AAD, IV                   | Success         | -                  |
|    8 | Decrypt   | AAD, IV                   | Success         | -                  |
|    9 | Revoke    | -                         | Success         | -                  |
|   10 | Destroy   | UID=$UNIQUE_IDENTIFIER_1  | Success         | -                  |
|   11 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   12 | Encrypt   | AAD, IV                   | Success         | -                  |
|   13 | Decrypt   | AAD, IV                   | Success         | -                  |
|   14 | Revoke    | -                         | Success         | -                  |
|   15 | Destroy   | UID=$UNIQUE_IDENTIFIER_2  | Success         | -                  |
|   16 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   17 | Encrypt   | AAD, IV                   | Success         | -                  |
|   18 | Decrypt   | AAD, IV                   | Success         | -                  |
|   19 | Revoke    | -                         | Success         | -                  |
|   20 | Destroy   | UID=$UNIQUE_IDENTIFIER_3  | Success         | -                  |
|   21 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   22 | Encrypt   | AAD, IV                   | Success         | -                  |
|   23 | Decrypt   | AAD, IV                   | Success         | -                  |
|   24 | Revoke    | -                         | Success         | -                  |
|   25 | Destroy   | UID=$UNIQUE_IDENTIFIER_4  | Success         | -                  |
|   26 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   27 | Encrypt   | AAD, IV                   | Success         | -                  |
|   28 | Decrypt   | AAD, IV                   | Success         | -                  |
|   29 | Revoke    | -                         | Success         | -                  |
|   30 | Destroy   | UID=$UNIQUE_IDENTIFIER_5  | Success         | -                  |
|   31 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   32 | Encrypt   | AAD, IV                   | Success         | -                  |
|   33 | Decrypt   | AAD, IV                   | Success         | -                  |
|   34 | Revoke    | -                         | Success         | -                  |
|   35 | Destroy   | UID=$UNIQUE_IDENTIFIER_6  | Success         | -                  |
|   36 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   37 | Encrypt   | AAD, IV                   | Success         | -                  |
|   38 | Decrypt   | AAD, IV                   | Success         | -                  |
|   39 | Revoke    | -                         | Success         | -                  |
|   40 | Destroy   | UID=$UNIQUE_IDENTIFIER_7  | Success         | -                  |
|   41 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   42 | Encrypt   | AAD, IV                   | Success         | -                  |
|   43 | Decrypt   | AAD, IV                   | Success         | -                  |
|   44 | Revoke    | -                         | Success         | -                  |
|   45 | Destroy   | UID=$UNIQUE_IDENTIFIER_8  | Success         | -                  |
|   46 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   47 | Encrypt   | AAD, IV                   | Success         | -                  |
|   48 | Decrypt   | AAD, IV                   | Success         | -                  |
|   49 | Revoke    | -                         | Success         | -                  |
|   50 | Destroy   | UID=$UNIQUE_IDENTIFIER_9  | Success         | -                  |
|   51 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   52 | Encrypt   | AAD, IV                   | Success         | -                  |
|   53 | Decrypt   | AAD, IV                   | Success         | -                  |
|   54 | Revoke    | -                         | Success         | -                  |
|   55 | Destroy   | UID=$UNIQUE_IDENTIFIER_10 | Success         | -                  |
|   56 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   57 | Encrypt   | AAD, IV                   | Success         | -                  |
|   58 | Decrypt   | AAD, IV                   | Success         | -                  |
|   59 | Revoke    | -                         | Success         | -                  |
|   60 | Destroy   | UID=$UNIQUE_IDENTIFIER_11 | Success         | -                  |
|   61 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   62 | Encrypt   | AAD, IV                   | Success         | -                  |
|   63 | Decrypt   | AAD, IV                   | Success         | -                  |
|   64 | Revoke    | -                         | Success         | -                  |
|   65 | Destroy   | UID=$UNIQUE_IDENTIFIER_12 | Success         | -                  |
|   66 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   67 | Encrypt   | AAD, IV                   | Success         | -                  |
|   68 | Decrypt   | AAD, IV                   | Success         | -                  |
|   69 | Revoke    | -                         | Success         | -                  |
|   70 | Destroy   | UID=$UNIQUE_IDENTIFIER_13 | Success         | -                  |
|   71 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   72 | Encrypt   | AAD, IV                   | Success         | -                  |
|   73 | Decrypt   | AAD, IV                   | Success         | -                  |
|   74 | Revoke    | -                         | Success         | -                  |
|   75 | Destroy   | UID=$UNIQUE_IDENTIFIER_14 | Success         | -                  |
|   76 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   77 | Encrypt   | AAD, IV                   | Success         | -                  |
|   78 | Decrypt   | AAD, IV                   | Success         | -                  |
|   79 | Revoke    | -                         | Success         | -                  |
|   80 | Destroy   | UID=$UNIQUE_IDENTIFIER_15 | Success         | -                  |
|   81 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   82 | Encrypt   | AAD, IV                   | Success         | -                  |
|   83 | Decrypt   | AAD, IV                   | Success         | -                  |
|   84 | Revoke    | -                         | Success         | -                  |
|   85 | Destroy   | UID=$UNIQUE_IDENTIFIER_16 | Success         | -                  |
|   86 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   87 | Encrypt   | AAD, IV                   | Success         | -                  |
|   88 | Decrypt   | AAD, IV                   | Success         | -                  |
|   89 | Revoke    | -                         | Success         | -                  |
|   90 | Destroy   | UID=$UNIQUE_IDENTIFIER_17 | Success         | -                  |
|   91 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   92 | Encrypt   | AAD, IV                   | Success         | -                  |
|   93 | Decrypt   | AAD, IV                   | Success         | -                  |
|   94 | Revoke    | -                         | Success         | -                  |
|   95 | Destroy   | UID=$UNIQUE_IDENTIFIER_18 | Success         | -                  |
|   96 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|   97 | Encrypt   | AAD, IV                   | Success         | -                  |
|   98 | Decrypt   | AAD, IV                   | Success         | -                  |
|   99 | Revoke    | -                         | Success         | -                  |
|  100 | Destroy   | UID=$UNIQUE_IDENTIFIER_19 | Success         | -                  |
|  101 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|  102 | Encrypt   | AAD, IV                   | Success         | -                  |
|  103 | Decrypt   | AAD, IV                   | Success         | -                  |
|  104 | Revoke    | -                         | Success         | -                  |
|  105 | Destroy   | UID=$UNIQUE_IDENTIFIER_20 | Success         | -                  |
|  106 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|  107 | Encrypt   | AAD, IV                   | Success         | -                  |
|  108 | Decrypt   | AAD, IV                   | Success         | -                  |
|  109 | Revoke    | -                         | Success         | -                  |
|  110 | Destroy   | UID=$UNIQUE_IDENTIFIER_21 | Success         | -                  |
|  111 | Register  | ObjectType=SymmetricKey   | Success         | -                  |
|  112 | Encrypt   | AAD                       | Success         | -                  |
|  113 | Decrypt   | AAD, IV                   | Success         | -                  |
|  114 | Revoke    | -                         | Success         | -                  |
|  115 | Destroy   | UID=$UNIQUE_IDENTIFIER_22 | Success         | -                  |

### mandatory/CS-BC-M-GCM-3-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Encrypt   | AAD, IV, Init            | Success         | -                  |
|    3 | Encrypt   | Final, Corr              | Success         | -                  |
|    4 | Revoke    | -                        | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/CS-RNG-M-1-14.xml

| Step | Operation   | Details | Expected Status | Client Correlation |
| ---: | ----------- | ------- | --------------- | ------------------ |
|    1 | RNGRetrieve | -       | Success         | -                  |

### mandatory/MSGENC-HTTPS-M-1-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | OperationFailed | -                  |
|    2 | Query     | -       | Success         | -                  |

### mandatory/MSGENC-JSON-M-1-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | OperationFailed | -                  |
|    2 | Query     | -       | Success         | -                  |

### mandatory/MSGENC-XML-M-1-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | OperationFailed | -                  |
|    2 | Query     | -       | Success         | -                  |

### mandatory/OMOS-M-1-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=OpaqueObject  | Success         | -                  |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SASED-M-1-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | Success         | -                  |

### mandatory/SASED-M-2-14.xml

| Step | Operation | Details               | Expected Status | Client Correlation |
| ---: | --------- | --------------------- | --------------- | ------------------ |
|    1 | Locate    | Attributes=0          | Success         | -                  |
|    2 | Register  | ObjectType=SecretData | Success         | -                  |

### mandatory/SASED-M-3-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Locate        | Attributes=0             | Success         | -                  |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | Get           | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKFF-M-1-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKFF-M-10-14.xml

| Step | Operation        | Details                  | Expected Status | Client Correlation |
| ---: | ---------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create           | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Activate         | -                        | Success         | -                  |
|    4 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Locate           | Attributes=0             | Success         | -                  |
|    6 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    7 | Revoke           | -                        | Success         | -                  |
|    8 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    9 | GetAttributeList | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   10 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   11 | AddAttribute     | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   12 | ModifyAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   13 | DeleteAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   14 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   15 | Destroy          | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKFF-M-11-14.xml

| Step | Operation        | Details                  | Expected Status | Client Correlation |
| ---: | ---------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create           | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Activate         | -                        | Success         | -                  |
|    4 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Locate           | Attributes=0             | Success         | -                  |
|    6 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    7 | Revoke           | -                        | Success         | -                  |
|    8 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    9 | GetAttributeList | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   10 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   11 | AddAttribute     | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   12 | ModifyAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   13 | DeleteAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   14 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   15 | Destroy          | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKFF-M-12-14.xml

| Step | Operation        | Details                  | Expected Status | Client Correlation |
| ---: | ---------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create           | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Activate         | -                        | Success         | -                  |
|    4 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Locate           | Attributes=0             | Success         | -                  |
|    6 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    7 | Revoke           | -                        | Success         | -                  |
|    8 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    9 | GetAttributeList | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   10 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   11 | AddAttribute     | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   12 | ModifyAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   13 | DeleteAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   14 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   15 | Destroy          | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKFF-M-2-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKFF-M-3-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKFF-M-4-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKFF-M-5-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Locate    | Attributes=0             | Success         | -                  |
|    3 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Locate    | Attributes=0             | Success         | -                  |

### mandatory/SKFF-M-6-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Locate    | Attributes=0             | Success         | -                  |
|    3 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Locate    | Attributes=0             | Success         | -                  |

### mandatory/SKFF-M-7-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Locate    | Attributes=0             | Success         | -                  |
|    3 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Locate    | Attributes=0             | Success         | -                  |

### mandatory/SKFF-M-8-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | Locate    | Attributes=0             | Success         | -                  |
|    3 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Locate    | Attributes=0             | Success         | -                  |

### mandatory/SKFF-M-9-14.xml

| Step | Operation        | Details                  | Expected Status | Client Correlation |
| ---: | ---------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create           | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Activate         | -                        | Success         | -                  |
|    4 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Locate           | Attributes=0             | Success         | -                  |
|    6 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    7 | Revoke           | -                        | Success         | -                  |
|    8 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    9 | GetAttributeList | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   10 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   11 | AddAttribute     | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   12 | ModifyAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   13 | DeleteAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   14 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|   15 | Destroy          | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKLC-M-1-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKLC-M-2-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Activate      | -                        | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    6 | Revoke        | -                        | Success         | -                  |
|    7 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    8 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SKLC-M-3-14.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create          | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Activate        | -                        | Success         | -                  |
|    4 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | ModifyAttribute | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    6 | Revoke          | -                        | Success         | -                  |
|    7 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    8 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### mandatory/SUITEB_128-M-1-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | Success         | -                  |

### mandatory/SUITEB_192-M-1-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | Success         | -                  |

### mandatory/TL-M-1-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | Success         | -                  |

### mandatory/TL-M-2-14.xml

| Step | Operation | Details                 | Expected Status | Client Correlation |
| ---: | --------- | ----------------------- | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey | Success         | -                  |

### mandatory/TL-M-3-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Locate    | Attributes=0             | Success         | -                  |
|    2 | Locate    | Attributes=0             | Success         | -                  |
|    3 | Locate    | Attributes=0             | Success         | -                  |
|    4 | Locate    | Attributes=0             | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### optional/AKLC-O-1-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | CreateKeyPair | -                        | Success         | -                  |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    6 | Destroy       | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |
|    7 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | -                  |

### optional/CS-RNG-O-1-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | RNGSeed   | -       | Success         | -                  |

### optional/CS-RNG-O-2-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | RNGSeed   | -       | Success         | -                  |

### optional/CS-RNG-O-3-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | RNGSeed   | -       | Success         | -                  |

### optional/CS-RNG-O-4-14.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | RNGSeed   | -       | OperationFailed | -                  |

### optional/OMOS-O-1-14.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=OpaqueObject  | Success         | -                  |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |

### optional/SKLC-O-1-14.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | -                  |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    3 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
