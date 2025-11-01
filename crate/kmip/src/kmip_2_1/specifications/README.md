# KMIP 2.1 XML Specifications – Test Flow Overview

This directory contains the KMIP 2.1 conformance test vectors (XML) organized per profile:

- `XML/mandatory/` – Mandatory profile test cases
- `XML/optional/` – Optional profile test cases

They originate from the OASIS KMIP Profiles v2.1 repository of test cases. Our test harness parses each XML into structured KMIP requests/responses and executes them against the KMS, validating both behavior and payloads.

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

The table below summarizes the steps the harness performs for the common KMIP operations encountered in the vectors, including which fields are considered “relevant” for request preparation and response validation.

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

Notes:

- ID Placeholder: if a request omits `UniqueIdentifier`, the server may use the last UID. Vectors use `$UNIQUE_IDENTIFIER_0`, `$UNIQUE_IDENTIFIER_1`, etc.; the harness maps them to concrete values across requests.
- AEAD (e.g., AES-GCM): Encrypt may omit IV (RandomIV) with AAD; subsequent Decrypt must supply the captured IV and Tag with the same AAD.
- Multipart (Encrypt/Decrypt/MAC): we propagate `CorrelationValue` and honor `InitIndicator`/`FinalIndicator` flags.

## Example: BL-M-1-21 (mandatory)

The `BL-M-1-21.xml` vector exercises a canonical lifecycle of a symmetric key.

| Step | Operation       | Relevant inputs                                                             | Expected response focus                                      | Notes              |
| ---: | --------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------ | ------------------ |
|    1 | Interop (Begin) | InteropIdentifier=BL-M-1-21                                                 | Success                                                      | Start of test      |
|    2 | Register        | ObjectType=SymmetricKey; AES-128 Raw key; Name=BL-M-1-21; UsageMask=Encrypt | UniqueIdentifier=$UNIQUE_IDENTIFIER_0                        | Set ID Placeholder |
|    3 | Locate          | Name=BL-M-1-21                                                              | UniqueIdentifier=$UNIQUE_IDENTIFIER_0                        | Confirms register  |
|    4 | Get             | UniqueIdentifier=$UNIQUE_IDENTIFIER_0                                       | ObjectType=SymmetricKey; KeyFormat=Raw; AES-128 key material | Consistency check  |
|    5 | Destroy         | UniqueIdentifier=$UNIQUE_IDENTIFIER_0                                       | UniqueIdentifier=$UNIQUE_IDENTIFIER_0                        | Clean up           |
|    6 | Log             | LogMessage="Registered a symmetric key."                                    | Success                                                      | Informational      |
|    7 | Interop (End)   | InteropIdentifier=BL-M-1-21                                                 | Success                                                      | End of test        |

This pattern (Begin → operations → End) recurs across the suite, with operation specifics varying by profile (block cipher modes, key lengths, RSA OAEP, MACs, PKCS#11, etc.).

## Tips when reading vectors

- Look for `Operation` inside each `RequestMessage/BatchItem` to identify the step.
- In `RequestPayload`, look for `UniqueIdentifier`, `ObjectType`, `CryptographicParameters`, and op-specific elements (e.g., AAD, Tag).
- The `ResponseMessage/BatchItem` shows the required result and, when present, the authoritative `UniqueIdentifier` and outputs.

---
If you need a per-file, step-by-step expansion similar to BL-M-1-21 above, we can generate it on demand, but the high-level flow and table here should suffice for navigation and maintenance.

## Per-file summaries

Each table lists the RequestMessage operations in order. Details are best-effort and include common inputs like UID, ObjectType/Alg/Len, or flags (AAD/IV/Tag/Init/Final/Corr). Additional columns include the expected ResultStatus from the corresponding ResponseMessage and the ClientCorrelationValue from the RequestHeader when present.

### mandatory/AKLC-M-1-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | CreateKeyPair | -                        | Success         | AKLC-M-1-21 step=0 |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-1-21 step=1 |
|    3 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-M-1-21 step=2 |
|    4 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-1-21 step=3 |
|    5 | Destroy       | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-M-1-21 step=4 |

### mandatory/AKLC-M-2-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | CreateKeyPair | -                        | Success         | AKLC-M-2-21 step=0 |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-2-21 step=1 |
|    3 | Activate      | -                        | Success         | AKLC-M-2-21 step=2 |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-2-21 step=3 |
|    5 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-M-2-21 step=4 |
|    6 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | AKLC-M-2-21 step=5 |
|    7 | Destroy       | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-M-2-21 step=6 |
|    8 | Revoke        | -                        | Success         | AKLC-M-2-21 step=7 |
|    9 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-2-21 step=8 |
|   10 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-2-21 step=9 |

### mandatory/AKLC-M-3-21.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | CreateKeyPair   | -                        | Success         | AKLC-M-3-21 step=0 |
|    2 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-3-21 step=1 |
|    3 | Activate        | -                        | Success         | AKLC-M-3-21 step=2 |
|    4 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-3-21 step=3 |
|    5 | ModifyAttribute | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | AKLC-M-3-21 step=4 |
|    6 | Revoke          | -                        | Success         | AKLC-M-3-21 step=5 |
|    7 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-3-21 step=6 |
|    8 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-M-3-21 step=7 |
|    9 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-M-3-21 step=8 |
|   10 | Destroy         | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-M-3-21 step=9 |

### mandatory/AX-M-1-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | AX-M-1-21 step=0   |
|    2 | AddAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | AX-M-1-21 step=1   |
|    3 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | AX-M-1-21 step=2   |
|    4 | Revoke        | -                        | Success         | AX-M-1-21 step=3   |
|    5 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | AX-M-1-21 step=4   |

### mandatory/AX-M-2-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | AX-M-2-21 step=0   |
|    2 | Create        | ObjectType=SymmetricKey  | Success         | AX-M-2-21 step=1   |
|    3 | AddAttribute  | UID=$UNIQUE_IDENTIFIER_1 | Success         | AX-M-2-21 step=2   |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | AX-M-2-21 step=3   |
|    5 | Revoke        | -                        | Success         | AX-M-2-21 step=4   |
|    6 | Destroy       | UID=$UNIQUE_IDENTIFIER_1 | Success         | AX-M-2-21 step=5   |
|    7 | Revoke        | -                        | Success         | AX-M-2-21 step=6   |
|    8 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | AX-M-2-21 step=7   |

### mandatory/BL-M-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop   | Begin: BL-M-1-21         | Success         | -                  |
|    2 | Register  | ObjectType=SymmetricKey  | Success         | -                  |
|    3 | Locate    | Name=BL-M-1-21           | Success         | -                  |
|    4 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    6 | Log       | -                        | Success         | -                  |
|    7 | Interop   | End: BL-M-1-21           | Success         | -                  |

### mandatory/BL-M-10-21.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop         | Begin: BL-M-10-21        | Success         | -                  |
|    2 | Register        | ObjectType=Certificate   | Success         | -                  |
|    3 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | ModifyAttribute | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    5 | Interop         | End: BL-M-10-21          | Success         | -                  |

### mandatory/BL-M-11-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-11-21        | Success         | -                  |
|    2 | Register      | ObjectType=PrivateKey    | Success         | -                  |
|    3 | Revoke        | -                        | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Interop       | End: BL-M-11-21          | Success         | -                  |

### mandatory/BL-M-12-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-12-21        | Success         | -                  |
|    2 | Register      | ObjectType=PublicKey     | Success         | -                  |
|    3 | Get           | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Interop       | End: BL-M-12-21          | Success         | -                  |

### mandatory/BL-M-13-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-13-21        | Success         | -                  |
|    2 | Register      | ObjectType=PrivateKey    | Success         | -                  |
|    3 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | Get           | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    6 | Interop       | End: BL-M-13-21          | Success         | -                  |

### mandatory/BL-M-2-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-2-21         | Success         | -                  |
|    2 | Register      | ObjectType=SymmetricKey  | Success         | -                  |
|    3 | Activate      | -                        | OperationUndone | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Interop       | End: BL-M-2-21           | Success         | -                  |

### mandatory/BL-M-3-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-3-21         | Success         | -                  |
|    2 | Register      | ObjectType=SymmetricKey  | Success         | -                  |
|    3 | Get           | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Check         | -                        | Success         | -                  |
|    6 | Check         | -                        | OperationFailed | -                  |
|    7 | Interop       | End: BL-M-3-21           | Success         | -                  |

### mandatory/BL-M-4-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-4-21         | Success         | -                  |
|    2 | Register      | ObjectType=SecretData    | Success         | -                  |
|    3 | Locate        | Attributes=3             | Success         | -                  |
|    4 | Get           | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    6 | Get           | UID=AAABBBCCC            | OperationFailed | -                  |
|    7 | Interop       | End: BL-M-4-21           | Success         | -                  |

### mandatory/BL-M-5-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-5-21         | Success         | -                  |
|    2 | Register      | ObjectType=OpaqueObject  | Success         | -                  |
|    3 | Get           | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | AddAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | AddAttribute  | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    6 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    7 | Interop       | End: BL-M-5-21           | Success         | -                  |

### mandatory/BL-M-6-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-6-21         | Success         | -                  |
|    2 | Register      | ObjectType=PublicKey     | Success         | -                  |
|    3 | Get           | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    6 | Interop       | End: BL-M-6-21           | Success         | -                  |

### mandatory/BL-M-7-21.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop         | Begin: BL-M-7-21         | Success         | -                  |
|    2 | Register        | ObjectType=PrivateKey    | Success         | -                  |
|    3 | ModifyAttribute | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    4 | Revoke          | -                        | Success         | -                  |
|    5 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    6 | Interop         | End: BL-M-7-21           | Success         | -                  |

### mandatory/BL-M-8-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-8-21         | Success         | -                  |
|    2 | Register      | ObjectType=PublicKey     | Success         | -                  |
|    3 | AddAttribute  | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    4 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    6 | Get           | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | -                  |
|    7 | Interop       | End: BL-M-8-21           | Success         | -                  |

### mandatory/BL-M-9-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Interop       | Begin: BL-M-9-21         | Success         | -                  |
|    2 | Register      | ObjectType=PrivateKey    | Success         | -                  |
|    3 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | -                  |
|    5 | Interop       | End: BL-M-9-21           | Success         | -                  |

### mandatory/CS-AC-M-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=PrivateKey    | Success         | CS-AC-M-1-21 step=0 |
|    2 | Sign      | -                        | Success         | CS-AC-M-1-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-1-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-1-21 step=3 |

### mandatory/CS-AC-M-2-21.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation  |
| ---: | --------------- | ------------------------ | --------------- | ------------------- |
|    1 | Register        | ObjectType=PublicKey     | Success         | CS-AC-M-2-21 step=0 |
|    2 | SignatureVerify | -                        | Success         | CS-AC-M-2-21 step=1 |
|    3 | SignatureVerify | -                        | Success         | CS-AC-M-2-21 step=2 |
|    4 | SignatureVerify | -                        | Success         | CS-AC-M-2-21 step=3 |
|    5 | Revoke          | -                        | Success         | CS-AC-M-2-21 step=4 |
|    6 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-2-21 step=5 |

### mandatory/CS-AC-M-3-21.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation  |
| ---: | --------------- | ------------------------ | --------------- | ------------------- |
|    1 | Register        | ObjectType=PrivateKey    | Success         | CS-AC-M-3-21 step=0 |
|    2 | Register        | ObjectType=PublicKey     | Success         | CS-AC-M-3-21 step=1 |
|    3 | Sign            | -                        | Success         | CS-AC-M-3-21 step=2 |
|    4 | SignatureVerify | -                        | Success         | CS-AC-M-3-21 step=3 |
|    5 | SignatureVerify | -                        | Success         | CS-AC-M-3-21 step=4 |
|    6 | Revoke          | -                        | Success         | CS-AC-M-3-21 step=5 |
|    7 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-3-21 step=6 |
|    8 | Revoke          | -                        | Success         | CS-AC-M-3-21 step=7 |
|    9 | Destroy         | UID=$UNIQUE_IDENTIFIER_1 | Success         | CS-AC-M-3-21 step=8 |

### mandatory/CS-AC-M-4-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-AC-M-4-21 step=0 |
|    2 | MAC       | -                        | Success         | CS-AC-M-4-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-4-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-4-21 step=3 |

### mandatory/CS-AC-M-5-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-AC-M-5-21 step=0 |
|    2 | MACVerify | -                        | Success         | CS-AC-M-5-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-5-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-5-21 step=3 |

### mandatory/CS-AC-M-6-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-AC-M-6-21 step=0 |
|    2 | MAC       | -                        | Success         | CS-AC-M-6-21 step=1 |
|    3 | MACVerify | -                        | Success         | CS-AC-M-6-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-AC-M-6-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-6-21 step=4 |

### mandatory/CS-AC-M-7-21.xml

| Step | Operation | Details | Expected Status | Client Correlation  |
| ---: | --------- | ------- | --------------- | ------------------- |
|    1 | Hash      | -       | Success         | CS-AC-M-7-21 step=0 |
|    2 | Hash      | -       | Success         | CS-AC-M-7-21 step=1 |

### mandatory/CS-AC-M-8-21.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation  |
| ---: | --------------- | ------------------------ | --------------- | ------------------- |
|    1 | Register        | ObjectType=PrivateKey    | Success         | CS-AC-M-8-21 step=0 |
|    2 | Register        | ObjectType=PublicKey     | Success         | CS-AC-M-8-21 step=1 |
|    3 | Sign            | -                        | OperationFailed | CS-AC-M-8-21 step=2 |
|    4 | SignatureVerify | -                        | OperationFailed | CS-AC-M-8-21 step=3 |
|    5 | Revoke          | -                        | Success         | CS-AC-M-8-21 step=4 |
|    6 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-8-21 step=5 |
|    7 | Revoke          | -                        | Success         | CS-AC-M-8-21 step=6 |
|    8 | Destroy         | UID=$UNIQUE_IDENTIFIER_1 | Success         | CS-AC-M-8-21 step=7 |

### mandatory/CS-AC-M-OAEP-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | CS-AC-M-OAEP-1-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-AC-M-OAEP-1-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-1-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-1-21 step=3 |

### mandatory/CS-AC-M-OAEP-10-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation        |
| ---: | --------- | ------------------------ | --------------- | ------------------------- |
|    1 | Register  | ObjectType=PrivateKey    | Success         | CS-AC-M-OAEP-10-21 step=0 |
|    2 | Decrypt   | -                        | Success         | CS-AC-M-OAEP-10-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-10-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-10-21 step=3 |

### mandatory/CS-AC-M-OAEP-2-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | CS-AC-M-OAEP-2-21 step=0 |
|    2 | Decrypt   | -                        | Success         | CS-AC-M-OAEP-2-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-2-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-2-21 step=3 |

### mandatory/CS-AC-M-OAEP-3-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | CS-AC-M-OAEP-3-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-AC-M-OAEP-3-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-3-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-3-21 step=3 |

### mandatory/CS-AC-M-OAEP-4-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | CS-AC-M-OAEP-4-21 step=0 |
|    2 | Decrypt   | -                        | Success         | CS-AC-M-OAEP-4-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-4-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-4-21 step=3 |

### mandatory/CS-AC-M-OAEP-5-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | CS-AC-M-OAEP-5-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-AC-M-OAEP-5-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-5-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-5-21 step=3 |

### mandatory/CS-AC-M-OAEP-6-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | CS-AC-M-OAEP-6-21 step=0 |
|    2 | Decrypt   | -                        | Success         | CS-AC-M-OAEP-6-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-6-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-6-21 step=3 |

### mandatory/CS-AC-M-OAEP-7-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | CS-AC-M-OAEP-7-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-AC-M-OAEP-7-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-7-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-7-21 step=3 |

### mandatory/CS-AC-M-OAEP-8-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PrivateKey    | Success         | CS-AC-M-OAEP-8-21 step=0 |
|    2 | Decrypt   | -                        | Success         | CS-AC-M-OAEP-8-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-8-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-8-21 step=3 |

### mandatory/CS-AC-M-OAEP-9-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=PublicKey     | Success         | CS-AC-M-OAEP-9-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-AC-M-OAEP-9-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-AC-M-OAEP-9-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-AC-M-OAEP-9-21 step=3 |

### mandatory/CS-BC-M-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | CS-BC-M-1-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-BC-M-1-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-BC-M-1-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-1-21 step=3 |

### mandatory/CS-BC-M-10-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation   |
| ---: | --------- | ------------------------ | --------------- | -------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-10-21 step=0 |
|    2 | Encrypt   | IV                       | Success         | CS-BC-M-10-21 step=1 |
|    3 | Decrypt   | IV                       | Success         | CS-BC-M-10-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-10-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-10-21 step=4 |

### mandatory/CS-BC-M-11-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation   |
| ---: | --------- | ------------------------ | --------------- | -------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-11-21 step=0 |
|    2 | Encrypt   | IV                       | Success         | CS-BC-M-11-21 step=1 |
|    3 | Decrypt   | IV                       | Success         | CS-BC-M-11-21 step=2 |
|    4 | Decrypt   | -                        | OperationFailed | CS-BC-M-11-21 step=3 |
|    5 | Decrypt   | IV                       | Success         | CS-BC-M-11-21 step=4 |
|    6 | Revoke    | -                        | Success         | CS-BC-M-11-21 step=5 |
|    7 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-11-21 step=6 |

### mandatory/CS-BC-M-12-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation   |
| ---: | --------- | ------------------------ | --------------- | -------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-12-21 step=0 |
|    2 | Encrypt   | IV                       | Success         | CS-BC-M-12-21 step=1 |
|    3 | Decrypt   | -                        | OperationFailed | CS-BC-M-12-21 step=2 |
|    4 | Decrypt   | IV                       | Success         | CS-BC-M-12-21 step=3 |
|    5 | Revoke    | -                        | Success         | CS-BC-M-12-21 step=4 |
|    6 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-12-21 step=5 |

### mandatory/CS-BC-M-13-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation   |
| ---: | --------- | ------------------------ | --------------- | -------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-13-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-BC-M-13-21 step=1 |
|    3 | Decrypt   | -                        | OperationFailed | CS-BC-M-13-21 step=2 |
|    4 | Decrypt   | IV                       | Success         | CS-BC-M-13-21 step=3 |
|    5 | Revoke    | -                        | Success         | CS-BC-M-13-21 step=4 |
|    6 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-13-21 step=5 |

### mandatory/CS-BC-M-14-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation   |
| ---: | --------- | ------------------------ | --------------- | -------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-14-21 step=0 |
|    2 | Encrypt   | -                        | OperationFailed | CS-BC-M-14-21 step=1 |
|    3 | Decrypt   | -                        | OperationFailed | CS-BC-M-14-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-14-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-14-21 step=4 |

### mandatory/CS-BC-M-2-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | CS-BC-M-2-21 step=0 |
|    2 | Decrypt   | -                        | Success         | CS-BC-M-2-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-BC-M-2-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-2-21 step=3 |

### mandatory/CS-BC-M-3-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | CS-BC-M-3-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-BC-M-3-21 step=1 |
|    3 | Decrypt   | -                        | Success         | CS-BC-M-3-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-3-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-3-21 step=4 |

### mandatory/CS-BC-M-4-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-4-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-BC-M-4-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-BC-M-4-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-4-21 step=3 |

### mandatory/CS-BC-M-5-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-5-21 step=0 |
|    2 | Decrypt   | -                        | Success         | CS-BC-M-5-21 step=1 |
|    3 | Revoke    | -                        | Success         | CS-BC-M-5-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-5-21 step=3 |

### mandatory/CS-BC-M-6-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-6-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-BC-M-6-21 step=1 |
|    3 | Decrypt   | -                        | Success         | CS-BC-M-6-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-6-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-6-21 step=4 |

### mandatory/CS-BC-M-7-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-7-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-BC-M-7-21 step=1 |
|    3 | Encrypt   | -                        | OperationFailed | CS-BC-M-7-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-7-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-7-21 step=4 |

### mandatory/CS-BC-M-8-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-8-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-BC-M-8-21 step=1 |
|    3 | Decrypt   | -                        | Success         | CS-BC-M-8-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-8-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-8-21 step=4 |

### mandatory/CS-BC-M-9-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation  |
| ---: | --------- | ------------------------ | --------------- | ------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-9-21 step=0 |
|    2 | Encrypt   | -                        | Success         | CS-BC-M-9-21 step=1 |
|    3 | Decrypt   | -                        | Success         | CS-BC-M-9-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-9-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-9-21 step=4 |

### mandatory/CS-BC-M-CHACHA20-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation           |
| ---: | --------- | ------------------------ | --------------- | ---------------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-CHACHA20-1-21 step=0 |
|    2 | Encrypt   | IV                       | Success         | CS-BC-M-CHACHA20-1-21 step=1 |
|    3 | Decrypt   | IV                       | Success         | CS-BC-M-CHACHA20-1-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-CHACHA20-1-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-CHACHA20-1-21 step=4 |

### mandatory/CS-BC-M-CHACHA20-2-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation           |
| ---: | --------- | ------------------------ | --------------- | ---------------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-CHACHA20-2-21 step=0 |
|    2 | Encrypt   | IV                       | Success         | CS-BC-M-CHACHA20-2-21 step=1 |
|    3 | Decrypt   | IV                       | Success         | CS-BC-M-CHACHA20-2-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-CHACHA20-2-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-CHACHA20-2-21 step=4 |

### mandatory/CS-BC-M-CHACHA20-3-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation           |
| ---: | --------- | ------------------------ | --------------- | ---------------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-CHACHA20-3-30 step=0 |
|    2 | Encrypt   | IV                       | Success         | CS-BC-M-CHACHA20-3-30 step=1 |
|    3 | Decrypt   | IV                       | Success         | CS-BC-M-CHACHA20-3-30 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-CHACHA20-3-30 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-CHACHA20-3-30 step=4 |

### mandatory/CS-BC-M-CHACHA20POLY1305-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation                    |
| ---: | --------- | ------------------------ | --------------- | ------------------------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-CHACHA20POLY1305-1-21 step=0  |
|    2 | Encrypt   | AAD, IV                  | Success         | CS-BC-M-CHACHA20POLY1305-1-21 step=1  |
|    3 | Decrypt   | AAD, IV                  | Success         | CS-BC-M-CHACHA20POLY1305-1-21 step=2  |
|    4 | Decrypt   | AAD, IV                  | OperationFailed | CS-BC-M-CHACHA20POLY1305-1-21 step=3  |
|    5 | Decrypt   | AAD, IV                  | OperationFailed | CS-BC-M-CHACHA20POLY1305-1-21 step=4  |
|    6 | Decrypt   | AAD, IV                  | OperationFailed | CS-BC-M-CHACHA20POLY1305-1-21 step=5  |
|    7 | Decrypt   | AAD, IV                  | Success         | CS-BC-M-CHACHA20POLY1305-1-21 step=6  |
|    8 | Encrypt   | AAD, IV                  | OperationFailed | CS-BC-M-CHACHA20POLY1305-1-21 step=7  |
|    9 | Encrypt   | AAD, IV                  | OperationFailed | CS-BC-M-CHACHA20POLY1305-1-21 step=8  |
|   10 | Revoke    | -                        | Success         | CS-BC-M-CHACHA20POLY1305-1-21 step=9  |
|   11 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-CHACHA20POLY1305-1-21 step=10 |

### mandatory/CS-BC-M-GCM-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation       |
| ---: | --------- | ------------------------ | --------------- | ------------------------ |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-GCM-1-21 step=0  |
|    2 | Encrypt   | IV                       | Success         | CS-BC-M-GCM-1-21 step=1  |
|    3 | Decrypt   | IV                       | Success         | CS-BC-M-GCM-1-21 step=2  |
|    4 | Decrypt   | IV                       | OperationFailed | CS-BC-M-GCM-1-21 step=3  |
|    5 | Decrypt   | IV                       | OperationFailed | CS-BC-M-GCM-1-21 step=4  |
|    6 | Decrypt   | IV                       | OperationFailed | CS-BC-M-GCM-1-21 step=5  |
|    7 | Decrypt   | IV                       | Success         | CS-BC-M-GCM-1-21 step=6  |
|    8 | Encrypt   | IV                       | OperationFailed | CS-BC-M-GCM-1-21 step=7  |
|    9 | Encrypt   | IV                       | OperationFailed | CS-BC-M-GCM-1-21 step=8  |
|   10 | Revoke    | -                        | Success         | CS-BC-M-GCM-1-21 step=9  |
|   11 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-GCM-1-21 step=10 |

### mandatory/CS-BC-M-GCM-2-21.xml

| Step | Operation | Details                   | Expected Status | Client Correlation        |
| ---: | --------- | ------------------------- | --------------- | ------------------------- |
|    1 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=0   |
|    2 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=1   |
|    3 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=2   |
|    4 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=3   |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0  | Success         | CS-BC-M-GCM-2-21 step=4   |
|    6 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=5   |
|    7 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=6   |
|    8 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=7   |
|    9 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=8   |
|   10 | Destroy   | UID=$UNIQUE_IDENTIFIER_1  | Success         | CS-BC-M-GCM-2-21 step=9   |
|   11 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=10  |
|   12 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=11  |
|   13 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=12  |
|   14 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=13  |
|   15 | Destroy   | UID=$UNIQUE_IDENTIFIER_2  | Success         | CS-BC-M-GCM-2-21 step=14  |
|   16 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=15  |
|   17 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=16  |
|   18 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=17  |
|   19 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=18  |
|   20 | Destroy   | UID=$UNIQUE_IDENTIFIER_3  | Success         | CS-BC-M-GCM-2-21 step=19  |
|   21 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=20  |
|   22 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=21  |
|   23 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=22  |
|   24 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=23  |
|   25 | Destroy   | UID=$UNIQUE_IDENTIFIER_4  | Success         | CS-BC-M-GCM-2-21 step=24  |
|   26 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=25  |
|   27 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=26  |
|   28 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=27  |
|   29 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=28  |
|   30 | Destroy   | UID=$UNIQUE_IDENTIFIER_5  | Success         | CS-BC-M-GCM-2-21 step=29  |
|   31 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=30  |
|   32 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=31  |
|   33 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=32  |
|   34 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=33  |
|   35 | Destroy   | UID=$UNIQUE_IDENTIFIER_6  | Success         | CS-BC-M-GCM-2-21 step=34  |
|   36 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=35  |
|   37 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=36  |
|   38 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=37  |
|   39 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=38  |
|   40 | Destroy   | UID=$UNIQUE_IDENTIFIER_7  | Success         | CS-BC-M-GCM-2-21 step=39  |
|   41 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=40  |
|   42 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=41  |
|   43 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=42  |
|   44 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=43  |
|   45 | Destroy   | UID=$UNIQUE_IDENTIFIER_8  | Success         | CS-BC-M-GCM-2-21 step=44  |
|   46 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=45  |
|   47 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=46  |
|   48 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=47  |
|   49 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=48  |
|   50 | Destroy   | UID=$UNIQUE_IDENTIFIER_9  | Success         | CS-BC-M-GCM-2-21 step=49  |
|   51 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=50  |
|   52 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=51  |
|   53 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=52  |
|   54 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=53  |
|   55 | Destroy   | UID=$UNIQUE_IDENTIFIER_10 | Success         | CS-BC-M-GCM-2-21 step=54  |
|   56 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=55  |
|   57 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=56  |
|   58 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=57  |
|   59 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=58  |
|   60 | Destroy   | UID=$UNIQUE_IDENTIFIER_11 | Success         | CS-BC-M-GCM-2-21 step=59  |
|   61 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=60  |
|   62 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=61  |
|   63 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=62  |
|   64 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=63  |
|   65 | Destroy   | UID=$UNIQUE_IDENTIFIER_12 | Success         | CS-BC-M-GCM-2-21 step=64  |
|   66 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=65  |
|   67 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=66  |
|   68 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=67  |
|   69 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=68  |
|   70 | Destroy   | UID=$UNIQUE_IDENTIFIER_13 | Success         | CS-BC-M-GCM-2-21 step=69  |
|   71 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=70  |
|   72 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=71  |
|   73 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=72  |
|   74 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=73  |
|   75 | Destroy   | UID=$UNIQUE_IDENTIFIER_14 | Success         | CS-BC-M-GCM-2-21 step=74  |
|   76 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=75  |
|   77 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=76  |
|   78 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=77  |
|   79 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=78  |
|   80 | Destroy   | UID=$UNIQUE_IDENTIFIER_15 | Success         | CS-BC-M-GCM-2-21 step=79  |
|   81 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=80  |
|   82 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=81  |
|   83 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=82  |
|   84 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=83  |
|   85 | Destroy   | UID=$UNIQUE_IDENTIFIER_16 | Success         | CS-BC-M-GCM-2-21 step=84  |
|   86 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=85  |
|   87 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=86  |
|   88 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=87  |
|   89 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=88  |
|   90 | Destroy   | UID=$UNIQUE_IDENTIFIER_17 | Success         | CS-BC-M-GCM-2-21 step=89  |
|   91 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=90  |
|   92 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=91  |
|   93 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=92  |
|   94 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=93  |
|   95 | Destroy   | UID=$UNIQUE_IDENTIFIER_18 | Success         | CS-BC-M-GCM-2-21 step=94  |
|   96 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=95  |
|   97 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=96  |
|   98 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=97  |
|   99 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=98  |
|  100 | Destroy   | UID=$UNIQUE_IDENTIFIER_19 | Success         | CS-BC-M-GCM-2-21 step=99  |
|  101 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=100 |
|  102 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=101 |
|  103 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=102 |
|  104 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=103 |
|  105 | Destroy   | UID=$UNIQUE_IDENTIFIER_20 | Success         | CS-BC-M-GCM-2-21 step=104 |
|  106 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=105 |
|  107 | Encrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=106 |
|  108 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=107 |
|  109 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=108 |
|  110 | Destroy   | UID=$UNIQUE_IDENTIFIER_21 | Success         | CS-BC-M-GCM-2-21 step=109 |
|  111 | Register  | ObjectType=SymmetricKey   | Success         | CS-BC-M-GCM-2-21 step=110 |
|  112 | Encrypt   | AAD                       | Success         | CS-BC-M-GCM-2-21 step=111 |
|  113 | Decrypt   | AAD, IV                   | Success         | CS-BC-M-GCM-2-21 step=112 |
|  114 | Revoke    | -                         | Success         | CS-BC-M-GCM-2-21 step=113 |
|  115 | Destroy   | UID=$UNIQUE_IDENTIFIER_22 | Success         | CS-BC-M-GCM-2-21 step=114 |

### mandatory/CS-BC-M-GCM-3-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation      |
| ---: | --------- | ------------------------ | --------------- | ----------------------- |
|    1 | Register  | ObjectType=SymmetricKey  | Success         | CS-BC-M-GCM-3-21 step=0 |
|    2 | Encrypt   | AAD, IV, Init            | Success         | CS-BC-M-GCM-3-21 step=1 |
|    3 | Encrypt   | Final, Corr              | Success         | CS-BC-M-GCM-3-21 step=2 |
|    4 | Revoke    | -                        | Success         | CS-BC-M-GCM-3-21 step=3 |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | CS-BC-M-GCM-3-21 step=4 |

### mandatory/CS-RNG-M-1-21.xml

| Step | Operation   | Details | Expected Status | Client Correlation   |
| ---: | ----------- | ------- | --------------- | -------------------- |
|    1 | RNGRetrieve | -       | Success         | CS-RNG-M-1-21 step=0 |

### mandatory/MSGENC-HTTPS-M-1-21.xml

| Step | Operation | Details | Expected Status | Client Correlation         |
| ---: | --------- | ------- | --------------- | -------------------------- |
|    1 | Query     | -       | OperationFailed | MSGENC-HTTPS-M-1-21 step=0 |
|    2 | Query     | -       | Success         | MSGENC-HTTPS-M-1-21 step=1 |

### mandatory/MSGENC-JSON-M-1-21.xml

| Step | Operation | Details | Expected Status | Client Correlation        |
| ---: | --------- | ------- | --------------- | ------------------------- |
|    1 | Query     | -       | OperationFailed | MSGENC-JSON-M-1-21 step=0 |
|    2 | Query     | -       | Success         | MSGENC-JSON-M-1-21 step=1 |

### mandatory/MSGENC-XML-M-1-21.xml

| Step | Operation | Details | Expected Status | Client Correlation       |
| ---: | --------- | ------- | --------------- | ------------------------ |
|    1 | Query     | -       | OperationFailed | MSGENC-XML-M-1-21 step=0 |
|    2 | Query     | -       | Success         | MSGENC-XML-M-1-21 step=1 |

### mandatory/OMOS-M-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=OpaqueObject  | Success         | OMOS-M-1-21 step=0 |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | OMOS-M-1-21 step=1 |

### mandatory/PKCS11-M-1-21.xml

| Step | Operation | Details | Expected Status | Client Correlation   |
| ---: | --------- | ------- | --------------- | -------------------- |
|    1 | PKCS_11   | -       | Success         | PKCS11-M-1-21 step=0 |
|    2 | PKCS_11   | -       | Success         | PKCS11-M-1-21 step=1 |
|    3 | PKCS_11   | -       | Success         | PKCS11-M-1-21 step=2 |

### mandatory/QS-M-1-21.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | Success         | QS-M-1-21 step=0   |

### mandatory/QS-M-2-21.xml

| Step | Operation | Details                 | Expected Status | Client Correlation |
| ---: | --------- | ----------------------- | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey | OperationFailed | QS-M-2-21 step=0   |

### mandatory/SASED-M-1-21.xml

| Step | Operation | Details | Expected Status | Client Correlation  |
| ---: | --------- | ------- | --------------- | ------------------- |
|    1 | Query     | -       | Success         | SASED-M-1-21 step=0 |

### mandatory/SASED-M-2-21.xml

| Step | Operation | Details                | Expected Status | Client Correlation  |
| ---: | --------- | ---------------------- | --------------- | ------------------- |
|    1 | Locate    | Name=SASED-M-2-21-name | Success         | SASED-M-2-21 step=0 |
|    2 | Register  | ObjectType=SecretData  | Success         | SASED-M-2-21 step=1 |

### mandatory/SASED-M-3-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation  |
| ---: | ------------- | ------------------------ | --------------- | ------------------- |
|    1 | Locate        | Attributes=2             | Success         | SASED-M-3-21 step=0 |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | SASED-M-3-21 step=1 |
|    3 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | SASED-M-3-21 step=2 |
|    4 | Get           | UID=$UNIQUE_IDENTIFIER_0 | Success         | SASED-M-3-21 step=3 |
|    5 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | SASED-M-3-21 step=4 |

### mandatory/SKFF-M-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | SKFF-M-1-21 step=0 |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-1-21 step=1 |

### mandatory/SKFF-M-10-21.xml

| Step | Operation        | Details                  | Expected Status | Client Correlation   |
| ---: | ---------------- | ------------------------ | --------------- | -------------------- |
|    1 | Create           | ObjectType=SymmetricKey  | Success         | SKFF-M-10-21 step=0  |
|    2 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=1  |
|    3 | Activate         | -                        | Success         | SKFF-M-10-21 step=2  |
|    4 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=3  |
|    5 | Locate           | Name=SKFF-M-10-21        | Success         | SKFF-M-10-21 step=4  |
|    6 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=5  |
|    7 | Revoke           | -                        | Success         | SKFF-M-10-21 step=6  |
|    8 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=7  |
|    9 | GetAttributeList | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=8  |
|   10 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=9  |
|   11 | AddAttribute     | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=10 |
|   12 | ModifyAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=11 |
|   13 | DeleteAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=12 |
|   14 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=13 |
|   15 | Destroy          | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-10-21 step=14 |

### mandatory/SKFF-M-11-21.xml

| Step | Operation        | Details                  | Expected Status | Client Correlation   |
| ---: | ---------------- | ------------------------ | --------------- | -------------------- |
|    1 | Create           | ObjectType=SymmetricKey  | Success         | SKFF-M-11-21 step=0  |
|    2 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=1  |
|    3 | Activate         | -                        | Success         | SKFF-M-11-21 step=2  |
|    4 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=3  |
|    5 | Locate           | Name=SKFF-M-11-21        | Success         | SKFF-M-11-21 step=4  |
|    6 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=5  |
|    7 | Revoke           | -                        | Success         | SKFF-M-11-21 step=6  |
|    8 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=7  |
|    9 | GetAttributeList | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=8  |
|   10 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=9  |
|   11 | AddAttribute     | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=10 |
|   12 | ModifyAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=11 |
|   13 | DeleteAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=12 |
|   14 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=13 |
|   15 | Destroy          | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-11-21 step=14 |

### mandatory/SKFF-M-12-21.xml

| Step | Operation        | Details                  | Expected Status | Client Correlation   |
| ---: | ---------------- | ------------------------ | --------------- | -------------------- |
|    1 | Create           | ObjectType=SymmetricKey  | Success         | SKFF-M-12-21 step=0  |
|    2 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=1  |
|    3 | Activate         | -                        | Success         | SKFF-M-12-21 step=2  |
|    4 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=3  |
|    5 | Locate           | Name=SKFF-M-12-21        | Success         | SKFF-M-12-21 step=4  |
|    6 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=5  |
|    7 | Revoke           | -                        | Success         | SKFF-M-12-21 step=6  |
|    8 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=7  |
|    9 | GetAttributeList | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=8  |
|   10 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=9  |
|   11 | AddAttribute     | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=10 |
|   12 | ModifyAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=11 |
|   13 | DeleteAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=12 |
|   14 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=13 |
|   15 | Destroy          | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-12-21 step=14 |

### mandatory/SKFF-M-2-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | SKFF-M-2-21 step=0 |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-2-21 step=1 |

### mandatory/SKFF-M-3-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | SKFF-M-3-21 step=0 |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-3-21 step=1 |

### mandatory/SKFF-M-4-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | SKFF-M-4-21 step=0 |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-4-21 step=1 |

### mandatory/SKFF-M-5-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | SKFF-M-5-21 step=0 |
|    2 | Locate    | Name=SKFF-M-5-21         | Success         | SKFF-M-5-21 step=1 |
|    3 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-5-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-5-21 step=3 |
|    5 | Locate    | Attributes=1             | Success         | SKFF-M-5-21 step=4 |

### mandatory/SKFF-M-6-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | SKFF-M-6-21 step=0 |
|    2 | Locate    | Name=SKFF-M-6-21         | Success         | SKFF-M-6-21 step=1 |
|    3 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-6-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-6-21 step=3 |
|    5 | Locate    | Attributes=1             | Success         | SKFF-M-6-21 step=4 |

### mandatory/SKFF-M-7-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | SKFF-M-7-21 step=0 |
|    2 | Locate    | Name=SKFF-M-7-21         | Success         | SKFF-M-7-21 step=1 |
|    3 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-7-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-7-21 step=3 |
|    5 | Locate    | Attributes=1             | Success         | SKFF-M-7-21 step=4 |

### mandatory/SKFF-M-8-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey  | Success         | SKFF-M-8-21 step=0 |
|    2 | Locate    | Name=SKFF-M-8-21         | Success         | SKFF-M-8-21 step=1 |
|    3 | Get       | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-8-21 step=2 |
|    4 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-8-21 step=3 |
|    5 | Locate    | Attributes=1             | Success         | SKFF-M-8-21 step=4 |

### mandatory/SKFF-M-9-21.xml

| Step | Operation        | Details                  | Expected Status | Client Correlation  |
| ---: | ---------------- | ------------------------ | --------------- | ------------------- |
|    1 | Create           | ObjectType=SymmetricKey  | Success         | SKFF-M-9-21 step=0  |
|    2 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=1  |
|    3 | Activate         | -                        | Success         | SKFF-M-9-21 step=2  |
|    4 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=3  |
|    5 | Locate           | Name=SKFF-M-9-21         | Success         | SKFF-M-9-21 step=4  |
|    6 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=5  |
|    7 | Revoke           | -                        | Success         | SKFF-M-9-21 step=6  |
|    8 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=7  |
|    9 | GetAttributeList | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=8  |
|   10 | GetAttributes    | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=9  |
|   11 | AddAttribute     | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=10 |
|   12 | ModifyAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=11 |
|   13 | DeleteAttribute  | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=12 |
|   14 | Get              | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=13 |
|   15 | Destroy          | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKFF-M-9-21 step=14 |

### mandatory/SKLC-M-1-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | SKLC-M-1-21 step=0 |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-1-21 step=1 |
|    3 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-1-21 step=2 |

### mandatory/SKLC-M-2-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | SKLC-M-2-21 step=0 |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-2-21 step=1 |
|    3 | Activate      | -                        | Success         | SKLC-M-2-21 step=2 |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-2-21 step=3 |
|    5 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | SKLC-M-2-21 step=4 |
|    6 | Revoke        | -                        | Success         | SKLC-M-2-21 step=5 |
|    7 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-2-21 step=6 |
|    8 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-2-21 step=7 |

### mandatory/SKLC-M-3-21.xml

| Step | Operation       | Details                  | Expected Status | Client Correlation |
| ---: | --------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create          | ObjectType=SymmetricKey  | Success         | SKLC-M-3-21 step=0 |
|    2 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-3-21 step=1 |
|    3 | Activate        | -                        | Success         | SKLC-M-3-21 step=2 |
|    4 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-3-21 step=3 |
|    5 | ModifyAttribute | UID=$UNIQUE_IDENTIFIER_0 | OperationFailed | SKLC-M-3-21 step=4 |
|    6 | Revoke          | -                        | Success         | SKLC-M-3-21 step=5 |
|    7 | GetAttributes   | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-3-21 step=6 |
|    8 | Destroy         | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-M-3-21 step=7 |

### mandatory/TL-M-1-21.xml

| Step | Operation | Details | Expected Status | Client Correlation |
| ---: | --------- | ------- | --------------- | ------------------ |
|    1 | Query     | -       | Success         | TL-M-1-21 step=0   |

### mandatory/TL-M-2-21.xml

| Step | Operation | Details                 | Expected Status | Client Correlation |
| ---: | --------- | ----------------------- | --------------- | ------------------ |
|    1 | Create    | ObjectType=SymmetricKey | Success         | TL-M-2-21 step=0   |

### mandatory/TL-M-3-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Locate    | Attributes=2             | Success         | TL-M-3-21 step=0   |
|    2 | Locate    | Attributes=2             | Success         | TL-M-3-21 step=1   |
|    3 | Locate    | Attributes=2             | Success         | TL-M-3-21 step=2   |
|    4 | Locate    | Attributes=2             | Success         | TL-M-3-21 step=3   |
|    5 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | TL-M-3-21 step=4   |

### optional/AKLC-O-1-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | CreateKeyPair | -                        | Success         | AKLC-O-1-21 step=0 |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-O-1-21 step=1 |
|    3 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-O-1-21 step=2 |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | AKLC-O-1-21 step=3 |
|    5 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-O-1-21 step=4 |
|    6 | Destroy       | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-O-1-21 step=5 |
|    7 | GetAttributes | UID=$UNIQUE_IDENTIFIER_1 | Success         | AKLC-O-1-21 step=6 |

### optional/CS-RNG-O-1-21.xml

| Step | Operation | Details | Expected Status | Client Correlation   |
| ---: | --------- | ------- | --------------- | -------------------- |
|    1 | RNGSeed   | -       | Success         | CS-RNG-O-1-21 step=0 |

### optional/CS-RNG-O-2-21.xml

| Step | Operation | Details | Expected Status | Client Correlation   |
| ---: | --------- | ------- | --------------- | -------------------- |
|    1 | RNGSeed   | -       | Success         | CS-RNG-O-2-21 step=0 |

### optional/CS-RNG-O-3-21.xml

| Step | Operation | Details | Expected Status | Client Correlation   |
| ---: | --------- | ------- | --------------- | -------------------- |
|    1 | RNGSeed   | -       | Success         | CS-RNG-O-3-21 step=0 |

### optional/CS-RNG-O-4-21.xml

| Step | Operation | Details | Expected Status | Client Correlation   |
| ---: | --------- | ------- | --------------- | -------------------- |
|    1 | RNGSeed   | -       | OperationFailed | CS-RNG-O-4-21 step=0 |

### optional/OMOS-O-1-21.xml

| Step | Operation | Details                  | Expected Status | Client Correlation |
| ---: | --------- | ------------------------ | --------------- | ------------------ |
|    1 | Register  | ObjectType=OpaqueObject  | Success         | OMOS-O-1-21 step=0 |
|    2 | Destroy   | UID=$UNIQUE_IDENTIFIER_0 | Success         | OMOS-O-1-21 step=1 |

### optional/SKLC-O-1-21.xml

| Step | Operation     | Details                  | Expected Status | Client Correlation |
| ---: | ------------- | ------------------------ | --------------- | ------------------ |
|    1 | Create        | ObjectType=SymmetricKey  | Success         | SKLC-O-1-21 step=0 |
|    2 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-O-1-21 step=1 |
|    3 | Destroy       | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-O-1-21 step=2 |
|    4 | GetAttributes | UID=$UNIQUE_IDENTIFIER_0 | Success         | SKLC-O-1-21 step=3 |
