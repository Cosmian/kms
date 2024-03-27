# Cosmian KMIP

The `cosmian_kmip` library implements the KMIP standard such as operations, objects, types, etc.
It also implements the TTLV serialization format.

Using feature `openssl` it provides conversions from KMIP objects to OpenSSL objects.

For specific Cosmian crypto-systems, you can use the [cosmian_kmip](https://github.com/Cosmian/kms/tree/main/crate/kmip) to generate KMIP data with an abstraction level.

## Supported KMIP Objects

```mermaid
erDiagram
    Object ||--o| PrivateKey : enum
    Object ||--o| PublicKey : enum
    Object ||--o| SymmetricKey : enum
    Object ||--o| Certificate : enum

    PrivateKey ||--o| KeyBlock : has
    PublicKey ||--o| KeyBlock : has
    SymmetricKey ||--o| KeyBlock : has
    Certificate ||--o| CertificateType : has
    Certificate ||--o| CertificateValue : "DER bytes"

    KeyBlock ||--|| KeyFormatType : has
    KeyBlock ||--o| KeyCompressionType : has
    KeyBlock ||--|| KeyValue : has
    KeyBlock ||--|| CryptographicAlgorithm : has
    KeyBlock ||--|| CryptographicLength : i32
    KeyBlock ||--o| KeyWrappingData : has

    KeyValue ||--|| KeyMaterial : has
    KeyValue ||--o| Attributes : has

    KeyMaterial ||--o| BytesString : enum
    KeyMaterial ||--o| TransparentSymmetricKey : enum

    KeyWrappingData ||--|| WrappingMethod : has
    KeyWrappingData ||--o| EncryptionKeyInformation : has
    KeyWrappingData ||--o| MacSignatureKeyInformation : has
    KeyWrappingData ||--o| mac_or_signature : bytes
    KeyWrappingData ||--o| iv_counter_nonce : bytes
    KeyWrappingData ||--o| EncodingOption : has

    WrappingMethod ||--o| Encrypt : enum

    EncryptionKeyInformation ||--|| UniqueIdentifier : has
    EncryptionKeyInformation ||--o| CryptographicParameters : has

    EncodingOption ||--o| NoEncoding : enum
    EncodingOption ||--o| TTLVEncoding : enum

```

<!--

    Unsupported WrappingMethods

    WrappingMethod ||--o| MACSign : enum
    WrappingMethod ||--o| EncryptThenMACSign : enum
    WrappingMethod ||--o| MACSignThenEncrypt : enum
    WrappingMethod ||--o| TR31 : enum

-->
