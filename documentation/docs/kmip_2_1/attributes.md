In [chapter 4](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html#_Toc32239322), the KMIP 2.1 specification specifies a list of 63 Attributes, mostly made of enumerations and data structures, often nested in each other. Despite this impressive list, and as expected in such a large specification, KMIP allows for extensions to support new cryptographic schemes such as the ones enabled by Cosmian.

Extensions in KMIP consist mostly in augmenting enumerations with new values and attributing a specific prefix values, usually `0x8880` to the new variants.

To support [Covercrypt](https://github.com/Cosmian/cover_crypt), Cosmian is using a few extensions listed below.

#### Key Format Type

The Key Format Type attribute is a required attribute of a Cryptographic Object.

It is set by the server, but a particular Key Format Type MAY be requested by the client if the cryptographic material is produced by the server (i.e., Create, Create Key Pair, Create Split Key, Re-key, Re-key Key Pair, Derive Key) on the client's behalf. The server SHALL comply with the client's requested format or SHALL fail the request. When the server calculates a Digest for the object, it SHALL compute the digest on the data in the assigned Key Format Type, as well as a digest in the default KMIP Key Format Type for that type of key and the algorithm requested (if a non-default value is specified).

##### Extensions

```c
CoverCryptSecretKey = 0x8880_000C,
CoverCryptPublicKey = 0x8880_000D,
```

#### Cryptographic Algorithm

The Cryptographic Parameters attribute is a structure that contains a set of OPTIONAL fields that describe certain cryptographic parameters to be used when performing cryptographic operations using the object. Specific fields MAY pertain only to certain types of Managed Objects. The Cryptographic Parameters attribute of a Certificate object identifies the cryptographic parameters of the public key contained within the Certificate.

The Cryptographic Algorithm is also used to specify the parameters for cryptographic operations. For operations involving digital signatures, either the Digital Signature Algorithm can be specified or the Cryptographic Algorithm and Hashing Algorithm combination can be specified.

Random IV can be used to request that the KMIP server generate an appropriate IV for a cryptographic operation that uses an IV. The generated Random IV is returned in the response to the cryptographic operation.

IV Length is the length of the Initialization Vector in bits. This parameter SHALL be provided when the specified Block Cipher Mode supports variable IV lengths such as CTR or GCM.

Tag Length is the length of the authenticator tag in bytes. This parameter SHALL be provided when the Block Cipher Mode is GCM.

The IV used with counter modes of operation (e.g., CTR and GCM) cannot repeat for a given cryptographic key. To prevent an IV/key reuse, the IV is often constructed of three parts: a fixed field, an invocation field, and a counter as described in [SP800-38A] and [SP800-38D]. The Fixed Field Length is the length of the fixed field portion of the IV in bits. The Invocation Field Length is the length of the invocation field portion of the IV in bits. The Counter Length is the length of the counter portion of the IV in bits.

Initial Counter Value is the starting counter value for CTR mode (for [RFC3686] it is 1).

##### Extensions

```c
CoverCrypt = 0x8880_0004,
```

#### Vendor Attributes

All keys managed by the Cosmian KMS server are primarily a `KeyMaterial` made of bytes. Some keys, typically those of ABE, also carry information regarding the underlying access policies. This information is carried together with the keys using [VendorAttributes](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html#_Toc32239382)

Typically a vendor attribute is made of 3 values: a `Vendor Identification` - always hardcoded to `cosmian` - and a tuple `Attribute Name`, `Attribute Value`.

Covercrypt uses a few vendor attributes which names can be seen in the code [attributes.rs](https://github.com/Cosmian/kms/blob/main/crate/kmip/src/crypto/cover_crypt/attributes.rs) file.

The attributes names and corresponding values used for a given `KeyFormatType` are as follows:

- `VENDOR_ATTR_COVER_CRYPT_POLICY = "cover_crypt_policy"`: the JSONified Policy found in the master keys.

- `VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY = "cover_crypt_access_policy"`: the JSONified boolean Access Policy found in a user key

In addition, the `VENDOR_ATTR_COVER_CRYPT_ATTR = "cover_crypt_attributes"` name is used in Locate requests to identify User Decryption Keys holding certain Policy Attributes.
