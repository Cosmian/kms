
This document is the main documentation of the Cosmian Key Management System.

## Introduction

The Cosmian Key Management System (KMS) is a high performance server application written in [Rust](https://www.rust-lang.org/) which provides a REST API to store and manage keys and secrets used with Cosmian cryptographic stacks.

The REST API follows the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the OASIS normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html). Only a limited set of operations of the KMIP 2.1 specification, described below, is supported but which is sufficient to exercise Cosmian cryptographic stacks.

This KMS completes classic offering of KMS servers on the market which are usually unable to natively support advanced cryptography. Do not hesitate to contact the Cosmian team if you wish to see additional cryptographic objects supported inside the Cosmian KMS.

## Advanced Cryptography

The Cosmian KMS server's primary goal is to provide support for storing, managing and performing cryptographic operations on the advanced cryptographic objects used by Cosmian, such as Attribute Based Encryption keys. Some of these cryptographic stacks, such as Searchable Encryption are built on top of classic symmetric primitives such as AES which are also available through the API of this KMS.

The supported cryptographic schemes are listed below.


#### AES 256 GCM

Used as a building block for other cryptographic primitives below, AES 256 GCM is fully supported in the KMS.
Keys are set to 256 bits to provide ~128 bits quantum resistance and the scheme uses Galois Counter Mode to offer a fast authenticated encryption algorithm. 

This implementation uses a 96 bits Nonce, a 128 bits MAC and is based on the AES native interface when available in the CPU or uses the Rust AES software package otherwise. See the [aes-gcm](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm) Rust crate for details and Cosmian wrapper in [cosmian_crypto_base](https://github.com/Cosmian/crypto_base)


#### xChacha20 Poly1305

As an alternative symmetric cryptographic building block to AES GCM, the xChacha20 Poly1305 construction found in [libsodium](https://doc.libsodium.org/) is also available in the KMS.


#### Ristretto x25519

Base elliptic curve cryptography is provided using curve 25519 on the prime order Ristretto group. 

The curve implementation is from the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) repository while the [cosmian_crypto_base](https://github.com/Cosmian/crypto_base) open source library provides an implementation of ECIES on the curve (Elliptic Curve Integrated Encryption Scheme).

#### Attribute Based Encryption (ABE)

The goal of Attribute Based Encryption is to embed access policies in cipher texts and user decryption keys to strongly control access to data without the use of a centralized authorization system.

The KMS supports a Key Policy Attributes Based Encryption known as GPSW06 based on the paper [Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data ](https://eprint.iacr.org/2006/309.pdf) by vipul Goyal, Omkant Pandey, Amit Sahai, Brent Waters. The implementation uses the BLS12-381 elliptic curve.

Please refer to this (Cosmian abe_gpsw repository)[https://github.com/Cosmian/abe_gpsw] for details on GPSW and BLS12-381.


#### Decentralized Multi-Client Functional Encryption (DMCFE)

DMCFE is used to apply linear functions to data encrypted by multiple data providers under their own key. The result consumer owns a functional key, which gives it with the ability to apply the embedded function to the encrypted data and decrypt the result.

The implementation is based on the paper [Implementation of a Decentralized Multi-Client Inner-Product Functional Encryption in the Random-Oracle Model](https://eprint.iacr.org/2020/788.pdf) by Michel Abdalla, Florian Bourse, Hugo Marival, David Pointcheval, Azam Soleimanian, and Hendrik Waldner. This implementation uses Learning With Errors (LWE) as a cryptographic scheme, a quantum resistant encryption scheme.


#### Format Preserving Encryption (FPE)

Format Preserving Encryption (FPE) is, as the name implies, used to keep the format of the encrypted data identical to that of the clear text data. Consider a credit card number of 16 digits; after encryption, the cipher text will still look like a 16 digit credit card number. FPE is particularly useful to add encryption in forms or databases where the data format cannot be changed.

Cosmian KMS exposes the [NIST recommended FF1 algorithm](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf). A [recent cryptanalysis paper](https://eprint.iacr.org/2020/1311) has exposed new attacks, and the Cosmian implementation of FF1 includes the increased umber of rounds of the Feistel recommended in the paper. Cosmian has open-sourced its implementation in [cosmian_crypto_base](https://github.com/Cosmian/crypto_base); check the `ff1.rs` files for details.


#### Torus Fully Homomorphic Encryption (TFHE)

Cosmian KMS also exposes cryptographic routines, key generation, encryption and decryption using Learning with Errors which are appropriate to use with TFHE. [LWE](https://en.wikipedia.org/wiki/Learning_with_errors) is used in cryptography to build a quantum resistant encryption scheme. [TFHE](https://eprint.iacr.org/2018/421) is a variant of fully homomorphic encryption over the torus, that is appropriate to perform secure computations on boolean circuits.

Please note that encryption with LWE for TFHE may result in very large cipher texts and lead to KMS performance issues.


## KMIP 2.1 Support

The Key Management Interoperability Protocol Specification Version 2.1 and Key Management Interoperability Protocol Profiles Version 2.1 are [OASIS](https://www.oasis-open.org/) Standards.

The goal of the OASIS KMIP is to define a single, comprehensive protocol for communication between encryption systems and a broad range of new and legacy enterprise applications, including email, databases, and storage devices. By removing redundant, incompatible key management processes, KMIP provides better data security while at the same time reducing expenditures on multiple products.

KMIP is a massive specification and support is limited to the requirements of Cosmian advanced cryptography. Although the KMS server functionalities evolve quickly to support the growing demand of customers, the Cosmian KMS server, ike most KMS server, is in no way claiming to be a complete solution for all cryptographic objects and operations.


### KMIP Objects

The KMIP 2.1 specification pre-defines a set of 9 cryptographic objects. Cosmian support its cryptographic library needs though the use of 4 of these objects


| Object              | Cosmian KMS                           |
| ------------------- | --------------------------------------|
| Certificate         | -                                     |
| Certificate Request | -                                     |
| Opaque Object       | -                                     |
| PGP Key             | -                                     |
| Private Key         | ABE, X25519                           |
| Public Key          | ABE, X25519                           |
| Secret Data         | DMCFE                                 |
| Split Key           | -                                     |
| Symmetric key       | SSE, AES, TFHE, DMCFE, FPE, xChacha20 |


The DMCE Functional Key does not exist as a separate object in the KMIP standard is mapped to a Secret Data Object.

The LWE keys used with DMCE and TFHE are actually symmetric keys, they both encrypt and decrypt, although there exists a sort of "Public Key" which is an Encryption of the value zero. Being a probabilistic Cipher Text, this "Publik Key" is not mapped to any KMP object.


### KMIP Object Attributes

In [chapter 4](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html#_Toc32239322), the KMIP 2.1 specifications specifies a list of 63 Attributes, mostly made of enumerations and data structures, often nested in each other. Despite this impressive list, and as expected in such a large specification, KMIP allows for extensions to support new cryptographic schemes such as the ones enabled by Cosmian.

Extensions in KMIP consist mostly in augmenting enumerations with new values and attributing a specific prefix values, usually `0x8880` to the new variants.

The Cosmian extensions are listed below. They can also be viewed in the open sourced [Cosmian java library](https://github.com/Cosmian/cosmian_java_lib/) which implements the KMIP specifications required to interact with the Cosmian KMS server. For instance, the `CryptographicAlgorithm` enumeration extensions can be viewed in [this java source code](https://github.com/Cosmian/cosmian_java_lib/blob/main/src/main/java/com/cosmian/rest/kmip/types/CryptographicAlgorithm.java)


##### KeyFormatType

The Key Format Type attribute is a required attribute of a Cryptographic Object. 

It is set by the server, but a particular Key Format Type MAY be requested by the client if the cryptographic material is produced by the server (i.e., Create, Create Key Pair, Create Split Key, Re-key, Re-key Key Pair, Derive Key) on the client’s behalf. The server SHALL comply with the client’s requested format or SHALL fail the request. When the server calculates a Digest for the object, it SHALL compute the digest on the data in the assigned Key Format Type, as well as a digest in the default KMIP Key Format Type for that type of key and the algorithm requested (if a non-default value is specified).

*Extensions*

```
McfeSecretKey = 0x8880_0001,
McfeMasterSecretKey = 0x8880_0002,
McfeFunctionalKey = 0x8880_0003,
McfeFksSecretKey = 0x8880_0004,
EnclaveECKeyPair = 0x8880_0005,
EnclaveECSharedKey = 0x8880_0006,
TFHE = 0x8880_0007,
AbeMasterSecretKey = 0x8880_0008,
AbeMasterPublicKey = 0x8880_0009,
AbeUserDecryptionKey = 0x8880_000A,
AbeSymmetricKey = 0x8880_000B,
```

##### CryptographicAlgorithm

The Cryptographic Parameters attribute is a structure that contains a set of OPTIONAL fields that describe certain cryptographic parameters to be used when performing cryptographic operations using the object. Specific fields MAY pertain only to certain types of Managed Objects. The Cryptographic Parameters attribute of a Certificate object identifies the cryptographic parameters of the public key contained within the Certificate.

The Cryptographic Algorithm is also used to specify the parameters for cryptographic operations. For operations involving digital signatures, either the Digital Signature Algorithm can be specified or the Cryptographic Algorithm and Hashing Algorithm combination can be specified.

Random IV can be used to request that the KMIP server generate an appropriate IV for a cryptographic operation that uses an IV. The generated Random IV is returned in the response to the cryptographic operation.

IV Length is the length of the Initialization Vector in bits. This parameter SHALL be provided when the specified Block Cipher Mode supports variable IV lengths such as CTR or GCM.

Tag Length is the length of the authenticator tag in bytes. This parameter SHALL be provided when the Block Cipher Mode is GCM.

The IV used with counter modes of operation (e.g., CTR and GCM) cannot repeat for a given cryptographic key. To prevent an IV/key reuse, the IV is often constructed of three parts: a fixed field, an invocation field, and a counter as described in [SP800-38A] and [SP800-38D]. The Fixed Field Length is the length of the fixed field portion of the IV in bits. The Invocation Field Length is the length of the invocation field portion of the IV in bits. The Counter Length is the length of the counter portion of the IV in bits.

Initial Counter Value is the starting counter value for CTR mode (for [RFC3686] it is 1).

*Extensions*

```
    LWE = 0x8880_0001,
    TFHE = 0x8880_0002,
    ABE = 0x8880_0003,
```

##### Vendor Attributes

All keys managed by the Cosmian KMS server are primarily a `KeyMaterial` made of bytes. Some keys, typically those of ABE, also carry information regarding the underlying access policies. This information is carried together with the keys using [VendorAttributes](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html#_Toc32239382)

Typically a vendor attribute is made of 3 values: a `Vendor Identification` - always hardcoded to `cosmian`  - and a tuple `Attribute Name`, `Attribute Value`.
The different attribute names can be seen in the [VendorAttributes.java](https://github.com/Cosmian/cosmian_java_lib/blob/main/src/main/java/com/cosmian/rest/kmip/types/VendorAttribute.java) file of the Cosmian Java Lib.

The attributes names and corresponding values used for a given `KeyFormatType` are as follows:

- `AbeMasterSecretKey` and `AbeMasterPublicKey`:
    - `VENDOR_ATTR_ABE_POLICY = "abe_policy"` : the JSONified Policy
- `AbeUserDecryptionKey`:
    - `VENDOR_ATTR_ABE_ACCESS_POLICY = "abe_access_policy"`: The JSONified boolean Access Policy of the key
  

In addition the `VENDOR_ATTR_ABE_ATTR = "abe_attributes"` name is used in Locate requests to identify User Decryption Keys holding certain Policy Attributes.


### KMIP Operations

In [chapter 6](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html#_Toc32239394), the KMIP 2.1 specifications describe 57 potential operations that can be performed on a KMS.

Out of this list, the Cosmian KMS server ony requires 9 operations to provide all required functionalities to support the cryptographic schemes available on the server. KMIP operations are usually made of large nested objects, a lot of them being optional. Despite the details provided in the specifications, some of the options are subject to interpretation and the list below disambiguate the Cosmian implementation.

KMIP states that a number of the operations are affected by a mechanism referred to as the ID Placeholder. It is a variable stored inside the server that is preserved during the execution of a batch of operations. Maintaining this value requires maintaining state during a batch session across multiple requests, and potentially multiple servers. The performance gain of using placeholder IDs is not obvious and the added complexity of maintaining sessions across multiple servers when scaling horizontally is not worth in Cosmian view for the type of operations conducted on the server. The Cosmian KMS servers are kept stateless to simplify horizontal scaling and therefore do not support placeholder IDs for now.

#### Import

##### specification

This operation requests the server to Import a Managed Object specified by its Unique Identifier. 
The request specifies the object being imported and all the attributes to be assigned to the object. 

The attribute rules for each attribute for “Initially set by” and “When implicitly set” SHALL NOT be enforced as all attributes MUST be set to the supplied values rather than any server generated values.

The response contains the Unique Identifier provided in the request or assigned by the server. The server SHALL copy the Unique Identifier returned by this operations into the ID Placeholder variable.

##### implementation

The server fully implements import operations for the supported objects in PlainText mode but only for Symmetric Keys in Wrapped mode.

=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

String uniqueIdentifier = ..., 
PrivateKey key = ...;
boolean replaceExisting = ...;
            
Import request = new Import(uniqueIdentifier, ObjectType.Private_Key, Optional.of(replaceExisting),
                    Optional.empty(), key.attributes(), key);
ImportResponse response = this.kmip.importObject(request);
```

=== "Java ABE"
``` java
Abe abe = new Abe(new RestClient(KMS_SERVER_URL, API_KEY));

String privateMasterKeyUniqueIdentifier = ...;
PrivateKey privateMasterKey = ...;
boolean replaceExisting = ...;
abe.importPrivateMasterKey(privateMasterKeyUniqueIdentifier, privateMasterKey, replaceExisting);

String publicMasterKeyUniqueIdentifier = ...;
PublicKey publicMasterKey = ...;
boolean replaceExisting = ...;
abe.importPublicMasterKey(publicMasterKeyUniqueIdentifier, publicMasterKey, replaceExisting);

String userDecryptionKeyUniqueIdentifier = ...;
PrivateKey userDecryptionKey = ...;
boolean replaceExisting = ...;
abe.importUserDecryptionKey(userDecryptionKeyUniqueIdentifier, userDecryptionKey, replaceExisting);
```

#### Create

##### specification

This operation requests the server to generate a new symmetric key or generate Secret Data as a Managed Cryptographic Object.

The request contains information about the type of object being created, and some of the attributes to be assigned to the object (e.g., Cryptographic Algorithm, Cryptographic Length, etc.). 

The response contains the Unique Identifier of the created object. The server SHALL copy the Unique Identifier returned this operation into the ID Placeholder variable.
    
##### implementation

The Cosmian KMS server support creation of all supported objects except for Public Keys which are creates using the [Create Key Pair](#create-key-pair) operation (as one would expect).

=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

Attributes commonAttributes = new Attributes(ObjectType.Private_Key, Optional.of(CryptographicAlgorithm.ABE));
commonAttributes.setKeyFormatType(Optional.of(KeyFormatType.AbeUserDecryptionKey)); 

// convert the Access Policy to attributes and attach it to the common attributes
AccessPolicy accessPolicy = new And(new Or(new Attr("Department", "FIN"), new Attr("Department", "MKG")),
				new Attr("Security Level", "Protected"));
VendorAttribute accessPolicyAttribute = accessPolicy.toVendorAttribute();
commonAttributes.setVendorAttributes(Optional.of(new VendorAttribute[] { accessPolicyAttribute }));
// link to the master private key
commonAttributes.setLink(new Link[] {new Link(LinkType.Parent_Link, new LinkedObjectIdentifier(privateMasterKeyUniqueIdentifier)) });

Create request = new Create(ObjectType.Private_Key, commonAttributes, Optional.empty());
CreateResponse response = kmip.create(request);
String keyUniqueIdentifier = response.getUniqueIdentifier();
```

=== "Java ABE"
``` java
Abe abe = new Abe(new RestClient(KMS_SERVER_URL, API_KEY));

String privateMasterKeyUniqueIdentifier = ...;
AccessPolicy accessPolicy = new And(new Or(new Attr("Department", "FIN"), new Attr("Department", "MKG")),
				new Attr("Security Level", "Protected"));

String userKeyUid = abe.createUserDecryptionKey(accessPolicy, privateMasterKeyUniqueIdentifier);
```

#### Create Key Pair

##### specification

This operation requests the server to generate a new public/private key pair and register the two corresponding new Managed Cryptographic Object.

The request contains attributes to be assigned to the objects (e.g., Cryptographic Algorithm, Cryptographic Length, etc.). Attributes MAY be specified for both keys at the same time by specifying a Common Attributes object in the request. 

Attributes not common to both keys (e.g., Name, Cryptographic Usage Mask) MAY be specified using the Private Key Attributes and Public Key Attributes objects in the request, which take precedence over the Common Attributes object.

For the Private Key, the server SHALL create a Link attribute of Link Type Public Key pointing to the Public Key. For the Public Key, the server SHALL create a Link attribute of Link Type Private Key pointing to the Private Key. The response contains the Unique Identifiers of both created objects. The ID Placeholder value SHALL be set to the Unique Identifier of the Private Key.

##### implementation

The Create Key Pair operation is used to create Curve 25519 Key Pairs as well as ABE Master Key Pairs.

=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

Policy policy = new Policy(20)
				.addAxis("Security Level", new String[] { "Protected", "Confidential", "Top Secret" }, true)
				.addAxis("Department", new String[] { "FIN", "MKG", "HR" }, false);

Attributes commonAttributes = new Attributes(ObjectType.Private_Key, Optional.of(CryptographicAlgorithm.ABE));
commonAttributes.setKeyFormatType(Optional.of(KeyFormatType.AbeMasterSecretKey));

// convert the Policy to attributes and attach it to the common attributes
VendorAttribute policy_attribute = policy.toVendorAttribute();
commonAttributes.setVendorAttributes(Optional.of(new VendorAttribute[] { policy_attribute }));

CreateKeyPair request = new CreateKeyPair(Optional.of(commonAttributes), Optional.empty());
CreateKeyPairResponse response = kmip.createKeyPair(request);
String masterPrivateKeyUniqueIdentifier =  response.getPrivateKeyUniqueIdentifier();
String masterPublicKeyUniqueIdentifier = response.getPublicKeyUniqueIdentifier();
```

=== "Java ABE"
``` java
Abe abe = new Abe(new RestClient(KMS_SERVER_URL, API_KEY));

Policy policy = new Policy(20)
				.addAxis("Security Level", new String[] { "Protected", "Confidential", "Top Secret" }, true)
				.addAxis("Department", new String[] { "FIN", "MKG", "HR" }, false);

String[] ids = abe.createMasterKeyPair(policy);
String masterPrivateKeyUniqueIdentifier =  ids[0];
String masterPublicKeyUniqueIdentifier = ids[1];
```
#### Decrypt

##### specification

This operation requests the server to perform a decryption operation on the provided data using a Managed Cryptographic Object as the key for the decryption operation.

The request contains information about the cryptographic parameters (mode and padding method), the data to be decrypted, and the IV/Counter/Nonce to use. The cryptographic parameters MAY be omitted from the request as they can be specified as associated attributes of the Managed Cryptographic Object. The initialization vector/counter/nonce MAY also be omitted from the request if the algorithm does not use an IV/Counter/Nonce.

The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and the result of the decryption operation.

The success or failure of the operation is indicated by the Result Status (and if failure the Result Reason) in the response header.

##### implementation

When used with an ABE user decryption key, this operation will attempt to perform a hybrid ABE+AES 256GCM decryption. The first 4 bytes of the cipher text are expected to be the ABE encrypted header length encoded as an an unsigned 32 bit in big endian format. The following bytes should contain the ABE header, made of an ABE encryption of the symmetric key, optionally followed by the symmetrically encoded meta data. The rest of the cipher text is the AES encrypted content.


=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

String userDecryptionKeyUniqueIdentifier = ...;
byte[] encryptedData = ...;
Optional<byte[]> authenticated_encryption_additional_data = ...;

Decrypt request = new Decrypt(userDecryptionKeyUniqueIdentifier, encryptedData, authenticated_encryption_additional_data);
DecryptResponse response = kmip.decrypt(request);
if (response.getData().isPresent()) {
    return response.getData().get();
}
throw new CosmianException("No decrypted data in response !");
```

=== "Java ABE"
``` java
Abe abe = new Abe(new RestClient(KMS_SERVER_URL, API_KEY));

String userDecryptionKeyUniqueIdentifier = ...;
byte[] encryptedData = ...;
Optional<byte[]> authenticated_encryption_additional_data = ...;
byte[] clearText = abe.kmsDecrypt(userDecryptionKeyUniqueIdentifier, encryptedData, 
                    Optional.of(authenticated_encryption_additional_data));
```

#### Destroy

##### specification

This operation is used to indicate to the server that the key material for the specified Managed Object SHALL be destroyed or rendered inaccessible. The meta-data for the key material SHALL be retained by the server. Objects SHALL only be destroyed if they are in either Pre-Active or Deactivated state.

##### implementation

Destroyed keys are set in the state `destroyed` on the Cosmian KMS Server.

=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

String uniqueIdentifier = ...;

Destroy request = new Destroy(Optional.of(uniqueIdentifier));
DestroyResponse response = kmip.destroy(request);
```

#### Encrypt

##### specification


This operation requests the server to perform an encryption operation on the provided data using a Managed Cryptographic Object as the key for the encryption operation.

The request contains information about the cryptographic parameters (mode and padding method), the data to be encrypted, and the IV/Counter/Nonce to use. The cryptographic parameters MAY be omitted from the request as they can be specified as associated attributes of the Managed Cryptographic Object. The IV/Counter/Nonce MAY also be omitted from the request if the cryptographic parameters indicate that the server shall generate a Random IV on behalf of the client or the encryption algorithm does not need an IV/Counter/Nonce. The server does not store or otherwise manage the IV/Counter/Nonce.

If the Managed Cryptographic Object referenced has a Usage Limits attribute then the server SHALL obtain an allocation from the current Usage Limits value prior to performing the encryption operation. If the allocation is unable to be obtained the operation SHALL return with a result status of Operation Failed and result reason of Permission Denied.

The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and the result of the encryption operation.

The success or failure of the operation is indicated by the Result Status (and if failure the Result Reason) in the response header.

##### implementation

When used with ABE master public key, this operation will perform an ABE+AES256GCM hybrid encryption. A symmetric key will be randomly generated and used to encrypt the content using AES 256 GCM. The symmetric key, will be encrypted using the ABE and given policy attributes in a header. The cipher text will then be the concatenation of 
    - 4 bytes representing the ABE encrypted header length encoded as an an unsigned 32 bit in big endian format
    - the ABE header
    - the symmetrically encrypted content
Note: the passed in the authentication parameters (typically the resource UID) used for authentication of the symmetrically encrypted content are NOT encrypted as part of the ABE header and must be re-supplied on decryption.


=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

// The policy attributes that will be used to encrypt the content. They must
// exist in the policy associated with the Public Key
Attr[] attributes = new Attr[] { new Attr("Department", "FIN"), new Attr("Security Level", "Confidential") };

String publicKeyUniqueIdentifier = ...;
byte[] clearText = ...;

// For ABE we need to use a specific structure to pass the policy attributes
// to the Encrypt operation
DataToEncrypt dataToEncrypt = new DataToEncrypt(attributes, clearText);
ObjectMapper mapper = new ObjectMapper();
byte[] bytes = mapper.writeValueAsBytes(dataToEncrypt);

Encrypt request = new Encrypt(publicKeyUniqueIdentifier, bytes, Optional.empty(), Optional.empty());
EncryptResponse response = this.kmip.encrypt(request);
if (response.getData().isPresent()) {
    return response.getData().get();
}
throw new CosmianException("No encrypted data in response !");
```

=== "Java ABE"
``` java
Abe abe = new Abe(new RestClient(KMS_SERVER_URL, API_KEY));

// The policy attributes that will be used to encrypt the content. They must
// exist in the policy associated with the Public Key
Attr[] attributes = new Attr[] { new Attr("Department", "FIN"), new Attr("Security Level", "Confidential") };

String publicKeyUniqueIdentifier = ...;
byte[] clearText = ...;

byte[] cipherText = abe.kmsEncrypt(publicKeyUniqueIdentifier, clearText, attributes, Optional.empty());
```

#### Get

##### specification

This operation requests that the server returns the Managed Object specified by its Unique Identifier. Only a single object is returned. 

The response contains the Unique Identifier of the object, along with the object itself, which MAY be wrapped using a wrapping key as specified in the request. The following key format capabilities SHALL be assumed by the client; restrictions apply when the client requests the server to return an object in a particular
format: 

 - If a client registered a key in a given format, the server SHALL be able to return the key during the Get operation in the same format that was used when the key was registered. 
 
 - Any other format conversion MAY be supported by the server. 
 
 If Key Format Type is specified to be PKCS#12 then the response payload shall be a PKCS#12 container as specified by [RFC7292]. 
 
The Unique Identifier shall be either that of a private key or certificate to be included in the response. 

The container shall be protected using the Secret Data object specified via the private key or certificate’s PKCS#12 Password Link. The current certificate chain shall also be included as determined by using the private key’s Public Key link to get the corresponding public key (where relevant), and then using that public key’s PKCS#12 Certificate Link to get the base certificate, and then using each certificate’s Certificate Link to build the certificate chain.  It is an error if there is more than one valid certificate chain.

##### implementation

The Cosmian KMS server returns the retrieved object in the same format as it was inserted and does not perform conversion.

=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

String userDecryptionKeyUniqueIdentifier = ...;

Get request = new Get(userDecryptionKeyUniqueIdentifier);
// It is better to specify the format and perform additional filtering server side
request.setKeyFormatType(Optional.of(KeyFormatType.AbeUserDecryptionKey));
GetResponse response = kmip.get(request);
Object object = response.getObject();
if (!(object instanceof PrivateKey)) {
    throw new CosmianException(
            "No ABE User Decryption Key at identifier " + userDecryptionKeyUniqueIdentifier);
}
```

=== "Java ABE"
``` java
Abe abe = new Abe(new RestClient(KMS_SERVER_URL, API_KEY));

String privateMasterKeyUniqueIdentifier = ...;
PublicKey masterPublicKey = abe.retrievePrivateMasterKey(privateMasterKeyUniqueIdentifier);

String publicMasterKeyUniqueIdentifier = ...;
PrivateKey masterPrivateKey = abe.retrievePublicMasterKey(publicMasterKeyUniqueIdentifier);

String userDecryptionKeyUniqueIdentifier = ...;
PrivateKey userKey = abe.retrieveUserDecryptionKey(userDecryptionKeyUniqueIdentifier);
```


#### Get Attributes

##### specification

This operation requests one or more attributes associated with a Managed Object. 

The object is specified by its Unique Identifier, and the attributes are specified by their name in the request. 

If a specified attribute has multiple instances, then all instances are returned. If a specified attribute does not exist (i.e., has no value), then it SHALL NOT be present in the returned response. If none of the requested attributes exist, then the response SHALL consist only of the Unique Identifier. The same Attribute Reference SHALL NOT be present more than once in a request.

If no Attribute Reference is provided, the server SHALL return all attributes.

##### implementation

The Cosmian KMS server fully implements Get Attributes on the supported Objects.


=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

String userDecryptionKeyUniqueIdentifier = ...;

GetAttributes request = new GetAttributes(userDecryptionKeyUniqueIdentifier, Optional.empty());
GetAttributesResponse response = kmip.get(request);
Attributes attributes = response.getAttributes();
```

#### Locate

##### specification

This operation requests that the server search for one or more Managed Objects, depending on the attributes specified in the request. All attributes are allowed to be used. The request MAY contain a Maximum Items field, which specifies the maximum number of objects to be returned. If the Maximum Items field is omitted, then the server MAY return all objects matched, or MAY impose an internal maximum limit due to resource limitations.

The request MAY contain an Offset Items field, which specifies the number of objects to skip that satisfy the identification criteria specified in the request. An Offset Items field of 0 is the same as omitting the Offset Items field. If both Offset Items and Maximum Items are specified in the request, the server skips Offset Items objects and returns up to Maximum Items objects.

If more than one object satisfies the identification criteria specified in the request, then the response MAY contain Unique Identifiers for multiple Managed Objects. Responses containing Unique Identifiers for multiple objects SHALL be returned in descending order of object creation (most recently created object first).  Returned objects SHALL match all of the attributes in the request. If no objects match, then an empty response payload is returned. If no attribute is specified in the request, any object SHALL be deemed to match the Locate request. The response MAY include Located Items which is the count of all objects that satisfy the identification criteria.

The server returns a list of Unique Identifiers of the found objects, which then MAY be retrieved using the Get operation. If the objects are archived, then the Recover and Get operations are REQUIRED to be used to obtain those objects. If a single Unique Identifier is returned to the client, then the server SHALL copy the Unique Identifier returned by this operation into the ID Placeholder variable.  If the Locate operation matches more than one object, and the Maximum Items value is omitted in the request, or is set to a value larger than one, then the server SHALL empty the ID Placeholder, causing any subsequent operations that are batched with the Locate, and which do not specify a Unique Identifier explicitly, to fail. This ensures that these batched operations SHALL proceed only if a single object is returned by Locate.

The Date attributes in the Locate request (e.g., Initial Date, Activation Date, etc.) are used to specify a time or a time range for the search. If a single instance of a given Date attribute is used in the request (e.g., the Activation Date), then objects with the same Date attribute are considered to be matching candidate objects. If two instances of the same Date attribute are used (i.e., with two different values specifying a range), then objects for which the Date attribute is inside or at a limit of the range are considered to be matching candidate objects. If a Date attribute is set to its largest possible value, then it is equivalent to an undefined attribute.

When the Cryptographic Usage Mask attribute is specified in the request, candidate objects are compared against this field via an operation that consists of a logical AND of the requested mask with the mask in the candidate object, and then a comparison of the resulting value with the requested mask. For example, if the request contains a mask value of 10001100010000, and a candidate object mask contains 10000100010000, then the logical AND of the two masks is 10000100010000, which is compared against the mask value in the request (10001100010000) and the match fails. This means that a matching candidate object has all of the bits set in its mask that are set in the requested mask, but MAY have additional bits set.

When the Usage Limits attribute is specified in the request, matching candidate objects SHALL have a Usage Limits Count and Usage Limits Total equal to or larger than the values specified in the request.

When an attribute that is defined as a structure is specified, all of the structure fields are not REQUIRED to be specified. For instance, for the Link attribute, if the Linked Object Identifier value is specified without the Link Type value, then matching candidate objects have the Linked Object Identifier as specified, irrespective of their Link Type.

When the Object Group attribute and the Object Group Member flag are specified in the request, and the value specified for Object Group Member is ‘Group Member Fresh’, matching candidate objects SHALL be fresh objects from the object group. If there are no more fresh objects in the group, the server MAY choose to generate a new object on-the-fly, based on server policy. If the value specified for Object Group Member is ‘Group Member Default’, the server locates the default object as defined by server policy.

The Storage Status Mask field is used to indicate whether on-line objects (not archived or destroyed), archived objects, destroyed objects or any combination of the above are to be searched.The server SHALL NOT return unique identifiers for objects that are destroyed unless the Storage Status Mask field includes the Destroyed Storage indicator. The server SHALL NOT return unique identifiers for objects that are archived unless the Storage Status Mask field includes the Archived Storage indicator.

##### implementation

Locate is currently limited to finding Objects `Link`ed to other objects using their uid or matching certain a certain `VendorAttribute` value.

#### Re-key Key Pair

##### specification

This request is used to generate a replacement key pair for an existing public/private key pair. It is analogous to the Create Key Pair operation, except that attributes of the replacement key pair are copied from the existing key pair, with the exception of the attributes listed in Re-key Key Pair Attribute Requirements tor.

As the replacement of the key pair takes over the name attribute for the existing public/private key pair, Re-key Key Pair SHOULD only be performed once on a given key pair.

For both the existing public key and private key, the server SHALL create a Link attribute of Link Type Replacement Key pointing to the replacement public and private key, respectively. For both the replacement public and private key, the server SHALL create a Link attribute of Link Type Replaced Key pointing to the existing public and private key, respectively.

The server SHALL copy the Private Key Unique Identifier of the replacement private key returned by this operation into the ID Placeholder variable.

An Offset MAY be used to indicate the difference between the Initial Date and the Activation Date of the replacement key pair. If no Offset is specified, the Activation Date and Deactivation Date values are copied from the existing key pair. If Offset is set and dates exist for the existing key pair, then the dates of the replacement key pair SHALL be set based on the dates of the existing key pair as follows

##### implementation

The Re-Key Key Pair Operation is the main mechanism to rotate ABE attributes on the Cosmian KMS Server. By updating, through this operation, the Policy held by a Master Private Key in it Vendor Attributes, the Cosmian KMS Server will automatically

 - update the Policy held by the Master Public Key 
 - and re-key all non revoked User Decryption Keys holding the rotated policy attributes in a way that they will now be able to decrypt cipher texts encrypted with attributes before and after the rotation.

 The operation has currently no other usages on the Cosmian server.


=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

String userDecryptionKeyUniqueIdentifier = ...;

// This will rekey in the KMS:
// 
// - the Master Public Key
// - all User Decryption Keys that contain one of these attributes in their
// policy and are not revoked.
// 
// the ABE policy attributes to rotate
Attr[] abePolicyAttributes = ...;

Attributes attributes = new Attributes(ObjectType.Private_Key, Optional.of(CryptographicAlgorithm.ABE));
attributes.keyFormatType(Optional.of(KeyFormatType.AbeMasterSecretKey));
attributes.vendorAttributes(
        Optional.of(new VendorAttribute[] { Attr.toVendorAttribute(abePolicyAttributes) }));
ReKeyKeyPair request = new ReKeyKeyPair(
        Optional.of(privateMasterKeyUniqueIdentifier),
        Optional.empty(),
        Optional.empty(),
        Optional.of(attributes),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty());
ReKeyKeyPairResponse response = this.kmip.reKeyKeyPair(request);
return response.getPublicKeyUniqueIdentifier();
```

=== "Java ABE"
``` java
Abe abe = new Abe(new RestClient(KMS_SERVER_URL, API_KEY));

String privateMasterKeyUniqueIdentifier = ...;
// This will rekey in the KMS:
// 
// - the Master Public Key
// - all User Decryption Keys that contain one of these attributes in their
// policy and are not revoked.
// 
// the ABE policy attributes to rotate
Attr[] abePolicyAttributes = ...;
abe.revokeAttributes(privateMasterKeyUniqueIdentifier, Attr[] abePolicyAttributes);
```

#### Revoke

##### specification

This operation requests the server to revoke a Managed Cryptographic Object or an Opaque Object. 

The request contains a reason for the revocation (e.g., “key compromise”, “cessation of operation”, etc.). 

The operation has one of two effects. If the revocation reason is “key compromise” or “CA compromise”, then the object is placed into the “compromised” state; the Date is set to the current date and time; and the Compromise Occurrence Date is set to the value (if provided) in the Revoke request and if a value is not provided in the Revoke request then Compromise Occurrence Date SHOULD be set to the Initial Date for the object. If the revocation reason is neither “key compromise” nor “CA compromise”, the object is placed into the “deactivated” state, and the Deactivation Date is set to the current date and time.

##### implementation

The state of the object is kept as specified bu the revocation reason is currently not maintained.


=== "Java raw"
``` java
Kmip kmip = new Kmip(new RestClient(KMS_SERVER_URL, API_KEY));

String keyUniqueIdentifier = ...;

Revoke request = new Revoke(Optional.of(keyUniqueIdentifier), new RevocationReason("Revoked"),
                    Optional.empty());
RevokeResponse response = kmip.revoke(request);
```

=== "Java ABE"
``` java
Abe abe = new Abe(new RestClient(KMS_SERVER_URL, API_KEY));

String keyUniqueIdentifier = ...;
abe.revokeKey(keyUniqueIdentifier);
```


### KMIP JSON Profile

The server implements the [JSON Profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the KMIP 2.1 specifications.

Direct REST request can be performed by using the Http POST method on the `/kmip/2_1` endpoint os the server.

Examples in `bash` and `javascript` are provided below.

#### using bash

The bash script below gives some example on how the operations can be used to interact with the KMS from the server side :

```sh
s#!/bin/sh
​
set -eE
​
check_command_exist() {
  my_command="$1"
  if ! command -v $my_command &>/dev/null; then
    echo "$my_command could not be found"
    exit
  fi
}
​
kms_post() {
  JSON_PAYLOAD=$1
  response=$(curl -s -X POST "http://localhost:9998/kmip/2_1" -d ${JSON_PAYLOAD} -H "Content-Type: application/json")
}
​
check_command_exist jq
check_command_exist curl
​
####
#
# Create an ABE Master Private key + ABE public key.
# Remark:
#   AttributeValue contains the ABE policy in hexadecimal-json format. As example here:
#     {"last_attribute":9,"max_attribute":100,"store":{"Entity":[["377","378","379"],false],"Country":[["france","germany","italy","hungary","spain","belgium"],false]},"attribute_to_int":{"Country::spain":[8],"Country::belgium":[9],"Entity::379":[3],"Entity::378":[2],"Country::italy":[6],"Entity::377":[1],"Country::france":[4],"Country::hungary":[7],"Country::germany":[5]}}
kms_post '{"tag":"CreateKeyPair","type":"Structure","value":[{"tag":"CommonAttributes","type":"Structure","value":[{"tag":"CryptographicAlgorithm","type":"Enumeration","value":"ABE"},{"tag":"KeyFormatType","type":"Enumeration","value":"AbeMasterSecretKey"},{"tag":"Link","type":"Structure","value":[]},{"tag":"ObjectType","type":"Enumeration","value":"PrivateKey"},{"tag":"VendorAttributes","type":"Structure","value":[{"tag":"VendorAttributes","type":"Structure","value":[{"tag":"String","type":"TextString","value":"cosmian"},{"tag":"String","type":"TextString","value":"abe_attributes"},{"tag":"String","type":"TextString","value":"abe_policy"},{"tag":"String","type":"TextString","value":"abe_access_policy"},{"tag":"String","type":"TextString","value":"abe_header_uid"},{"tag":"VendorIdentification","type":"TextString","value":"cosmian"},{"tag":"AttributeName","type":"TextString","value":"abe_policy"},{"tag":"AttributeValue","type":"ByteString","value":"7B226C6173745F617474726962757465223A392C226D61785F617474726962757465223A3130302C2273746F7265223A7B22456E74697479223A5B5B22333737222C22333738222C22333739225D2C66616C73655D2C22436F756E747279223A5B5B226672616E6365222C226765726D616E79222C226974616C79222C2268756E67617279222C22737061696E222C2262656C6769756D225D2C66616C73655D7D2C226174747269627574655F746F5F696E74223A7B22436F756E7472793A3A737061696E223A5B385D2C22436F756E7472793A3A62656C6769756D223A5B395D2C22456E746974793A3A333739223A5B335D2C22456E746974793A3A333738223A5B325D2C22436F756E7472793A3A6974616C79223A5B365D2C22456E746974793A3A333737223A5B315D2C22436F756E7472793A3A6672616E6365223A5B345D2C22436F756E7472793A3A68756E67617279223A5B375D2C22436F756E7472793A3A6765726D616E79223A5B355D7D7D"}]}]}]}]}'
private_key_uid=$(echo $response | jq -r .value[0].value)
# Response example: it contains the UIDs of ABE Master Private key and ABE public key
# {"tag":"CreateKeyPairResponse","type":"Structure","value":[{"tag":"PrivateKeyUniqueIdentifier","type":"TextString","value":"769d77a9-28fa-4ccd-b5d8-b03d74f0a001"},{"tag":"PublicKeyUniqueIdentifier","type":"TextString","value":"53e950e8-4e87-4001-87dd-8dd955a8156a"}]}
​
####
#
# Create an ABE user decryption key
# Remark:
#   this user has its own access policy in hexadecimal-json format embbeded in the decryption key:
#     {"And":[{"Attr":"Entity::377"},{"Attr":"Country::france"}]}
#   the request contains the reference of the ABE Master Private key
kms_post "{\"tag\":\"Create\",\"type\":\"Structure\",\"value\":[{\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"PrivateKey\"},{\"tag\":\"Attributes\",\"type\":\"Structure\",\"value\":[{\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"ABE\"},{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"AbeUserDecryptionKey\"},{\"tag\":\"Link\",\"type\":\"Structure\",\"value\":[{\"tag\":\"Link\",\"type\":\"Structure\",\"value\":[{\"tag\":\"LinkType\",\"type\":\"Enumeration\",\"value\":\"ParentLink\"},{\"tag\":\"LinkedObjectIdentifier\",\"type\":\"TextString\",\"value\":\"${private_key_uid}\"}]}]},{\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"PrivateKey\"},{\"tag\":\"VendorAttributes\",\"type\":\"Structure\",\"value\":[{\"tag\":\"VendorAttributes\",\"type\":\"Structure\",\"value\":[{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"cosmian\"},{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"abe_attributes\"},{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"abe_policy\"},{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"abe_access_policy\"},{\"tag\":\"String\",\"type\":\"TextString\",\"value\":\"abe_header_uid\"},{\"tag\":\"VendorIdentification\",\"type\":\"TextString\",\"value\":\"cosmian\"},{\"tag\":\"AttributeName\",\"type\":\"TextString\",\"value\":\"abe_access_policy\"},{\"tag\":\"AttributeValue\",\"type\":\"ByteString\",\"value\":\"7B22416E64223A5B7B2241747472223A22456E746974793A3A333737227D2C7B2241747472223A22436F756E7472793A3A6672616E6365227D5D7D\"}]}]}]}]}"
user_decryption_key_id=$(echo $response | jq -r .value[1].value)
# Response examle: it contains the UID of the user decryption key
# {"tag":"CreateResponse","type":"Structure","value":[{"tag":"ObjectType","type":"Enumeration","value":"PrivateKey"},{"tag":"UniqueIdentifier","type":"TextString","value":"78b5d54d-01b0-464e-a36f-3ec5db5216ef"}]}
​
####
#
# Import a symmetric key. This key has been wrapped outside the KMS with AES256-GCM (nonce appears in `IVCounterNonce`)
# Remark:
#   UID is generated by the client and replace existing KMS-object (if found)
wrapped_symmetric_key_id="9962bbbe-6525-423d-bf66-71c28fe6f6b9"
kms_post "{\"tag\":\"Import\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${wrapped_symmetric_key_id}\"},{\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"SymmetricKey\"},{\"tag\":\"ReplaceExisting\",\"type\":\"Boolean\",\"value\":true},{\"tag\":\"KeyWrapType\",\"type\":\"Enumeration\",\"value\":\"AsRegistered\"},{\"tag\":\"Attributes\",\"type\":\"Structure\",\"value\":[{\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"AES\"},{\"tag\":\"Link\",\"type\":\"Structure\",\"value\":[]},{\"tag\":\"ObjectType\",\"type\":\"Enumeration\",\"value\":\"SymmetricKey\"}]},{\"tag\":\"Object\",\"type\":\"Structure\",\"value\":[{\"tag\":\"KeyBlock\",\"type\":\"Structure\",\"value\":[{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"TransparentSymmetricKey\"},{\"tag\":\"KeyValue\",\"type\":\"ByteString\",\"value\":\"8C74023889DA771591F06A6C23A5BB1B7A8E4C7FE4BDF3D2C66B3A6709BC51CF80E9EBADE25D29E3130EF211ED4BAA5B\"},{\"tag\":\"CryptographicAlgorithm\",\"type\":\"Enumeration\",\"value\":\"AES\"},{\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":256},{\"tag\":\"KeyWrappingData\",\"type\":\"Structure\",\"value\":[{\"tag\":\"WrappingMethod\",\"type\":\"Enumeration\",\"value\":\"Encrypt\"},{\"tag\":\"IVCounterNonce\",\"type\":\"ByteString\",\"value\":\"498F84E0E1BB74792C00F5B1\"}]}]}]}]}"
​
####
#
# Get KMS objects: ABE Public key, Abe User decryption key or wrapped symmetric key
# Remark:
#
kms_post "{\"tag\":\"Get\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${wrapped_symmetric_key_id}\"},{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"AbeMasterPublicKey\"}]}"
echo "Wrapped symmetric key: $response"
​
kms_post "{\"tag\":\"Get\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${private_key_uid}\"},{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"AbeUserDecryptionKey\"}]}"
echo "ABE Master private key: $response"
​
kms_post "{\"tag\":\"Get\",\"type\":\"Structure\",\"value\":[{\"tag\":\"UniqueIdentifier\",\"type\":\"TextString\",\"value\":\"${user_decryption_key_id}\"},{\"tag\":\"KeyFormatType\",\"type\":\"Enumeration\",\"value\":\"TransparentSymmetricKey\"}]}"
echo "ABE User decryption key: $response"
```

#### using javascript

 The Javascript instructions below give some example on how the operations can be used to interact with the KMS from the client side :

``` javascript
import fetch from "node-fetch";

const url = "http://localhost:9998/kmip/2_1";

const importPayload = {
  "tag" : "Import",
  "value" : [ {
    "tag" : "UniqueIdentifier",
    "type" : "TextString",
    "value" : "unique_identifier"
  }, {
    "tag" : "ObjectType",
    "type" : "Enumeration",
    "value" : "SymmetricKey"
  }, {
    "tag" : "ReplaceExisting",
    "type" : "Boolean",
    "value" : true
  }, {
    "tag" : "KeyWrapType",
    "type" : "Enumeration",
    "value" : "AsRegistered"
  }, {
    "tag" : "Attributes",
    "value" : [ {
      "tag" : "Link",
      "value" : [ ]
    }, {
      "tag" : "ObjectType",
      "type" : "Enumeration",
      "value" : "OpaqueObject"
    } ]
  }, {
    "tag" : "Object",
    "value" : [ {
      "tag" : "KeyBlock",
      "value" : [ {
        "tag" : "KeyFormatType",
        "type" : "Enumeration",
        "value" : "TransparentSymmetricKey"
      }, {
        "tag" : "KeyValue",
        "value" : [ {
          "tag" : "KeyMaterial",
          "value" : [ {
            "tag" : "Key",
            "type" : "ByteString",
            "value" : "6279746573"
          } ]
        } ]
      }, {
        "tag" : "CryptographicAlgorithm",
        "type" : "Enumeration",
        "value" : "AES"
      }, {
        "tag" : "CryptographicLength",
        "type" : "Integer",
        "value" : 256
      } ]
    } ]
  } ]
}
// Server response : Upserting object of type: SymmetricKey, with uid: unique_identifier

const createPayload = {
  "tag": "Create",
  "type": "Structure",
  "value": [
    {
      "tag": "ObjectType",
      "type": "Enumeration",
      "value": "SymmetricKey"
    },
    {
      "tag": "Attributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "AES"
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentSymmetricKey"
        },
        {
          "tag": "Link",
          "type": "Structure",
          "value": []
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "SymmetricKey"
        }
      ]
    }
  ]
}
// Server response : Created KMS Object of type SymmetricKey with id eb9c5a0d-afa3-4d06-8673-3dc51431268f

const getPayload = {
  "tag": "Get",
  "type": "Structure",
  "value": [
    {
      "tag": "UniqueIdentifier",
      "type": "TextString",
      "value": "eb9c5a0d-afa3-4d06-8673-3dc51431268f"
    }
  ]
}
// Server response : Retrieved Object: SymmetricKey with id eb9c5a0d-afa3-4d06-8673-3dc51431268f

const encryptPayload = {
  "tag": "Encrypt",
  "type": "Structure",
  "value": [
    {
      "tag": "UniqueIdentifier",
      "type": "TextString",
      "value": "eb9c5a0d-afa3-4d06-8673-3dc51431268f"
    },
    {
      "tag": "IvCounterNonce",
      "type": "ByteString",
      "value": "747765616b56616c7565"
    }
  ]
}
// Server response : POST /kmip. Request: "Encrypt"

const decryptPayload = {
  "tag": "Decrypt",
  "type": "Structure",
  "value": [
    {
      "tag": "UniqueIdentifier",
      "type": "TextString",
      "value": "eb9c5a0d-afa3-4d06-8673-3dc51431268f"
    },
    {
      "tag": "IvCounterNonce",
      "type": "ByteString",
      "value": "747765616b56616c7565"
    }
  ]
}
// Server response : POST /kmip. Request: "Decrypt"

const locatePayload = {
  "tag": "Locate",
  "type": "Structure",
  "value": [
    {
      "tag": "Attributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "AES"
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentSymmetricKey"
        },
        {
          "tag": "Link",
          "type": "Structure",
          "value": []
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "SymmetricKey"
        }
      ]
    }
  ]
}
```


## Authentication

The KMS server provides a way to authenticate access, through [Access Tokens](https://auth0.com/docs/secure/tokens#access-tokens).

A valid access token is required to access the KMS REST API. The token must be carried in HTTP header `Authorization`.

The authentication is enabled if the environment variable `KMS_DELEGATED_AUTHORITY_DOMAIN` is provided when starting the KMS Docker container (see below). The variable should contain the URL of the domain i.e.
```
-e KMS_DELEGATED_AUTHORITY_DOMAIN=my_auth_domain.com
```

If the flag is not provided, the authentication is _completely_ disabled.

## Deployment

The KMS server is packaged in a single Docker image based on Ubuntu 21.10.

### Installing

Install the Docker image:

```console
sudo docker load < cosmian_kms_server_1_2_1.tar.gz
```
### Running

The KMS server can be run in 2 modes:

 - in light mode, mostly for testing, using an embedded SQLite database
 - in db mode, using an external PostgreSQL Database

#### Light mode

The light mode is for single server run and persists data _inside_ the container (in `/tmp/kms.db`) by default. The root directory for the DB inside the container can be changed by setting the environment variable `KMS_ROOT_DIR` i.e.
```
-e KMS_ROOT_DIR=/root
```

To run in light mode, using the defaults, simply run the container as

```
sudo docker run -p 9998:9998 cosmian/kms_server:1.2.1
```

The server REST port will be available on 9998.

#### DB mode


In DB mode, the server is using Postgre SQL database to store its objects. 
An URL must be provided to allow the KMS server to connect to the database (see below).


Before running the server a dedicated database with a dedicated user should be created on the PostgreSQL instance. Here are example instructions to create a database called `kms` owned by a user `kms_user` with password `kms_password`:


1. Connect to psql under user `postgres`

```
sudo -u postgres psql
```

2. Create user `kms_user` with password `kms_password`

```
create user kms_user with encrypted password 'kms_password';
```

The user and password can obviously be set to any other appropriate values.

3. Create database `kms` under owner `kms_user`

```
create database kms owner=kms_user;
```

Likewise, the database can be set to another name.

4. Connection `POSTGRES_URL`

Assuming a server running on 1.2.3.4, the environment variable to pass with the connection URL will be

```
KMS_POSTGRES_URL=CONNECTION=postgresql://kms_user:kms_password@1.2.3.4:5432:kms
```

5. Launch the KMS server on port 9998

```sh
sudo docker run \
-p 9998:9998 \
-e KMS_POSTGRES_URL=CONNECTION=postgresql://kms_user:kms_password@1.2.3.4:5432:kms \
-e KMS_DELEGATED_AUTHORITY_DOMAIN=my_auth_domain.com \
cosmian/kms_server:1.2.1
```

###### Note

On linux, if PostgreSQL is running on the docker host, the network should be mapped to the `host` and launched using


```sh
sudo docker run \
-e KMS_POSTGRES_URL=postgresql://kms_user:kms_password@localhost:5432/kms \
--network host \
cosmian/kms_server:1.2.1
```
The port wil be `9998`; this can be changed by setting the environment variable `KMS_PORT=[port]`

### Versions correspondence

#### Versions

KMS Server | Java Lib | abe_gpsw lib
-----------|----------|--------------
1.2.0      | 0.5.0    | 0.3.0
1.2.1      | 0.5.1    | 0.4.0

#### Repositories

Cosmian Java Lib: https://github.com/Cosmian/cosmian_java_lib
abe_gpsw lib    : https://github.com/Cosmian/abe_gpsw 
