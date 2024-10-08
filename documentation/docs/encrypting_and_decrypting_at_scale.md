# Encrypting and decrypting at scale

The Cosmian KMS is particularly suited for client-side encryption scenarios which may require
high-performance encryption and decryption.

The KMS offers two mechanisms for encrypting and decrypting data:

- by calling the `Encrypt` and `Decrypt` operations on the KMS KMIP API and benefiting from its
  parallelization, concurrency, and optimized batching capabilities.
- by using the `ckms` CLI client to encrypt and decrypt data locally, including large files.

## Calling the KMS API

The KMS provides a high-performance encryption and
decryption API that can be used to encrypt and decrypt data at scale.

### Parallelization, concurrency, and batching

Due to its stateless user session model, the Cosmian KMS is designed to take advantage of modern
multi-core processors and can parallelize encryption and decryption operations across multiple
cores. Parallelization can be achieved by scaling vertically (increasing the number of cores on a
single machine) or horizontally (increasing the number of machines in a cluster).

The Cosmian KMS can also handle multiple concurrent encryption and decryption requests on a
single core using (async) concurrency primitives.
The asynchronous model optimizes the use of CPU resources by allowing the CPU to perform other tasks
while waiting for I/O operations to complete.

Finally, batching can be used to further optimize the performance of encryption and decryption
operations. Batching allows multiple encryption or decryption operations to be performed in a
single request, reducing the overhead of making multiple requests to the KMS.

### Efficient batching

#### The KMIP way

Batching in KMIP is achieved by sending multiple `Operation`s in a single KMIP `Message` operation.
The protocol is extremely flexible and allows for a wide range of operations to be batched together.

The Cosmian KMS supports batching using the KMIP protocol.

#### Optimized batching

However, the overhead of the KMIP protocol can be significant, especially for small data sizes.
Each `Operation` in a KMIP message carries a significant amount of metadata, which can be
prohibitively expensive for small data sizes.

When batching encryption or decryption requests, it is likely that the metadata is identical for
each request, and the overhead of unnecessarily sending the metadata multiple times can be
significant.

To address this issue, the Cosmian KMS provides an optimized batching API that allows multiple
encryption or decryption requests to be batched together in a single request, without the overhead
of the KMIP protocol. The optimized batching API is designed to be lightweight and efficient,
allowing multiple encryption or decryption requests to be batched together with minimal overhead.

The method is to use a single `Encrypt` or `Decrypt` operation with multiple data items encoded in
the `data` field of the request.

#### Encoding scheme

The encoding scheme is called `BulkData` and encodes an array of items, each item being an array of
bytes. It works as follows

- the encoded data starts with the 2-byte fixed sequence `0x87 0x87`
- followed by the unsigned leb128 encoded number of items in the array
- followed, for each item, by
  - the unsigned leb128 encoded byte length of the item
  - the item itself

```text
BulkData = 0x87 0x87 <number of items> <item 1 length> <item 1> ... <item n length> <item n>

number of items = leb128 encoded number of items
item 1 length = leb128 encoded length of item 1
```

When the server receives an `Encrypt` or `Decrypt` operation and detects the header `0x87 0x87`, it
attempts to decode the data as a `BulkData` array. If the decoding is unsuccessful, the server
falls back to the standard KMIP protocol (i.e., single item encryption or decryption).

If the decoding is successful, the server processes each item in the array as a separate encryption
or decryption request and re-encodes the results.

When processing symmetric encryption results, the server will first, for each encrypted item,
concatenate the IV, the ciphertext, and the MAC, and then encode the result as a single item in the
`BulkData` array.

For AES-GCM encryption, the concatenation is as follows:

- the IV (12 bytes)
- the ciphertext (same size as the plaintext)
- the MAC (16 bytes)

### Performance heuristics

The Cosmian KMS uses heuristics to determine the optimal batch size for encryption and decryption
requests. The heuristics take into account the size of the data, the number of cores available, and
the expected latency of the KMS.

Typically, for 64-byte data items, the optimal batch size is around 100,000 items. With these
kinds of batch sizes, each CPU core should be sent an average of five batches to maximize
concurrency.

Hence, to encrypt 5 million messages on 10 core machines, 50 requests of 100,000 items each
should be sent in parallel. On a standard server CPU, the total processing time should be around 8
seconds, excluding network latency.

## Using the `ckms` CLI client

The `ckms` CLI client can be used to encrypt and decrypt data locally, including large files.

Encryption can be performed in two modes:

- server side: the file data is sent server side and encrypted there. This mode is well suited
  for small or medium files and where a direct encryption scheme is required.
- client side: the file data is encrypted locally using a hybrid encryption scheme with key
  wrapping. This mode is well suited for any type of files, including large ones, and where
  high performance is required.

### Server side encryption and decryption

When using server side encryption or decryption, the file content is sent to the server. To use
this method use the `encrypt` or `decrypt` command of the `ckms` CLI client WITHOUT specifying a
`--key-encryption-algorithm` option.

Say, the KMS holds a 256-bit AES key with the ID `43d28ec7-7438-4d2c-a1a0-00379fa4fe5d`
and you want to encrypt a file `image.png` with AES 256-bit GCM encryption:

```bash
ckms sym encrypt \
--data-encryption-algorithm aes-gcm \
--key-id 43d28ec7-7438-4d2c-a1a0-00379fa4fe5d \
--output-file image.enc \
image.png
```

To decrypt the file, use the `decrypt` command:

```bash
ckms sym decrypt \
--data-encryption-algorithm aes-gcm \
--key-id 43d28ec7-7438-4d2c-a1a0-00379fa4fe5d \
--output-file decrypted-image.png \
image.enc
```

#### Available ciphers

The following ciphers are available for server-side encryption and decryption:

| Cipher            | Description                | NIST Certified? |
| ----------------- | -------------------------- | --------------- |
| aes-gcm           | AES in Galois Counter Mode | yes             |
| aes-xts           | AES XTS                    | yes             |
| aes-gcm-siv       | AES GCM SIV                | no              |
| chacha20-poly1305 | ChaCha20 Poly1305          | no              |

When in doubt, use AES GCM with a 256-bit key. AES GCM is NIST-certified (as NIST SP
800–38D) and well suited for arbitrary encryption of data with length of up to 2^39–256 bits ~ 64
GB.

Please note that for AES XTS, that

- the key size must be doubled to achieve the same security level: 256 bits for AES 128 and 512 bits
  for AES 256.
- there is no authentication

#### Format of the encrypted file

The encrypted file is the concatenation of the IV (or Tweak for XTS), the ciphertext, and the
MAC (None for XTS).

```bash
IV || Ciphertext || MAC
```

With these symmetric block ciphers, the size of the ciphertext is equal to the size of the
plaintext.

The table below shows the size of the IV (tweak for XTS) and the MAC in bytes.

| Cipher            | IV size | MAC size |
| ----------------- | ------- | -------- |
| aes-gcm           | 12      | 16       |
| aes-xts           | 16      | 0        |
| aes-gcm-siv       | 12      | 16       |
| chacha20-poly1305 | 12      | 16       |

### Client side encryption and decryption

When using client side encryption or decryption, the file content is encrypted locally using a
hybrid encryption scheme with key wrapping:

- a random data encryption key (DEK) is generated. The key size is 256 bits for all schemes except
  for AES, where the key size is 512 bits to provide 256 bits of classic security, 128 bits
  post-quantum.
- the DEK is used to locally encrypt the file content using the specified
  `--data-encryption-algorithm` for the data encryption mechanism (DEM).
- the DEK is server side encrypted (i.e., wrapped) using the specified
  `--key-encryption-algorithm` for the key encryption mechanism (KEM) and the KMS key encryption
  key (KEK) identified by `--key-id`.

To use this method, use the `encrypt` or `decrypt` command and specify BOTH the
`--key-encryption-algorithm` and `--data-encryption-algorithm`.

Say, the KMS holds a 256-bit AES KEK (key encryption key) with the ID
`43d28ec7-7438-4d2c-a1a0-00379fa4fe5d` and you want to client-side encrypt a file `image.png`
with AES-GCM encryption, the ephemeral KEK key being wrapped with RFC5649 (a.k.a. NIST key wrap):

```bash
ckms sym encrypt \
--data-encryption-algorithm aes-gcm \
--key-encryption-algorithm rfc5649 \
--key-id 43d28ec7-7438-4d2c-a1a0-00379fa4fe5d \
--output-file image.enc \
image.png
```

To decrypt the file, use the `decrypt` command:

```bash
ckms sym decrypt \
--data-encryption-algorithm aes-gcm \
--key-encryption-algorithm rfc5649 \
--key-id 43d28ec7-7438-4d2c-a1a0-00379fa4fe5d \
--output-file decrypted-image.png \
image.enc
```

#### Available ciphers

The following ciphers are available for client-side encryption and decryption:

* Data Encryption *

| Cipher            | Description                | NIST Certified? |
| ----------------- | -------------------------- | --------------- |
| aes-gcm           | AES in Galois Counter Mode | yes             |
| aes-xts           | AES XTS                    | yes             |
| chacha20-poly1305 | ChaCha20 Poly1305          | no              |

* Key Wrapping (Encryption) *

| Cipher            | Description                | NIST Certified? |
| ----------------- | -------------------------- | --------------- |
| rfc5649           | NIST Key Wrap              | yes             |
| aes-gcm           | AES in Galois Counter Mode | yes             |
| aes-xts           | AES XTS                    | yes             |
| aes-gcm-siv       | AES GCM SIV                | no              |
| chacha20-poly1305 | ChaCha20 Poly1305          | no              |

When in doubt, use the AES GCM data encryption scheme with the AES GCM key encryption scheme (or
RFC5649) with a 256-bit key. These are the most widely used schemes, and they are NIST-certified.

#### Format of the encrypted file

The encrypted file is the concatenation of

- the length of the key wrapping (a.k.a. encapsulation) in unsigned LEB 128 format
- the key encapsulation
- the data encryption mechanism (DEM) IV (or tweak for XTS)
- the ciphertext (same size as the plaintext)
- the data encryption mechanism (DEM) MAC

```bash
encapsulation length || encapsulation || DEM IV || Ciphertext || DEM MAC
```

The key `encapsulation` is the concatenation of

- the key encryption mechanism (KEM) IV (or tweak for XTS, none for RFC5649)
- the encrypted DEK (same length as the DEK, +8 bytes for RFC5649)
- the key encryption mechanism (KEM) MAC (none for XTS and RFC5649)

```bash
KEM IV || Encrypted DEK || KEM MAC
```

Using AES GCM as a KEM and a DEM, the details will be as follows:

- 1 unsigned LEB 128 byte holding the length of the encapsulation (60)
- 60 bytes of encapsulation decomposed in :
  - 12 byte KEM IV
  - 32 bytes encrypted DEK
  - 16 byte KEM MAC
- 12 bytes of DEM IV
- x bytes of ciphertext (same size as plaintext)
- 16 bytes of DEM MAC
