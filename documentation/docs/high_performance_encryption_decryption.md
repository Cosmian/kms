<h1>High performance encryption and decryption</h1>

The Cosmian KMS is particularly suited for client-side encryption scenarios which may require high
performance encryption and decryption. The KMS provides a high performance encryption and decryption
API that can be used to encrypt and decrypt data at scale.

## Parallelization, concurrency, and batching

Dur to its stateless user sesison model, the Cosmian KMS is designed to take advantage of modern
multicore processors and can parallelize encryption and decryption operations across multiple
cores. Parallelization can be achieved by scaling vertically (increasing the number of cores on a
single machine) or horizontally (increasing the number of machines in a cluster).

The Cosmian KMS can also handle multiple concurrent encryption and decryption requests on a
single core using (async) concurrency primitivies. The asynchronous model optimizes the use of
CPU resources by allowing the CPU to perform other tasks while waiting for I/O operations to
complete.

FInally, batching can be used to further optimize the performance of encryption and decryption
operations. Batching allows multiple encryption or decryption operations to be performed in a
single request, reducing the overhead of making multiple requests to the KMS.

## Batching, the KMIP way

Batching in KMIP is achieved by sending multiple `Operation`s in a single KMIP `Message` operation.
The protocol is extremely flexible and allows for a wide range of operations to be batched together.

The Cosmian KMS supports batching using the KMIP protocol.

## Optimized batching

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

### Encoding scheme

The encoding scheme is called `BulkData` and encodes an array of items, each item being an array of
bytes. It works as follows

- the encoded data starts with the 2-byte fixed sequence `0x87 0x87`
- followed by the unsigned leb128 encoded number of items in the array
- followed, for each item, by
    - the unsigned leb128 encoded byte length of the item
    - the item itself

When the server receives an `Encrypt` or `Decrypt` operation and detects the header `0x87 0x87`, it
attempts to decode the data as a `BulkData` array. If the decoding is unsuccessful, the server
falls back to the standard KMIP protocol (i.e., single item encryption or decryption).

If the decoding is successful, the server processes each item in the array as a separate encryption
or decryption request and re-encodes the results.

When processing symmetric encryption results, the server will first, for each encrypted item,
concatenate the IV, the ciphertext and the MAC, and then encode the result as a single item in the
`BulkData` array.

For AES-GCM encryption, the concatenation is as follows:

- the IV (12 bytes)
- the ciphertext (same size as the plaintext)
- the MAC (16 bytes)

## Performance heuristics

The Cosmian KMS uses heuristics to determine the optimal batch size for encryption and decryption
requests. The heuristics take into account the size of the data, the number of cores available, and
the expected latency of the KMS.

Typically, for 64-byte data items, the optimal batch size is around 100,000 items. With these
kinds of batch sizes, each CPU core should be sent an average of five batches to maximize
concurrency.

Hence, to encrypt 5 million messages on 10 core machines, 50 requests of 100,000 items each
should be sent in parallel. On a standard server CPU, the total processing time should be around 8
seconds, excluding network latency.



