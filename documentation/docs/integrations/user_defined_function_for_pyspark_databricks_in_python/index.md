# User Defined Functions in Python for Cosmian KMS

Cosmian maintains a [Python UDF library](https://github.com/Cosmian/cosmian_kms_python_udf) that enables efficient,
large-scale cryptographic operations with the Cosmian KMS.

## Purpose and Applications

These User Defined Functions (UDFs) are designed specifically for:

- Data processing platforms like PySpark, Databricks, Snowflake, and Kafka
- Implementing application-level encryption in Big Data environments
- Protecting sensitive data by encrypting it before storage and only decrypting during processing
- Minimizing clear-text exposure of sensitive information

## Technical Capabilities

The library provides:

- Batch processing capabilities for efficient encryption/decryption
- Parallelization to optimize throughput
- Support for multiple encryption contexts and key identifiers
- Performance optimizations for Big Data workloads

Expected throughput is in the range of 5 million decryption in 5 seconds with a 10 vCPU KMS instance.

## Supported Cryptographic Algorithms

The UDFs support several NIST-approved and RFC-standardized algorithms:

- **AES-GCM** (NIST SP 800-38D): Standard authenticated encryption
- **AES-GCM-SIV** (RFC 8452): Deterministic authenticated encryption with nonce misuse resistance
- **AES-XTS** (NIST SP 800-38E): Storage encryption for fixed-length data
- **ChaCha20-Poly1305** (RFC 8439): High-performance authenticated encryption

## Performance Considerations

Key performance factors include:

- Network latency between the UDF execution environment and KMS server
- Batch size optimization for your specific workload
- Algorithm selection based on security requirements
- Potential use of deterministic encryption (like AES-GCM-SIV) for performance-critical applications

Check the [encryption and decryption a scale section](../encrypting_and_decrypting_at_scale.md) for details.

## Getting Started

For implementation details, examples, and best practices, refer to
the [GitHub repository](https://github.com/Cosmian/cosmian_kms_python_udf), particularly the `tests` directory which
contains practical code samples for various use cases.
