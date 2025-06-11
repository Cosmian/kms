# KMIP Support

The Cosmian KMS server implements both KMIP 1.x and 2.x interfaces. KMIP (Key Management Interoperability Protocol) is
an [OASIS](https://www.oasis-open.org/) standard designed to standardize communication between key management systems
and encryption clients.

## Connection Options

- **Binary Protocol**: Available on port 5696
    - TLS secured
    - Client certificate required for authentication

- **JSON Protocol**: Available on port 9998 via REST POST
    - Optional TLS security
    - Multiple [authentication mechanisms](../authentication.md) supported
    - Endpoints:
        - `/kmip`: Handles KMIP 1.x and 2.x `RequestMessage`
        - `/kmip/2_1`: Specifically for KMIP 2.1 `RequestMessage` or operations like `Create`, `Encrypt`, `Decrypt`,
          etc.

## Implementation Details

Internally, all KMIP messages are translated to KMIP 2.1 specifications and converted back to KMIP 1.x when necessary.
The Cosmian KMS server implements a targeted subset of
the [KMIP 2.1 protocol](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html).

## Purpose of KMIP

The OASIS KMIP standard aims to:

- Define a comprehensive protocol for communication between encryption systems and enterprise applications
- Support diverse applications including email, databases, and storage devices
- Eliminate redundant and incompatible key management processes
- Enhance data security while reducing costs associated with multiple products

## Scope of Implementation

KMIP is an extensive specification. While the Cosmian KMS server does not implement the entire standard, it supports the
features necessary for advanced cryptographic use cases. The implementation continues to evolve to meet customer
requirements, though like most KMS servers, it doesn't support all possible cryptographic objects and operations.

The following pages document the supported features of the KMIP 2.1 specification and Cosmian-specific extensions.
