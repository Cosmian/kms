The Cosmian KMS server exposes a **KMIP 2.1** REST API on the `/kmip_2_1` endpoint that follows
the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415)
of
the
OASIS-normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html).

The Cosmian KMS server supports a subset of the KMIP 2.1 protocol.

The Key Management Interoperability Protocol Specification Version 2.1 and Key Management Interoperability Protocol
Profiles Version 2.1 are [OASIS](https://www.oasis-open.org/) Standards.

The goal of the OASIS KMIP is to define a single, comprehensive protocol for communication between encryption systems
and a broad range of new and legacy enterprise applications, including email, databases, and storage devices. By
removing redundant, incompatible key management processes, KMIP provides better data security while at the same time
reducing expenditures on multiple products.

KMIP is a massive specification, and support meets the requirements of Cosmian advanced cryptography usage cases.
Although the KMS server functionalities evolve quickly to support the growing demand of customers,
the Cosmian KMS server, like most KMS servers, does not support all cryptographic objects and operations.

The following pages describe the supported features of the KMIP 2.1 specification as well as Cosmian extensions.
