The Cosmian Key Management System (KMS) is a high-performance server application written in [**Rust**](https://www.rust-lang.org/) that provides an API to store and manage keys and secrets used with Cosmian cryptographic stacks. The code of the server is open-sourced to Cosmian customers. 

The Cosmian KMS server exposes a **KMIP 2.1** API that follows the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the OASIS-normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html).

The server is usually queried using the **`ckms`** [Command Line Interface](./cli/cli.md) or one of the Java, Javascript, or Python **Cloudproof libraries**. Check the [Cloudproof documentation](https://docs.cosmian.com/cloudproof_encryption/application_level_encryption/) and the [Cosmian Github](https://github.com/Cosmian) for details.



1. [Installation](./installing.md)
2. [Authentication and Authorization](./auth.md)
3. [The ckms Command Line Interface](./cli/cli.md)
4. [KMIP 2.1 implementation](./kmip_2_1/index.md)