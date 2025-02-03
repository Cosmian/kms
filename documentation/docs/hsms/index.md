# HSM Support

The Cosmian KMS can be configured to use HSMs to store and manage keys and create KMS keys
wrapped by the HSM
keys. This provides the best of both worlds: the security of an HSM at rest and the scalability of a KMS at runtime.

Cosmian KMS natively integrates with
the [Proteccio](https://eviden.com/solutions/digital-security/data-encryption/trustway-proteccio-nethsm/)  and
the [Utimaco general purpose](https://utimaco.com/solutions/applications/general-purpose-hardware-security-modules)
HSMs.

## Main use case and benefits

Aside from providing a single interface to manage both KMS and HSM keys,
the main use case for HSM support is to host keys in the KMS that
are [wrapped by keys stored in the HSM](./hsm_operations.md/#creating-a-kms-key-wrapped-by-an-hsm-key).

This combination provides the best of both worlds:

- the **scalability** and performance of the KMS **at runtime** to answer a large number of requests concurrently,
- and the **hardware security** of the HSM **at rest**, which may be a compliance requirement in some industries.

Typical use cases include:

- securing workplace applications such as [MS 365](https://www.microsoft.com/en-us/microsoft-365)
  or [Google Workspace](https://workspace.google.com),
  where concurrent requests from
  potentially a large
  number of users need to be processed quickly,
- securing big data applications such as
  Hadoop/Spark, [Snowflake](https://snowflake.com), [Databricks](https://databricks.com) where a large number of
  encryption and decryption requests need to be processed on each request on the fly.

### At Rest

KMS keys are stored in the KMS database in a wrapped form, and the wrapping key is stored in the HSM. This
provides an additional layer of security for the keys stored in the KMS since the keys stored in the HSM are protected
by the HSM's hardware security mechanisms, and benefit from the HSM certifications.

#### At Runtime

Encryption and decryption requests from applications are processed by the KMS, which first unwraps
the keys stored in the KMS database using the keys stored in the HSM. Contrarily to the HSM, the KMS is a highly
scalable and performant system that can handle a large number of requests concurrently.
