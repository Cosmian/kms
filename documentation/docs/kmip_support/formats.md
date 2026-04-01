KMIP Objects may be manipulated in various standardized formats.

### Import - Export

The KMIP 2.1 specification states that keys have a default Key Format Type that SHALL be produced by KMIP servers.
When requesting the export of an Object without specifying the Key Format Type, a default Key Format Type by object
(and algorithm) should be used as listed in the following table:

| Type                | Default Key Format Type     | Available Key Format Types Import/Export                  |
|---------------------|-----------------------------|-----------------------------------------------------------|
| Certificate         | X.509                       | X.509                                                     |
| Certificate Request | PKCS#10                     | PKCS#10                                                   |
| Opaque Object       | Opaque                      |                                                           |
| PGP Key             | Raw                         |                                                           |
| Secret Data         | Raw                         |                                                           |
| Symmetric Key       | Raw                         | Raw                                                       |
| Split Key           | Raw                         |                                                           |
| RSA Private Key     | PKCS#1                      | PKCS#1, PKCS#8, Transparent RSA Private Key               |
| RSA Public Key      | PKCS#1                      | PKCS#1, PKCS#8 (SPKI), Transparent RSA Public Key         |
| EC Private Key      | Transparent EC Private Key  | Transparent EC Private Key, PKCS#8, EC Private Key (SEC1) |
| EC Public Key       | Transparent EC Public Key   | Transparent EC Public Key, PKCS#8 (SPKI)                  |
| DSA Private Key     | Transparent DSA Private Key |                                                           |
| DSA Public Key      | Transparent DSA Public Key  |                                                           |

- All ASN.1 based formats are available as `PEM` or `DER` encoded
- `SPKI` is denoted `PKCS8` for public keys in KMIP
- `SEC1` (called `ECPrivateKey` in KMIP) is only available for NIST curves (i.e. not for curve 25519 and curve 448)
  private keys.
- The `D` field of the `Transparent EC Private Key` is:
    - the (absolute) value of the Big Integer of the scalar for NIST curves
    - the Big Integer value of the private key raw bytes (as big endian) for Curve 25519 and Curve 448
- The `Q String` field of the `Transparent EC Public Key` is:
    - the uncompressed point octet form as defined in RFC5480 and used in certificates and TLS records for NIST curves.
    - the raw bytes of the public key for Curve 25519 and Curve 448

### Internal storage

The IETF now recommends using PKCS#8 and Subject Public Key Info (SPKI) as default formats for inter-operability.
This server enforces the KMIP 2.1 default export formats above but the storage formats used in the database are:

- `PKCS#8 DER` for RSA and EC private Keys (RFC 5208 and 5958).
- `SPKI DER` (RFC 5480) for RSA and EC public keys, using the Key Format Type PKCS#8, since SPKI is not listed.
- `X509 DER` for certificates (RFC 5280).
- `PKCS#10 DER` for certificate requests (RFC 2986).
- `TransparentSymmetricKey` for symmetric keys
- `Raw` for opaque objects and Secret Data

Users requesting keys are therefore encouraged to request them in these storage formats to avoid conversions and match
recent RFCs.
