# OpenPGP Key Support

Eviden KMS supports OpenPGP transferable secret and public keys (`ObjectType::PGPKey`) in **non-FIPS builds only**.
OpenPGP keys can be created, imported, exported, and used for the KMIP `Encrypt`, `Decrypt`, `Sign`, and
`SignatureVerify` operations. See the [supported objects](./objects.md) and
[supported formats](./formats.md) pages for the KMIP-level summary.

```mermaid
flowchart TD
    subgraph Clients["Clients & Applications"]
        CLI["ckms pgp (CLI)"]
        UI["Web UI (/ui/pgp/*)"]
        GPG["GnuPG (gpg 2.1+)"]
        EXT["Custom Apps (KMIP 2.1 / REST)"]
    end

    subgraph KMS["Eviden KMS Server (non-FIPS)"]
        DISPATCH["KMIP Dispatcher & Routing"]
        subgraph PGP_OPS["OpenPGP Engine (RFC 4880 / RFC 9580)"]
            CORE["Key Generation & Formatting<br/>Ed25519 / RSA v4 TPK"]
            CRYPTO["Crypto Operations<br/>Encrypt (v1 SEIPD / AES-256)<br/>Decrypt (Binary / ASCII Armor)<br/>Sign (Detached SHA-256)<br/>SignatureVerify (Primary + Subkeys)"]
        end
        DB[("Database Store<br/>PostgreSQL / SQLite")]
    end

    CLI -->|"HTTP / REST TTLV"| DISPATCH
    UI -->|"WASM Bridge / TTLV"| DISPATCH
    EXT -->|"KMIP 2.1 / TTLV"| DISPATCH
    DISPATCH --> CORE
    DISPATCH --> CRYPTO
    CORE <--> DB
    CRYPTO <--> DB

    GPG -.->|"--import (pub.asc / sec.asc)"| CLI
    GPG -.->|"--verify (detached sig)"| CLI
    CLI -.->|"export (pgp-public / pgp-secret)"| GPG
    GPG -.->|"--decrypt (msg.bin)"| CLI
```

!!! warning Non-FIPS only
    OpenPGP algorithms (Ed25519, Curve25519, RSA key profiles) are not FIPS 140-3 approved.
    `PGPKey` support is compiled out of FIPS builds; creating or importing an OpenPGP key on a
    FIPS server returns a `NotSupported` error.

## Key profiles

OpenPGP keys are created via KMIP `Create` with `ObjectType::PGPKey`, or the `ckms pgp keys create`
command. Two algorithm profiles are supported:

- **Ed25519** (default): an Ed25519 primary key (certify and sign) with a Curve25519/cv25519 ECDH
  encryption subkey.
- **RSA**: an RSA primary key (certify and sign) with an RSA encryption subkey. Supported modulus
  sizes are **2048**, **3072**, or **4096** bits.

Keys are generated **unprotected** inside the KMS protection boundary.

## Identification and tags

- **System tag** — the KMS automatically attaches the `_pgp` system tag to every created or imported
  OpenPGP key, alongside the user-supplied tags.
- **User ID** — the `pgp-user-id` vendor attribute (`VENDOR_ATTR_PGP_USER_ID`) holds the OpenPGP
  User ID packet, e.g. `Alice <alice@example.com>`. It is set from `--user-id` on `ckms pgp keys create`,
  and is carried back out as the User ID when the key is exported to GnuPG.

## Interoperability with GnuPG

The KMS interoperates directly with GnuPG (`gpg` v2.1+). The commands below are the exact commands
exercised by the `.mise/scripts/test/test_gnupg.sh` end-to-end suite.

### KMS → GnuPG

Create an Ed25519 key, export it, and let `gpg` verify a KMS signature and decrypt a KMS-encrypted
message:

```bash
# Create the key and export the secret armor so gpg can decrypt
ckms pgp keys create --algorithm ed25519 --user-id "CI <ci@example.com>" --tag pgp-ci
ckms pgp export --tag pgp-ci --key-format pgp-secret sec.asc
gpg --batch --import sec.asc

# KMS signs, gpg verifies
ckms pgp sign --tag pgp-ci -o data.sig data.txt
gpg --verify data.sig data.txt

# KMS encrypts, gpg decrypts
ckms pgp encrypt --tag pgp-ci -o msg.bin data.txt
gpg --decrypt msg.bin > out.txt
```

!!! tip Export formats
    `--key-format pgp-secret` exports an ASCII-armored `-----BEGIN PGP PRIVATE KEY BLOCK-----`;
    `--key-format pgp-public` exports `-----BEGIN PGP PUBLIC KEY BLOCK-----`. Both are armored text,
    so the client does **not** re-encode them as PEM.

### GnuPG → KMS

Generate an unprotected key in GnuPG with an explicit encryption subkey, import it into the KMS, and
let the KMS decrypt a GnuPG-encrypted message and verify a GnuPG-produced detached signature:

```bash
# 1. Generate an unprotected key with an encryption subkey (non-AEAD preferences)
cat << 'EOF' | gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase "" --generate-key
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign,cert
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Preferences: AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed
Name-Real: GPG User
Name-Email: gpg@example.com
Expire-Date: 0
%no-protection
%commit
EOF

# 2. Export the secret armor and import it into the KMS under a fresh ID
gpg --batch --armor --export-secret-keys "gpg@example.com" > gpg-sec.asc
ckms pgp import --key-format pgp gpg-sec.asc gpg-imported

# 3. GnuPG encrypts, KMS decrypts
gpg --batch --trust-model always --recipient "gpg@example.com" --output msg.gpg --encrypt data.txt
ckms pgp decrypt -k gpg-imported -o out.txt msg.gpg
diff data.txt out.txt

# 4. GnuPG signs (binary and ASCII-armored detached), KMS verifies
gpg --batch --local-user "gpg@example.com" --detach-sign --output gpg.sig data.txt
ckms pgp sign-verify -k gpg-imported data.txt gpg.sig
gpg --batch --local-user "gpg@example.com" --armor --detach-sign --output gpg.asc data.txt
ckms pgp sign-verify -k gpg-imported data.txt gpg.asc
```

!!! note Generating GnuPG keys for the KMS
    `gpg --quick-generate-key` does **not** create an encryption subkey by default, and batch-generated
    keys default to SEIPDv2/AEAD packets the KMS cannot decrypt. Use the explicit `--generate-key`
    parameter file above, which adds an `ecdh`/`cv25519` encryption subkey and pins non-AEAD
    preferences. GnuPG keys imported into the KMS must be unprotected (`%no-protection` / empty
    passphrase), because the KMS cannot use passphrase-protected secret keys.

!!! note Trust model
    `gpg --encrypt` to a freshly imported key requires `--trust-model always`; without it GnuPG
    refuses with *"There is no assurance this key belongs to the named user"*.

## Applicable standards and format adoption

OpenPGP has evolved through the IETF standards track:

- **RFC 2440** (Historic) — initial IETF OpenPGP specification (obsoleted by RFC 4880).
- **RFC 4880** (Standards Track) — defines version 4 (v4) Transferable Secret and Public Keys and
  Symmetrically Encrypted Integrity Protected Data (v1 SEIPD).
- **RFC 9580** (Standards Track, July 2024, obsoletes RFC 4880, 5581, 6637) — current IETF standard
  defining version 6 (v6) keys and v2 SEIPD with AEAD, while formally preserving and specifying
  version 4 key format and packet structures (§10.1 *Transferable Public Keys*, §10.2 *Transferable Secret Keys*).

### Format adoption in Eviden KMS

Eviden KMS strictly adopts the **IETF OpenPGP Transferable Key format** (RFC 4880 and RFC 9580 §10.1 & §10.2, v4 packets)
and v1 SEIPD (AES-256) encryption:

- **Key encapsulation**: managed objects are stored and transferred using standard v4 Key packets.
  In KMIP, these are represented by vendor extensions `KeyFormatType::OpenPgpSecretKey` (`0x88800007`)
  and `KeyFormatType::OpenPgpPublicKey` (`0x88800008`).
- **Message encryption**: produces standard v3 PKESK packets followed by a v1 SEIPD container (RFC 9580 §5.1.1, §5.13.1, §10.3.2.1).
- **Interoperability**: because Eviden KMS generates and expects standard RFC 4880 / RFC 9580 v4 structures,
  it interoperates out-of-the-box with any standard OpenPGP implementation, including GnuPG and commercial
  OpenPGP-compliant tooling. Non-standard extensions, such as experimental AEAD packet types (packet tag 20),
  are rejected by the server parser.

## Limitations

The server pins the following constraints for OpenPGP keys. Each is asserted by the
`pgp_gnupg_tests` interoperability suite in `crate/test_kms_server/src/pgp_gnupg_tests.rs`.

!!! warning No passphrase-protected keys
    OpenPGP secret keys stored in the KMS cannot be passphrase-protected. `Decrypt` and `Sign`
    return `OpenPGP secret key is passphrase-protected; Decrypt/Sign are not supported`. Import
    unprotected secret keys only.

!!! warning Binary output, detached signatures only
    - `Encrypt` and `Sign` always emit **binary** OpenPGP packets (PKESK + SEIPDv1/AES-256; detached
      binary signatures). Callers needing ASCII armor must armor the output themselves.
    - `SignatureVerify` accepts only **detached** signatures (`gpg --detach-sign`). Inline
      (`gpg --sign`) and cleartext (`gpg --clearsign`) signatures are rejected.
    - `Decrypt` and `SignatureVerify` accept both binary and ASCII-armored inputs.
    - The KMS verifies against the primary key first, then every public subkey — a signing-subkey
      signature validates against the published certificate.

!!! warning No streaming or pre-hashed data
    - Supplying `DigestedData` to `Sign` or `SignatureVerify` returns an error: OpenPGP signatures
      require the full message.
    - Supplying `InitIndicator` or `CorrelationValue` (streaming / multi-part) returns an error:
      streaming is not supported for OpenPGP keys.

!!! warning Wrap-on-create unsupported
    OpenPGP keys cannot be wrapped at `Create` time using `wrapping_key_id`: the server's at-rest
    wrap path does not support the `PGPKey` encoding. A wrapped OpenPGP key cannot be unwrapped on
    export either; requesting an explicit `KeyFormatType` on a wrapped key returns an error.
