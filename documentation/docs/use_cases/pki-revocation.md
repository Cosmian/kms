# Revocation & CRL Distribution

Certificate revocation in the Eviden KMS follows the two-phase model defined by
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280):

1. **Revoke** a certificate — the KMIP `Revoke` operation marks the certificate
   `Deactivated` or `Compromised` in the KMS database.
2. **Publish** the revocation — the `Generate-CRL` operation (or automatic
   post-revocation refresh) signs a fresh CRL that relying parties can fetch.

## CRL generation

The KMS generates X.509 v2 Certificate Revocation Lists (CRLs) per
[RFC 5280 §5](https://www.rfc-editor.org/rfc/rfc5280#section-5).

A CRL lists all certificates issued by a CA that have been revoked. The KMS
automatically collects **all** revoked certificates — those in `Deactivated` or
`Compromised` state with a `CertificateLink` pointing to the issuer — regardless
of which user owns each certificate record in the KMS database, then signs the
CRL with the CA private key.

**CLI usage:**

```bash
ckms certificates generate-crl \
  --certificate-id <CA_CERT_ID> \
  --validity-days 7 \
  --output-format pem \
  --output-file /tmp/crl.pem
```

**REST endpoint (authenticated):**

```http
GET /certificates/{issuer_id}/crl?format=pem&validity_days=7
```

Returns `application/pkix-crl` (DER, default) or `application/x-pem-file` (PEM).

!!! note "Access control"
    Any **authenticated** user with `Get` access to the CA certificate may call
    this endpoint — no Crypto Officer role is required. CRL content is public
    information (RFC 5280 §3); the authentication check exists to prevent the CA
    private key from being used as an unauthenticated signing oracle, not to
    restrict access to the revocation list itself.

The generated CRL includes:

- **Authority Key Identifier** (AKI) — derived from the CA's `subjectKeyIdentifier`
  extension if present, or from a SHA-1 hash of the CA's `SubjectPublicKeyInfo` DER.
- **CRL Number** — monotonically increasing integer, seeded at startup from
  `max(unix_timestamp, db_max_crl_number + 1)` to guarantee strict monotonicity
  across server restarts (RFC 5280 §5.2.3).
- Per-entry **CRL Reason Code** — mapped from the KMIP revocation reason stored at
  revocation time (RFC 5280 §5.3.1).
- Per-entry **Invalidity Date** — `GeneralizedTime`-encoded date of compromise when
  available in object attributes (RFC 5280 §5.3.2).

### Configuration

```toml
# kms.toml
[crl]
crl_default_validity_days = 7   # default CRL validity in days (1–365)
crl_refresh_check_hours   = 1   # background refresh check interval; 0 = disabled
crl_refresh_overlap_hours = 24  # pre-regenerate this many hours before expiry
```

All three keys may also be set as CLI flags or environment variables:

```bash
--crl-default-validity-days 7
--crl-refresh-check-hours   1
--crl-refresh-overlap-hours 24
```

## Automatic CRL regeneration on revocation

When `kms_public_url` is set in `kms.toml`, the server **automatically regenerates**
the issuer's CRL in the background whenever a certificate is revoked via the
`Revoke` operation. The regeneration is fire-and-forget: it does not block the
`Revoke` response, and any signing failure is logged at `WARN` level without
affecting the revocation outcome.

```toml
# kms.toml — enables CDP auto-injection and auto-CRL regeneration
kms_public_url = "https://kms.example.com"
```

The updated CRL is immediately available at the public CDP endpoint:

```http
GET /public/certificates/{issuer_id}/crl    # no authentication required
```

## Scheduled CRL refresh

A background scheduler wakes every `crl_refresh_check_hours` (default: 1 h) and
regenerates any stored CRL whose `nextUpdate` timestamp falls within
`crl_refresh_overlap_hours` (default: 24 h) of the current time. This prevents
relying parties from seeing an expired CRL during the window between the scheduled
expiry and the next revocation-triggered regeneration.

Set `crl_refresh_check_hours = 0` to disable the background scheduler entirely
(CRLs will only be refreshed on explicit `generate-crl` calls or `Revoke` events).

## CRL distribution points

When `kms_public_url` is configured, the KMS **automatically injects** a
`crlDistributionPoints` (CDP) extension into every CA-issued certificate, pointing
to the server's own public CRL endpoint:

```text
https://<kms_public_url>/public/certificates/<issuer_id>/crl
```

You do **not** need to supply a CDP extension manually for KMS-issued certificates
when `kms_public_url` is set.

To override or set a custom CDP manually (e.g. for an external CA), add a
`crlDistributionPoints` entry in the extension config file passed via
`--certificate-extensions`:

```ini
[ v3_ext ]
crlDistributionPoints=URI:http://ca.example.com/crl.pem
```

## Public (unauthenticated) CRL endpoint

`GET /public/certificates/{issuer_id}/crl` is intended for CRL Distribution Point
(CDP) URIs embedded in certificates. Any relying party — browser, TLS stack, OCSP
client — can fetch the current CRL without credentials, as required by
[RFC 5280 §3](https://www.rfc-editor.org/rfc/rfc5280#section-3).

The response includes:

- `Content-Type: application/pkix-crl`
- `Last-Modified` (RFC 7231 IMF-fixdate)
- `Cache-Control: public, max-age=N` where N is derived from `nextUpdate − 60 s`

The endpoint returns **404** only if the CRL has never been generated and no CRL
is stored in the database.

!!! note "Cold-start behaviour"
    Generated CRLs are persisted in the KMS database (`crls` table) and reloaded
    on server restart, so the public endpoint continues to serve the last signed CRL
    without requiring a manual `generate-crl` call after each restart.

!!! note "OCSP responder"
    The KMS also includes a built-in OCSP responder (RFC 6960) for real-time,
    per-certificate revocation status — see
    [OCSP Responder](pki-ocsp.md).

## Authority Information Access (AIA)

The AIA extension (`authorityInfoAccess`, OID `1.3.6.1.5.5.7.1.1`) can be added
via the extension config file to point relying parties to an OCSP responder or to
the CA issuer certificate:

```ini
[ v3_ext ]
authorityInfoAccess=OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://ca.example.com/ca.crt
```

## No Revocation Available (`id-ce-noRevAvail`, RFC 9608)

For **self-signed certificates** (no issuer key provided) that do not carry a CRL
distribution point, the KMS automatically adds the `id-ce-noRevAvail` extension
(OID `2.5.29.56`, RFC 9608 §2). This signals to relying parties that no
revocation information is available for this certificate, and that they MUST NOT
reject it for lack of a CRL or OCSP response.

This behaviour applies to **all algorithms** (RSA, EC, ML-DSA, SLH-DSA, …).

When validating a chain, the KMS skips CRL fetching for any certificate that
carries this extension.
