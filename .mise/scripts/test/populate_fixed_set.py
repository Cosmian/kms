#!/usr/bin/env python3
"""Populate the deterministic `mig_*` + `bulk_*` coverage set over KMIP 2.1 JSON."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

from kmip_json_client import (
    DEFAULT_ACTIVATION_DATE,
    FUTURE_ACTIVATION_DATE,
    KmipClient,
    KmipRequestError,
    build_certify,
    build_create_key_pair,
    build_create_symmetric_key,
    build_destroy,
    build_import_certificate,
    build_import_opaque_object,
    build_import_secret_data,
    build_revoke,
    build_set_attribute,
    find_tag_value,
    is_unsupported_feature_error,
    link_attribute,
    make_mtls_context,
    name_attribute,
    vendor_attribute,
)

GRANTEE_USER = "user.client@acme.com"
AUDITOR_USER = "bulk_auditor"

# Hex-encoded JSON access policy `{"Security Level::<":["Protected","Confidential"],"Department":["MKG","FIN"]}`
COVERCRYPT_POLICY_HEX = (
    "7B225365637572697479204C6576656C3A3A3C223A5B2250726F746563746564222C"
    "22436F6E666964656E7469616C225D2C224465706172746D656E74223A5B224D4B47"
    "222C2246494E225D7D"
)


def pem_cert_to_der_hex(pem_path: Path) -> str:
    """Convert a PEM certificate file into uppercase hex DER bytes."""
    lines = [
        line.strip()
        for line in pem_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("-----")
    ]
    return base64.b64decode("".join(lines)).hex().upper()


def _item_record(
    *,
    uid: str,
    layer: str,
    status: str,
    required: bool,
    object_type: str,
    algorithm: str | None = None,
    length: int | None = None,
    expected_state: str = "Active",
    user_tags: list[str] | None = None,
    wrapping_key_uid: str | None = None,
    links: dict[str, str] | None = None,
    grants: dict[str, list[str]] | None = None,
    usages: list[str] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "uid": uid,
        "layer": layer,
        "status": status,
        "required": required,
        "reason": reason,
        "object_type": object_type,
        "algorithm": algorithm,
        "length": length,
        "expected_state": expected_state,
        "user_tags": sorted(user_tags or []),
        "wrapping_key_uid": wrapping_key_uid,
        "links": dict(links or {}),
        "grants": {u: sorted(ops) for u, ops in (grants or {}).items()},
        "usages": list(usages or []),
    }


def _run_step(
    items: list[dict[str, Any]],
    *,
    required: bool,
    fallback_entry: dict[str, Any],
    action: Any,
) -> None:
    try:
        produced = action()
        items.extend(produced)
    except KmipRequestError as exc:
        if not required and is_unsupported_feature_error(exc):
            skipped = dict(fallback_entry)
            skipped["status"] = "skipped"
            skipped["reason"] = str(exc)
            items.append(skipped)
        else:
            failed = dict(fallback_entry)
            failed["status"] = "failed"
            failed["reason"] = str(exc)
            items.append(failed)


def _populate_mig_layer(
    client: KmipClient, items: list[dict[str, Any]], sample_cert_der_hex: str | None
) -> None:
    def create_mig_kek() -> list[dict[str, Any]]:
        client.kmip(
            build_create_symmetric_key(
                "mig_kek",
                algorithm="AES",
                length=256,
                usage_mask=2108,
                tags=["mig"],
            ),
            uid="mig_kek",
        )
        client.grant_access("mig_kek", GRANTEE_USER, ["get", "encrypt", "decrypt"])
        return [
            _item_record(
                uid="mig_kek",
                layer="mig",
                status="created",
                required=True,
                object_type="SymmetricKey",
                algorithm="AES",
                length=256,
                user_tags=["mig"],
                grants={GRANTEE_USER: ["get", "encrypt", "decrypt"]},
                usages=["encrypt", "decrypt", "wrap"],
            )
        ]

    _run_step(
        items,
        required=True,
        fallback_entry=_item_record(
            uid="mig_kek",
            layer="mig",
            status="failed",
            required=True,
            object_type="SymmetricKey",
            algorithm="AES",
            length=256,
        ),
        action=create_mig_kek,
    )

    def create_mig_wrapped() -> list[dict[str, Any]]:
        client.kmip(
            build_create_symmetric_key(
                "mig_wrapped",
                algorithm="AES",
                length=256,
                usage_mask=12,
                tags=["mig"],
                wrapping_key_uid="mig_kek",
            ),
            uid="mig_wrapped",
        )
        return [
            _item_record(
                uid="mig_wrapped",
                layer="mig",
                status="created",
                required=True,
                object_type="SymmetricKey",
                algorithm="AES",
                length=256,
                user_tags=["mig"],
                wrapping_key_uid="mig_kek",
                usages=["encrypt", "decrypt"],
            )
        ]

    _run_step(
        items,
        required=True,
        fallback_entry=_item_record(
            uid="mig_wrapped",
            layer="mig",
            status="failed",
            required=True,
            object_type="SymmetricKey",
            algorithm="AES",
            length=256,
        ),
        action=create_mig_wrapped,
    )

    def create_mig_rsa_and_cert() -> list[dict[str, Any]]:
        resp = client.kmip(
            build_create_key_pair(
                "mig_rsa",
                algorithm="RSA",
                length=2048,
                key_format_type="TransparentRSAPrivateKey",
                usage_mask=2097164,
                tags=["mig"],
            ),
            uid="mig_rsa",
        )
        pk_uid = str(find_tag_value(resp, "PublicKeyUniqueIdentifier") or "mig_rsa_pk")
        client.kmip(
            build_certify(
                pk_uid,
                "mig_cert",
                subject_cn="Migration fixture",
                tags=["mig"],
            ),
            uid="mig_cert",
        )
        records = [
            _item_record(
                uid="mig_rsa",
                layer="mig",
                status="created",
                required=True,
                object_type="PrivateKey",
                algorithm="RSA",
                length=2048,
                user_tags=["mig"],
                links={"PublicKeyLink": pk_uid},
                usages=["sign_rsa_pss"],
            ),
            _item_record(
                uid=pk_uid,
                layer="mig",
                status="created",
                required=True,
                object_type="PublicKey",
                algorithm="RSA",
                length=2048,
                user_tags=["mig"],
                links={"PrivateKeyLink": "mig_rsa"},
                usages=["verify_rsa_pss"],
            ),
            _item_record(
                uid="mig_cert",
                layer="mig",
                status="created",
                required=True,
                object_type="Certificate",
                user_tags=["mig"],
            ),
        ]
        if sample_cert_der_hex:
            client.kmip(
                build_import_certificate(
                    "mig_imported_cert",
                    sample_cert_der_hex,
                    tags=["mig"],
                ),
                uid="mig_imported_cert",
            )
            records.append(
                _item_record(
                    uid="mig_imported_cert",
                    layer="mig",
                    status="created",
                    required=True,
                    object_type="Certificate",
                    user_tags=["mig"],
                )
            )
        return records

    _run_step(
        items,
        required=True,
        fallback_entry=_item_record(
            uid="mig_rsa",
            layer="mig",
            status="failed",
            required=True,
            object_type="PrivateKey",
            algorithm="RSA",
            length=2048,
        ),
        action=create_mig_rsa_and_cert,
    )

    def create_mig_revoked() -> list[dict[str, Any]]:
        client.kmip(
            build_create_symmetric_key(
                "mig_revoked",
                algorithm="AES",
                length=256,
                usage_mask=12,
                tags=["mig"],
            ),
            uid="mig_revoked",
        )
        client.kmip(build_revoke("mig_revoked", "CessationOfOperation"), uid="mig_revoked")
        return [
            _item_record(
                uid="mig_revoked",
                layer="mig",
                status="created",
                required=True,
                object_type="SymmetricKey",
                algorithm="AES",
                length=256,
                expected_state="Deactivated",
                user_tags=["mig"],
            )
        ]

    _run_step(
        items,
        required=True,
        fallback_entry=_item_record(
            uid="mig_revoked",
            layer="mig",
            status="failed",
            required=True,
            object_type="SymmetricKey",
            algorithm="AES",
            length=256,
            expected_state="Deactivated",
        ),
        action=create_mig_revoked,
    )


def _populate_bulk_layer(
    client: KmipClient, items: list[dict[str, Any]], variant: str
) -> None:
    for uid, bits, tags in [
        ("bulk_aes_128", 128, ["bulk"]),
        ("bulk_aes_192", 192, ["bulk"]),
        ("bulk_aes_256", 256, ["bulk", "env:prod/eu", "émoji-🔐"]),
    ]:

        def create_aes(
            u: str = uid, b: int = bits, t: list[str] = tags
        ) -> list[dict[str, Any]]:
            name_val = "bulk-shared-aes-256" if u == "bulk_aes_256" else None
            client.kmip(
                build_create_symmetric_key(
                    u,
                    algorithm="AES",
                    length=b,
                    usage_mask=2108,
                    tags=t,
                    name=name_val,
                ),
                uid=u,
            )
            grants: dict[str, list[str]] = {}
            if u == "bulk_aes_256":
                client.kmip(
                    build_set_attribute(
                        u, link_attribute("CertificateLink", "mig_cert")
                    ),
                    uid=u,
                )
                client.grant_access(u, GRANTEE_USER, ["encrypt", "decrypt"])
                client.grant_access(u, AUDITOR_USER, ["get", "locate"])
                grants = {
                    GRANTEE_USER: ["encrypt", "decrypt"],
                    AUDITOR_USER: ["get", "locate"],
                }
            return [
                _item_record(
                    uid=u,
                    layer="bulk",
                    status="created",
                    required=True,
                    object_type="SymmetricKey",
                    algorithm="AES",
                    length=b,
                    user_tags=t,
                    links={"CertificateLink": "mig_cert"} if u == "bulk_aes_256" else {},
                    grants=grants,
                    usages=["encrypt", "decrypt"],
                )
            ]

        _run_step(
            items,
            required=True,
            fallback_entry=_item_record(
                uid=uid,
                layer="bulk",
                status="failed",
                required=True,
                object_type="SymmetricKey",
                algorithm="AES",
                length=bits,
            ),
            action=create_aes,
        )

    for uid, kek in [
        ("bulk_sym_wrapped", "mig_kek"),
        ("bulk_wrapped_2", "bulk_aes_256"),
    ]:

        def create_wrapped(u: str = uid, k: str = kek) -> list[dict[str, Any]]:
            client.kmip(
                build_create_symmetric_key(
                    u,
                    algorithm="AES",
                    length=256,
                    usage_mask=12,
                    tags=["bulk"],
                    wrapping_key_uid=k,
                ),
                uid=u,
            )
            return [
                _item_record(
                    uid=u,
                    layer="bulk",
                    status="created",
                    required=True,
                    object_type="SymmetricKey",
                    algorithm="AES",
                    length=256,
                    user_tags=["bulk"],
                    wrapping_key_uid=k,
                    usages=["encrypt", "decrypt"],
                )
            ]

        _run_step(
            items,
            required=True,
            fallback_entry=_item_record(
                uid=uid,
                layer="bulk",
                status="failed",
                required=True,
                object_type="SymmetricKey",
                algorithm="AES",
                length=256,
            ),
            action=create_wrapped,
        )

    def create_rsa_3072_and_cert2() -> list[dict[str, Any]]:
        resp = client.kmip(
            build_create_key_pair(
                "bulk_rsa_3072",
                algorithm="RSA",
                length=3072,
                key_format_type="TransparentRSAPrivateKey",
                usage_mask=2097164,
                tags=["bulk"],
            ),
            uid="bulk_rsa_3072",
        )
        pk_uid = str(
            find_tag_value(resp, "PublicKeyUniqueIdentifier") or "bulk_rsa_3072_pk"
        )
        client.kmip(
            build_certify(
                pk_uid,
                "bulk_cert_2",
                subject_cn="Bulk fixture secondary",
                tags=["bulk"],
            ),
            uid="bulk_cert_2",
        )
        return [
            _item_record(
                uid="bulk_rsa_3072",
                layer="bulk",
                status="created",
                required=True,
                object_type="PrivateKey",
                algorithm="RSA",
                length=3072,
                user_tags=["bulk"],
                links={"PublicKeyLink": pk_uid},
                usages=["sign_rsa_pss"],
            ),
            _item_record(
                uid=pk_uid,
                layer="bulk",
                status="created",
                required=True,
                object_type="PublicKey",
                algorithm="RSA",
                length=3072,
                user_tags=["bulk"],
                links={"PrivateKeyLink": "bulk_rsa_3072"},
                usages=["verify_rsa_pss"],
            ),
            _item_record(
                uid="bulk_cert_2",
                layer="bulk",
                status="created",
                required=True,
                object_type="Certificate",
                user_tags=["bulk"],
            ),
        ]

    _run_step(
        items,
        required=True,
        fallback_entry=_item_record(
            uid="bulk_rsa_3072",
            layer="bulk",
            status="failed",
            required=True,
            object_type="PrivateKey",
            algorithm="RSA",
            length=3072,
        ),
        action=create_rsa_3072_and_cert2,
    )

    for uid, curve in [("bulk_ec_p256", "P256"), ("bulk_ec_p384", "P384")]:

        def create_ec(u: str = uid, c: str = curve) -> list[dict[str, Any]]:
            resp = client.kmip(
                build_create_key_pair(
                    u,
                    algorithm="ECDSA",
                    curve=c,
                    key_format_type="ECPrivateKey",
                    usage_mask=2097167,
                    tags=["bulk"],
                ),
                uid=u,
            )
            pk_uid = str(find_tag_value(resp, "PublicKeyUniqueIdentifier") or f"{u}_pk")
            return [
                _item_record(
                    uid=u,
                    layer="bulk",
                    status="created",
                    required=True,
                    object_type="PrivateKey",
                    algorithm="ECDSA",
                    user_tags=["bulk"],
                    links={"PublicKeyLink": pk_uid},
                    usages=["sign_ecdsa"],
                ),
                _item_record(
                    uid=pk_uid,
                    layer="bulk",
                    status="created",
                    required=True,
                    object_type="PublicKey",
                    algorithm="ECDSA",
                    user_tags=["bulk"],
                    links={"PrivateKeyLink": u},
                    usages=["verify_ecdsa"],
                ),
            ]

        _run_step(
            items,
            required=True,
            fallback_entry=_item_record(
                uid=uid,
                layer="bulk",
                status="failed",
                required=True,
                object_type="PrivateKey",
                algorithm="ECDSA",
            ),
            action=create_ec,
        )

    def create_secret_and_opaque() -> list[dict[str, Any]]:
        client.kmip(
            build_import_secret_data(
                "bulk_secret_data", "DEADBEEFCAFE0123456789ABCDEF", tags=["bulk"]
            ),
            uid="bulk_secret_data",
        )
        client.kmip(
            build_import_opaque_object(
                "bulk_opaque", "48656C6C6F204F7061717565", tags=["bulk"]
            ),
            uid="bulk_opaque",
        )
        return [
            _item_record(
                uid="bulk_secret_data",
                layer="bulk",
                status="created",
                required=True,
                object_type="SecretData",
                user_tags=["bulk"],
            ),
            _item_record(
                uid="bulk_opaque",
                layer="bulk",
                status="created",
                required=True,
                object_type="OpaqueObject",
                user_tags=["bulk"],
            ),
        ]

    _run_step(
        items,
        required=True,
        fallback_entry=_item_record(
            uid="bulk_secret_data",
            layer="bulk",
            status="failed",
            required=True,
            object_type="SecretData",
        ),
        action=create_secret_and_opaque,
    )

    def create_lifecycle_keys() -> list[dict[str, Any]]:
        client.kmip(
            build_create_symmetric_key(
                "bulk_preactive",
                algorithm="AES",
                length=256,
                usage_mask=12,
                tags=["bulk"],
                activation_date=FUTURE_ACTIVATION_DATE,
            ),
            uid="bulk_preactive",
        )
        for uid, reason in [
            ("bulk_compromised", "KeyCompromise"),
            ("bulk_destroyed", "Superseded"),
        ]:
            client.kmip(
                build_create_symmetric_key(
                    uid,
                    algorithm="AES",
                    length=256,
                    usage_mask=12,
                    tags=["bulk"],
                    activation_date=DEFAULT_ACTIVATION_DATE,
                ),
                uid=uid,
            )
            client.kmip(build_revoke(uid, reason), uid=uid)
        client.kmip(build_destroy("bulk_destroyed"), uid="bulk_destroyed")
        return [
            _item_record(
                uid="bulk_preactive",
                layer="bulk",
                status="created",
                required=True,
                object_type="SymmetricKey",
                algorithm="AES",
                length=256,
                expected_state="PreActive",
                user_tags=["bulk"],
            ),
            _item_record(
                uid="bulk_compromised",
                layer="bulk",
                status="created",
                required=True,
                object_type="SymmetricKey",
                algorithm="AES",
                length=256,
                expected_state="Compromised",
                user_tags=["bulk"],
            ),
            _item_record(
                uid="bulk_destroyed",
                layer="bulk",
                status="created",
                required=True,
                object_type="SymmetricKey",
                algorithm="AES",
                length=256,
                expected_state="Destroyed",
                user_tags=["bulk"],
            ),
        ]

    _run_step(
        items,
        required=True,
        fallback_entry=_item_record(
            uid="bulk_preactive",
            layer="bulk",
            status="failed",
            required=True,
            object_type="SymmetricKey",
            algorithm="AES",
            length=256,
        ),
        action=create_lifecycle_keys,
    )

    if variant == "non-fips":
        _populate_non_fips_optional_items(client, items)


def _populate_non_fips_optional_items(
    client: KmipClient, items: list[dict[str, Any]]
) -> None:
    def create_ed25519() -> list[dict[str, Any]]:
        resp = client.kmip(
            build_create_key_pair(
                "bulk_ed25519",
                algorithm="Ed25519",
                curve="CURVEED25519",
                key_format_type="ECPrivateKey",
                usage_mask=12,
                tags=["bulk", "non-fips"],
            ),
            uid="bulk_ed25519",
        )
        pk_uid = str(
            find_tag_value(resp, "PublicKeyUniqueIdentifier") or "bulk_ed25519_pk"
        )
        return [
            _item_record(
                uid="bulk_ed25519",
                layer="bulk",
                status="created",
                required=False,
                object_type="PrivateKey",
                algorithm="Ed25519",
                user_tags=["bulk", "non-fips"],
                links={"PublicKeyLink": pk_uid},
            ),
            _item_record(
                uid=pk_uid,
                layer="bulk",
                status="created",
                required=False,
                object_type="PublicKey",
                algorithm="Ed25519",
                user_tags=["bulk", "non-fips"],
                links={"PrivateKeyLink": "bulk_ed25519"},
            ),
        ]

    _run_step(
        items,
        required=False,
        fallback_entry=_item_record(
            uid="bulk_ed25519",
            layer="bulk",
            status="skipped",
            required=False,
            object_type="PrivateKey",
            algorithm="Ed25519",
        ),
        action=create_ed25519,
    )

    def create_covercrypt() -> list[dict[str, Any]]:
        resp = client.kmip(
            build_create_key_pair(
                "bulk_covercrypt",
                algorithm="CoverCrypt",
                key_format_type="CoverCryptSecretKey",
                usage_mask=4194304,
                tags=["bulk", "non-fips"],
                extra_common_attributes=[
                    {"tag": "ObjectType", "type": "Enumeration", "value": "PrivateKey"},
                    vendor_attribute(
                        "cover_crypt_access_structure",
                        COVERCRYPT_POLICY_HEX,
                        value_type="ByteString",
                    ),
                ],
            ),
            uid="bulk_covercrypt",
        )
        pk_uid = str(
            find_tag_value(resp, "PublicKeyUniqueIdentifier") or "bulk_covercrypt_pk"
        )
        return [
            _item_record(
                uid="bulk_covercrypt",
                layer="bulk",
                status="created",
                required=False,
                object_type="PrivateKey",
                algorithm="CoverCrypt",
                user_tags=["bulk", "non-fips"],
                links={"PublicKeyLink": pk_uid},
            ),
            _item_record(
                uid=pk_uid,
                layer="bulk",
                status="created",
                required=False,
                object_type="PublicKey",
                algorithm="CoverCrypt",
                user_tags=["bulk", "non-fips"],
                links={"PrivateKeyLink": "bulk_covercrypt"},
            ),
        ]

    _run_step(
        items,
        required=False,
        fallback_entry=_item_record(
            uid="bulk_covercrypt",
            layer="bulk",
            status="skipped",
            required=False,
            object_type="PrivateKey",
            algorithm="CoverCrypt",
        ),
        action=create_covercrypt,
    )


def populate_fixed_set(
    client: KmipClient,
    *,
    variant: str,
    sample_cert_der_hex: str | None = None,
    server_version: str | None = None,
) -> dict[str, Any]:
    """Populate the `mig_*` and `bulk_*` objects and return the structured manifest dict."""
    resolved_version = server_version
    if not resolved_version:
        try:
            resolved_version = client.get_version()
        except KmipRequestError:
            resolved_version = "unknown"

    items: list[dict[str, Any]] = []
    _populate_mig_layer(client, items, sample_cert_der_hex)
    _populate_bulk_layer(client, items, variant)
    return {
        "manifest_version": 1,
        "server_version": resolved_version,
        "variant": variant,
        "layer": "fixed",
        "items": items,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Populate deterministic mig_* and bulk_* KMS objects via KMIP 2.1 JSON."
    )
    parser.add_argument("--url", required=True, help="KMS base URL (e.g. https://127.0.0.1:9998)")
    parser.add_argument(
        "--variant",
        choices=("fips", "non-fips"),
        default="fips",
        help="Server build variant",
    )
    parser.add_argument("--manifest", required=True, type=Path, help="Output JSON manifest path")
    parser.add_argument("--server-version", default=None, help="Fallback server version string")
    parser.add_argument("--ca-cert", type=Path, default=None, help="CA certificate PEM path for mTLS")
    parser.add_argument("--client-cert", type=Path, default=None, help="Owner client certificate PEM")
    parser.add_argument("--client-key", type=Path, default=None, help="Owner client key PEM")
    parser.add_argument(
        "--sample-cert",
        type=Path,
        default=None,
        help="Optional X.509 PEM certificate to import as mig_imported_cert",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    ssl_ctx = None
    if args.ca_cert and args.client_cert and args.client_key:
        ssl_ctx = make_mtls_context(args.ca_cert, args.client_cert, args.client_key)

    sample_der_hex = (
        pem_cert_to_der_hex(args.sample_cert)
        if args.sample_cert and args.sample_cert.is_file()
        else None
    )
    client = KmipClient(args.url, ssl_context=ssl_ctx)
    manifest = populate_fixed_set(
        client,
        variant=args.variant,
        sample_cert_der_hex=sample_der_hex,
        server_version=args.server_version,
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    failed = [item for item in manifest["items"] if item["status"] == "failed"]
    skipped = [item for item in manifest["items"] if item["status"] == "skipped"]
    created = [item for item in manifest["items"] if item["status"] == "created"]
    for item in skipped:
        print(
            f"[SKIP] {item['uid']} ({item.get('algorithm') or item['object_type']}): {item['reason']}",
            file=sys.stderr,
        )
    if failed:
        for item in failed:
            print(
                f"ERROR: fixed-set item {item['uid']} failed: {item['reason']}",
                file=sys.stderr,
            )
        return 1
    print(
        f"Populated fixed set on KMS {manifest['server_version']} ({args.variant}): "
        f"created={len(created)} skipped={len(skipped)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
