#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::redundant_closure_for_method_calls)]

use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use clap::ValueEnum;
use cosmian_kms_cli_actions::{
    actions::{
        attributes::CCryptographicAlgorithm, secret_data::create_secret::CreateSecretDataAction,
    },
    reexport::cosmian_kms_client::{
        cosmian_kmip::kmip_2_1::kmip_types::Tag,
        reexport::cosmian_kms_client_utils::{
            certificate_utils::Algorithm, create_utils::SecretDataType, import_utils::KeyUsage,
        },
    },
};
use serde_json::Value;
use strum::IntoEnumIterator;
use tempfile::NamedTempFile;
use test_kms_server::start_default_test_kms_server;

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        certificates::certify::{CertifyOp, certify},
        secret_data::create_secret::create_secret_data,
        symmetric::create_key::create_symmetric_key,
        utils::{owner_config, recover_cmd_logs},
    },
};

/// Get attributes of a KMS object and return the parsed JSON output.
fn get_attributes(cli_conf_path: &str, key_id: &str) -> CosmianResult<Value> {
    let output_file = NamedTempFile::new()?;
    let output_path = output_file.path().to_string_lossy().to_string();

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(SUB_COMMAND)
        .args(["get", "--id", key_id, "--output-file", &output_path]);
    let output = recover_cmd_logs(&mut cmd);
    if !output.status.success() {
        return Err(CosmianError::Default(
            std::str::from_utf8(&output.stderr)?.to_owned(),
        ));
    }

    let contents = std::fs::read_to_string(output_file.path())?;
    let json: Value = serde_json::from_str(&contents)?;
    Ok(json)
}

/// Delete attributes of a KMS object by specifying each attribute to delete.
fn delete_attributes(cli_conf_path: &str, key_id: &str, extra_args: &[&str]) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args = vec!["delete", "--id", key_id];
    args.extend(extra_args);
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Build the CLI args for setting a specific attribute combination.
fn build_set_args(
    activation_date: Option<i64>,
    cryptographic_length: Option<i32>,
    key_usage: &[&str],
    links: &[(&str, &str)],
    name: Option<&str>,
    vendor: Option<(&str, &str, &str)>,
) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(date) = activation_date {
        args.push("--activation-date".to_owned());
        args.push(date.to_string());
    }
    if let Some(length) = cryptographic_length {
        args.push("--cryptographic-length".to_owned());
        args.push(length.to_string());
    }
    for usage in key_usage {
        args.push("--key-usage".to_owned());
        args.push((*usage).to_owned());
    }
    for (flag, value) in links {
        args.push(format!("--{flag}"));
        args.push((*value).to_owned());
    }
    if let Some(name_value) = name {
        args.push("--name".to_owned());
        args.push(name_value.to_owned());
    }
    if let Some((vendor_id, attr_name, attr_value)) = vendor {
        args.push("--vendor-identification".to_owned());
        args.push(vendor_id.to_owned());
        args.push("-n".to_owned());
        args.push(attr_name.to_owned());
        args.push("--attribute-value".to_owned());
        args.push(attr_value.to_owned());
    }
    args
}

/// Use `set_attribute` from test_modify_attribute (reuse existing helper).
fn set_attribute(cli_conf_path: &str, key_id: &str, extra_args: &[&str]) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args = vec!["set", "--id", key_id];
    args.extend(extra_args);
    cmd.arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Verify that the given attributes are present in the JSON response.
fn verify_attributes_present(
    json: &Value,
    activation_date: Option<i64>,
    cryptographic_length: Option<i32>,
    key_usage: &[&str],
    name: Option<&str>,
) {
    if let Some(date) = activation_date {
        let got = json[&Tag::ActivationDate.to_string()].as_i64().unwrap();
        assert_eq!(got, date, "ActivationDate mismatch");
    }
    if let Some(length) = cryptographic_length {
        let got = json[&Tag::CryptographicLength.to_string()]
            .as_i64()
            .unwrap();
        assert_eq!(got, i64::from(length), "CryptographicLength mismatch");
    }
    if !key_usage.is_empty() {
        assert!(
            json.get(&Tag::CryptographicUsageMask.to_string()).is_some(),
            "CryptographicUsageMask should be present"
        );
    }
    if let Some(name_value) = name {
        let names = json[&Tag::Name.to_string()].as_array().unwrap();
        assert!(
            names.iter().any(|n| {
                n.get("NameValue")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s == name_value)
            }),
            "Expected name '{name_value}' not found in {names:?}"
        );
    }
}

/// Verify that the given attributes are absent from the JSON response.
fn verify_attributes_absent(
    json: &Value,
    activation_date: Option<i64>,
    cryptographic_length: Option<i32>,
    key_usage: &[&str],
    name: Option<&str>,
) {
    if activation_date.is_some() {
        assert!(
            json.get(&Tag::ActivationDate.to_string()).is_none(),
            "ActivationDate should be absent after deletion"
        );
    }
    if cryptographic_length.is_some() {
        assert!(
            json.get(&Tag::CryptographicLength.to_string()).is_none(),
            "CryptographicLength should be absent after deletion"
        );
    }
    if !key_usage.is_empty() {
        assert!(
            json.get(&Tag::CryptographicUsageMask.to_string()).is_none(),
            "CryptographicUsageMask should be absent after deletion"
        );
    }
    if name.is_some() {
        assert!(
            json.get(&Tag::Name.to_string()).is_none(),
            "Name should be absent after deletion"
        );
    }
}

/// Check the full set/get/delete cycle for a given key.
fn check_set_delete_attributes(cli_conf_path: &str, key_id: &str) -> CosmianResult<()> {
    let key_usage = &["Encrypt", "Decrypt"];
    let links: Vec<(&str, &str)> = vec![
        ("public-key-id", "public_key_id"),
        ("private-key-id", "private_key_id"),
        ("certificate-id", "certificate_id"),
        ("p12-id", "pkcs12_certificate_id"),
        ("p12-pwd", "toto"),
        ("parent-id", "parent_id"),
        ("child-id", "child_id"),
    ];

    // Test combinations of activation_date × cryptographic_length
    for activation_date in [None, Some(5)] {
        for cryptographic_length in [None, Some(256)] {
            let args = build_set_args(
                activation_date,
                cryptographic_length,
                key_usage,
                &links,
                Some("my-object-name"),
                Some(("cosmian", "my_new_attribute", "AABBCCDDEEFF")),
            );
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            set_attribute(cli_conf_path, key_id, &args_ref)?;

            // Get and verify attributes are present
            let json = get_attributes(cli_conf_path, key_id)?;
            verify_attributes_present(
                &json,
                activation_date,
                cryptographic_length,
                key_usage,
                Some("my-object-name"),
            );

            // Delete same attributes
            delete_attributes(cli_conf_path, key_id, &args_ref)?;

            // Verify attributes are gone
            let json = get_attributes(cli_conf_path, key_id)?;
            verify_attributes_absent(
                &json,
                activation_date,
                cryptographic_length,
                key_usage,
                Some("my-object-name"),
            );
        }
    }

    // Test cryptographic algorithm one by one
    for algo in CCryptographicAlgorithm::iter() {
        let algo_str = algo
            .to_possible_value()
            .expect("valid value")
            .get_name()
            .to_string();
        set_attribute(
            cli_conf_path,
            key_id,
            &["--cryptographic-algorithm", &algo_str],
        )?;

        let json = get_attributes(cli_conf_path, key_id)?;
        assert!(
            json.get(&Tag::CryptographicAlgorithm.to_string()).is_some(),
            "CryptographicAlgorithm should be present after setting {algo_str}"
        );

        delete_attributes(
            cli_conf_path,
            key_id,
            &["--cryptographic-algorithm", &algo_str],
        )?;

        let json = get_attributes(cli_conf_path, key_id)?;
        assert!(
            json.get(&Tag::CryptographicAlgorithm.to_string()).is_none(),
            "CryptographicAlgorithm should be absent after deleting {algo_str}"
        );
    }

    // Test key usage one by one
    for key_usage in KeyUsage::iter() {
        let usage_str = key_usage
            .to_possible_value()
            .expect("valid value")
            .get_name()
            .to_string();
        set_attribute(cli_conf_path, key_id, &["--key-usage", &usage_str])?;

        let json = get_attributes(cli_conf_path, key_id)?;
        assert!(
            json.get(&Tag::CryptographicUsageMask.to_string()).is_some(),
            "CryptographicUsageMask should be present after setting {usage_str}"
        );

        delete_attributes(cli_conf_path, key_id, &["--key-usage", &usage_str])?;

        let json = get_attributes(cli_conf_path, key_id)?;
        assert!(
            json.get(&Tag::CryptographicUsageMask.to_string()).is_none(),
            "CryptographicUsageMask should be absent after deleting {usage_str}"
        );
    }

    // Test delete all attributes by tag reference
    for tag in Tag::iter() {
        let tag_str = tag.to_string();
        // Ignore errors — some tags may not exist on the object
        drop(delete_attributes(
            cli_conf_path,
            key_id,
            &["--attribute", &tag_str],
        ));
    }

    Ok(())
}

/// Exhaustive test that sets, gets, and deletes all attribute types on
/// an AES key and a self-signed certificate.
///
/// Ported from `clap/tests/attributes/test_set_attribute.rs`.
#[ignore = "Too much verbosity"]
#[tokio::test]
async fn test_set_attribute() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    // AES 256 bit key
    let key_id = create_symmetric_key(&owner_conf, &[])?;
    check_set_delete_attributes(&owner_conf, &key_id)?;

    // Self-signed certificate
    let cert_id = certify(
        &owner_conf,
        CertifyOp {
            generate_keypair: true,
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned(),
            ),
            algorithm: Some(Algorithm::NistP256),
            tags: Some(vec!["certify_self_signed_attr_test".to_owned()]),
            ..CertifyOp::default()
        },
    )?;
    check_set_delete_attributes(&owner_conf, &cert_id)?;

    Ok(())
}

/// Regression test for GitHub issue #746.
///
/// **Bug**: Setting the `Name` attribute via vendor extension stored
/// it as `VendorAttribute` instead of the standard KMIP `Name` attribute.
///
/// **Fix**: A dedicated `--name <value>` flag creates `Attribute::Name` directly.
///
/// Ported from `clap/tests/attributes/test_set_attribute.rs`.
#[tokio::test]
async fn test_issue_746_name_attribute_on_secret_data() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_conf = owner_config(ctx);

    // Create secret data (reproduces the issue's exact scenario)
    let secret_data_id = create_secret_data(
        &owner_conf,
        &CreateSecretDataAction {
            secret_value: Some(
                "fa6c1bfbf9f5073ca9f0cecac48248dd3b59b3a37f06b95280013c7004097872f\
                 5908d1f536e2990880c25d23f0bb4c21eabf5cb08c3f6a660fac5a813d802a81\
                 442186e448fffc8"
                    .to_owned(),
            ),
            secret_type: SecretDataType::Password,
            ..Default::default()
        },
    )?;

    // Set the Name attribute using the dedicated --name flag
    let name_value = "0c1eecd2-9c1a-47f3-9c4c-482310d14af6";
    set_attribute(&owner_conf, &secret_data_id, &["--name", name_value])?;

    // Get attributes and verify
    let json = get_attributes(&owner_conf, &secret_data_id)?;

    // The Name MUST be stored as standard KMIP attribute (under Tag::Name key)
    let name_key = Tag::Name.to_string();
    assert!(
        json.get(&name_key).is_some(),
        "Name attribute must be stored as standard KMIP Name attribute (issue #746)"
    );
    let names = json[&name_key].as_array().unwrap();
    assert!(
        names.iter().any(|n| {
            n.get("NameValue")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == name_value)
        }),
        "Expected name '{name_value}' in standard KMIP Name attribute, got: {names:?}"
    );

    // The Name must NOT appear in VendorExtension (that was the bug)
    let vendor_key = Tag::VendorExtension.to_string();
    assert!(
        json.get(&vendor_key).is_none(),
        "Name attribute must NOT be stored in VendorExtension (regression for issue #746)"
    );

    Ok(())
}
