//! `ckms` tests against the Cosmian CSE deployments and the real Gmail API. The Gmail calls are
//! read-only; the `key-pairs create --dry-run` test creates objects in the KMS and removes them.
//! Ignored by default; `mise run test:cloud:google-cse-remote` runs them with `CKMS_CSE_CONF`.

use cosmian_config_utils::ConfigUtils;
use tempfile::TempDir;

use crate::{
    config::{CKMS_CONF_ENV, ClientConfig},
    tests::utils::ckms_bin,
};

const HOSTS: [&str; 2] = ["https://cse.cosmian.com", "https://cse.test.cosmian.com"];
const KACLS_URLS: [&str; 2] = [
    "https://cse.cosmian.com/google_cse",
    "https://cse.test.cosmian.com/google_cse",
];
const USER: &str = "blue@cosmian.com";
const DRY_RUN_USER: &str = "john.doe@acme.com";
const CSE_KEY_ID: &str = "google_cse";
/// Private key of the `cosmian_intermediate_ca` certificate; `-i` takes the key, not the certificate.
const ISSUER_PRIVATE_KEY_ID: &str = "cosmian_intermediate_ca_sk";

/// Write a copy of the `CKMS_CSE_CONF` config pointing at `server_url` without access token;
/// the source file is never modified. Returns the copy's path.
fn remote_conf(dir: &TempDir, server_url: &str) -> String {
    let source = std::env::var("CKMS_CSE_CONF")
        .expect("CKMS_CSE_CONF must point to a ckms TOML with gmail_api_conf");
    let mut conf = ClientConfig::from_toml(&source).unwrap();
    // The refresh token is only needed by the login test: `ckms login oauth --refresh` reports its absence.
    assert!(
        conf.kms_config.gmail_api_conf.is_some(),
        "{source}: gmail_api_conf is missing"
    );
    conf.kms_config.http_config.server_url = server_url.to_owned();
    conf.kms_config.http_config.access_token = None;
    let path = dir.path().join("ckms.toml");
    let path = path.to_str().unwrap().to_owned();
    conf.to_toml(&path).unwrap();
    path
}

/// Run `ckms <args>`; nothing is echoed to the test output.
fn ckms_raw(conf: &str, args: &[&str]) -> std::process::Output {
    ckms_bin()
        .env(CKMS_CONF_ENV, conf)
        .args(args)
        .output()
        .unwrap()
}

/// Run `ckms <args>`: stdout on success, stderr on failure.
///
/// Unlike `run_ckms`, nothing is echoed to the test output: the Gmail responses carry key
/// material (`kaclsData`) that must not reach public CI logs.
fn ckms(conf: &str, args: &[&str]) -> Result<String, String> {
    let output = ckms_raw(conf, args);
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// Run `ckms <args>` and parse the JSON object printed on stdout, ignoring any log lines around it.
fn gmail_json(conf: &str, args: &[&str]) -> serde_json::Value {
    let stdout = ckms(conf, args).unwrap_or_else(|e| panic!("ckms {args:?} failed: {e}"));
    let (Some(start), Some(end)) = (stdout.find('{'), stdout.rfind('}')) else {
        panic!("no JSON object in the output of ckms {args:?}");
    };
    serde_json::from_str(&stdout[start..=end])
        .unwrap_or_else(|e| panic!("invalid JSON from ckms {args:?}: {e}"))
}

#[test]
#[ignore = "Requires CKMS_CSE_CONF and network access to cse.cosmian.com, cse.test.cosmian.com and Auth0"]
fn remote_cse_login_with_refresh_token() {
    for host in HOSTS {
        let dir = TempDir::new().unwrap();
        let conf = remote_conf(&dir, host);

        // the KMS rejects calls without a token
        assert!(
            ckms(&conf, &["access-rights", "owned"]).is_err(),
            "{host}: call without token must fail"
        );

        let out =
            ckms(&conf, &["login", "oauth", "--refresh"]).unwrap_or_else(|e| panic!("{host}: {e}"));
        assert!(
            out.contains("Success! The access token was saved"),
            "{host}: unexpected login output"
        );

        let saved = ClientConfig::from_toml(&conf)
            .unwrap()
            .kms_config
            .http_config;
        let token = saved.access_token.unwrap_or_default();
        assert_eq!(token.split('.').count(), 3, "{host}: not a JWT");
        assert!(
            saved.oauth2_conf.is_some_and(|c| c.refresh_token.is_some()),
            "{host}: refresh_token lost"
        );

        ckms(&conf, &["access-rights", "owned"]).unwrap_or_else(|e| panic!("{host}: {e}"));
    }
}

#[test]
#[ignore = "Requires CKMS_CSE_CONF and network access to the Gmail API"]
fn remote_cse_gmail_identities_and_key_pairs() {
    // The Gmail calls do not touch the KMS: any host will do.
    let dir = TempDir::new().unwrap();
    let conf = remote_conf(&dir, HOSTS[0]);

    let identities = gmail_json(&conf, &["google", "identities", "list", USER]);
    let identity = identities["cseIdentities"]
        .as_array()
        .and_then(|l| l.iter().find(|i| i["emailAddress"] == USER))
        .unwrap_or_else(|| panic!("no CSE identity for {USER}: {identities}"));
    let key_pair_id = identity["primaryKeyPairId"]
        .as_str()
        .or_else(|| identity["signAndEncryptKeyPairs"]["encryptionKeyPairId"].as_str())
        .unwrap_or_else(|| panic!("identity without key pair id: {identity}"));

    let list = gmail_json(&conf, &["google", "key-pairs", "list", USER]);
    assert!(
        list["cseKeyPairs"]
            .as_array()
            .is_some_and(|l| !l.is_empty()),
        "no key pairs for {USER}"
    );

    // `get` rather than a search of `list`, which returns only the first page.
    let pair = gmail_json(
        &conf,
        &["google", "key-pairs", "get", "--user-id", USER, key_pair_id],
    );
    assert_eq!(pair["keyPairId"], key_pair_id);
    assert_eq!(
        pair["enablementState"], "enabled",
        "key pair {key_pair_id} is not enabled"
    );
    assert!(
        pair["subjectEmailAddresses"]
            .as_array()
            .is_some_and(|l| l.iter().any(|e| e == USER)),
        "key pair {key_pair_id} is not issued to {USER}: {}",
        pair["subjectEmailAddresses"]
    );
    let uris: Vec<&str> = pair["privateKeyMetadata"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["kaclsKeyMetadata"]["kaclsUri"].as_str())
        .collect();
    assert!(
        uris.iter()
            .any(|u| KACLS_URLS.contains(&u.trim_end_matches('/'))),
        "no kaclsUri on a Cosmian host: {uris:?}"
    );
}

/// Objects that `google key-pairs create --dry-run` leaves in the KMS: the dry run only skips the
/// Gmail push. They are revoked and removed on drop, even when an assertion fails.
struct KmsObjects<'a> {
    conf: &'a str,
    private_key_id: Option<String>,
    certificate_id: Option<String>,
}

impl KmsObjects<'_> {
    /// Record the ids printed by `key-pairs create`.
    fn record(&mut self, stdout: &str) {
        for line in stdout.lines() {
            if let Some(ids) = line.split("RSA keypair ID used: private_key ").nth(1) {
                self.private_key_id = ids.split(" - public_key ").next().map(str::to_owned);
            }
            if let Some(id) = line.split("certificate ID: ").nth(1) {
                self.certificate_id = Some(id.trim().to_owned());
            }
        }
    }

    /// Revoke then remove the recorded objects; returns one message per failed command.
    /// The ids are forgotten, so a later call (e.g. from `Drop`) does nothing.
    fn cleanup(&mut self) -> Vec<String> {
        let mut commands: Vec<[Vec<&str>; 2]> = Vec::new();
        let certificate_id = self.certificate_id.take();
        let private_key_id = self.private_key_id.take();
        if let Some(id) = &certificate_id {
            commands.push([
                vec!["certificates", "revoke", "-c", id, "test cleanup"],
                vec!["certificates", "destroy", "-c", id, "--remove"],
            ]);
        }
        if let Some(id) = &private_key_id {
            commands.push([
                vec!["rsa", "keys", "revoke", "-k", id, "test cleanup"],
                vec!["rsa", "keys", "destroy", "-k", id, "--remove"],
            ]);
        }
        commands
            .iter()
            .flatten()
            .filter_map(|args| {
                ckms(self.conf, args)
                    .err()
                    .map(|e| format!("`ckms {args:?}` failed: {e}"))
            })
            .collect()
    }
}

/// Fallback for a panicking test: `cleanup` has already emptied the ids on the success path.
impl Drop for KmsObjects<'_> {
    fn drop(&mut self) {
        for failure in self.cleanup() {
            eprintln!("cleanup failed: {failure}");
        }
    }
}

#[test]
#[ignore = "Requires CKMS_CSE_CONF and network access to cse.cosmian.com and Auth0"]
fn remote_cse_key_pair_create_dry_run() {
    let dir = TempDir::new().unwrap();
    let conf = remote_conf(&dir, HOSTS[0]);
    // Defence in depth: without `gmail_api_conf` nothing can reach the Gmail API,
    // even if `--dry-run` stopped being honoured.
    let mut config = ClientConfig::from_toml(&conf).unwrap();
    config.kms_config.gmail_api_conf = None;
    config.to_toml(&conf).unwrap();

    ckms(&conf, &["login", "oauth", "--refresh"]).unwrap_or_else(|e| panic!("login failed: {e}"));

    let extensions = format!(
        "{}/../../../test_data/certificates/gmail_cse/example_user.ext",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = ckms_raw(
        &conf,
        &[
            "google",
            "key-pairs",
            "create",
            "--cse-key-id",
            CSE_KEY_ID,
            "-s",
            "CN=john.doe@acme.com",
            "-i",
            ISSUER_PRIVATE_KEY_ID,
            "-e",
            &extensions,
            DRY_RUN_USER,
            "--dry-run",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut created = KmsObjects {
        conf: &conf,
        private_key_id: None,
        certificate_id: None,
    };
    created.record(&stdout);

    assert!(
        output.status.success(),
        "key-pairs create --dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Dry run mode - key pair not pushed to Gmail API"),
        "dry-run message missing"
    );
    assert!(
        !stdout.contains("Pushing new keypair") && !stdout.contains("Key pair inserted"),
        "the key pair was pushed to Gmail"
    );
    assert!(
        created.private_key_id.is_some() && created.certificate_id.is_some(),
        "no key pair / certificate id in the output"
    );
    let failures = created.cleanup();
    assert!(failures.is_empty(), "objects left in the KMS: {failures:?}");
}
