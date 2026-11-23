//! `ckms kv`: read and write the Vault KV v2-compatible secret store of the KMS
//! (`/<mount>/data/*` and `/<mount>/metadata/*`).

use std::collections::BTreeMap;

use clap::{Args, Subcommand, builder::NonEmptyStringValueParser};
use cosmian_kms_client::{KmsClient, read_bytes_from_file};
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    actions::console::Stdout,
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Manage secrets in the KMS Vault KV v2-compatible store.
///
/// The store must be enabled on the server (`kv_enabled = true`). Secrets are key/value maps
/// addressed by a slash-separated path; every write creates a new version.
#[derive(Subcommand, Debug)]
pub enum KvCommands {
    Put(PutAction),
    Get(GetAction),
    List(ListAction),
    Delete(DeleteAction),
}

impl KvCommands {
    /// Run the selected `kv` sub-command.
    ///
    /// # Errors
    /// Returns an error if the arguments are invalid or the server request fails.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Put(action) => action.run(&kms_rest_client).await,
            Self::Get(action) => action.run(&kms_rest_client).await,
            Self::List(action) => action.run(&kms_rest_client).await,
            Self::Delete(action) => action.run(&kms_rest_client).await,
        }
    }
}

/// Options shared by every `kv` sub-command.
#[derive(Args, Debug)]
pub struct KvMount {
    /// Name of the KV mount configured on the server (`kv_mount`).
    #[clap(long, default_value = "kv", verbatim_doc_comment)]
    pub mount: String,
}

/// Write a secret: creates a new version at `PATH`.
///
/// Values given on the command line are visible to other local users through the process list;
/// prefer `--from-file` for sensitive values.
#[derive(Args, Debug)]
pub struct PutAction {
    #[clap(flatten)]
    pub mount: KvMount,

    /// Secret path, e.g. `database/app`.
    #[clap(required = true)]
    pub path: String,

    /// `KEY=VALUE` pairs forming the secret. Values are stored as strings.
    #[clap(value_name = "KEY=VALUE")]
    pub pairs: Vec<String>,

    /// Read the secret from a JSON object file instead of `KEY=VALUE` pairs.
    /// Values keep their JSON type (strings, numbers, booleans, null, arrays, objects).
    #[clap(
        long,
        value_name = "FILE",
        conflicts_with = "pairs",
        verbatim_doc_comment
    )]
    pub from_file: Option<std::path::PathBuf>,

    /// Destroy this version automatically after the duration (e.g. `30s`, `5m`, `1h`, `2d`).
    #[clap(long)]
    pub ttl: Option<String>,

    /// Owner the path must belong to. Required to write to a path another user owns and
    /// shared with you; the write is refused when the path has a different owner.
    #[clap(long, value_name = "USER", value_parser = NonEmptyStringValueParser::new())]
    pub expected_owner: Option<String>,
}

/// Body of a KV v2 write; `options` is sent only when an option is set.
#[derive(Serialize)]
struct PutRequest<'a> {
    data: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<PutOptions<'a>>,
}

#[derive(Serialize)]
struct PutOptions<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_owner: Option<&'a str>,
}

impl PutAction {
    /// # Errors
    /// Returns an error if the secret is empty or the server rejects the write.
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let data = if let Some(file) = &self.from_file {
            let content = Zeroizing::new(read_bytes_from_file(file)?);
            match serde_json::from_slice::<Value>(&content)
                .with_context(|| format!("{} is not valid JSON", file.display()))?
            {
                Value::Object(map) => map,
                _ => cli_bail!("{} must contain a JSON object", file.display()),
            }
        } else {
            parse_pairs(&self.pairs)?
        };
        if data.is_empty() {
            cli_bail!("the secret must contain at least one KEY=VALUE pair");
        }

        let endpoint = secret_endpoint(&self.mount.mount, "data", &self.path)?;
        let response: Value = kms_rest_client
            .post_no_ttlv(&endpoint, Some(&self.request(data)))
            .await?;
        let version = response
            .pointer("/data/version")
            .and_then(Value::as_u64)
            .context("the server response carries no version")?;
        Stdout::new(&format!(
            "Secret written to {} (version {version}).",
            self.path
        ))
        .write()
    }

    fn request(&self, data: Map<String, Value>) -> PutRequest<'_> {
        let ttl = self.ttl.as_deref();
        let expected_owner = self.expected_owner.as_deref();
        PutRequest {
            data,
            options: (ttl.is_some() || expected_owner.is_some()).then_some(PutOptions {
                ttl,
                expected_owner,
            }),
        }
    }
}

/// Read a secret (latest version unless `--version` is given).
#[derive(Args, Debug)]
pub struct GetAction {
    #[clap(flatten)]
    pub mount: KvMount,

    /// Secret path, e.g. `database/app`.
    #[clap(required = true)]
    pub path: String,

    /// Read this version instead of the latest.
    #[clap(long)]
    pub version: Option<u64>,

    /// Print only the raw value of this key.
    #[clap(long)]
    pub field: Option<String>,
}

#[derive(Serialize)]
struct VersionQuery {
    version: u64,
}

impl GetAction {
    /// # Errors
    /// Returns an error if the secret does not exist (or is deleted), the requested field is
    /// missing, or the server request fails.
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let endpoint = secret_endpoint(&self.mount.mount, "data", &self.path)?;
        let query = self.version.map(|version| VersionQuery { version });
        let response: Value = kms_rest_client
            .get_no_ttlv(&endpoint, query.as_ref())
            .await?;
        let data = response
            .pointer("/data/data")
            .and_then(Value::as_object)
            .context("the server response carries no secret data")?;
        let output = if let Some(field) = &self.field {
            match data.get(field) {
                Some(Value::String(value)) => value.clone(),
                Some(other) => other.to_string(),
                None => cli_bail!("the secret at {} has no field '{field}'", self.path),
            }
        } else {
            serde_json::to_string_pretty(data).context("serializing the secret")?
        };
        Stdout::new(&output).write()
    }
}

/// List the keys directly under a prefix. Nested paths end with `/`.
#[derive(Args, Debug)]
pub struct ListAction {
    #[clap(flatten)]
    pub mount: KvMount,

    /// Path prefix; lists the root of the mount when omitted.
    #[clap(default_value = "")]
    pub prefix: String,
}

impl ListAction {
    /// # Errors
    /// Returns an error if the server request fails; an empty prefix (`404`) lists nothing.
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let endpoint = mount_endpoint(&self.mount.mount, "metadata", &self.prefix)?;
        let Some(response) = kms_rest_client
            .get_no_ttlv_or_not_found::<Value, _>(
                &endpoint,
                Some(&BTreeMap::from([("list", "true")])),
            )
            .await?
        else {
            return Stdout::new("").write();
        };
        let keys = response
            .pointer("/data/keys")
            .and_then(Value::as_array)
            .context("the server response carries no key list")?;
        let keys = keys
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        Stdout::new(&keys).write()
    }
}

/// Delete a secret: soft-deletes the latest version, or with `--destroy` removes every version
/// and the metadata.
#[derive(Args, Debug)]
pub struct DeleteAction {
    #[clap(flatten)]
    pub mount: KvMount,

    /// Secret path, e.g. `database/app`.
    #[clap(required = true)]
    pub path: String,

    /// Permanently destroy all versions and the metadata.
    #[clap(long)]
    pub destroy: bool,
}

impl DeleteAction {
    /// # Errors
    /// Returns an error if the secret does not exist or the server request fails.
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let (endpoint, message) = if self.destroy {
            (
                secret_endpoint(&self.mount.mount, "metadata", &self.path)?,
                format!("Secret {} destroyed (all versions).", self.path),
            )
        } else {
            (
                secret_endpoint(&self.mount.mount, "data", &self.path)?,
                format!("Latest version of secret {} deleted.", self.path),
            )
        };
        kms_rest_client.delete_no_content(&endpoint).await?;
        Stdout::new(&message).write()
    }
}

/// Split `KEY=VALUE` arguments into a JSON object; a key may not repeat.
fn parse_pairs(pairs: &[String]) -> KmsCliResult<Map<String, Value>> {
    let mut data = Map::new();
    for pair in pairs {
        let Some((key, value)) = pair.split_once('=') else {
            cli_bail!("'{pair}' is not a KEY=VALUE pair");
        };
        if key.is_empty() {
            cli_bail!("'{pair}' has an empty key");
        }
        if data
            .insert(key.to_owned(), Value::String(value.to_owned()))
            .is_some()
        {
            cli_bail!("key '{key}' is given more than once");
        }
    }
    Ok(data)
}

/// Endpoint of the secret at `path`, which must not be empty.
fn secret_endpoint(mount: &str, kind: &str, path: &str) -> KmsCliResult<String> {
    if path.trim_matches('/').is_empty() {
        cli_bail!("the secret path must not be empty");
    }
    mount_endpoint(mount, kind, path)
}

/// `/<mount>/<kind>/<path>`; an empty `path` addresses the mount root (listing).
fn mount_endpoint(mount: &str, kind: &str, path: &str) -> KmsCliResult<String> {
    Ok(format!(
        "/{}/{kind}/{}",
        encode_segment(mount)?,
        encode_path(path)?
    ))
}

fn encode_segment(segment: &str) -> KmsCliResult<String> {
    if segment.is_empty() || segment.contains('/') {
        cli_bail!("'{segment}' is not a valid mount name");
    }
    encode_path(segment)
}

/// Percent-encode every `/`-separated segment of `path` (no leading or trailing `/`).
fn encode_path(path: &str) -> KmsCliResult<String> {
    let mut url = Url::parse("http://kms.invalid/").context("building the request path")?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| crate::error::KmsCliError::Default("invalid request path".to_owned()))?;
        segments.clear();
        segments.extend(path.split('/').filter(|segment| !segment.is_empty()));
    }
    Ok(url.path().trim_start_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_become_a_json_object() {
        let data = parse_pairs(&["user=app".to_owned(), "password=a=b".to_owned()]).unwrap();
        assert_eq!(data.get("user"), Some(&Value::String("app".to_owned())));
        assert_eq!(data.get("password"), Some(&Value::String("a=b".to_owned())));
    }

    #[test]
    fn invalid_pairs_are_rejected() {
        let error = |pairs: &[&str]| {
            parse_pairs(&pairs.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>())
                .unwrap_err()
                .to_string()
        };
        assert!(error(&["no-equals"]).contains("not a KEY=VALUE pair"));
        assert!(error(&["=value"]).contains("empty key"));
        assert!(error(&["k=1", "k=2"]).contains("more than once"));
    }

    #[test]
    fn paths_are_percent_encoded_per_segment() {
        assert_eq!(
            secret_endpoint("kv", "data", "/database/my app?x#y/").unwrap(),
            "/kv/data/database/my%20app%3Fx%23y"
        );
        assert!(
            secret_endpoint("kv", "data", "///")
                .unwrap_err()
                .to_string()
                .contains("must not be empty")
        );
        assert!(
            secret_endpoint("a/b", "data", "p")
                .unwrap_err()
                .to_string()
                .contains("not a valid mount name")
        );
    }

    #[test]
    fn root_prefix_is_empty() {
        assert_eq!(
            mount_endpoint("kv", "metadata", "").unwrap(),
            "/kv/metadata/"
        );
        assert_eq!(
            mount_endpoint("kv", "metadata", "myapp/").unwrap(),
            "/kv/metadata/myapp"
        );
    }

    fn put(ttl: Option<&str>, expected_owner: Option<&str>) -> PutAction {
        PutAction {
            mount: KvMount {
                mount: "kv".to_owned(),
            },
            path: "p".to_owned(),
            pairs: Vec::new(),
            from_file: None,
            ttl: ttl.map(str::to_owned),
            expected_owner: expected_owner.map(str::to_owned),
        }
    }

    #[test]
    fn put_options_are_sent_only_when_set() {
        let data = parse_pairs(&["k=v".to_owned()]).unwrap();
        let body = |action: PutAction| serde_json::to_value(action.request(data.clone())).unwrap();
        assert_eq!(
            body(put(None, None)),
            serde_json::json!({ "data": { "k": "v" } })
        );
        assert_eq!(
            body(put(None, Some("alice"))),
            serde_json::json!({ "data": { "k": "v" }, "options": { "expected_owner": "alice" } })
        );
        assert_eq!(
            body(put(Some("1h"), Some("alice"))),
            serde_json::json!({
                "data": { "k": "v" },
                "options": { "ttl": "1h", "expected_owner": "alice" }
            })
        );
    }
}
