mod aws_xks_config;
mod encrypt_decrypt;
mod error;
mod health_status;
mod key_metadata;
mod sigv4_middleware;

pub use aws_xks_config::AwsXksConfig;
pub(crate) use encrypt_decrypt::{decrypt, encrypt};
pub(crate) use error::{xks_json_error_handler, xks_path_not_found_handler};
pub(crate) use health_status::get_health_status;
pub(crate) use key_metadata::get_key_metadata;
pub use sigv4_middleware::Sigv4MWare;

#[cfg(test)]
mod tests;

use crate::{error::KmsError, result::KResultHelper};

/// Reserved KMS identity under which every AWS XKS operation is executed.
///
/// The AWS XKS proxy authenticates the caller (AWS KMS) through the shared `SigV4` secret in
/// [`Sigv4MWare`]; that signature — not the `awsPrincipalArn` carried in the request body —
/// is the real trust boundary, matching AWS's documented "the AWS key policy is the source
/// of truth" model. All XKS-triggered KMS operations therefore run under this single,
/// stable identity rather than the transient caller ARN, so any correctly-signed request can
/// use the key regardless of which IAM role AWS used.
///
/// XKS keys remain **owned by `default_username`** so operators keep full administrative
/// control (list, revoke, destroy, export) and so key creation still satisfies the
/// `privileged_users` policy. This identity is merely *granted* `Encrypt`, `Decrypt`, and
/// `GetAttributes` on each XKS key: it is a least-privilege delegate that can perform the
/// cryptographic operations XKS needs and nothing else.
///
/// The value is deliberately wrapped in square brackets so it cannot collide with any
/// identity a client could authenticate as: JWT `email`/subject, TLS certificate Common
/// Names, AWS principal ARNs, and API-token user names can never contain the bracket
/// framing. Combined with the grant-based model, the set of objects reachable through the
/// XKS endpoints is exactly the set of XKS keys — no other object can be touched.
pub(crate) const AWS_XKS_SERVICE_USER: &str = "[aws-xks-service]";

#[derive(Debug, Clone)]
pub struct AwsXksParams {
    pub region: String,
    pub service: String,
    pub sigv4_access_key_id: String,
    pub sigv4_secret_access_key: String,
}

impl TryFrom<AwsXksConfig> for AwsXksParams {
    type Error = KmsError;

    fn try_from(config: AwsXksConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            region: config
                .aws_xks_region
                .context("AWS XKS region is required")?,
            service: config
                .aws_xks_service
                .context("AWS XKS service is required")?,
            sigv4_access_key_id: config
                .aws_xks_sigv4_access_key_id
                .context("AWS XKS SigV4 access key ID is required")?,
            sigv4_secret_access_key: config
                .aws_xks_sigv4_secret_access_key
                .context("AWS XKS SigV4 secret access key is required")?,
        })
    }
}
