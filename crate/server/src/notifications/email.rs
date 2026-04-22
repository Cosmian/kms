use cosmian_logger::warn;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::config::SmtpConfig;

/// Validated SMTP connection parameters derived from [`SmtpConfig`].
#[derive(Clone, Debug)]
pub struct SmtpParams {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

impl SmtpParams {
    /// Build `SmtpParams` from a `SmtpConfig`. Returns `None` if `host` is not set.
    #[must_use]
    pub fn from_config(cfg: &SmtpConfig) -> Option<Self> {
        let host = cfg.host.as_ref()?.clone();
        let from = cfg.from.clone().unwrap_or_default();
        let to = cfg
            .to
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        Some(Self {
            host,
            port: cfg.port,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            from,
            to,
        })
    }
}

/// Email notifier that sends SMTP notifications for key rotation events.
///
/// Uses STARTTLS (port 587 by default). TLS is handled via `native-tls`.
/// Initialised by [`EmailNotifier::new`] from validated [`SmtpParams`].
/// If the SMTP host is not configured, the notifier is disabled entirely —
/// see [`SmtpParams::from_config`].
pub struct EmailNotifier {
    from: String,
    to: Vec<String>,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailNotifier {
    /// Build an `EmailNotifier` from SMTP parameters.
    ///
    /// Returns an error if the STARTTLS relay cannot be configured (e.g. invalid
    /// hostname, missing credentials when required).
    ///
    /// # Errors
    /// Returns a `lettre` SMTP error if the transport cannot be built.
    pub fn new(params: SmtpParams) -> Result<Self, lettre::transport::smtp::Error> {
        let builder =
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&params.host)?.port(params.port);
        let transport = if let (Some(user), Some(pass)) = (&params.username, &params.password) {
            builder.credentials(Credentials::new(user.clone(), pass.clone()))
        } else {
            builder
        }
        .build();
        Ok(Self {
            from: params.from,
            to: params.to,
            transport,
        })
    }

    /// Build and send an email. Logs a warning on any error; never panics.
    async fn send(&self, subject: &str, body: String) {
        if self.to.is_empty() {
            return;
        }
        let from = match self.from.parse::<Mailbox>() {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "email notifier: invalid 'from' address {:?}: {e}",
                    self.from
                );
                return;
            }
        };
        let mut builder = Message::builder().from(from).subject(subject);
        for addr in &self.to {
            match addr.parse::<Mailbox>() {
                Ok(m) => builder = builder.to(m),
                Err(e) => warn!("email notifier: invalid 'to' address {addr:?}: {e}"),
            }
        }
        let message = match builder.body(body) {
            Ok(m) => m,
            Err(e) => {
                warn!("email notifier: failed to build message: {e}");
                return;
            }
        };
        if let Err(e) = self.transport.send(message).await {
            warn!("email notifier: failed to send message: {e}");
        }
    }

    /// Send a notification that a key was successfully auto-rotated.
    pub async fn send_rotation_success(
        &self,
        uid: &str,
        object_type: &str,
        owner: &str,
        algorithm: &str,
        generation: i32,
        rotated_at: OffsetDateTime,
    ) {
        let rotated_at_str = rotated_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| rotated_at.to_string());
        let subject = format!("[KMS] Key rotation succeeded — {uid}");
        let body = format!(
            "The following cryptographic object was automatically rotated.\n\n\
             \x20 Object ID  : {uid}\n\
             \x20 Type       : {object_type}\n\
             \x20 Algorithm  : {algorithm}\n\
             \x20 Generation : {generation}\n\
             \x20 Rotated at : {rotated_at_str} (UTC)\n\
             \x20 Owner      : {owner}\n\n\
             This is an automated notification from the Cosmian KMS server.\n"
        );
        self.send(&subject, body).await;
    }

    /// Send a notification that auto-rotation of a key failed.
    pub async fn send_rotation_failure(&self, uid: &str, owner: &str, error: &str) {
        let subject = format!("[KMS] Key rotation FAILED — {uid}");
        let body = format!(
            "Automatic rotation of the following object FAILED.\n\
             Manual intervention may be required.\n\n\
             \x20 Object ID : {uid}\n\
             \x20 Owner     : {owner}\n\
             \x20 Error     : {error}\n\n\
             Please check the server logs for further details.\n\n\
             This is an automated notification from the Cosmian KMS server.\n"
        );
        self.send(&subject, body).await;
    }

    /// Send a warning that a key is approaching its scheduled renewal date.
    pub async fn send_renewal_warning(
        &self,
        uid: &str,
        object_type: &str,
        owner: &str,
        days_until_renewal: u32,
        rotate_interval_days: i32,
    ) {
        let subject = format!("[KMS] Key renewal in {days_until_renewal} day(s) — {uid}");
        let body = format!(
            "A cryptographic object is approaching its scheduled renewal date.\n\n\
             \x20 Object ID          : {uid}\n\
             \x20 Type               : {object_type}\n\
             \x20 Owner              : {owner}\n\
             \x20 Days until renewal : {days_until_renewal}\n\
             \x20 Rotation interval  : {rotate_interval_days} day(s)\n\n\
             No action is required if auto-rotation is enabled.\n\
             If you manage rotation manually, please rotate the key before the deadline.\n\n\
             This is an automated notification from the Cosmian KMS server.\n"
        );
        self.send(&subject, body).await;
    }
}
