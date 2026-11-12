//! An unprivileged OpenSSH server that trusts a CA public key, to check a KMS-issued
//! certificate against a real `sshd` (accepted before expiry, rejected afterwards).
//!
//! `sshd -i` runs per connection as the client's `ProxyCommand` and speaks over its pipes, so
//! no TCP port is picked, raced or polled.
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use tempfile::TempDir;

use crate::{error::KmsError, result::KResult};

fn server_error(context: &str, error: impl std::fmt::Display) -> KmsError {
    KmsError::ServerError(format!("{context}: {error}"))
}

/// Locate an OpenSSH binary in `PATH` or the usual system directories.
fn find_tool(name: &str) -> KResult<PathBuf> {
    let mut directories: Vec<PathBuf> = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect())
        .unwrap_or_default();
    directories.extend(["/usr/sbin", "/usr/bin", "/usr/local/sbin"].map(PathBuf::from));
    directories
        .into_iter()
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            KmsError::ServerError(format!(
                "OpenSSH `{name}` is required by the HSM SSH CA test but was not found"
            ))
        })
}

/// A system OpenSSH command without the FIPS OpenSSL environment of the test shell
/// (`LD_PRELOAD`, `OPENSSL_CONF`, ...): the system `sshd` links its own libcrypto and fails
/// to sign the key exchange when it inherits the Nix FIPS configuration.
fn system_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    for variable in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
    ] {
        command.env_remove(variable);
    }
    command
}

fn run(command: &mut Command, context: &str) -> KResult<()> {
    let output = command.output().map_err(|e| server_error(context, e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(KmsError::ServerError(format!(
            "{context}: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

/// Quote `path` for the shell that runs the `ProxyCommand`.
fn shell_quoted(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

pub(super) struct Sshd {
    dir: TempDir,
    daemon: PathBuf,
    ssh: PathBuf,
    /// The account sshd authenticates: the user running the test.
    pub(super) login: String,
}

impl Sshd {
    /// Prepare an `sshd` configuration with `ca_public_key` (OpenSSH text) as the only trusted
    /// user CA, check it, and generate the user key pair used to request certificates.
    pub(super) fn start(ca_public_key: &str) -> KResult<Self> {
        let sshd = find_tool("sshd")?;
        let ssh = find_tool("ssh")?;
        let ssh_keygen = find_tool("ssh-keygen")?;
        let id = find_tool("id")?;
        let dir =
            tempfile::tempdir().map_err(|e| server_error("creating the sshd directory", e))?;

        let login = system_command(id)
            .arg("-un")
            .output()
            .map_err(|e| server_error("running `id -un`", e))?;
        let login = String::from_utf8_lossy(&login.stdout).trim().to_owned();
        if login.is_empty() {
            return Err(KmsError::ServerError(
                "cannot determine the login name".to_owned(),
            ));
        }

        for key in ["host_key", "user_key"] {
            run(
                system_command(&ssh_keygen)
                    .args(["-q", "-t", "ecdsa", "-b", "256", "-N", "", "-f"])
                    .arg(dir.path().join(key)),
                "ssh-keygen",
            )?;
        }
        fs::write(dir.path().join("trusted_user_ca_keys"), ca_public_key)
            .map_err(|e| server_error("writing the trusted CA key", e))?;

        let path = |name: &str| dir.path().join(name).display().to_string();
        fs::write(
            dir.path().join("sshd_config"),
            format!(
                "HostKey {}\nTrustedUserCAKeys {}\nAuthorizedKeysFile none\n\
                 PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n\
                 StrictModes no\nLogLevel DEBUG1\n",
                path("host_key"),
                path("trusted_user_ca_keys"),
            ),
        )
        .map_err(|e| server_error("writing sshd_config", e))?;
        // Fail fast with sshd's own diagnostics on a configuration it refuses.
        run(
            system_command(&sshd)
                .arg("-t")
                .arg("-f")
                .arg(dir.path().join("sshd_config")),
            "checking sshd_config",
        )?;
        Ok(Self {
            dir,
            daemon: sshd,
            ssh,
            login,
        })
    }

    /// The OpenSSH public key to certify.
    pub(super) fn user_public_key(&self) -> KResult<String> {
        fs::read_to_string(self.dir.path().join("user_key.pub"))
            .map(|key| key.trim().to_owned())
            .map_err(|e| server_error("reading the user public key", e))
    }

    /// Whether sshd authenticates the login account with `certificate` (OpenSSH text).
    pub(super) fn accepts(&self, certificate: &str) -> KResult<bool> {
        let certificate_file = self.dir.path().join("user_key-cert.pub");
        fs::write(&certificate_file, certificate)
            .map_err(|e| server_error("writing the certificate", e))?;
        let proxy_command = format!(
            "ProxyCommand={} -i -f {} -E {}",
            shell_quoted(&self.daemon),
            shell_quoted(&self.dir.path().join("sshd_config")),
            shell_quoted(&self.dir.path().join("sshd.log")),
        );
        let status = system_command(&self.ssh)
            .args(["-F", "/dev/null", "-o"])
            .arg(proxy_command)
            .arg("-i")
            .arg(self.dir.path().join("user_key"))
            .arg("-o")
            .arg(format!("CertificateFile={}", certificate_file.display()))
            .args([
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
            ])
            .arg(format!("{}@kms-sshd-test", self.login))
            .arg("true")
            .stdin(Stdio::null())
            .status()
            .map_err(|e| server_error("running ssh", e))?;
        Ok(status.success())
    }

    /// The sshd log, for failure messages.
    pub(super) fn log(&self) -> String {
        fs::read_to_string(self.dir.path().join("sshd.log")).unwrap_or_default()
    }
}
