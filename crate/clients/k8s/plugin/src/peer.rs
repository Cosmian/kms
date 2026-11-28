//! Peer-credential filtering of the plugin's Unix socket.

use std::io;

use tokio::net::{UnixListener, UnixStream};
use tokio_stream::{Stream, StreamExt as _, wrappers::UnixListenerStream};
use tracing::warn;

/// Whether a peer running as `uid` may use the plugin.
#[must_use]
pub fn peer_allowed(allowed: &[u32], uid: u32) -> bool {
    allowed.contains(&uid)
}

/// Accept connections on `listener`, silently dropping (with a warning) every peer whose
/// UID is not in `allowed`. A peer whose credentials cannot be read is dropped too.
pub fn allowed_peers(
    listener: UnixListener,
    allowed: Vec<u32>,
) -> impl Stream<Item = io::Result<UnixStream>> {
    UnixListenerStream::new(listener).filter(move |conn| {
        let Ok(stream) = conn else {
            return true;
        };
        match stream.peer_cred() {
            Ok(cred) if peer_allowed(&allowed, cred.uid()) => true,
            Ok(cred) => {
                warn!(
                    uid = cred.uid(),
                    gid = cred.gid(),
                    "rejected KMS plugin peer"
                );
                false
            }
            Err(e) => {
                warn!(error = %e, "cannot read KMS plugin peer credentials: rejected");
                false
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::peer_allowed;

    #[test]
    fn peer_allowed_matches_listed_uids_only() {
        assert!(peer_allowed(&[65532, 0], 65532));
        assert!(peer_allowed(&[65532, 0], 0));
        assert!(!peer_allowed(&[65532], 1000));
        assert!(!peer_allowed(&[], 0));
    }
}
