//! Smart connector for `hyper` that supports direct connections and HTTP
//! CONNECT proxy tunneling.
//!
//! [`SmartConnector`] implements `tower::Service<Uri>` and returns a
//! `TokioIo<TcpStream>` regardless of whether it connects directly or
//! tunnels through a forward proxy. This makes it a drop-in replacement
//! for `hyper_util::client::legacy::connect::HttpConnector`.

use std::{
    fmt::Write,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use hyper::Uri;
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tower_service::Service;
use tracing::debug;

use super::ProxyParams;

/// A connector that either connects directly or tunnels through an HTTP
/// CONNECT proxy, depending on the target host and the exclusion list.
///
/// Always returns `TokioIo<TcpStream>`, making it compatible with
/// `hyper_openssl::client::legacy::HttpsConnector<SmartConnector>`.
#[derive(Clone)]
pub(crate) struct SmartConnector {
    proxy_params: Option<ProxyParams>,
}

impl SmartConnector {
    /// Create a connector that always connects directly (no proxy).
    pub(crate) const fn direct() -> Self {
        Self { proxy_params: None }
    }

    /// Create a connector that tunnels through the given proxy.
    pub(crate) const fn with_proxy(proxy_params: ProxyParams) -> Self {
        Self {
            proxy_params: Some(proxy_params),
        }
    }

    /// Check if the given host should bypass the proxy (direct connect).
    fn should_bypass(&self, host: &str) -> bool {
        let Some(ref params) = self.proxy_params else {
            return true; // No proxy configured → always direct
        };
        params.exclusion_list.iter().any(|pattern| {
            if pattern.starts_with('.') {
                // Suffix match: ".example.com" matches "foo.example.com"
                host.ends_with(pattern) || host == &pattern[1..]
            } else {
                host == pattern
            }
        })
    }
}

impl Service<Uri> for SmartConnector {
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = TokioIo<TcpStream>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let host = req.host().unwrap_or("localhost").to_owned();
        let port = req.port_u16().unwrap_or_else(|| {
            if req.scheme_str() == Some("https") {
                443
            } else {
                80
            }
        });

        if self.should_bypass(&host) {
            // Direct connection
            return Box::pin(async move {
                let stream = TcpStream::connect(format!("{host}:{port}")).await?;
                Ok(TokioIo::new(stream))
            });
        }

        // CONNECT tunnel through proxy
        // `should_bypass` returns true when proxy_params is None,
        // so if we reach here proxy_params is always Some.
        let Some(proxy_params) = self.proxy_params.clone() else {
            return Box::pin(async move {
                let stream = TcpStream::connect(format!("{host}:{port}")).await?;
                Ok(TokioIo::new(stream))
            });
        };
        Box::pin(async move {
            let tunnel = establish_connect_tunnel(&proxy_params, &host, port).await?;
            Ok(TokioIo::new(tunnel))
        })
    }
}

/// Establish an HTTP CONNECT tunnel through the proxy.
///
/// Connects to the proxy, sends `CONNECT host:port HTTP/1.1`, reads the
/// response, and returns the raw `TcpStream` ready for TLS upgrade.
async fn establish_connect_tunnel(
    proxy_params: &ProxyParams,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let proxy_host = proxy_params
        .url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy URL has no host"))?;
    let proxy_port = proxy_params.url.port_or_known_default().unwrap_or(8080);
    let proxy_addr = format!("{proxy_host}:{proxy_port}");

    debug!("CONNECT tunnel: {proxy_addr} → {target_host}:{target_port}");

    // Connect to the proxy
    let mut stream = TcpStream::connect(&proxy_addr).await.map_err(|e| {
        Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "Failed to connect to proxy {proxy_addr}: {e}"
        ))
    })?;

    // Build CONNECT request
    let mut request = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\n\
         Host: {target_host}:{target_port}\r\n"
    );

    // Add proxy authentication
    if let Some(ref username) = proxy_params.basic_auth_username {
        use base64::Engine;
        let password = proxy_params.basic_auth_password.as_deref().unwrap_or("");
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        let _ = write!(request, "Proxy-Authorization: Basic {credentials}\r\n");
    } else if let Some(ref auth_value) = proxy_params.custom_auth_header {
        let _ = write!(request, "Proxy-Authorization: {auth_value}\r\n");
    }

    request.push_str("\r\n");

    // Send CONNECT request
    stream.write_all(request.as_bytes()).await?;

    // Read response headers byte-by-byte until \r\n\r\n
    let mut header_buf = Vec::with_capacity(512);
    let mut tmp = [0_u8; 1];
    loop {
        stream.read_exact(&mut tmp).await.map_err(|e| {
            Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "Proxy closed connection during CONNECT response: {e}"
            ))
        })?;
        header_buf.push(tmp[0]);
        if header_buf.len() >= 4
            && header_buf.get(header_buf.len() - 4..) == Some(b"\r\n\r\n".as_slice())
        {
            break;
        }
        if header_buf.len() > 8_192 {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "Proxy CONNECT response headers too large (>8KB)",
            )));
        }
    }

    // Parse status code from first line
    let response_str = String::from_utf8_lossy(&header_buf);
    let status_code: u16 = response_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if status_code != 200 {
        return Err(Box::new(io::Error::other(format!(
            "Proxy CONNECT to {target_host}:{target_port} failed with status {status_code}: {}",
            response_str.lines().next().unwrap_or("unknown")
        ))));
    }

    debug!("CONNECT tunnel established: {target_host}:{target_port}");
    Ok(stream)
}
