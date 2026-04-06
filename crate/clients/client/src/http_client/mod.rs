pub use client::{HttpClient, HttpClientConfig};
pub use error::HttpClientError;
pub use login::{LoginState, Oauth2LoginConfig};
pub use proxy_params::ProxyParams;

mod client;
mod error;
mod login;
mod proxy_params;
#[cfg(test)]
mod tests;
mod tls;

pub mod reexport {
    pub use reqwest;
}
