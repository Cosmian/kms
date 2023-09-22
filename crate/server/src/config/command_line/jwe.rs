use std::{ops::Deref, str::FromStr};

use clap::Args;
use josekit::jwk::Jwk as JoseJwk;

#[derive(Debug, Clone)]
pub struct Jwk(JoseJwk);

impl FromStr for Jwk {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(JoseJwk::from_reader(&mut s.as_bytes()).map_err(
            |err| format!("'{s}' is not a valid JWK ({err})"),
        )?))
    }
}

impl Deref for Jwk {
    type Target = JoseJwk;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Args, Default, Clone)]
pub struct JWEConfig {
    /// Enable the use of encryption by providing a JWK private key as JSON
    #[clap(long, env = "JWK_PRIVATE_KEY", value_parser = clap::value_parser!(Jwk))]
    pub jwk_private_key: Option<Jwk>,
}
