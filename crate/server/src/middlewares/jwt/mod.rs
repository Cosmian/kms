//! JWT Authentication Module
//!
//! This module provides JWT (JSON Web Token) based authentication for the KMS server.
//! It includes components for token validation, JWKS (JSON Web Key Set) management,
//! and middleware integration.

mod jwt_config;
pub(crate) use jwt_config::{JwtConfig, JwtTokenHeaders, UserClaim};

mod jwks;
pub(crate) use jwks::JwksManager;

mod jwt_middleware;
pub(crate) use jwt_middleware::JwtAuth;

mod jwt_token_auth;
