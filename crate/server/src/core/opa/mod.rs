//! OPA (Open Policy Agent) authorization integration.
//!
//! This module provides the OPA client and input document construction used
//! to evaluate RBAC decisions via a sidecar OPA server.

mod client;
mod config;
mod context;
mod input;

pub(crate) use client::OpaClient;
pub(crate) use config::{OpaMode, OpaParams};
pub(crate) use context::{OPA_USER_CONTEXT, OpaUserContext, get_opa_user_context};
pub(crate) use input::OpaInput;
