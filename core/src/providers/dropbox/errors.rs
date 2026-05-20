//! Error type and short stderr mapping for the Dropbox provider.
//!
//! Mirrors `onedrive::errors`: typed errors stay rich for the TUI,
//! the CLI maps them to a single short, sanitised line.

use thiserror::Error;

use crate::http::tls_error::{TLS_TRUST_HINT, tls_trust_hint};
use crate::providers::oauth::PasteCodeError;

#[derive(Debug, Error)]
pub enum DropboxError {
    #[error("oauth: {0}")]
    Oauth(#[from] PasteCodeError),

    #[error("invalid root folder")]
    BadRoot,

    #[error("token expired and refresh failed")]
    TokenExpired,

    #[error("auth failed")]
    Unauthorized,

    #[error("not found")]
    NotFound,

    #[error("conflict")]
    Conflict,

    #[error("rate limited")]
    RateLimited,

    #[error("server error: {status}")]
    ServerError { status: u16 },

    #[error("network error")]
    Network,

    #[error("TLS verification failed — {0}")]
    TlsTrustFailed(&'static str),

    #[error("local io error")]
    LocalIo,

    #[error("malformed response")]
    Decode,
}

impl DropboxError {
    pub fn from_ureq_transport(err: &ureq::Error) -> Self {
        match tls_trust_hint(err) {
            Some(hint) => Self::TlsTrustFailed(hint),
            None => Self::Network,
        }
    }
}

/// Single short, sanitised line for stderr / exit-code 9 path.
/// Mirrors `onedrive::diagnose` — keep stable for scripts.
pub fn diagnose(err: &DropboxError) -> &'static str {
    match err {
        DropboxError::Oauth(_) => "oauth flow error",
        DropboxError::BadRoot => "invalid root folder",
        DropboxError::TokenExpired => "token expired",
        DropboxError::Unauthorized => "auth failed",
        DropboxError::NotFound => "not found",
        DropboxError::Conflict => "conflict",
        DropboxError::RateLimited => "rate limited",
        DropboxError::ServerError { .. } => "server error",
        DropboxError::Network => "network error",
        DropboxError::TlsTrustFailed(_) => TLS_TRUST_HINT,
        DropboxError::LocalIo => "local file error",
        DropboxError::Decode => "bad server response",
    }
}
