//! Classify [`ureq::Error`] values that look like a TLS trust failure
//! and turn them into a short, actionable hint for the operator.
//!
//! rustls renders certificate failures as IO errors whose `Display`
//! starts with `invalid peer certificate: ...` (see rustls 0.23
//! `error.rs::Error::Display`). The classifier matches that prefix,
//! the platform-verifier wrapper used by `rustls-platform-verifier`,
//! and the bare `ureq::Error::Tls` variant.

use ureq::Error as UreqError;

/// Human-friendly hint to append to a transport-level error message
/// when the failure looks like a TLS handshake rejection.
pub const TLS_TRUST_HINT: &str =
    "TLS verification failed. This often means a corporate proxy is \
    intercepting HTTPS with a private root CA. Ask your administrator \
    to install that CA in the system trust store, or export \
    SSL_CERT_FILE=/path/to/corp-ca.pem and re-run.";

pub fn tls_trust_hint(err: &UreqError) -> Option<&'static str> {
    if looks_like_tls_trust_failure(err) {
        Some(TLS_TRUST_HINT)
    } else {
        None
    }
}

/// Render a ureq transport error as a single line, appending the
/// TLS trust hint if the underlying failure looks like a certificate
/// rejection. Use this from any provider client whose error type
/// already carries a `String` payload — keeps the surface stable
/// while making cert failures actionable.
pub fn transport_message(err: &UreqError) -> String {
    match tls_trust_hint(err) {
        Some(hint) => format!("{err} — {hint}"),
        None => format!("{err}"),
    }
}

fn looks_like_tls_trust_failure(err: &UreqError) -> bool {
    match err {
        UreqError::Tls(_) => true,
        UreqError::Io(io_err) => {
            // rustls renders every certificate verification failure as
            // `invalid peer certificate: <reason>`, which covers the
            // platform-verifier path on macOS / Linux / Windows too.
            let s = io_err.to_string();
            s.contains("invalid peer certificate") || s.contains("UnknownIssuer")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn classifies_rustls_invalid_peer_certificate() {
        let io_err = io::Error::other("invalid peer certificate: UnknownIssuer");
        let err = UreqError::Io(io_err);
        assert_eq!(tls_trust_hint(&err), Some(TLS_TRUST_HINT));
    }

    #[test]
    fn classifies_ureq_tls_variant() {
        let err = UreqError::Tls("tls handshake failed");
        assert_eq!(tls_trust_hint(&err), Some(TLS_TRUST_HINT));
    }

    #[test]
    fn ignores_unrelated_io_error() {
        let io_err = io::Error::other("connection refused");
        let err = UreqError::Io(io_err);
        assert_eq!(tls_trust_hint(&err), None);
    }

    #[test]
    fn transport_message_appends_hint_on_tls_failure() {
        let io_err = io::Error::other("invalid peer certificate: UnknownIssuer");
        let err = UreqError::Io(io_err);
        let msg = transport_message(&err);
        assert!(msg.contains("invalid peer certificate"));
        assert!(msg.contains("TLS verification failed"));
    }

    #[test]
    fn transport_message_leaves_unrelated_errors_untouched() {
        let io_err = io::Error::other("connection refused");
        let err = UreqError::Io(io_err);
        let msg = transport_message(&err);
        assert!(!msg.contains("TLS verification failed"));
    }
}
