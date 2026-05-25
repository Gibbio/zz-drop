//! Shared HTTP/TLS agent factory.
//!
//! Every outbound HTTP client in `zz-drop-core` (provider REST
//! clients, WebDAV, OAuth flows, [`crate::api::client::ApiClient`])
//! goes through [`build_agent`] so the TLS trust set is uniform.
//!
//! ## Trust set
//!
//! - Default: the operating system's trust store, via
//!   [`ureq::tls::RootCerts::PlatformVerifier`] (Security.framework
//!   on macOS, the system CA bundle on Linux; zz-drop ships Unix-only,
//!   so the verifier's Windows/SChannel backend is never reached).
//!   This is what makes zz-drop work behind corporate
//!   TLS-inspection proxies and against self-hosted Nextcloud
//!   instances whose chain ends at a CA the user has already
//!   installed system-wide.
//! - Override: `SSL_CERT_FILE` (the OpenSSL convention). When set
//!   and readable, its PEM contents become the *only* trusted
//!   roots — useful when a corporate CA is only available as a
//!   `.pem` file.
//!
//! There is no "disable verification" path. An unverifiable
//! certificate is a hard failure.

use std::time::Duration;

use ureq::Agent;
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig, parse_pem};

pub mod tls_error;

#[derive(Clone, Debug, Default)]
pub struct AgentOpts {
    pub timeout_resolve: Option<Duration>,
    pub timeout_connect: Option<Duration>,
    pub timeout_global: Option<Duration>,
    pub http_status_as_error: Option<bool>,
    pub allow_non_standard_methods: bool,
}

/// Default DNS-resolve and TCP-connect timeout applied alongside the
/// global timeout. Bounds the connection-setup phase so a slow or
/// unresponsive provider host can't hang the (single-threaded) agent
/// for the whole global window. See audit D5.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

impl AgentOpts {
    pub fn with_global_timeout(secs: u64) -> Self {
        Self {
            timeout_resolve: Some(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)),
            timeout_connect: Some(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)),
            timeout_global: Some(Duration::from_secs(secs)),
            ..Self::default()
        }
    }
}

pub fn build_agent(opts: AgentOpts) -> Agent {
    let mut b = Agent::config_builder().tls_config(build_tls_config());
    if let Some(t) = opts.timeout_resolve {
        b = b.timeout_resolve(Some(t));
    }
    if let Some(t) = opts.timeout_connect {
        b = b.timeout_connect(Some(t));
    }
    if let Some(t) = opts.timeout_global {
        b = b.timeout_global(Some(t));
    }
    if let Some(v) = opts.http_status_as_error {
        b = b.http_status_as_error(v);
    }
    if opts.allow_non_standard_methods {
        b = b.allow_non_standard_methods(true);
    }
    b.build().into()
}

/// Outcome of consulting `SSL_CERT_FILE`.
enum SslCertFile {
    /// Variable unset (or empty) — use the OS trust store.
    Unset,
    /// Variable set and at least one certificate parsed — use exactly
    /// these as the trust roots.
    Certs(Vec<Certificate<'static>>),
    /// Variable set but the file could not be read or yielded no usable
    /// certificate. We must **not** silently fall back to the system
    /// trust store the operator meant to override.
    Unusable,
}

fn build_tls_config() -> TlsConfig {
    match ssl_cert_file_roots() {
        SslCertFile::Unset => TlsConfig::builder()
            .root_certs(RootCerts::PlatformVerifier)
            .build(),
        SslCertFile::Certs(certs) => {
            TlsConfig::builder().root_certs(RootCerts::from(certs)).build()
        }
        SslCertFile::Unusable => {
            // Fail closed: `SSL_CERT_FILE` was set but unusable, so trust
            // an EMPTY root set — every TLS handshake then fails — rather
            // than reverting to the platform store the operator pinned
            // away from. Better a loud connection failure than silently
            // honoring roots they tried to exclude (audit D4).
            TlsConfig::builder()
                .root_certs(RootCerts::from(Vec::<Certificate<'static>>::new()))
                .build()
        }
    }
}

fn ssl_cert_file_roots() -> SslCertFile {
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
        return SslCertFile::Unset;
    };
    if path.is_empty() {
        return SslCertFile::Unset;
    }
    match std::fs::read(&path) {
        Ok(bytes) => certs_from_pem(&bytes),
        Err(_) => SslCertFile::Unusable,
    }
}

fn certs_from_pem(bytes: &[u8]) -> SslCertFile {
    let certs: Vec<Certificate<'static>> = parse_pem(bytes)
        .filter_map(Result::ok)
        .filter_map(|item| match item {
            PemItem::Certificate(c) => Some(c),
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        SslCertFile::Unusable
    } else {
        SslCertFile::Certs(certs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_agent_with_defaults() {
        let _ = build_agent(AgentOpts::default());
    }

    #[test]
    fn builds_agent_with_timeouts_and_webdav_flag() {
        let opts = AgentOpts {
            timeout_resolve: Some(Duration::from_secs(5)),
            timeout_connect: Some(Duration::from_secs(5)),
            timeout_global: Some(Duration::from_secs(30)),
            http_status_as_error: Some(false),
            allow_non_standard_methods: true,
        };
        let _ = build_agent(opts);
    }

    #[test]
    fn ssl_cert_file_bytes_without_valid_cert_are_unusable() {
        // A set-but-broken SSL_CERT_FILE must classify as Unusable so
        // build_tls_config fails closed instead of using the OS store.
        assert!(matches!(certs_from_pem(b""), SslCertFile::Unusable));
        assert!(matches!(
            certs_from_pem(b"not a pem file at all"),
            SslCertFile::Unusable
        ));
        // A PEM block of the wrong type (a key, not a certificate) also
        // yields no trusted roots → Unusable.
        let key_pem = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(matches!(certs_from_pem(key_pem), SslCertFile::Unusable));
    }

    #[test]
    fn build_tls_config_does_not_panic_on_empty_roots() {
        // Fail-closed path builds an Agent with an empty root set; it
        // must not panic at construction (connections fail at handshake).
        let _ = build_agent(AgentOpts::default());
    }

    #[test]
    fn with_global_timeout_also_bounds_connect_and_resolve() {
        // Every provider client builds on this constructor; it must set
        // connect + resolve caps, not just the global one (D5).
        let opts = AgentOpts::with_global_timeout(30);
        assert_eq!(opts.timeout_global, Some(Duration::from_secs(30)));
        assert_eq!(
            opts.timeout_connect,
            Some(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
        );
        assert_eq!(
            opts.timeout_resolve,
            Some(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
        );
    }
}
