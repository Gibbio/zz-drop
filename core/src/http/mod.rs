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
//!   on macOS, SChannel on Windows, the system CA bundle on Linux).
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

impl AgentOpts {
    pub fn with_global_timeout(secs: u64) -> Self {
        Self {
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

fn build_tls_config() -> TlsConfig {
    if let Some(certs) = load_ssl_cert_file_env() {
        return TlsConfig::builder().root_certs(RootCerts::from(certs)).build();
    }
    TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build()
}

fn load_ssl_cert_file_env() -> Option<Vec<Certificate<'static>>> {
    let path = std::env::var_os("SSL_CERT_FILE")?;
    let bytes = std::fs::read(path).ok()?;
    let certs: Vec<Certificate<'static>> = parse_pem(&bytes)
        .filter_map(Result::ok)
        .filter_map(|item| match item {
            PemItem::Certificate(c) => Some(c),
            _ => None,
        })
        .collect();
    if certs.is_empty() { None } else { Some(certs) }
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
}
