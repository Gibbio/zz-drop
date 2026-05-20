//! OAuth 2.0 Authorization Code + PKCE client without `redirect_uri`.
//!
//! Used by providers whose OAuth server does not support the RFC 8628
//! Device Authorization Grant — Dropbox in particular. The user opens
//! a URL in any browser, approves the access, and the authorization
//! server displays a short code on its own page for the user to type
//! back into the TUI. The TUI then exchanges that code for tokens
//! using the PKCE `code_verifier` it generated locally — no
//! `client_secret`, no ephemeral local HTTP server.
//!
//! This module duplicates a small amount of HTTP / OAuth-error
//! plumbing already present in [`super::device_flow`]. The
//! duplication is intentional: the device-flow code path ships in
//! production for OneDrive and Google Drive, and a refactor that
//! shared internal helpers between the two flows would force changes
//! to that frozen surface for no behavioural gain. Keep the two
//! files structurally similar so a future cleanup task can lift the
//! shared bits into a small `oauth/http_util.rs` if it ever
//! materialises.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use ureq::Agent;
use ureq::http::Request;
use url::form_urlencoded;

use super::device_flow::{DeviceFlowError, TokenResponse};
use crate::http::tls_error::tls_trust_hint;
use crate::http::{AgentOpts, build_agent};

const USER_AGENT: &str = "zz-drop";

/// Inputs to a paste-code exchange. Endpoints and credentials are
/// borrowed: a single [`PasteCodeFlow`] is short-lived and never
/// outlives the provider setup screen.
#[derive(Clone, Debug)]
pub struct PasteCodeConfig<'a> {
    pub authorize_endpoint: &'a str,
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    /// Extra query parameters appended to the authorize URL — for
    /// example Dropbox's `token_access_type=offline`, which is the
    /// only way to get a refresh token from that endpoint.
    pub authorize_extra: &'a [(&'a str, &'a str)],
    /// Optional `scope` query parameter on the authorize URL. Some
    /// providers (Dropbox) take scope from the app registration and
    /// ignore the URL parameter; in that case set this to `None`.
    pub scope: Option<&'a str>,
}

/// Error type for paste-code flow operations. Mirrors
/// [`DeviceFlowError`] in spirit but keeps a separate name so
/// callers see which flow surfaced the error.
#[derive(Debug, Error)]
pub enum PasteCodeError {
    #[error("invalid endpoint")]
    BadEndpoint,

    #[error("network error")]
    Network,

    #[error("TLS verification failed — {0}")]
    TlsTrustFailed(&'static str),

    #[error("server returned {status}")]
    ServerError { status: u16 },

    #[error("malformed response")]
    Decode,

    #[error("user denied authorization")]
    AccessDenied,

    #[error("authorization code expired or already used")]
    Expired,

    #[error("invalid client")]
    InvalidClient,

    #[error("invalid grant")]
    InvalidGrant,

    #[error("oauth error: {0}")]
    Other(String),
}

impl PasteCodeError {
    fn from_ureq_transport(err: &ureq::Error) -> Self {
        match tls_trust_hint(err) {
            Some(hint) => Self::TlsTrustFailed(hint),
            None => Self::Network,
        }
    }
}

/// PKCE-driven Authorization Code client.
///
/// Construction generates a fresh `code_verifier` from the OS RNG;
/// [`Self::authorize_url`] returns a URL whose `code_challenge` is
/// the base64url(sha256(verifier)) value of that verifier;
/// [`Self::exchange_code`] sends the verifier alongside the code the
/// user pasted back, completing the proof of possession.
pub struct PasteCodeFlow<'a> {
    cfg: PasteCodeConfig<'a>,
    code_verifier: String,
    agent: Agent,
}

impl<'a> PasteCodeFlow<'a> {
    pub fn new(cfg: PasteCodeConfig<'a>) -> Self {
        Self::with_verifier(cfg, generate_code_verifier())
    }

    /// Construct a flow with an externally supplied PKCE verifier.
    /// Used when the verifier must persist across two distinct
    /// invocations of the flow — e.g. the TUI generates the URL on
    /// the first tick, the operator pastes the code back several
    /// ticks later, and the exchange must use the same verifier
    /// that produced the original `code_challenge`.
    pub fn with_verifier(cfg: PasteCodeConfig<'a>, code_verifier: String) -> Self {
        let agent: Agent = build_agent(AgentOpts {
            http_status_as_error: Some(false),
            ..AgentOpts::with_global_timeout(30)
        });
        Self {
            cfg,
            code_verifier,
            agent,
        }
    }

    /// Read-only accessor for the PKCE verifier so callers can
    /// stash it across the gap between authorize-URL creation and
    /// the eventual code → tokens exchange. Treat the returned
    /// string as a short-lived secret: it is only valid until the
    /// exchange completes (or the consent times out).
    pub fn verifier(&self) -> &str {
        &self.code_verifier
    }

    /// Construct the authorize URL the user must open in a browser
    /// to approve access. The returned URL embeds the PKCE
    /// `code_challenge` derived from the locally generated
    /// verifier — `exchange_code` must be called on the same
    /// [`PasteCodeFlow`] instance, otherwise the verifier is lost.
    pub fn authorize_url(&self) -> String {
        let challenge = code_challenge_s256(&self.code_verifier);
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("client_id", self.cfg.client_id);
        serializer.append_pair("response_type", "code");
        serializer.append_pair("code_challenge", &challenge);
        serializer.append_pair("code_challenge_method", "S256");
        if let Some(scope) = self.cfg.scope {
            serializer.append_pair("scope", scope);
        }
        for (k, v) in self.cfg.authorize_extra {
            serializer.append_pair(k, v);
        }
        let query = serializer.finish();
        format!("{}?{}", self.cfg.authorize_endpoint, query)
    }

    /// Exchange the user-provided authorization code for tokens.
    pub fn exchange_code(&self, code: &str) -> Result<TokenResponse, PasteCodeError> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.cfg.client_id)
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("code_verifier", &self.code_verifier)
            .finish();
        let (status, bytes) = self.post_form(self.cfg.token_endpoint, body.into_bytes())?;
        if status == 200 {
            return serde_json::from_slice(&bytes).map_err(|_| PasteCodeError::Decode);
        }
        Err(parse_oauth_error(status, &bytes))
    }

    /// Refresh tokens using a stored `refresh_token`. Stateless wrt
    /// the PKCE `code_verifier` — fine to call on a fresh instance.
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, PasteCodeError> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.cfg.client_id)
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", refresh_token)
            .finish();
        let (status, bytes) = self.post_form(self.cfg.token_endpoint, body.into_bytes())?;
        if status == 200 {
            return serde_json::from_slice(&bytes).map_err(|_| PasteCodeError::Decode);
        }
        Err(parse_oauth_error(status, &bytes))
    }

    fn post_form(&self, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), PasteCodeError> {
        let req = Request::builder()
            .method("POST")
            .uri(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/json")
            .body(body)
            .map_err(|_| PasteCodeError::BadEndpoint)?;

        let resp = self.agent.run(req);
        let mut response = match resp {
            Ok(r) => r,
            Err(e) => return Err(PasteCodeError::from_ureq_transport(&e)),
        };
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .read_to_vec()
            .map_err(|_| PasteCodeError::Decode)?;
        Ok((status, bytes))
    }
}

impl fmt::Debug for PasteCodeFlow<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasteCodeFlow { <redacted> }")
    }
}

/// Map a paste-code error onto the device-flow error vocabulary so
/// providers that already key off [`DeviceFlowError`] can route
/// paste-code failures through the same downstream classifier.
impl From<PasteCodeError> for DeviceFlowError {
    fn from(value: PasteCodeError) -> Self {
        match value {
            PasteCodeError::BadEndpoint => DeviceFlowError::BadEndpoint,
            PasteCodeError::Network => DeviceFlowError::Network,
            PasteCodeError::TlsTrustFailed(hint) => DeviceFlowError::TlsTrustFailed(hint),
            PasteCodeError::ServerError { status } => DeviceFlowError::ServerError { status },
            PasteCodeError::Decode => DeviceFlowError::Decode,
            PasteCodeError::AccessDenied => DeviceFlowError::AccessDenied,
            PasteCodeError::Expired => DeviceFlowError::Expired,
            PasteCodeError::InvalidClient => DeviceFlowError::InvalidClient,
            PasteCodeError::InvalidGrant => DeviceFlowError::InvalidGrant,
            PasteCodeError::Other(s) => DeviceFlowError::Other(s),
        }
    }
}

#[derive(Deserialize)]
struct OAuthErrorBody {
    error: String,
    #[serde(default)]
    #[allow(dead_code)]
    error_description: Option<String>,
}

fn parse_oauth_error(status: u16, body: &[u8]) -> PasteCodeError {
    match serde_json::from_slice::<OAuthErrorBody>(body) {
        Ok(parsed) => match parsed.error.as_str() {
            "access_denied" => PasteCodeError::AccessDenied,
            "expired_token" | "invalid_request" => PasteCodeError::Expired,
            "invalid_client" => PasteCodeError::InvalidClient,
            "invalid_grant" => PasteCodeError::InvalidGrant,
            other => PasteCodeError::Other(other.to_string()),
        },
        Err(_) => PasteCodeError::ServerError { status },
    }
}

/// 32 random bytes encoded as base64url without padding → 43-char
/// ASCII string. RFC 7636 mandates 43–128 unreserved characters; 43
/// gives us 256 bits of entropy with the smallest URL footprint.
fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn code_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_verifier_is_43_chars_url_safe() {
        let v = generate_code_verifier();
        assert_eq!(v.len(), 43);
        // base64url uses `[A-Za-z0-9_-]`, no padding
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn challenge_matches_rfc_7636_test_vector() {
        // RFC 7636 §B Appendix B reference vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = code_challenge_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn authorize_url_includes_pkce_params_and_extras() {
        let cfg = PasteCodeConfig {
            authorize_endpoint: "https://example.com/oauth2/authorize",
            token_endpoint: "https://example.com/oauth2/token",
            client_id: "abc123",
            authorize_extra: &[("token_access_type", "offline")],
            scope: None,
        };
        let flow = PasteCodeFlow::new(cfg);
        let url = flow.authorize_url();
        assert!(url.starts_with("https://example.com/oauth2/authorize?"));
        assert!(url.contains("client_id=abc123"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("token_access_type=offline"));
        // No `redirect_uri` and no `scope` when not requested.
        assert!(!url.contains("redirect_uri"));
        assert!(!url.contains("scope="));
    }

    #[test]
    fn authorize_url_includes_scope_when_set() {
        let cfg = PasteCodeConfig {
            authorize_endpoint: "https://example.com/oauth2/authorize",
            token_endpoint: "https://example.com/oauth2/token",
            client_id: "abc123",
            authorize_extra: &[],
            scope: Some("files.read files.write"),
        };
        let url = PasteCodeFlow::new(cfg).authorize_url();
        // url-encoded space
        assert!(url.contains("scope=files.read+files.write") || url.contains("scope=files.read%20files.write"));
    }

    #[test]
    fn parses_terminal_errors() {
        assert!(matches!(
            parse_oauth_error(400, br#"{"error":"access_denied"}"#),
            PasteCodeError::AccessDenied
        ));
        assert!(matches!(
            parse_oauth_error(400, br#"{"error":"invalid_grant"}"#),
            PasteCodeError::InvalidGrant
        ));
        assert!(matches!(
            parse_oauth_error(401, br#"{"error":"invalid_client"}"#),
            PasteCodeError::InvalidClient
        ));
    }

    #[test]
    fn falls_back_to_server_error_on_non_json_body() {
        match parse_oauth_error(503, b"<html>upstream</html>") {
            PasteCodeError::ServerError { status } => assert_eq!(status, 503),
            _ => panic!("expected ServerError"),
        }
    }

    #[test]
    fn debug_redacts() {
        let cfg = PasteCodeConfig {
            authorize_endpoint: "x",
            token_endpoint: "x",
            client_id: "x",
            authorize_extra: &[],
            scope: None,
        };
        let flow = PasteCodeFlow::new(cfg);
        let d = format!("{flow:?}");
        assert!(!d.contains(&flow.code_verifier));
        assert!(d.contains("redacted"));
    }
}
