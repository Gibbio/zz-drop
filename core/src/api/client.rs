//! Synchronous HTTP client for the zz-drop API v1.
//!
//! Used by both `zz-drop` (CLI) and `zz-drop-tui` (setup UI). Ureq is
//! the chosen transport — same crate the WebDAV client already uses, so
//! TLS / DNS / runtime is single-versioned in the binaries.
//!
//! The client is **synchronous**. Both consumers run their own event
//! loop and call into the API at well-defined moments (login, push,
//! pull); there is no benefit to dragging in an async runtime.
//!
//! Privacy / security:
//! - The bearer token is never logged.
//! - Password and TOTP code are passed by value to a single function;
//!   neither lives on the struct.
//! - `Debug` for `ApiClient` is custom and skips the token.

use std::time::Duration;

use thiserror::Error;
use ureq::Agent;
use ureq::http::Request;

use crate::api::{
    ApiErrorBody, ApiErrorCode, BASE_PATH, CreateProfileRequest, LoginRequest, LoginResponse,
    LoginTotpChallenge, ProfileList, ProfileSummary, RegisterRequest, TotpDisableRequest,
    TotpEnrollResponse, TotpLoginRequest, TotpVerifyRequest,
};
use crate::http::tls_error::transport_message;
use crate::http::{AgentOpts, build_agent};

/// Result of `POST /auth/login`. Either an immediate session (TOTP off
/// for the account) or a short-lived challenge that must be exchanged
/// for a session via [`ApiClient::login_totp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    Session(LoginResponse),
    TotpRequired(LoginTotpChallenge),
}

#[derive(Debug, Error)]
pub enum ApiClientError {
    #[error("network: {0}")]
    Network(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("api: {0:?} — {1}")]
    Api(ApiErrorCode, String),
    #[error("missing session token")]
    NoToken,
}

/// Synchronous client for one server / one optional session.
pub struct ApiClient {
    base: String,
    agent: Agent,
    token: Option<String>,
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("base", &self.base)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl ApiClient {
    /// `base_url` is the server root, *without* `/api/v1`. The client
    /// joins the base path itself so callers don't have to remember.
    pub fn new(base_url: impl Into<String>) -> Self {
        // `http_status_as_error(false)` lets us read the JSON error
        // body returned by the server on non-2xx responses; without it
        // ureq raises a `Status` error before the body is delivered.
        // DNS + TCP connect fail fast (5s) so an unreachable server
        // surfaces a "network error" within seconds instead of
        // letting the TUI sit on a "logging in…" footer for the
        // full 30s global timeout. The global cap stays 30s to
        // give blob upload / download enough headroom.
        let agent: Agent = build_agent(AgentOpts {
            timeout_resolve: Some(Duration::from_secs(5)),
            timeout_connect: Some(Duration::from_secs(5)),
            timeout_global: Some(Duration::from_secs(30)),
            http_status_as_error: Some(false),
            ..AgentOpts::default()
        });
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            agent,
            token: None,
        }
    }

    /// Attach a session token. The client will include it as
    /// `Authorization: Bearer <token>` on every authenticated request.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    fn url(&self, path: &str) -> String {
        format!("{base}{base_path}{path}", base = self.base, base_path = BASE_PATH)
    }

    fn auth_header(&self) -> Result<String, ApiClientError> {
        let t = self.token.as_ref().ok_or(ApiClientError::NoToken)?;
        Ok(format!("Bearer {t}"))
    }

    // ── auth ────────────────────────────────────────────────────────

    /// `POST /auth/register`. Returns `()` on success (server responds
    /// 201 No Content). The password is consumed and not retained.
    pub fn register(&self, email: &str, password: &str) -> Result<(), ApiClientError> {
        let body = serde_json::to_vec(&RegisterRequest {
            email: email.to_string(),
            password: password.to_string(),
        })
        .map_err(|e| ApiClientError::Decode(e.to_string()))?;
        let req = Request::builder()
            .method("POST")
            .uri(self.url("/auth/register"))
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        require_2xx(resp).map(|_| ())
    }

    /// `POST /auth/login`. Returns either an immediate session or a
    /// challenge to be exchanged via [`Self::login_totp`].
    pub fn login(&self, email: &str, password: &str) -> Result<LoginOutcome, ApiClientError> {
        let body = serde_json::to_vec(&LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        })
        .map_err(|e| ApiClientError::Decode(e.to_string()))?;
        let req = Request::builder()
            .method("POST")
            .uri(self.url("/auth/login"))
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        let raw = read_body_2xx(resp)?;
        // Discriminate by presence of `totp_required`. The two payloads
        // are disjoint so a peek at the JSON is enough.
        let v: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| ApiClientError::Decode(e.to_string()))?;
        if v.get("totp_required").is_some() {
            let c: LoginTotpChallenge =
                serde_json::from_value(v).map_err(|e| ApiClientError::Decode(e.to_string()))?;
            Ok(LoginOutcome::TotpRequired(c))
        } else {
            let r: LoginResponse =
                serde_json::from_value(v).map_err(|e| ApiClientError::Decode(e.to_string()))?;
            Ok(LoginOutcome::Session(r))
        }
    }

    /// `POST /auth/totp/login`. Step 2 of the two-step login: exchange
    /// a challenge + 6-digit code (or a recovery code) for a session.
    pub fn login_totp(
        &self,
        challenge: &str,
        code: &str,
    ) -> Result<LoginResponse, ApiClientError> {
        let body = serde_json::to_vec(&TotpLoginRequest {
            challenge: challenge.to_string(),
            code: code.to_string(),
        })
        .map_err(|e| ApiClientError::Decode(e.to_string()))?;
        let req = Request::builder()
            .method("POST")
            .uri(self.url("/auth/totp/login"))
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        let raw = read_body_2xx(resp)?;
        serde_json::from_slice(&raw).map_err(|e| ApiClientError::Decode(e.to_string()))
    }

    // ── profiles ────────────────────────────────────────────────────

    /// `GET /profiles` — list aliases.
    pub fn list_profiles(&self) -> Result<ProfileList, ApiClientError> {
        let req = Request::builder()
            .method("GET")
            .uri(self.url("/profiles"))
            .header("Authorization", self.auth_header()?)
            .body(Vec::<u8>::new())
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        let raw = read_body_2xx(resp)?;
        serde_json::from_slice(&raw).map_err(|e| ApiClientError::Decode(e.to_string()))
    }

    /// `POST /profiles` — create an alias.
    pub fn create_profile(&self, alias: &str) -> Result<ProfileSummary, ApiClientError> {
        let body = serde_json::to_vec(&CreateProfileRequest {
            alias: crate::api::Alias::new(alias)
                .map_err(|e| ApiClientError::Decode(e.to_string()))?,
        })
        .map_err(|e| ApiClientError::Decode(e.to_string()))?;
        let req = Request::builder()
            .method("POST")
            .uri(self.url("/profiles"))
            .header("Authorization", self.auth_header()?)
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        let raw = read_body_2xx(resp)?;
        serde_json::from_slice(&raw).map_err(|e| ApiClientError::Decode(e.to_string()))
    }

    /// `GET /profiles/{alias}/blob` — download the encrypted blob.
    pub fn get_blob(&self, alias: &str) -> Result<Vec<u8>, ApiClientError> {
        let req = Request::builder()
            .method("GET")
            .uri(self.url(&format!("/profiles/{alias}/blob")))
            .header("Authorization", self.auth_header()?)
            .body(Vec::<u8>::new())
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        read_body_2xx(resp)
    }

    /// `PUT /profiles/{alias}/blob?expected_version=N` — upload a blob.
    pub fn put_blob(
        &self,
        alias: &str,
        expected_version: u64,
        body: Vec<u8>,
    ) -> Result<ProfileSummary, ApiClientError> {
        let req = Request::builder()
            .method("PUT")
            .uri(self.url(&format!(
                "/profiles/{alias}/blob?expected_version={expected_version}"
            )))
            .header("Authorization", self.auth_header()?)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        let raw = read_body_2xx(resp)?;
        serde_json::from_slice(&raw).map_err(|e| ApiClientError::Decode(e.to_string()))
    }

    /// `DELETE /profiles/{alias}` — remove the alias + blob.
    pub fn delete_profile(&self, alias: &str) -> Result<(), ApiClientError> {
        let req = Request::builder()
            .method("DELETE")
            .uri(self.url(&format!("/profiles/{alias}")))
            .header("Authorization", self.auth_header()?)
            .body(Vec::<u8>::new())
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        require_2xx(resp).map(|_| ())
    }

    // ── totp (consume only) ─────────────────────────────────────────

    /// `POST /auth/totp/enroll`. Reference implementation only — the
    /// CLI/TUI v1 are not supposed to call this (enrollment lives in
    /// the web dashboard). Kept here so an admin tool / test can still
    /// drive the full flow.
    pub fn enroll_totp(&self) -> Result<TotpEnrollResponse, ApiClientError> {
        let req = Request::builder()
            .method("POST")
            .uri(self.url("/auth/totp/enroll"))
            .header("Authorization", self.auth_header()?)
            .header("Content-Type", "application/json")
            .body(b"{}".to_vec())
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        let raw = read_body_2xx(resp)?;
        serde_json::from_slice(&raw).map_err(|e| ApiClientError::Decode(e.to_string()))
    }

    /// `POST /auth/totp/verify` — activate a pending enrollment.
    pub fn verify_totp(&self, code: &str) -> Result<(), ApiClientError> {
        let body = serde_json::to_vec(&TotpVerifyRequest {
            code: code.to_string(),
        })
        .map_err(|e| ApiClientError::Decode(e.to_string()))?;
        let req = Request::builder()
            .method("POST")
            .uri(self.url("/auth/totp/verify"))
            .header("Authorization", self.auth_header()?)
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        require_2xx(resp).map(|_| ())
    }

    /// `POST /auth/totp/disable` — disable TOTP for the account.
    pub fn disable_totp(&self, password: &str, code: &str) -> Result<(), ApiClientError> {
        let body = serde_json::to_vec(&TotpDisableRequest {
            password: password.to_string(),
            code: code.to_string(),
        })
        .map_err(|e| ApiClientError::Decode(e.to_string()))?;
        let req = Request::builder()
            .method("POST")
            .uri(self.url("/auth/totp/disable"))
            .header("Authorization", self.auth_header()?)
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| ApiClientError::Transport(e.to_string()))?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| ApiClientError::Network(transport_message(&e)))?;
        require_2xx(resp).map(|_| ())
    }
}

// ── helpers ───────────────────────────────────────────────────────────

fn require_2xx(resp: ureq::http::Response<ureq::Body>) -> Result<(), ApiClientError> {
    let status = resp.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(());
    }
    let mut resp = resp;
    let bytes = resp
        .body_mut()
        .read_to_vec()
        .unwrap_or_default();
    map_error(status, &bytes)
}

fn read_body_2xx(resp: ureq::http::Response<ureq::Body>) -> Result<Vec<u8>, ApiClientError> {
    let status = resp.status().as_u16();
    let mut resp = resp;
    let bytes = resp
        .body_mut()
        .read_to_vec()
        .map_err(|e| ApiClientError::Network(e.to_string()))?;
    if (200..300).contains(&status) {
        Ok(bytes)
    } else {
        map_error::<Vec<u8>>(status, &bytes).map(|_| unreachable!())
    }
}

fn map_error<T>(status: u16, body: &[u8]) -> Result<T, ApiClientError> {
    if let Ok(api) = serde_json::from_slice::<ApiErrorBody>(body) {
        return Err(ApiClientError::Api(api.error, api.message));
    }
    let code = match status {
        400 => ApiErrorCode::InvalidRequest,
        401 => ApiErrorCode::Unauthorized,
        403 => ApiErrorCode::Forbidden,
        404 => ApiErrorCode::NotFound,
        409 => ApiErrorCode::VersionConflict,
        413 => ApiErrorCode::BlobTooLarge,
        429 => ApiErrorCode::RateLimited,
        _ => ApiErrorCode::ServerError,
    };
    Err(ApiClientError::Api(
        code,
        format!("HTTP {status} (no JSON error body)"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_token() {
        let c = ApiClient::new("https://example.org").with_token("super-secret-token");
        let s = format!("{c:?}");
        assert!(!s.contains("super-secret-token"), "got `{s}`");
        assert!(s.contains("redacted"), "got `{s}`");
    }

    #[test]
    fn url_concatenation_strips_trailing_slash() {
        let c = ApiClient::new("https://example.org/");
        assert_eq!(c.url("/info"), "https://example.org/api/v1/info");
        let c = ApiClient::new("https://example.org");
        assert_eq!(c.url("/info"), "https://example.org/api/v1/info");
    }

    #[test]
    fn no_token_means_auth_header_errors() {
        let c = ApiClient::new("https://example.org");
        assert!(matches!(c.auth_header(), Err(ApiClientError::NoToken)));
    }

    #[test]
    fn auth_header_format_when_token_set() {
        let c = ApiClient::new("https://example.org").with_token("abc.123");
        assert_eq!(c.auth_header().unwrap(), "Bearer abc.123");
    }
}
