//! OAuth 2.0 Device Authorization Grant client (RFC 8628).
//!
//! Used by providers whose setup happens inside the TUI without a local
//! browser available. The user reads a short `user_code` from the TUI,
//! opens `verification_uri` on any device with a browser, types the
//! code, and the TUI polls until the access/refresh token pair is
//! issued.
//!
//! The transport stays on the project-wide synchronous `ureq` stack,
//! so the response body is read manually even on non-2xx, in order to
//! decode the OAuth error JSON the spec mandates on `400`.

use std::fmt;

use serde::Deserialize;
use thiserror::Error;
use ureq::Agent;
use ureq::http::Request;
use url::form_urlencoded;

use crate::http::tls_error::tls_trust_hint;
use crate::http::{AgentOpts, build_agent};

const USER_AGENT: &str = "zz-drop";
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Error)]
pub enum DeviceFlowError {
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

    #[error("device code expired")]
    Expired,

    #[error("invalid client")]
    InvalidClient,

    #[error("invalid grant")]
    InvalidGrant,

    #[error("oauth error: {0}")]
    Other(String),
}

impl DeviceFlowError {
    fn from_ureq_transport(err: &ureq::Error) -> Self {
        match tls_trust_hint(err) {
            Some(hint) => Self::TlsTrustFailed(hint),
            None => Self::Network,
        }
    }
}

/// Inputs to a device flow exchange. Endpoint URLs and credentials are
/// borrowed: a single `DeviceFlowClient` is short-lived and never
/// outlives the profile setup screen.
#[derive(Clone, Debug)]
pub struct DeviceFlowConfig<'a> {
    pub device_code_endpoint: &'a str,
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    /// Some providers (Google for "TVs and Limited Input devices",
    /// Microsoft for confidential clients) require a client secret on
    /// the token request even though the secret is, for installed
    /// apps, not a real secret. Others use PKCE only and leave this
    /// `None`.
    pub client_secret: Option<&'a str>,
    pub scope: &'a str,
}

/// Successful response from the `device_authorization` endpoint.
#[derive(Clone, Deserialize)]
pub struct DeviceCodeResponse {
    /// Opaque code the client uses to poll the token endpoint.
    /// Treated as a short-lived secret: redacted in `Debug`.
    pub device_code: String,
    /// Short code shown to the user to type into the verification
    /// page on a second device.
    pub user_code: String,
    /// Verification URL the user opens. RFC 8628 names this field
    /// `verification_uri`; Google calls it `verification_url`.
    #[serde(alias = "verification_url")]
    pub verification_uri: String,
    /// Optional URL with the `user_code` already embedded — useful
    /// for QR codes.
    #[serde(default)]
    #[serde(alias = "verification_url_complete")]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    DEFAULT_POLL_INTERVAL_SECS
}

impl fmt::Debug for DeviceCodeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCodeResponse")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// Successful response from the token endpoint.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub token_type: String,
    #[serde(default)]
    pub scope: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenResponse { <redacted> }")
    }
}

/// Outcome of a single token-endpoint poll.
#[derive(Debug)]
pub enum PollOutcome {
    /// User has not yet completed the verification step. Caller should
    /// wait and poll again.
    Pending,
    /// Server asked for a slower polling cadence (RFC 8628 §3.5).
    /// Caller should add 5s to its current interval before polling
    /// again.
    SlowDown,
    /// User completed verification; tokens issued.
    Tokens(TokenResponse),
}

pub struct DeviceFlowClient<'a> {
    cfg: DeviceFlowConfig<'a>,
    agent: Agent,
}

impl<'a> DeviceFlowClient<'a> {
    pub fn new(cfg: DeviceFlowConfig<'a>) -> Self {
        // `http_status_as_error(false)` lets us read the body on 4xx
        // responses, which is required to decode the OAuth error JSON.
        let agent: Agent = build_agent(AgentOpts {
            http_status_as_error: Some(false),
            ..AgentOpts::with_global_timeout(30)
        });
        Self { cfg, agent }
    }

    /// POST to the `device_authorization` endpoint to start the flow.
    pub fn initiate(&self) -> Result<DeviceCodeResponse, DeviceFlowError> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.cfg.client_id)
            .append_pair("scope", self.cfg.scope)
            .finish();

        let body_bytes = body.into_bytes();
        let (status, body_bytes) = self.post_form(self.cfg.device_code_endpoint, body_bytes)?;

        if status == 200 {
            serde_json::from_slice(&body_bytes).map_err(|_| DeviceFlowError::Decode)
        } else {
            Err(parse_oauth_error(status, &body_bytes))
        }
    }

    /// Poll the token endpoint once with the user's `device_code`.
    pub fn poll_once(&self, device_code: &str) -> Result<PollOutcome, DeviceFlowError> {
        let body = self.token_form(&[
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ]);
        let (status, body_bytes) = self.post_form(self.cfg.token_endpoint, body)?;

        if status == 200 {
            let tokens: TokenResponse =
                serde_json::from_slice(&body_bytes).map_err(|_| DeviceFlowError::Decode)?;
            return Ok(PollOutcome::Tokens(tokens));
        }

        match parse_oauth_error(status, &body_bytes) {
            DeviceFlowError::Other(code) if code == "authorization_pending" => {
                Ok(PollOutcome::Pending)
            }
            DeviceFlowError::Other(code) if code == "slow_down" => Ok(PollOutcome::SlowDown),
            other => Err(other),
        }
    }

    /// Exchange a `refresh_token` for a fresh access token.
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, DeviceFlowError> {
        let body = self.token_form(&[
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ]);
        let (status, body_bytes) = self.post_form(self.cfg.token_endpoint, body)?;

        if status == 200 {
            serde_json::from_slice(&body_bytes).map_err(|_| DeviceFlowError::Decode)
        } else {
            Err(parse_oauth_error(status, &body_bytes))
        }
    }

    fn token_form(&self, extra: &[(&str, &str)]) -> Vec<u8> {
        let mut s = form_urlencoded::Serializer::new(String::new());
        s.append_pair("client_id", self.cfg.client_id);
        if let Some(secret) = self.cfg.client_secret {
            s.append_pair("client_secret", secret);
        }
        for (k, v) in extra {
            s.append_pair(k, v);
        }
        s.finish().into_bytes()
    }

    fn post_form(&self, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), DeviceFlowError> {
        let req = Request::builder()
            .method("POST")
            .uri(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/json")
            .body(body)
            .map_err(|_| DeviceFlowError::BadEndpoint)?;

        let resp = self.agent.run(req);
        let mut response = match resp {
            Ok(r) => r,
            Err(e) => return Err(DeviceFlowError::from_ureq_transport(&e)),
        };
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .read_to_vec()
            .map_err(|_| DeviceFlowError::Decode)?;
        Ok((status, bytes))
    }
}

#[derive(Deserialize)]
struct OAuthErrorBody {
    error: String,
    #[serde(default)]
    #[allow(dead_code)]
    error_description: Option<String>,
}

fn parse_oauth_error(status: u16, body: &[u8]) -> DeviceFlowError {
    match serde_json::from_slice::<OAuthErrorBody>(body) {
        Ok(parsed) => match parsed.error.as_str() {
            "access_denied" => DeviceFlowError::AccessDenied,
            "expired_token" => DeviceFlowError::Expired,
            "invalid_client" => DeviceFlowError::InvalidClient,
            "invalid_grant" => DeviceFlowError::InvalidGrant,
            // `authorization_pending` and `slow_down` are not real
            // errors during a poll — caller maps them via PollOutcome.
            other => DeviceFlowError::Other(other.to_string()),
        },
        Err(_) => DeviceFlowError::ServerError { status },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_device_code_google_shape() {
        let body = r#"{
            "device_code": "AH-1Ng0_DEVCODE",
            "user_code": "ABCD-EFGH",
            "verification_url": "https://www.google.com/device",
            "expires_in": 1800,
            "interval": 5
        }"#;
        let r: DeviceCodeResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.user_code, "ABCD-EFGH");
        assert_eq!(r.verification_uri, "https://www.google.com/device");
        assert_eq!(r.expires_in, 1800);
        assert_eq!(r.interval, 5);
    }

    #[test]
    fn parses_device_code_rfc_shape_with_complete_uri() {
        let body = r#"{
            "device_code": "DEVCODE",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 600
        }"#;
        let r: DeviceCodeResponse = serde_json::from_str(body).unwrap();
        assert!(r.verification_uri_complete.unwrap().contains("WDJB-MJHT"));
        assert_eq!(r.interval, 5, "default interval applied when missing");
    }

    #[test]
    fn debug_redacts_device_code_but_keeps_user_facing_fields() {
        let body = r#"{
            "device_code": "SECRET-CANARY",
            "user_code": "ABCD-EFGH",
            "verification_url": "https://www.google.com/device",
            "expires_in": 1800
        }"#;
        let r: DeviceCodeResponse = serde_json::from_str(body).unwrap();
        let d = format!("{r:?}");
        assert!(!d.contains("SECRET-CANARY"));
        assert!(d.contains("ABCD-EFGH"));
        assert!(d.contains("redacted"));
    }

    #[test]
    fn parses_token_response() {
        let body = r#"{
            "access_token": "ya29.AT-CANARY",
            "refresh_token": "1//RT-CANARY",
            "expires_in": 3599,
            "token_type": "Bearer",
            "scope": "https://www.googleapis.com/auth/drive.file"
        }"#;
        let t: TokenResponse = serde_json::from_str(body).unwrap();
        assert_eq!(t.expires_in, 3599);
        assert_eq!(t.token_type, "Bearer");
        assert!(t.refresh_token.is_some());
    }

    #[test]
    fn debug_fully_redacts_token_response() {
        let t = TokenResponse {
            access_token: "AT-CANARY".into(),
            refresh_token: Some("RT-CANARY".into()),
            expires_in: 3600,
            token_type: "Bearer".into(),
            scope: None,
        };
        let d = format!("{t:?}");
        assert!(!d.contains("AT-CANARY"));
        assert!(!d.contains("RT-CANARY"));
        assert!(d.contains("redacted"));
    }

    #[test]
    fn parses_pending_and_slow_down_errors() {
        let pending = br#"{"error":"authorization_pending"}"#;
        match parse_oauth_error(400, pending) {
            DeviceFlowError::Other(s) => assert_eq!(s, "authorization_pending"),
            _ => panic!("expected Other(authorization_pending)"),
        }

        let slow = br#"{"error":"slow_down","error_description":"slow down"}"#;
        match parse_oauth_error(400, slow) {
            DeviceFlowError::Other(s) => assert_eq!(s, "slow_down"),
            _ => panic!("expected Other(slow_down)"),
        }
    }

    #[test]
    fn parses_terminal_errors() {
        assert!(matches!(
            parse_oauth_error(400, br#"{"error":"access_denied"}"#),
            DeviceFlowError::AccessDenied
        ));
        assert!(matches!(
            parse_oauth_error(400, br#"{"error":"expired_token"}"#),
            DeviceFlowError::Expired
        ));
        assert!(matches!(
            parse_oauth_error(401, br#"{"error":"invalid_client"}"#),
            DeviceFlowError::InvalidClient
        ));
        assert!(matches!(
            parse_oauth_error(400, br#"{"error":"invalid_grant"}"#),
            DeviceFlowError::InvalidGrant
        ));
    }

    #[test]
    fn falls_back_to_server_error_on_non_json_body() {
        match parse_oauth_error(503, b"<html>upstream</html>") {
            DeviceFlowError::ServerError { status } => assert_eq!(status, 503),
            _ => panic!("expected ServerError"),
        }
    }
}
