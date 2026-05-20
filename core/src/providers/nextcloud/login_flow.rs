use std::fmt;

use serde::Deserialize;
use thiserror::Error;
use ureq::Agent;
use ureq::http::Request;

use crate::http::tls_error::tls_trust_hint;
use crate::http::{AgentOpts, build_agent};

#[derive(Debug, Error)]
pub enum LoginFlowError {
    #[error("invalid server url")]
    BadUrl,

    #[error("network error")]
    Network,

    #[error("TLS verification failed — {0}")]
    TlsTrustFailed(&'static str),

    #[error("server returned {status}")]
    ServerError { status: u16 },

    #[error("malformed response from server")]
    Decode,
}

impl LoginFlowError {
    fn from_ureq_transport(err: &ureq::Error) -> Self {
        match tls_trust_hint(err) {
            Some(hint) => Self::TlsTrustFailed(hint),
            None => Self::Network,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct LoginFlowInit {
    pub poll: PollInfo,
    pub login: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PollInfo {
    pub token: String,
    pub endpoint: String,
}

#[derive(Clone, Deserialize)]
pub struct LoginFlowResult {
    pub server: String,
    #[serde(rename = "loginName")]
    pub login_name: String,
    #[serde(rename = "appPassword")]
    pub app_password: String,
}

impl fmt::Debug for LoginFlowResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginFlowResult { <redacted> }")
    }
}

pub struct LoginFlowClient {
    agent: Agent,
}

impl Default for LoginFlowClient {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginFlowClient {
    pub fn new() -> Self {
        let agent: Agent = build_agent(AgentOpts::with_global_timeout(30));
        Self { agent }
    }

    /// POST /index.php/login/v2 — kicks off the flow and returns the
    /// browser URL plus the polling token.
    pub fn initiate(&self, server_url: &str) -> Result<LoginFlowInit, LoginFlowError> {
        let trimmed = server_url.trim_end_matches('/');
        let init_url = format!("{trimmed}/index.php/login/v2");

        let req = Request::builder()
            .method("POST")
            .uri(init_url)
            .header("User-Agent", "zz-drop")
            .header("Content-Length", "0")
            .body(Vec::<u8>::new())
            .map_err(|_| LoginFlowError::BadUrl)?;

        let resp = self.agent.run(req);
        let mut response = match resp {
            Ok(r) if r.status().as_u16() == 200 => r,
            Ok(r) => {
                return Err(LoginFlowError::ServerError {
                    status: r.status().as_u16(),
                });
            }
            Err(ureq::Error::StatusCode(s)) => return Err(LoginFlowError::ServerError { status: s }),
            Err(e) => return Err(LoginFlowError::from_ureq_transport(&e)),
        };

        let body = response
            .body_mut()
            .read_to_vec()
            .map_err(|_| LoginFlowError::Decode)?;
        serde_json::from_slice(&body).map_err(|_| LoginFlowError::Decode)
    }

    /// Single poll. Returns:
    /// - `Ok(Some(result))` when the user completed the flow,
    /// - `Ok(None)` when not yet (server returns 404 in that case),
    /// - `Err(...)` for transport / decode errors.
    pub fn poll_once(
        &self,
        poll: &PollInfo,
    ) -> Result<Option<LoginFlowResult>, LoginFlowError> {
        let body = format!("token={}", poll.token).into_bytes();
        let req = Request::builder()
            .method("POST")
            .uri(&poll.endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", "zz-drop")
            .body(body)
            .map_err(|_| LoginFlowError::BadUrl)?;

        let resp = self.agent.run(req);
        match resp {
            Ok(mut r) if r.status().as_u16() == 200 => {
                let body = r
                    .body_mut()
                    .read_to_vec()
                    .map_err(|_| LoginFlowError::Decode)?;
                let result: LoginFlowResult =
                    serde_json::from_slice(&body).map_err(|_| LoginFlowError::Decode)?;
                Ok(Some(result))
            }
            Ok(r) if r.status().as_u16() == 404 => Ok(None),
            Ok(r) => Err(LoginFlowError::ServerError {
                status: r.status().as_u16(),
            }),
            Err(ureq::Error::StatusCode(404)) => Ok(None),
            Err(ureq::Error::StatusCode(s)) => Err(LoginFlowError::ServerError { status: s }),
            Err(_) => Err(LoginFlowError::Network),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_init_response() {
        let body = r#"{
            "poll": {
                "token": "abc123",
                "endpoint": "https://nc.example.org/index.php/login/v2/poll"
            },
            "login": "https://nc.example.org/index.php/login/v2/flow/sometoken"
        }"#;
        let init: LoginFlowInit = serde_json::from_str(body).unwrap();
        assert_eq!(init.poll.token, "abc123");
        assert!(init.login.contains("/flow/"));
    }

    #[test]
    fn parses_result_response_with_camelcase_fields() {
        let body = r#"{
            "server": "https://nc.example.org",
            "loginName": "alice",
            "appPassword": "topsecret-app-pw"
        }"#;
        let r: LoginFlowResult = serde_json::from_str(body).unwrap();
        assert_eq!(r.server, "https://nc.example.org");
        assert_eq!(r.login_name, "alice");
        assert_eq!(r.app_password, "topsecret-app-pw");
    }

    #[test]
    fn debug_redacts_login_flow_result() {
        let r = LoginFlowResult {
            server: "https://nc.example.org".into(),
            login_name: "alice".into(),
            app_password: "topsecret-canary".into(),
        };
        let d = format!("{r:?}");
        assert!(!d.contains("topsecret-canary"));
        assert!(!d.contains("alice"));
    }
}
