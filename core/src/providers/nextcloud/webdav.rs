use base64::{Engine, engine::general_purpose::STANDARD as B64};
use thiserror::Error;
use ureq::Agent;
use ureq::http::Request;

use crate::http::tls_error::transport_message;
use crate::http::{AgentOpts, build_agent};

#[derive(Debug, Error)]
pub enum WebDavError {
    #[error("auth failed")]
    Unauthorized,

    #[error("not found")]
    NotFound,

    #[error("conflict")]
    Conflict,

    #[error("server error: {status}")]
    ServerError { status: u16 },

    #[error("transport error: {0}")]
    Transport(String),

    #[error("unexpected status: {status}")]
    UnexpectedStatus { status: u16 },

    #[error("io error")]
    Io,

    #[error("xml parse error")]
    XmlParse,
}

#[derive(Clone, Debug)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

impl BasicAuth {
    pub fn header_value(&self) -> String {
        let raw = format!("{}:{}", self.username, self.password);
        format!("Basic {}", B64.encode(raw))
    }
}

pub struct WebDavClient {
    auth: BasicAuth,
    agent: Agent,
}

impl WebDavClient {
    pub fn new(auth: BasicAuth) -> Self {
        // `allow_non_standard_methods` is required for WebDAV verbs:
        // ureq-proto 0.6 only whitelists GET/HEAD/POST/PUT/DELETE/CONNECT/
        // OPTIONS/TRACE/PATCH for HTTP/1.1 and rejects MKCOL, PROPFIND,
        // PROPPATCH, COPY, MOVE, LOCK, UNLOCK with `MethodVersionMismatch`
        // ("MKCOL not valid for HTTP version HTTP/1.1"). The flag bypasses
        // that check; it does not weaken TLS, auth, or any other validation.
        let agent: Agent = build_agent(AgentOpts {
            allow_non_standard_methods: true,
            ..AgentOpts::with_global_timeout(30)
        });
        Self { auth, agent }
    }

    pub fn put(&self, url: &str, body: Vec<u8>) -> Result<(), WebDavError> {
        let req = Request::builder()
            .method("PUT")
            .uri(url)
            .header("Authorization", self.auth.header_value())
            .body(body)
            .map_err(|e| WebDavError::Transport(format!("{e}")))?;
        let resp = self.agent.run(req);
        check_2xx_unit(resp)?;
        Ok(())
    }

    pub fn get(&self, url: &str) -> Result<Vec<u8>, WebDavError> {
        let req = Request::builder()
            .method("GET")
            .uri(url)
            .header("Authorization", self.auth.header_value())
            .body(Vec::<u8>::new())
            .map_err(|e| WebDavError::Transport(format!("{e}")))?;
        let resp = self.agent.run(req);
        let mut response = check_2xx(resp)?;
        response
            .body_mut()
            .read_to_vec()
            .map_err(|_| WebDavError::Io)
    }

    pub fn mkcol(&self, url: &str) -> Result<(), WebDavError> {
        let req = Request::builder()
            .method("MKCOL")
            .uri(url)
            .header("Authorization", self.auth.header_value())
            .body(Vec::<u8>::new())
            .map_err(|e| WebDavError::Transport(format!("{e}")))?;
        let resp = self.agent.run(req);
        match map_status(resp) {
            Ok(s) if s == 201 => Ok(()),
            Ok(s) => Err(WebDavError::UnexpectedStatus { status: s }),
            Err(WebDavError::UnexpectedStatus { status: 405 }) => Err(WebDavError::Conflict),
            Err(e) => Err(e),
        }
    }

    pub fn propfind(&self, url: &str, depth: &str) -> Result<String, WebDavError> {
        let body: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname/>
    <d:getcontentlength/>
    <d:resourcetype/>
  </d:prop>
</d:propfind>"#;

        let req = Request::builder()
            .method("PROPFIND")
            .uri(url)
            .header("Authorization", self.auth.header_value())
            .header("Depth", depth)
            .header("Content-Type", "application/xml")
            .body(body.to_vec())
            .map_err(|e| WebDavError::Transport(format!("{e}")))?;
        let resp = self.agent.run(req);

        let mut response = match map_status(resp) {
            Ok(207) => {
                // re-run to get the actual response: map_status consumed it.
                // Re-issue the request because the first response was consumed.
                let req2 = Request::builder()
                    .method("PROPFIND")
                    .uri(url)
                    .header("Authorization", self.auth.header_value())
                    .header("Depth", depth)
                    .header("Content-Type", "application/xml")
                    .body(body.to_vec())
                    .map_err(|e| WebDavError::Transport(format!("{e}")))?;
                self.agent
                    .run(req2)
                    .map_err(|e| WebDavError::Transport(format!("{e}")))?
            }
            Ok(s) => return Err(WebDavError::UnexpectedStatus { status: s }),
            Err(e) => return Err(e),
        };

        response
            .body_mut()
            .read_to_string()
            .map_err(|_| WebDavError::Io)
    }

    pub fn head(&self, url: &str) -> Result<bool, WebDavError> {
        let req = Request::builder()
            .method("HEAD")
            .uri(url)
            .header("Authorization", self.auth.header_value())
            .body(Vec::<u8>::new())
            .map_err(|e| WebDavError::Transport(format!("{e}")))?;
        let resp = self.agent.run(req);
        match map_status(resp) {
            Ok(_) => Ok(true),
            Err(WebDavError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn delete(&self, url: &str) -> Result<(), WebDavError> {
        let req = Request::builder()
            .method("DELETE")
            .uri(url)
            .header("Authorization", self.auth.header_value())
            .body(Vec::<u8>::new())
            .map_err(|e| WebDavError::Transport(format!("{e}")))?;
        let resp = self.agent.run(req);
        check_2xx_unit(resp)?;
        Ok(())
    }
}

type UreqRunResult =
    Result<ureq::http::Response<ureq::Body>, ureq::Error>;

fn map_status(resp: UreqRunResult) -> Result<u16, WebDavError> {
    match resp {
        Ok(r) => {
            let s = r.status().as_u16();
            if (200..=299).contains(&s) {
                Ok(s)
            } else {
                Err(classify(s))
            }
        }
        Err(ureq::Error::StatusCode(s)) => Err(classify(s)),
        Err(e) => Err(WebDavError::Transport(transport_message(&e))),
    }
}

fn check_2xx(resp: UreqRunResult) -> Result<ureq::http::Response<ureq::Body>, WebDavError> {
    match resp {
        Ok(r) => {
            let s = r.status().as_u16();
            if (200..=299).contains(&s) {
                Ok(r)
            } else {
                Err(classify(s))
            }
        }
        Err(ureq::Error::StatusCode(s)) => Err(classify(s)),
        Err(e) => Err(WebDavError::Transport(transport_message(&e))),
    }
}

fn check_2xx_unit(resp: UreqRunResult) -> Result<(), WebDavError> {
    let _ = check_2xx(resp)?;
    Ok(())
}

fn classify(status: u16) -> WebDavError {
    match status {
        401 | 403 => WebDavError::Unauthorized,
        404 => WebDavError::NotFound,
        409 => WebDavError::Conflict,
        500..=599 => WebDavError::ServerError { status },
        _ => WebDavError::UnexpectedStatus { status },
    }
}
