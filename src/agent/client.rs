use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use zz_drop_core::agent_proto::{
    AgentRequest, AgentResponse, EntryKindFilter, KekPayload, decode_response_body,
    encode_request_body, read_frame, write_frame,
};
use zz_drop_core::config::verify_private_dir;
use zz_drop_core::{PlainProfile, ProfileKek, ProfileSet};

use super::security::{check_peer_uid, current_euid, read_token_file};

#[derive(Debug)]
pub enum ClientError {
    SocketUnreachable(String),
    HandshakeFailed,
    Io(String),
    Encode(String),
    Decode(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketUnreachable(e) => write!(f, "agent unreachable: {e}"),
            Self::HandshakeFailed => write!(f, "handshake failed"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Encode(e) => write!(f, "encode: {e}"),
            Self::Decode(e) => write!(f, "decode: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

pub struct AgentClient {
    stream: UnixStream,
}

impl AgentClient {
    pub fn connect(socket: &Path, token_file: &Path) -> Result<Self, ClientError> {
        // Defend against a malicious agent squatting the socket path. On macOS
        // and XDG-less Linux the runtime dir lives under the world-writable
        // `/tmp`, so a different local user could pre-create it, drop a token
        // file and listen on the socket — then our `Unlock` would hand them the
        // KEK and the entire decrypted profile. Two checks before any secret
        // (the token, then the `Unlock` payload) leaves this process:
        //
        //   1. the runtime dir holding the socket + token must be a real
        //      directory owned by us with mode 0700 (no foreign pre-creation);
        //   2. the process accept()ing on the socket must run under our own UID
        //      (peer-cred check — the mirror of the agent's own check on us).
        //
        // A cross-UID attacker cannot run a process under our UID, so (2) makes
        // it impossible for a foreign agent to receive our secrets even if it
        // somehow controlled the path.
        if let Some(dir) = socket.parent() {
            verify_private_dir(dir, current_euid())
                .map_err(|e| ClientError::SocketUnreachable(e.to_string()))?;
        }

        let mut stream =
            UnixStream::connect(socket).map_err(|e| ClientError::SocketUnreachable(e.to_string()))?;

        check_peer_uid(&stream, current_euid()).map_err(|_| ClientError::HandshakeFailed)?;

        let token = read_token_file(token_file).map_err(|_| ClientError::HandshakeFailed)?;
        write_frame(&mut stream, &token).map_err(|_| ClientError::HandshakeFailed)?;

        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        Ok(Self { stream })
    }

    pub fn request(&mut self, req: &AgentRequest) -> Result<AgentResponse, ClientError> {
        let body = encode_request_body(req).map_err(|e| ClientError::Encode(e.to_string()))?;
        write_frame(&mut self.stream, &body).map_err(|e| ClientError::Io(e.to_string()))?;
        self.stream.flush().ok();

        let resp_body = read_frame(&mut self.stream).map_err(|e| ClientError::Io(e.to_string()))?;
        decode_response_body(&resp_body).map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn ping(&mut self) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::Ping)
    }

    pub fn unlock(
        &mut self,
        profile_set: ProfileSet,
        kek: &ProfileKek,
        active_alias: &str,
        ttl_secs: Option<u64>,
    ) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::Unlock {
            profile_set,
            kek: KekPayload::from_kek(kek),
            active_alias: active_alias.to_string(),
            ttl_secs,
        })
    }

    pub fn get_profile(&mut self) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::GetProfile)
    }

    pub fn update_profile(
        &mut self,
        profile: PlainProfile,
    ) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::UpdateProfile { profile })
    }

    pub fn update_profile_set(
        &mut self,
        profile_set: ProfileSet,
    ) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::UpdateProfileSet { profile_set })
    }

    pub fn set_active_alias(&mut self, alias: &str) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::SetActiveAlias {
            alias: alias.to_string(),
        })
    }

    pub fn lock(&mut self) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::Lock)
    }

    pub fn exit(&mut self) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::Exit)
    }

    pub fn status(&mut self) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::Status)
    }

    /// SACS: list a remote directory through the agent's cache.
    /// Caller is the shell completion script via `zz __complete`.
    pub fn list_remote(
        &mut self,
        prefix: Option<&str>,
        kind_filter: EntryKindFilter,
        max_results: u32,
    ) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::ListRemote {
            prefix: prefix.map(String::from),
            kind_filter,
            max_results,
        })
    }

    /// SACS: invalidate cached list entries for `prefix` and every
    /// parent up to root. Called by the CLI after a successful
    /// upload so the next completion sees the fresh state.
    pub fn invalidate_remote(
        &mut self,
        prefix: Option<&str>,
    ) -> Result<AgentResponse, ClientError> {
        self.request(&AgentRequest::InvalidateRemote {
            prefix: prefix.map(String::from),
        })
    }
}
