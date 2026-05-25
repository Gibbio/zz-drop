use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use zz_drop_core::agent_proto::{
    AgentRequest, AgentResponse, decode_request_body, encode_response_body, read_frame,
    write_frame,
};
use zz_drop_core::config::{Paths, ensure_dir, verify_private_dir};

use super::security::{
    TOKEN_LEN, check_peer_uid, current_euid, generate_token, token_matches, write_token_file,
};
use super::state::{AgentState, ListError};

pub const DEFAULT_TTL_SECS: u64 = 600;
pub const DEFAULT_IDLE_EXIT_SECS: u64 = 300;
pub const POLL_INTERVAL_MS: u64 = 100;

#[derive(Debug)]
pub enum ServerError {
    Io(String),
    Bind(String),
    Security(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Bind(e) => write!(f, "bind: {e}"),
            Self::Security(e) => write!(f, "security: {e}"),
        }
    }
}

impl std::error::Error for ServerError {}

pub struct ServerConfig {
    pub paths: Paths,
    pub ttl: Duration,
    pub idle_exit: Duration,
    pub poll_interval: Duration,
    /// If true, run setsid() to detach from the parent session. Set
    /// false in tests where we run the server in a thread of the test
    /// process.
    pub detach: bool,
}

impl ServerConfig {
    pub fn default_with_paths(paths: Paths) -> Self {
        Self {
            paths,
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            idle_exit: Duration::from_secs(DEFAULT_IDLE_EXIT_SECS),
            poll_interval: Duration::from_millis(POLL_INTERVAL_MS),
            detach: true,
        }
    }
}

pub fn run(config: ServerConfig) -> Result<(), ServerError> {
    if config.detach {
        let _ = rustix::process::setsid();
    }

    ensure_dir(&config.paths.runtime_dir, 0o700).map_err(|e| ServerError::Io(e.to_string()))?;
    // The runtime dir holds the socket + token. On macOS / XDG-less Linux it
    // lives under the world-writable `/tmp`; refuse to bind if it is not a real
    // directory owned by us with mode 0700 (another local user must not be able
    // to pre-create it and observe or hijack the socket/token).
    verify_private_dir(&config.paths.runtime_dir, current_euid())
        .map_err(|e| ServerError::Security(e.to_string()))?;
    ensure_dir(&config.paths.cache_dir, 0o700).map_err(|e| ServerError::Io(e.to_string()))?;

    zz_drop_core::diag_log::init(config.paths.debug_log_file(), "zz-agent");
    zz_drop_core::diag_log::log(&format!(
        "startup container={} ttl_secs={} idle_exit_secs={} build_id={}",
        config.paths.profiles_local_file.display(),
        config.ttl.as_secs(),
        config.idle_exit.as_secs(),
        super::lock::current_build_id().unwrap_or_else(|| "unknown".into()),
    ));

    if config.paths.agent_socket.exists() {
        std::fs::remove_file(&config.paths.agent_socket)
            .map_err(|e| ServerError::Io(e.to_string()))?;
    }

    let listener = UnixListener::bind(&config.paths.agent_socket)
        .map_err(|e| ServerError::Bind(e.to_string()))?;
    // Tighten the socket to 0600. The runtime dir is already 0700 and
    // verified ours (D1), so this is defense in depth (F4).
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &config.paths.agent_socket,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    listener
        .set_nonblocking(true)
        .map_err(|e| ServerError::Io(e.to_string()))?;

    let token = generate_token();
    write_token_file(&config.paths.token_file, &token)
        .map_err(|e| ServerError::Security(e.to_string()))?;

    // Write the build-aware lock file. Future clients compare the
    // recorded `build_id` to their own and SIGTERM us on mismatch.
    if let Some(build_id) = super::lock::current_build_id() {
        let pid = std::process::id();
        let _ = super::lock::write_lock(&config.paths.runtime_dir, pid, &build_id);
    }

    let state = Arc::new(AgentState::new(
        config.ttl,
        config.paths.profiles_local_file.clone(),
    ));
    let euid = current_euid();

    let exit_reason = loop {
        if state.should_exit() {
            break "exit_request";
        }

        state.check_ttl_and_lock();

        if !state.is_unlocked() && state.idle_for() > config.idle_exit {
            break "idle_exit";
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_connection(stream, &state, euid, &token);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(config.poll_interval);
            }
            Err(_e) => {
                std::thread::sleep(config.poll_interval);
            }
        }
    };

    zz_drop_core::diag_log::log(&format!("shutdown reason={exit_reason}"));

    let _ = std::fs::remove_file(&config.paths.agent_socket);
    let _ = std::fs::remove_file(&config.paths.token_file);
    super::lock::remove_lock(&config.paths.runtime_dir);
    Ok(())
}

#[derive(Debug)]
enum ConnError {
    Unauthorized,
    Io,
    Decode,
    Encode,
}

/// Short tag for the diag log: just the request discriminant —
/// never the contents (an `Unlock` payload contains the KEK and
/// the decoded container).
fn request_tag(req: &AgentRequest) -> &'static str {
    match req {
        AgentRequest::Ping => "ping",
        AgentRequest::Unlock { .. } => "unlock",
        AgentRequest::GetProfile => "get_profile",
        AgentRequest::UpdateProfile { .. } => "update_profile",
        AgentRequest::UpdateProfileSet { .. } => "update_profile_set",
        AgentRequest::SetActiveAlias { .. } => "set_active_alias",
        AgentRequest::ListRemote { .. } => "list_remote",
        AgentRequest::InvalidateRemote { .. } => "invalidate_remote",
        AgentRequest::Lock => "lock",
        AgentRequest::Exit => "exit",
        AgentRequest::Status => "status",
    }
}

fn handle_connection(
    mut stream: UnixStream,
    state: &Arc<AgentState>,
    expected_euid: u32,
    expected_token: &[u8; TOKEN_LEN],
) -> Result<(), ConnError> {
    // The listener is non-blocking; the accepted stream may inherit that
    // flag. Force blocking I/O for the request loop, otherwise read_frame
    // would WouldBlock immediately and we'd kill the connection after the
    // first request.
    stream
        .set_nonblocking(false)
        .map_err(|_| ConnError::Io)?;

    check_peer_uid(&stream, expected_euid).map_err(|_| ConnError::Unauthorized)?;

    let received = read_frame(&mut stream).map_err(|_| ConnError::Unauthorized)?;
    if received.len() != TOKEN_LEN {
        return Err(ConnError::Unauthorized);
    }
    let mut received_arr = [0u8; TOKEN_LEN];
    received_arr.copy_from_slice(&received);
    if !token_matches(&received_arr, expected_token) {
        return Err(ConnError::Unauthorized);
    }

    state.touch();

    loop {
        let body = match read_frame(&mut stream) {
            Ok(b) => b,
            Err(_) => break,
        };
        let request = decode_request_body(&body).map_err(|_| ConnError::Decode)?;

        state.touch();

        let response = dispatch(request.clone(), state);
        let response_body = encode_response_body(&response).map_err(|_| ConnError::Encode)?;
        write_frame(&mut stream, &response_body).map_err(|_| ConnError::Io)?;
        stream.flush().ok();

        if matches!(request, AgentRequest::Exit) {
            state.request_exit();
            break;
        }
    }
    Ok(())
}

fn dispatch(request: AgentRequest, state: &Arc<AgentState>) -> AgentResponse {
    use super::state::UpdateError;

    zz_drop_core::diag_log::log(&format!("request {}", request_tag(&request)));

    match request {
        AgentRequest::Ping => AgentResponse::Pong,
        AgentRequest::Unlock {
            profile_set,
            kek,
            active_alias,
            ttl_secs,
        } => {
            if !profile_set.contains_alias(&active_alias) {
                return AgentResponse::Error(zz_drop_core::AgentError::AliasNotFound);
            }
            state.unlock(
                profile_set,
                kek.into_kek(),
                active_alias,
                ttl_secs.map(Duration::from_secs),
            );
            AgentResponse::Unlocked
        }
        AgentRequest::GetProfile => match state.get_active_profile_renewing_ttl() {
            Some(p) => AgentResponse::Profile(p),
            None => AgentResponse::Error(zz_drop_core::AgentError::NotUnlocked),
        },
        AgentRequest::UpdateProfile { profile } => match state.update_profile(profile) {
            Ok(()) => AgentResponse::Updated,
            Err(UpdateError::NotUnlocked) => {
                AgentResponse::Error(zz_drop_core::AgentError::NotUnlocked)
            }
            Err(UpdateError::AliasNotFound) => {
                AgentResponse::Error(zz_drop_core::AgentError::AliasNotFound)
            }
            Err(UpdateError::Io(e)) => AgentResponse::Error(zz_drop_core::AgentError::Io {
                message: e.to_string(),
            }),
            Err(UpdateError::Crypto) => AgentResponse::Error(zz_drop_core::AgentError::Io {
                message: "re-encrypt failed".into(),
            }),
        },
        AgentRequest::UpdateProfileSet { profile_set } => match state.update_profile_set(profile_set) {
            Ok(()) => AgentResponse::Updated,
            Err(UpdateError::NotUnlocked) => {
                AgentResponse::Error(zz_drop_core::AgentError::NotUnlocked)
            }
            Err(UpdateError::AliasNotFound) => {
                AgentResponse::Error(zz_drop_core::AgentError::AliasNotFound)
            }
            Err(UpdateError::Io(e)) => AgentResponse::Error(zz_drop_core::AgentError::Io {
                message: e.to_string(),
            }),
            Err(UpdateError::Crypto) => AgentResponse::Error(zz_drop_core::AgentError::Io {
                message: "re-encrypt failed".into(),
            }),
        },
        AgentRequest::SetActiveAlias { alias } => match state.set_active_alias(&alias) {
            Ok(()) => AgentResponse::Updated,
            Err(UpdateError::NotUnlocked) => {
                AgentResponse::Error(zz_drop_core::AgentError::NotUnlocked)
            }
            Err(UpdateError::AliasNotFound) => {
                AgentResponse::Error(zz_drop_core::AgentError::AliasNotFound)
            }
            Err(_) => AgentResponse::Error(zz_drop_core::AgentError::NotUnlocked),
        },
        AgentRequest::ListRemote {
            prefix,
            kind_filter,
            max_results,
        } => match state.list_remote(prefix.as_deref(), kind_filter, max_results) {
            Ok(hit) => {
                let cached_at_secs = hit
                    .fetched_at
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                AgentResponse::RemoteList {
                    entries: hit.entries,
                    cached_at_secs,
                    truncated: hit.truncated,
                }
            }
            Err(ListError::NotUnlocked) => {
                AgentResponse::Error(zz_drop_core::AgentError::NotUnlocked)
            }
            Err(ListError::Provider(message)) => {
                AgentResponse::Error(zz_drop_core::AgentError::Io { message })
            }
        },
        AgentRequest::InvalidateRemote { prefix } => {
            state.invalidate_remote_prefix(prefix.as_deref());
            AgentResponse::Updated
        }
        AgentRequest::Lock => {
            state.lock();
            AgentResponse::Locked
        }
        AgentRequest::Exit => AgentResponse::Exited,
        AgentRequest::Status => AgentResponse::Status {
            unlocked: state.is_unlocked(),
            ttl_remaining_secs: state.ttl_remaining_secs(),
        },
    }
}

