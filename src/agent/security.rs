use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

pub const TOKEN_LEN: usize = 32;

#[derive(Debug)]
pub enum SecurityError {
    Io(String),
    Unauthorized,
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Unauthorized => write!(f, "unauthorized"),
        }
    }
}

impl std::error::Error for SecurityError {}

pub fn generate_token() -> [u8; TOKEN_LEN] {
    let mut buf = [0u8; TOKEN_LEN];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn write_token_file(path: &Path, token: &[u8; TOKEN_LEN]) -> Result<(), SecurityError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Create with mode 0600 in one step — no write-then-chmod window (F4).
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| SecurityError::Io(e.to_string()))?;
    f.write_all(token).map_err(|e| SecurityError::Io(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| SecurityError::Io(e.to_string()))?;
    Ok(())
}

pub fn read_token_file(path: &Path) -> Result<[u8; TOKEN_LEN], SecurityError> {
    let data = std::fs::read(path).map_err(|e| SecurityError::Io(e.to_string()))?;
    if data.len() != TOKEN_LEN {
        return Err(SecurityError::Unauthorized);
    }
    let mut buf = [0u8; TOKEN_LEN];
    buf.copy_from_slice(&data);
    Ok(buf)
}

pub fn token_matches(a: &[u8; TOKEN_LEN], b: &[u8; TOKEN_LEN]) -> bool {
    a.ct_eq(b).into()
}

pub fn check_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), SecurityError> {
    let uid = peer_uid(stream).map_err(|e| SecurityError::Io(e.to_string()))?;
    if uid == expected_uid {
        Ok(())
    } else {
        Err(SecurityError::Unauthorized)
    }
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let fd = stream.as_fd();
    let creds = rustix::net::sockopt::socket_peercred(fd)
        .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;
    Ok(creds.uid.as_raw())
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt};
    let fd = stream.as_fd();
    let cred = getsockopt(&fd, sockopt::LocalPeerCred)
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    Ok(cred.uid() as u32)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_uid(_stream: &UnixStream) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer UID check not implemented on this OS",
    ))
}

pub fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream as TestUnixStream;
    use tempfile::tempdir;

    #[test]
    fn token_round_trip() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("token");
        let t = generate_token();
        write_token_file(&path, &t).unwrap();
        let back = read_token_file(&path).unwrap();
        assert_eq!(t, back);
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("token");
        write_token_file(&path, &generate_token()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn token_match_constant_time() {
        let a = [1u8; TOKEN_LEN];
        let b = [1u8; TOKEN_LEN];
        let mut c = a;
        c[0] = 2;
        assert!(token_matches(&a, &b));
        assert!(!token_matches(&a, &c));
    }

    #[test]
    fn token_too_short_is_unauthorized() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("short");
        std::fs::write(&path, b"short").unwrap();
        let res = read_token_file(&path);
        assert!(matches!(res, Err(SecurityError::Unauthorized)));
    }

    #[test]
    fn peer_uid_matches_self_on_socketpair() {
        let (a, _b) = TestUnixStream::pair().unwrap();
        let me = current_euid();
        assert!(check_peer_uid(&a, me).is_ok());
    }

    #[test]
    fn peer_uid_mismatch_rejected() {
        let (a, _b) = TestUnixStream::pair().unwrap();
        let bogus = current_euid().wrapping_add(99_999);
        assert!(matches!(
            check_peer_uid(&a, bogus),
            Err(SecurityError::Unauthorized)
        ));
    }
}
