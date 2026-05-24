//! Build-aware agent lock file. Lets a fresh client recognise an
//! agent left over from a previous build of the same binary and
//! evict it cleanly before opening a connection.
//!
//! The wire problem: zz-drop / zz-drop-tui / zz-drop-core live in
//! separate cargo workspaces. After a change to a postcard-encoded
//! variant in `zz-drop-core`, rebuilding only one consumer leaves
//! the other speaking the old layout. If a long-lived agent
//! process stays up across the rebuild, the new client talks to
//! the old agent and silently mis-decodes — the historical
//! "frame truncated" / "wrong passphrase" loop.
//!
//! The fix: every time the agent boots it writes its PID and a
//! `build_id` into `<runtime_dir>/agent.lock`. The `build_id` is
//! derived from the binary's own mtime, which changes on every
//! `cargo build`. A client about to talk to the agent reads the
//! lock, compares `build_id` against its own, and on mismatch
//! `SIGTERM`s the stale agent + cleans up the socket/token/lock so
//! the next `zz z` spawns a fresh agent on the new layout.
//!
//! No protocol change, no new dependency.

use std::fs;
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

use rustix::process::{Pid, Signal, kill_process};

const LOCK_FILE_NAME: &str = "agent.lock";
const LOCK_MODE: u32 = 0o600;

/// Compile-time-stable identifier of the binary currently in use.
/// Built from the canonicalised path of `current_exe()` + its
/// mtime (unix seconds). Cargo touches the binary on every release
/// build, so two binaries from different builds always disagree.
/// Returns `None` when the exe path or its metadata is not
/// readable — the caller treats that as a no-op (stale check
/// disabled).
pub fn current_build_id() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let canonical = exe.canonicalize().ok()?;
    let mtime = fs::metadata(&canonical)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())?;
    Some(format!("{}|{}", canonical.display(), mtime))
}

/// Path of the lock file inside the runtime dir.
pub fn lock_path(runtime_dir: &Path) -> std::path::PathBuf {
    runtime_dir.join(LOCK_FILE_NAME)
}

/// Write the current process PID + `build_id` to `<runtime>/agent.lock`.
/// Called by the agent at startup, right after the token file is
/// in place.
pub fn write_lock(runtime_dir: &Path, pid: u32, build_id: &str) -> io::Result<()> {
    let path = lock_path(runtime_dir);
    let contents = format!("{pid}\n{build_id}\n");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // Create with mode 0600 in one step — no write-then-chmod window (F4).
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(LOCK_MODE)
            .open(&path)?;
        f.write_all(contents.as_bytes())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(LOCK_MODE))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, contents)?;
    }
    Ok(())
}

/// Outcome of [`check_for_stale_agent`].
#[derive(Debug)]
pub enum StaleCheck {
    /// No lock file on disk — either no agent ever ran in this
    /// runtime dir, or it was cleaned up already.
    NoLock,
    /// Lock file present, build_id matches: the running agent (if
    /// any) is the same build as us. Caller proceeds normally.
    Match,
    /// Lock file present, build_id differs. The function has
    /// already attempted to evict the stale agent: SIGTERM to its
    /// PID, removal of the socket / token / lock files. The next
    /// `zz z` will spawn a fresh agent.
    KilledStale,
    /// Lock file unreadable / malformed. Treated as "no lock" —
    /// the caller proceeds and the agent (if running) will be
    /// hit on the next connect.
    Unreadable,
}

/// Inspect the lock file. If it exists and the recorded `build_id`
/// matches the current binary's, returns [`StaleCheck::Match`]. If
/// it exists and the `build_id` differs, evict the old agent and
/// return [`StaleCheck::KilledStale`].
pub fn check_for_stale_agent(
    runtime_dir: &Path,
    socket: &Path,
    token_file: &Path,
) -> StaleCheck {
    let path = lock_path(runtime_dir);
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return StaleCheck::NoLock,
        Err(_) => return StaleCheck::Unreadable,
    };
    let mut lines = raw.lines();
    let pid: i32 = match lines.next().and_then(|s| s.parse().ok()) {
        Some(p) => p,
        None => return StaleCheck::Unreadable,
    };
    let agent_build = match lines.next() {
        Some(s) => s.to_string(),
        None => return StaleCheck::Unreadable,
    };
    let our_build = match current_build_id() {
        Some(b) => b,
        None => return StaleCheck::Unreadable,
    };
    if agent_build == our_build {
        return StaleCheck::Match;
    }

    // Mismatch: SIGTERM the stale agent, then wipe its files so
    // the next `zz z` spawn finds a clean slate. SIGTERM (not
    // SIGKILL) gives the agent a chance to drop secrets via the
    // existing zeroizing handlers.
    if pid > 0
        && let Some(p) = Pid::from_raw(pid)
    {
        let _ = kill_process(p, Signal::TERM);
    }
    let _ = fs::remove_file(socket);
    let _ = fs::remove_file(token_file);
    let _ = fs::remove_file(&path);
    StaleCheck::KilledStale
}

/// Best-effort: remove the lock file. Called at agent shutdown.
pub fn remove_lock(runtime_dir: &Path) {
    let _ = fs::remove_file(lock_path(runtime_dir));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn no_lock_returns_no_lock() {
        let dir = tempdir().unwrap();
        let r = check_for_stale_agent(
            dir.path(),
            &dir.path().join("agent.sock"),
            &dir.path().join("token"),
        );
        assert!(matches!(r, StaleCheck::NoLock), "got {r:?}");
    }

    #[test]
    fn matching_build_id_returns_match() {
        let dir = tempdir().unwrap();
        let our = current_build_id().expect("current_build_id");
        write_lock(dir.path(), 12345, &our).unwrap();
        let r = check_for_stale_agent(
            dir.path(),
            &dir.path().join("agent.sock"),
            &dir.path().join("token"),
        );
        assert!(matches!(r, StaleCheck::Match), "got {r:?}");
    }

    #[test]
    fn mismatched_build_id_evicts_files() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let token = dir.path().join("token");
        std::fs::write(&socket, b"x").unwrap();
        std::fs::write(&token, b"y").unwrap();
        // Use PID 0 so kill_process is a no-op (the function
        // skips PID <= 0).
        write_lock(dir.path(), 0, "/different/binary|0").unwrap();
        let r = check_for_stale_agent(dir.path(), &socket, &token);
        assert!(matches!(r, StaleCheck::KilledStale), "got {r:?}");
        assert!(!socket.exists(), "socket must be cleaned up");
        assert!(!token.exists(), "token must be cleaned up");
        assert!(!lock_path(dir.path()).exists(), "lock must be cleaned up");
    }

    #[test]
    fn unreadable_lock_returns_unreadable() {
        let dir = tempdir().unwrap();
        std::fs::write(lock_path(dir.path()), b"garbage with no newline").unwrap();
        let r = check_for_stale_agent(
            dir.path(),
            &dir.path().join("agent.sock"),
            &dir.path().join("token"),
        );
        assert!(matches!(r, StaleCheck::Unreadable), "got {r:?}");
    }

    #[test]
    fn write_lock_sets_0600_permissions() {
        let dir = tempdir().unwrap();
        write_lock(dir.path(), 1, "x").unwrap();
        let path = lock_path(dir.path());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, LOCK_MODE);
        }
    }

    #[test]
    fn current_build_id_is_stable_within_a_run() {
        let a = current_build_id();
        let b = current_build_id();
        assert_eq!(a, b);
    }
}
