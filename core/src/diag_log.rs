//! Append-only diagnostic log shared by `zz-drop` (CLI + agent)
//! and `zz-tui`. One file per uid, **off by default** — opt in by
//! setting `ZZ_DROP_DEBUG_LOG=1` (`on`/`true`/`yes` also accepted).
//! This keeps the "no log file" guarantee true unless the operator
//! explicitly turns diagnostics on. Rotated to `<file>.old` when it
//! crosses 8 MiB so it never grows without bound.
//!
//! ## Strict no-secret rule
//!
//! Never log:
//! - passphrases, KEK bytes, decrypted profile payloads
//! - OAuth tokens / refresh tokens / app-passwords
//! - Authorization headers, agent socket tokens
//! - any field of `PlainProfile` that contains provider auth
//!
//! Public-safe to log: alias names, KDF params, salt fingerprint
//! (FNV — non-reversible), file paths, mtime, exit code, request
//! discriminant, build_id. The contents above are already either
//! visible in the on-disk envelope JSON or in `ps`/`fs`-level
//! observation, so the log adds no new exposure.
//!
//! ## Concurrency
//!
//! Multiple binaries (`zz`, `zz-tui`, the spawned agent) write to
//! the same file via O_APPEND. POSIX guarantees `write()` < PIPE_BUF
//! is atomic; our lines are well under 1 KiB, so interleaving is
//! safe in practice.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cap above which the log gets rotated to `<file>.old` at next
/// `init()` call. Keeps the file bounded across long-lived sessions
/// without needing a background trimmer.
const ROTATE_AT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Default)]
struct Slot {
    path: Option<PathBuf>,
    enabled: bool,
    binary: &'static str,
}

static SLOT: OnceLock<Mutex<Slot>> = OnceLock::new();

fn slot() -> &'static Mutex<Slot> {
    SLOT.get_or_init(|| Mutex::new(Slot::default()))
}

fn env_enables() -> bool {
    matches!(
        std::env::var("ZZ_DROP_DEBUG_LOG").as_deref(),
        Ok("1") | Ok("on") | Ok("ON") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

/// Initialise the diagnostic log. Idempotent — only the first call
/// per process actually sets state. `binary` is a short tag used as
/// a column in every line so a multi-binary trace is greppable
/// (`bin=zz`, `bin=zz-tui`, `bin=zz-agent`).
pub fn init(path: PathBuf, binary: &'static str) {
    let Ok(mut s) = slot().lock() else { return };
    if s.path.is_some() {
        return;
    }
    s.enabled = env_enables();
    s.binary = binary;
    s.path = Some(path.clone());
    if !s.enabled {
        return;
    }
    rotate_if_oversize(&path);
}

fn rotate_if_oversize(path: &Path) {
    let size = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return,
    };
    if size < ROTATE_AT_BYTES {
        return;
    }
    let old = path.with_extension(match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => format!("{ext}.old"),
        None => "old".to_string(),
    });
    let _ = std::fs::rename(path, &old);
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append a single line. Best-effort — failures are swallowed,
/// the calling tool must keep working even if logging breaks.
/// Format: `<unix-secs> bin=<tag> pid=<pid> <msg>\n`.
pub fn log(msg: &str) {
    let (path, binary, enabled) = match slot().lock() {
        Ok(g) => (g.path.clone(), g.binary, g.enabled),
        Err(_) => return,
    };
    let Some(path) = path else { return };
    if !enabled {
        return;
    }
    let _ = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        writeln!(
            f,
            "{} bin={} pid={} {}",
            now_unix(),
            binary,
            std::process::id(),
            msg
        )?;
        Ok(())
    })();
}

/// Non-cryptographic 64-bit fingerprint. Used in log lines to ask
/// "did this byte slice change between two events?" — never used
/// to derive a key, never sent on the wire.
pub fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
