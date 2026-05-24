use std::path::{Path, PathBuf};

use thiserror::Error;

const APP_DIR_NAME: &str = "zz-drop";
const CONFIG_FILE_NAME: &str = "config.toml";
/// Encrypted container of profiles that live only on this machine.
/// If you lose either the file or the passphrase, the contents are
/// gone.
pub const PROFILES_LOCAL_FILE_NAME: &str = "profiles-local.zz";
/// Encrypted container of profiles cached from a
/// `zz-drop.net`-compatible API server. Recoverable from any shell
/// once the operator authenticates again.
pub const PROFILES_REMOTE_FILE_NAME: &str = "profiles-remote.zz";
/// Plaintext sidecar storing the alias of the inner profile last
/// selected from `profiles-local.zz`. Single line `<alias>\n`,
/// chmod 0600. Treated as untrusted input on read.
pub const LAST_DEFAULT_LOCAL_FILE_NAME: &str = "last-default-local";
/// Plaintext sidecar storing `<email>\n<alias>\n` for the remote
/// container — the email spares the operator a re-type on cold
/// start. chmod 0600. Treated as untrusted input on read.
pub const LAST_DEFAULT_REMOTE_FILE_NAME: &str = "last-default-remote";
const AGENT_SOCKET_NAME: &str = "agent.sock";
const TOKEN_FILE_NAME: &str = "token";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub config_file: PathBuf,
    /// `profiles-local.zz` — encrypted container of local-only
    /// profiles. Never synced anywhere.
    pub profiles_local_file: PathBuf,
    /// `profiles-remote.zz` — local cache of the encrypted
    /// container synced with the server.
    pub profiles_remote_file: PathBuf,
    /// `last-default-local` — sidecar plaintext: alias of the
    /// inner profile last picked from the local container.
    pub last_default_local_file: PathBuf,
    /// `last-default-remote` — sidecar plaintext: email + alias
    /// last used for the remote container.
    pub last_default_remote_file: PathBuf,
    pub agent_socket: PathBuf,
    pub token_file: PathBuf,
}

impl Paths {
    /// Pick the file `zz z` should unlock. Precedence: remote first
    /// (synced state is the source of truth), then local-only.
    /// Returns `None` if neither file exists.
    pub fn active_profile_file(&self) -> Option<&Path> {
        if self.profiles_remote_file.exists() {
            Some(&self.profiles_remote_file)
        } else if self.profiles_local_file.exists() {
            Some(&self.profiles_local_file)
        } else {
            None
        }
    }

    /// Path of the diagnostic log shared by all three binaries
    /// (CLI, TUI, agent). Lives in `cache_dir` so it survives a
    /// reboot (unlike `runtime_dir`) but isn't part of the
    /// "secrets" tree under `config_dir`. See
    /// `zz_drop_core::diag_log` for the no-secret rule.
    pub fn debug_log_file(&self) -> PathBuf {
        self.cache_dir.join("zz-drop.log")
    }
}

#[derive(Clone, Debug, Default)]
pub struct PathOverrides {
    pub config_dir: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub runtime_dir: Option<PathBuf>,
}

/// `ZZ_CONFIG_DIR` lets an operator (typically CI) redirect the
/// **entire** zz-drop state tree under a single root. Layout:
///
/// ```text
/// <root>/config   → profiles, config.toml, sidecars
/// <root>/cache    → zz-drop.log + future cache state
/// <root>/runtime  → agent socket + token
/// ```
///
/// `lookup` returns the env value or `None` for unset. The
/// closure injection mirrors `runtime::merge_env`: it keeps unit
/// tests off the racy process-global env mutators.
///
/// Returns `Ok(None)` when the variable is unset or empty (caller
/// uses OS defaults), `Ok(Some(_))` with three populated fields
/// when set to an absolute path, or `Err(_)` when the value is
/// present but rejected (relative path).
pub fn config_root_from_env<F>(lookup: F) -> Result<Option<PathOverrides>, PathError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(s) = lookup("ZZ_CONFIG_DIR") else {
        return Ok(None);
    };
    if s.is_empty() {
        return Ok(None);
    }
    let root = PathBuf::from(&s);
    if !root.is_absolute() {
        return Err(PathError::Io(format!(
            "ZZ_CONFIG_DIR=`{s}` must be an absolute path"
        )));
    }
    Ok(Some(PathOverrides {
        config_dir: Some(root.join("config")),
        cache_dir: Some(root.join("cache")),
        runtime_dir: Some(root.join("runtime")),
    }))
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("could not resolve home directory for the current user")]
    NoBaseDirs,

    #[error("io error: {0}")]
    Io(String),
}

pub fn discover_paths(uid: u32, overrides: &PathOverrides) -> Result<Paths, PathError> {
    // Defensive guard: when the calling binary lives inside a
    // `target/{debug,release}/deps/` directory it is a Cargo
    // integration-test binary, *not* a production build. Such a
    // binary must always pass an explicit `overrides.config_dir`
    // pointing at a `tempdir` so the test cannot clobber the
    // operator's real `profiles-local.zz`.
    //
    // Reason this exists: `directories` ignores `XDG_CONFIG_HOME`
    // on macOS and falls back to `~/Library/Application Support/`,
    // so the previous "set XDG_CONFIG_HOME in tests" pattern was
    // a no-op there and silently overwrote real user containers
    // during `cargo test`. The guard converts a silent footgun
    // into a loud test failure.
    //
    // Production binaries (`zz-drop`, `zz-tui`, `zz-agent`) live
    // at `target/{debug,release}/<name>` (no `/deps/` segment),
    // so they bypass this branch and behave normally.
    if overrides.config_dir.is_none()
        && std::env::var_os("ZZ_DROP_TEST_ALLOW_REAL_CONFIG").is_none()
        && running_under_cargo_test()
    {
        return Err(PathError::Io(
            "discover_paths called without config_dir override from a test binary; \
             tests must use an explicit tempdir to avoid clobbering the user's \
             profiles-local.zz (set ZZ_DROP_TEST_ALLOW_REAL_CONFIG=1 to bypass)"
                .into(),
        ));
    }

    let base = directories::BaseDirs::new().ok_or(PathError::NoBaseDirs)?;

    let config_dir = match &overrides.config_dir {
        Some(p) => p.clone(),
        None => base.config_dir().join(APP_DIR_NAME),
    };
    let cache_dir = match &overrides.cache_dir {
        Some(p) => p.clone(),
        None => base.cache_dir().join(APP_DIR_NAME),
    };
    let runtime_dir = match &overrides.runtime_dir {
        Some(p) => p.clone(),
        None => match base.runtime_dir() {
            Some(p) => p.join(APP_DIR_NAME),
            None => PathBuf::from(format!("/tmp/{APP_DIR_NAME}-{uid}")),
        },
    };

    let config_file = config_dir.join(CONFIG_FILE_NAME);
    let profiles_local_file = config_dir.join(PROFILES_LOCAL_FILE_NAME);
    let profiles_remote_file = config_dir.join(PROFILES_REMOTE_FILE_NAME);
    let last_default_local_file = config_dir.join(LAST_DEFAULT_LOCAL_FILE_NAME);
    let last_default_remote_file = config_dir.join(LAST_DEFAULT_REMOTE_FILE_NAME);
    let agent_socket = runtime_dir.join(AGENT_SOCKET_NAME);
    let token_file = runtime_dir.join(TOKEN_FILE_NAME);

    Ok(Paths {
        config_dir,
        cache_dir,
        runtime_dir,
        config_file,
        profiles_local_file,
        profiles_remote_file,
        last_default_local_file,
        last_default_remote_file,
        agent_socket,
        token_file,
    })
}

/// True when the current process executable path looks like a
/// Cargo test binary (`.../target/<profile>/deps/<hash>`). Cheap
/// heuristic — production binaries live one level up at
/// `target/<profile>/<binary>`, so they don't match.
fn running_under_cargo_test() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let s = exe.to_string_lossy();
    // Match `/target/...` AND `/deps/` to avoid false positives on
    // unrelated paths that happen to contain "deps".
    s.contains("/target/") && s.contains("/deps/")
}

#[cfg(unix)]
pub fn ensure_dir(path: &Path, mode: u32) -> Result<(), PathError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(path).map_err(|e| PathError::Io(e.to_string()))?;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|e| PathError::Io(e.to_string()))?;
    Ok(())
}

/// Verify that `path` is a directory we exclusively control: a real directory
/// (not a symlink), owned by `uid`, with **no** group/other permission bits set
/// (mode `0700` or stricter).
///
/// The agent socket and token file live in the runtime dir, which on macOS and
/// XDG-less Linux sits under the world-writable, sticky `/tmp`. Before a client
/// trusts a socket/token found there — or before the agent binds — we confirm
/// that another local user did not pre-create the directory and plant a
/// malicious socket. `symlink_metadata` is used so a planted symlink cannot
/// redirect the check to a directory the attacker controls. See `docs/agent.md`.
#[cfg(unix)]
pub fn verify_private_dir(path: &Path, uid: u32) -> Result<(), PathError> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path).map_err(|e| PathError::Io(e.to_string()))?;
    if !meta.is_dir() {
        return Err(PathError::Io(format!(
            "{} is not a directory; refusing to use it for the agent socket",
            path.display()
        )));
    }
    if meta.uid() != uid {
        return Err(PathError::Io(format!(
            "{} is owned by uid {} (expected {}); refusing",
            path.display(),
            meta.uid(),
            uid
        )));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(PathError::Io(format!(
            "{} has group/other permission bits (mode 0{:o}); refusing",
            path.display(),
            meta.mode() & 0o777
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn overrides_are_used_verbatim_and_files_are_appended() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("cfg");
        let cache = tmp.path().join("cache");
        let runtime = tmp.path().join("rt");

        let paths = discover_paths(
            1234,
            &PathOverrides {
                config_dir: Some(cfg.clone()),
                cache_dir: Some(cache.clone()),
                runtime_dir: Some(runtime.clone()),
            },
        )
        .unwrap();

        assert_eq!(paths.config_dir, cfg);
        assert_eq!(paths.cache_dir, cache);
        assert_eq!(paths.runtime_dir, runtime);
        assert_eq!(paths.config_file, cfg.join("config.toml"));
        assert_eq!(paths.profiles_local_file, cfg.join("profiles-local.zz"));
        assert_eq!(paths.profiles_remote_file, cfg.join("profiles-remote.zz"));
        assert_eq!(
            paths.last_default_local_file,
            cfg.join("last-default-local")
        );
        assert_eq!(
            paths.last_default_remote_file,
            cfg.join("last-default-remote")
        );
        assert_eq!(paths.agent_socket, runtime.join("agent.sock"));
        assert_eq!(paths.token_file, runtime.join("token"));
    }

    /// Regression guard: a test binary that calls `discover_paths`
    /// without supplying `config_dir` must fail loudly. Historically
    /// the previous "set XDG_CONFIG_HOME" pattern silently overwrote
    /// the maintainer's real `~/Library/Application Support/zz-drop/
    /// profiles-local.zz` on macOS, because `directories` ignores
    /// XDG on that platform. This test verifies the guard is wired.
    #[test]
    fn discover_paths_refuses_default_overrides_inside_test_binary() {
        let result = discover_paths(0, &PathOverrides::default());
        match result {
            Err(PathError::Io(msg)) => {
                assert!(
                    msg.contains("test binary"),
                    "guard message should mention 'test binary', got: {msg}"
                );
            }
            Err(other) => panic!("expected Io guard, got {other:?}"),
            Ok(_) => panic!("guard should reject default overrides inside cargo test"),
        }
    }

    #[test]
    fn active_profile_prefers_remote_then_falls_back_to_local() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("cfg");
        std::fs::create_dir_all(&cfg).unwrap();
        let paths = discover_paths(
            1,
            &PathOverrides {
                config_dir: Some(cfg.clone()),
                cache_dir: Some(tmp.path().join("ca")),
                runtime_dir: Some(tmp.path().join("rt")),
            },
        )
        .unwrap();

        assert!(paths.active_profile_file().is_none());

        std::fs::write(&paths.profiles_local_file, b"x").unwrap();
        assert_eq!(
            paths.active_profile_file().unwrap(),
            paths.profiles_local_file.as_path()
        );

        std::fs::write(&paths.profiles_remote_file, b"y").unwrap();
        assert_eq!(
            paths.active_profile_file().unwrap(),
            paths.profiles_remote_file.as_path()
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dir_creates_with_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("nested").join("dir");
        ensure_dir(&target, 0o700).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    /// Current euid, read from the owner of a file we just created
    /// (avoids a `rustix`/`libc` dependency in this crate's tests).
    #[cfg(unix)]
    fn own_uid(tmp: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        let probe = tmp.join(".uid-probe");
        std::fs::write(&probe, b"").unwrap();
        std::fs::metadata(&probe).unwrap().uid()
    }

    #[cfg(unix)]
    #[test]
    fn verify_private_dir_accepts_own_0700_dir() {
        let tmp = tempdir().unwrap();
        let uid = own_uid(tmp.path());
        let dir = tmp.path().join("rt");
        ensure_dir(&dir, 0o700).unwrap();
        assert!(verify_private_dir(&dir, uid).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn verify_private_dir_rejects_group_or_other_bits() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let uid = own_uid(tmp.path());
        let dir = tmp.path().join("rt");
        ensure_dir(&dir, 0o700).unwrap();
        // World-writable: exactly the /tmp-squat shape we must refuse.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(verify_private_dir(&dir, uid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn verify_private_dir_rejects_non_directory_and_symlink() {
        let tmp = tempdir().unwrap();
        let uid = own_uid(tmp.path());
        // A regular file where a directory is expected.
        let file = tmp.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(verify_private_dir(&file, uid).is_err());
        // A symlink to a (valid) dir must be refused without following it.
        let real = tmp.path().join("real");
        ensure_dir(&real, 0o700).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(verify_private_dir(&link, uid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn verify_private_dir_rejects_wrong_owner() {
        // We cannot chown without root, but we can assert a uid that is
        // definitely not the owner is rejected.
        let tmp = tempdir().unwrap();
        let uid = own_uid(tmp.path());
        let dir = tmp.path().join("rt");
        ensure_dir(&dir, 0o700).unwrap();
        assert!(verify_private_dir(&dir, uid.wrapping_add(99_999)).is_err());
    }

    // ---- ZZ_CONFIG_DIR ------------------------------------------------

    fn env_pair(key: &'static str, value: Option<&'static str>) -> impl Fn(&str) -> Option<String> {
        move |k| if k == key { value.map(|s| s.to_string()) } else { None }
    }

    #[test]
    fn zz_config_dir_unset_returns_none() {
        let res = config_root_from_env(|_| None).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn zz_config_dir_empty_returns_none() {
        let res = config_root_from_env(env_pair("ZZ_CONFIG_DIR", Some(""))).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn zz_config_dir_absolute_root_populates_all_three_fields() {
        let res = config_root_from_env(env_pair("ZZ_CONFIG_DIR", Some("/opt/zz-drop")))
            .unwrap()
            .unwrap();
        assert_eq!(res.config_dir.as_deref(), Some(std::path::Path::new("/opt/zz-drop/config")));
        assert_eq!(res.cache_dir.as_deref(), Some(std::path::Path::new("/opt/zz-drop/cache")));
        assert_eq!(res.runtime_dir.as_deref(), Some(std::path::Path::new("/opt/zz-drop/runtime")));
    }

    #[test]
    fn zz_config_dir_relative_is_rejected() {
        let err = config_root_from_env(env_pair("ZZ_CONFIG_DIR", Some("relative/path"))).unwrap_err();
        match err {
            PathError::Io(msg) => assert!(
                msg.contains("absolute"),
                "expected absolute-path complaint, got: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn zz_config_dir_then_discover_paths_layers_layout() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        let root_str = root.to_str().unwrap().to_string();
        let overrides = config_root_from_env(move |k| {
            if k == "ZZ_CONFIG_DIR" {
                Some(root_str.clone())
            } else {
                None
            }
        })
        .unwrap()
        .unwrap();
        let paths = discover_paths(4242, &overrides).unwrap();
        assert_eq!(paths.config_dir, root.join("config"));
        assert_eq!(paths.cache_dir, root.join("cache"));
        assert_eq!(paths.runtime_dir, root.join("runtime"));
        assert_eq!(
            paths.profiles_local_file,
            root.join("config").join("profiles-local.zz")
        );
        assert_eq!(paths.agent_socket, root.join("runtime").join("agent.sock"));
        assert_eq!(paths.debug_log_file(), root.join("cache").join("zz-drop.log"));
    }
}
