use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use zz_drop_core::agent_proto::{EntryKindFilter, RemoteListEntry};
use zz_drop_core::profile::format::encrypt_set_with_kek;
use zz_drop_core::{PlainProfile, ProfileKek, ProfileSet};

use super::list_cache::{Hit, ListCache};
use super::remote_client::{BuildError, RemoteClientCache};

/// Hard ceiling on entries returned from a single `ListRemote`,
/// enforced by the agent regardless of the client-requested
/// `max_results` (see `docs/agent-protocol.md`). Stops a buggy or
/// hostile client from pulling an unbounded listing through the agent.
const MAX_LIST_RESULTS: usize = 200;

/// Clamp the client-requested result count to the agent's hard cap.
fn effective_cap(max_results: u32) -> usize {
    (max_results as usize).min(MAX_LIST_RESULTS)
}

/// Non-cryptographic 64-bit fingerprint used in the diagnostic log
/// for the salt. Made for "did this 16-byte blob change between two
/// log lines?" — never used to derive a key, never sent on the wire.
fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub struct AgentState {
    inner: Mutex<Inner>,
    /// Container path to persist into when re-encrypting after
    /// `UpdateProfile` / `UpdateProfileSet`. Resolved once at agent
    /// startup so the test harness can inject a tempdir-rooted path
    /// without monkey-patching `discover_paths`.
    container_path: PathBuf,
    exit_flag: AtomicBool,
    list_cache: Mutex<ListCache>,
    remote_clients: RemoteClientCache,
}

struct Inner {
    profile_set: Option<ProfileSet>,
    /// KEK kept in zeroizing storage by `ProfileKek`. Used to
    /// re-encrypt the container after `UpdateProfile` /
    /// `UpdateProfileSet` so the operator never re-prompts the
    /// passphrase mid-session.
    kek: Option<ProfileKek>,
    /// Alias of the currently-active inner profile. `GetProfile`
    /// returns the entry of `profile_set` matching this alias.
    active_alias: Option<String>,
    /// Mtime of the container file at the moment of unlock. Used
    /// at save time to log a warning if the on-disk file changed
    /// behind our back (last-write-wins, no abort — resolution #7).
    container_mtime_at_unlock: Option<SystemTime>,
    unlocked_at: Option<Instant>,
    ttl: Duration,
    last_activity: Instant,
}

#[derive(Debug)]
pub enum UpdateError {
    NotUnlocked,
    AliasNotFound,
    Io(std::io::Error),
    Crypto,
}

impl AgentState {
    pub fn new(ttl: Duration, container_path: PathBuf) -> Self {
        Self {
            inner: Mutex::new(Inner {
                profile_set: None,
                kek: None,
                active_alias: None,
                container_mtime_at_unlock: None,
                unlocked_at: None,
                ttl,
                last_activity: Instant::now(),
            }),
            container_path,
            exit_flag: AtomicBool::new(false),
            list_cache: Mutex::new(ListCache::default()),
            remote_clients: RemoteClientCache::new(),
        }
    }

    pub fn unlock(
        &self,
        profile_set: ProfileSet,
        kek: ProfileKek,
        active_alias: String,
        ttl_override: Option<Duration>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ttl) = ttl_override {
            inner.ttl = ttl;
        }
        let mtime = std::fs::metadata(&self.container_path)
            .ok()
            .and_then(|m| m.modified().ok());
        zz_drop_core::diag_log::log(&format!(
            "unlock alias={} profiles={} kdf_m={} kdf_t={} kdf_p={} salt_fnv={:016x} container_mtime_unix={}",
            active_alias,
            profile_set.profiles.len(),
            kek.kdf_config().memory_kib,
            kek.kdf_config().iterations,
            kek.kdf_config().parallelism,
            fnv64(kek.salt()),
            mtime
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(-1),
        ));
        inner.profile_set = Some(profile_set);
        inner.kek = Some(kek);
        inner.active_alias = Some(active_alias);
        inner.container_mtime_at_unlock = mtime;
        let now = Instant::now();
        inner.unlocked_at = Some(now);
        inner.last_activity = now;
    }

    pub fn lock(&self) {
        zz_drop_core::diag_log::log("lock requested");
        {
            let mut inner = self.inner.lock().unwrap();
            inner.profile_set = None;
            inner.kek = None;
            inner.active_alias = None;
            inner.container_mtime_at_unlock = None;
            inner.unlocked_at = None;
            inner.last_activity = Instant::now();
        }
        self.drop_completion_caches();
    }

    /// Single place that wipes the SACS-related caches. Called
    /// from every transition that could change "what the active
    /// provider is": `lock`, TTL auto-lock, `update_profile{_set}`,
    /// `set_active_alias`, and explicit `InvalidateRemote` paths
    /// when the cache stops being trustworthy.
    fn drop_completion_caches(&self) {
        if let Ok(mut c) = self.list_cache.lock() {
            c.clear();
        }
        self.remote_clients.clear();
    }

    pub fn is_unlocked(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.profile_set.is_some()
    }

    pub fn touch(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.last_activity = Instant::now();
    }

    /// Snapshot the active inner profile and renew TTL.
    pub fn get_active_profile_renewing_ttl(&self) -> Option<PlainProfile> {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        inner.last_activity = now;
        if inner.unlocked_at.is_some() {
            inner.unlocked_at = Some(now);
        }
        let alias = inner.active_alias.as_deref()?.to_string();
        inner
            .profile_set
            .as_ref()?
            .find_by_alias(&alias)
            .cloned()
    }

    /// Switch the active alias without touching the container on
    /// disk. Returns `false` when the agent is locked or the alias
    /// is not present in the in-RAM container.
    pub fn set_active_alias(&self, alias: &str) -> Result<(), UpdateError> {
        {
            let mut inner = self.inner.lock().unwrap();
            if !inner.profile_set.as_ref().is_some_and(|s| s.contains_alias(alias)) {
                if inner.profile_set.is_none() {
                    return Err(UpdateError::NotUnlocked);
                }
                return Err(UpdateError::AliasNotFound);
            }
            inner.active_alias = Some(alias.to_string());
            inner.last_activity = Instant::now();
        }
        // The active provider may have changed → drop the warm
        // client and the previous list cache. The next
        // `ListRemote` rebuilds against the new active inner
        // profile.
        self.drop_completion_caches();
        Ok(())
    }

    /// Replace one inner profile (matched by `alias`) and re-encrypt
    /// the container to disk.
    pub fn update_profile(&self, profile: PlainProfile) -> Result<(), UpdateError> {
        let active_alias_was_target;
        let snapshot;
        {
            let mut inner = self.inner.lock().unwrap();
            let active = inner.active_alias.clone();
            let set = inner
                .profile_set
                .as_mut()
                .ok_or(UpdateError::NotUnlocked)?;
            let target = set
                .find_by_alias_mut(&profile.alias)
                .ok_or(UpdateError::AliasNotFound)?;
            active_alias_was_target = active.as_deref() == Some(profile.alias.as_str());
            *target = profile;
            snapshot = set.clone();
        }
        if active_alias_was_target {
            // Auth or root-folder-id changed for the active inner
            // profile → warm client is stale; remote layout the
            // operator sees may have changed indirectly too. Drop
            // both caches.
            self.drop_completion_caches();
        }
        self.persist(&snapshot)
    }

    /// Replace the entire in-RAM container and re-encrypt to disk.
    /// If the new set no longer contains the previously active alias,
    /// the active alias is cleared (`GetProfile` will then return
    /// `None` until the operator picks again via `SetActiveAlias`).
    pub fn update_profile_set(&self, set: ProfileSet) -> Result<(), UpdateError> {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.profile_set.is_none() {
                return Err(UpdateError::NotUnlocked);
            }
            let still_valid = inner
                .active_alias
                .as_deref()
                .is_some_and(|a| set.contains_alias(a));
            if !still_valid {
                inner.active_alias = None;
            }
            inner.profile_set = Some(set.clone());
            inner.last_activity = Instant::now();
        }
        // Wholesale container swap → assume the active provider
        // changed.
        self.drop_completion_caches();
        self.persist(&set)
    }

    fn persist(&self, set: &ProfileSet) -> Result<(), UpdateError> {
        let (kek, mtime_at_unlock, active_alias) = {
            let inner = self.inner.lock().unwrap();
            (
                inner.kek.clone().ok_or(UpdateError::NotUnlocked)?,
                inner.container_mtime_at_unlock,
                inner.active_alias.clone(),
            )
        };
        let path = &self.container_path;

        let pre_mtime_secs = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(-1);

        // Last-write-wins with mtime warning (resolution #7).
        let mtime_warn = if let Some(unlock_mt) = mtime_at_unlock
            && let Ok(meta) = std::fs::metadata(path)
            && let Ok(current_mt) = meta.modified()
            && current_mt > unlock_mt
        {
            eprintln!(
                "zz-drop agent: container at {} changed since unlock; overwriting",
                path.display()
            );
            true
        } else {
            false
        };

        let envelope = encrypt_set_with_kek(set, &kek).map_err(|_| UpdateError::Crypto)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(UpdateError::Io)?;
        }
        let tmp = path.with_extension("zz.tmp");
        std::fs::write(&tmp, envelope).map_err(UpdateError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(UpdateError::Io)?;
        }
        std::fs::rename(&tmp, path).map_err(UpdateError::Io)?;

        let post_mtime_secs = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(-1);
        zz_drop_core::diag_log::log(&format!(
            "persist alias={} profiles={} salt_fnv={:016x} kdf_m={} pre_mtime_unix={} post_mtime_unix={} mtime_warn={}",
            active_alias.as_deref().unwrap_or("<none>"),
            set.profiles.len(),
            fnv64(kek.salt()),
            kek.kdf_config().memory_kib,
            pre_mtime_secs,
            post_mtime_secs,
            mtime_warn,
        ));

        if let Ok(new_mt) = std::fs::metadata(path).and_then(|m| m.modified()) {
            self.inner.lock().unwrap().container_mtime_at_unlock = Some(new_mt);
        }
        Ok(())
    }

    /// Returns true if it just auto-locked.
    pub fn check_ttl_and_lock(&self) -> bool {
        let auto_locked = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(unlocked_at) = inner.unlocked_at
                && unlocked_at.elapsed() > inner.ttl
            {
                inner.profile_set = None;
                inner.kek = None;
                inner.active_alias = None;
                inner.container_mtime_at_unlock = None;
                inner.unlocked_at = None;
                true
            } else {
                false
            }
        };
        if auto_locked {
            zz_drop_core::diag_log::log("ttl_auto_lock");
            self.drop_completion_caches();
        }
        auto_locked
    }

    pub fn ttl_remaining_secs(&self) -> Option<u64> {
        let inner = self.inner.lock().unwrap();
        let unlocked_at = inner.unlocked_at?;
        let elapsed = unlocked_at.elapsed();
        if elapsed >= inner.ttl {
            Some(0)
        } else {
            Some((inner.ttl - elapsed).as_secs())
        }
    }

    pub fn idle_for(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        inner.last_activity.elapsed()
    }

    pub fn request_exit(&self) {
        self.exit_flag.store(true, Ordering::SeqCst);
    }

    pub fn should_exit(&self) -> bool {
        self.exit_flag.load(Ordering::SeqCst)
    }

    /// Serve a SACS list request. Cache hit → return cached
    /// payload (no network). Miss → build the active provider
    /// client (or reuse a cached one), call `RemoteFs::list`,
    /// store the result, return.
    ///
    /// Failure modes:
    /// - locked → `Err(ListError::NotUnlocked)`. The CLI maps this
    ///   to "no remote candidates this time" without surfacing
    ///   anything to the operator (design §9 "no-op if locked").
    /// - provider error → `Err(ListError::Provider(_))`. The
    ///   failed list is **not** cached so the next TAB tries
    ///   again instead of being poisoned for 60 s.
    pub fn list_remote(
        &self,
        prefix: Option<&str>,
        kind_filter: EntryKindFilter,
        max_results: u32,
    ) -> Result<Hit, ListError> {
        // Cheap path: cache hit short-circuits before any agent
        // bookkeeping or provider lookup.
        if let Some(hit) = self
            .list_cache
            .lock()
            .map(|mut c| c.get(prefix, kind_filter))
            .ok()
            .flatten()
        {
            return Ok(hit);
        }

        // Cache miss: we need the active inner profile. This also
        // renews the TTL — anyone listing the remote is using the
        // session, so the idle timer should not auto-lock under us.
        let profile = self
            .get_active_profile_renewing_ttl()
            .ok_or(ListError::NotUnlocked)?;

        // Run the provider list under the warm client. The slot
        // mutex is held for the duration of the network call —
        // single-threaded by design (`docs/sacs.md` "Latency").
        let raw = self
            .remote_clients
            .with_client(&profile, |client| {
                let segments: Vec<&str> = match prefix {
                    Some(p) => p
                        .trim_matches('/')
                        .split('/')
                        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
                        .collect(),
                    None => Vec::new(),
                };
                use crate::commands::remote_fs::RemoteFs;
                client.list(&segments)
            })
            .map_err(|e: BuildError| ListError::Provider(e.to_string()))?;
        let entries_raw = raw.map_err(|e| ListError::Provider(format!("{e:?}")))?;

        let cap = effective_cap(max_results);
        let truncated = entries_raw.len() > cap;
        let mut shaped: Vec<RemoteListEntry> = entries_raw
            .into_iter()
            .filter(|e| match kind_filter {
                EntryKindFilter::File => !e.is_directory,
                EntryKindFilter::Directory => e.is_directory,
                EntryKindFilter::Both => true,
            })
            .map(|e| RemoteListEntry {
                name: e.name,
                size: e.size,
                kind: if e.is_directory {
                    zz_drop_core::agent_proto::RemoteKind::Directory
                } else {
                    zz_drop_core::agent_proto::RemoteKind::File
                },
                mtime_secs: None,
            })
            .collect();
        if shaped.len() > cap {
            shaped.truncate(cap);
        }

        // Store the (possibly capped) payload, preserving the
        // truncation flag for the wire response.
        if let Ok(mut c) = self.list_cache.lock() {
            c.put(prefix, kind_filter, shaped.clone(), truncated);
        }

        Ok(Hit {
            fetched_at: SystemTime::now(),
            entries: shaped,
            truncated,
        })
    }

    /// Drop cached list entries for `prefix` and every parent
    /// up to root. Idempotent.
    pub fn invalidate_remote_prefix(&self, prefix: Option<&str>) {
        if let Ok(mut c) = self.list_cache.lock() {
            c.invalidate_prefix_to_root(prefix);
        }
    }

    #[cfg(test)]
    pub fn list_cache_len(&self) -> usize {
        self.list_cache.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn remote_client_populated(&self) -> bool {
        self.remote_clients.is_populated()
    }

    /// Test-only: inject a synthetic entry into the list cache so
    /// `lock` / `update_*` / `set_active_alias` drop hooks can be
    /// exercised without standing up a real provider. Production
    /// code populates the cache exclusively via `list_remote`.
    #[cfg(test)]
    pub fn test_inject_list_cache_entry(
        &self,
        prefix: Option<&str>,
        kind_filter: EntryKindFilter,
    ) {
        let entries = vec![RemoteListEntry {
            name: "stub.md".into(),
            size: Some(1),
            kind: zz_drop_core::agent_proto::RemoteKind::File,
            mtime_secs: None,
        }];
        if let Ok(mut c) = self.list_cache.lock() {
            c.put(prefix, kind_filter, entries, false);
        }
    }
}

#[derive(Debug)]
pub enum ListError {
    NotUnlocked,
    Provider(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use tempfile::tempdir;
    use zz_drop_core::Argon2idConfig;
    use zz_drop_core::profile::format::save_set_zz_with_config;

    const TEST_PASSPHRASE: &str = "correct horse battery staple";
    const FAST_KDF: Argon2idConfig = Argon2idConfig {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };

    fn sample_profile(alias: &str) -> PlainProfile {
        use zz_drop_core::{
            CollisionPolicy, NextcloudAuth, NextcloudProfile, ProfileSettings, ProviderProfile,
        };
        PlainProfile {
            profile_version: 1,
            profile_id: format!("p-{alias}"),
            alias: alias.into(),
            default_target: "t".into(),
            providers: vec![ProviderProfile::Nextcloud(NextcloudProfile {
                server_url: "https://x".into(),
                username: "u".into(),
                auth: NextcloudAuth::AppPassword { secret: "s".into() },
                remote_root: "/".into(),
            })],
            collision_policy: CollisionPolicy::Rename,
            settings: ProfileSettings::default(),
            created_at: "2026-04-26T00:00:00Z".into(),
            updated_at: "2026-04-26T00:00:00Z".into(),
        }
    }

    fn sample_set_with(aliases: &[&str]) -> ProfileSet {
        let mut s = ProfileSet::new();
        for a in aliases {
            s.profiles.push(sample_profile(a));
        }
        s
    }

    /// Build a fresh `AgentState` whose container path is a tempdir
    /// file populated with `set`. Encrypt-once via `save_set_zz` so
    /// the on-disk file exists and `unlock` can capture mtime.
    /// Returns the held tempdir (so the caller keeps it alive) and
    /// the state.
    fn fresh_state_with(set: &ProfileSet, active: &str) -> (tempfile::TempDir, AgentState) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("profiles-local.zz");
        let kek = save_set_zz_with_config(set, TEST_PASSPHRASE, &path, &FAST_KDF).unwrap();
        let s = AgentState::new(Duration::from_secs(600), path);
        s.unlock(set.clone(), kek, active.to_string(), None);
        (dir, s)
    }

    #[test]
    fn list_result_cap_is_enforced_at_200() {
        // The agent must clamp to its hard cap regardless of what the
        // client asks for (docs/agent-protocol.md), D14.
        assert_eq!(MAX_LIST_RESULTS, 200);
        assert_eq!(effective_cap(0), 0);
        assert_eq!(effective_cap(50), 50);
        assert_eq!(effective_cap(200), 200);
        assert_eq!(effective_cap(10_000), MAX_LIST_RESULTS);
        assert_eq!(effective_cap(u32::MAX), MAX_LIST_RESULTS);
    }

    #[test]
    fn starts_locked() {
        let dir = tempdir().unwrap();
        let s = AgentState::new(
            Duration::from_secs(600),
            dir.path().join("profiles-local.zz"),
        );
        assert!(!s.is_unlocked());
        assert!(s.get_active_profile_renewing_ttl().is_none());
    }

    #[test]
    fn unlock_then_lock() {
        let set = sample_set_with(&["a"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        assert!(s.is_unlocked());
        s.lock();
        assert!(!s.is_unlocked());
    }

    #[test]
    fn get_active_returns_matching_inner() {
        let set = sample_set_with(&["alpha", "beta", "gamma"]);
        let (_dir, s) = fresh_state_with(&set, "beta");
        let p = s.get_active_profile_renewing_ttl().unwrap();
        assert_eq!(p.alias, "beta");
    }

    #[test]
    fn set_active_alias_succeeds_for_existing() {
        let set = sample_set_with(&["alpha", "beta"]);
        let (_dir, s) = fresh_state_with(&set, "alpha");
        s.set_active_alias("beta").unwrap();
        let p = s.get_active_profile_renewing_ttl().unwrap();
        assert_eq!(p.alias, "beta");
    }

    #[test]
    fn set_active_alias_rejects_unknown() {
        let set = sample_set_with(&["a"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        assert!(matches!(
            s.set_active_alias("missing"),
            Err(UpdateError::AliasNotFound)
        ));
    }

    #[test]
    fn set_active_alias_when_locked_is_not_unlocked() {
        let dir = tempdir().unwrap();
        let s = AgentState::new(
            Duration::from_secs(600),
            dir.path().join("profiles-local.zz"),
        );
        assert!(matches!(
            s.set_active_alias("a"),
            Err(UpdateError::NotUnlocked)
        ));
    }

    #[test]
    fn update_profile_persists_to_disk() {
        let set = sample_set_with(&["a"]);
        let mut p = set.profiles[0].clone();
        let (dir, s) = fresh_state_with(&set, "a");
        let path = dir.path().join("profiles-local.zz");

        p.default_target = "renamed".into();
        s.update_profile(p).unwrap();

        let (loaded, _) =
            zz_drop_core::profile::format::load_set_zz(&path, TEST_PASSPHRASE).unwrap();
        assert_eq!(loaded.profiles[0].default_target, "renamed");
        let active = s.get_active_profile_renewing_ttl().unwrap();
        assert_eq!(active.default_target, "renamed");
    }

    #[test]
    fn update_profile_set_replaces_full_container() {
        let set1 = sample_set_with(&["a"]);
        let (dir, s) = fresh_state_with(&set1, "a");
        let path = dir.path().join("profiles-local.zz");

        let set2 = sample_set_with(&["a", "b"]);
        s.update_profile_set(set2).unwrap();

        let (loaded, _) =
            zz_drop_core::profile::format::load_set_zz(&path, TEST_PASSPHRASE).unwrap();
        assert_eq!(loaded.profiles.len(), 2);
        assert!(loaded.contains_alias("b"));
    }

    #[test]
    fn update_profile_set_clears_active_when_alias_dropped() {
        let set1 = sample_set_with(&["a", "b"]);
        let (_dir, s) = fresh_state_with(&set1, "b");
        let set2 = sample_set_with(&["a"]);
        s.update_profile_set(set2).unwrap();
        assert!(s.get_active_profile_renewing_ttl().is_none());
        s.set_active_alias("a").unwrap();
        assert!(s.get_active_profile_renewing_ttl().is_some());
    }

    #[test]
    fn update_profile_with_unknown_alias_is_alias_not_found() {
        let set = sample_set_with(&["a"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        let stranger = sample_profile("stranger");
        assert!(matches!(
            s.update_profile(stranger),
            Err(UpdateError::AliasNotFound)
        ));
    }

    #[test]
    fn ttl_auto_lock_after_expiration() {
        let set = sample_set_with(&["a"]);
        let dir = tempdir().unwrap();
        let path = dir.path().join("profiles-local.zz");
        let kek = save_set_zz_with_config(&set, TEST_PASSPHRASE, &path, &FAST_KDF).unwrap();
        let s = AgentState::new(Duration::from_millis(50), path);
        s.unlock(set, kek, "a".into(), None);
        assert!(s.is_unlocked());
        sleep(Duration::from_millis(120));
        assert!(s.check_ttl_and_lock());
        assert!(!s.is_unlocked());
    }

    #[test]
    fn get_active_renews_ttl() {
        // Generous TTL margin so the test stays robust on noisy
        // runners (macOS Apple Silicon CI in particular). Even
        // 250ms / 120+120ms was tight enough to flake. We're
        // testing the *logic* of TTL renewal, not its precision —
        // a wide window is fine.
        let set = sample_set_with(&["a"]);
        let dir = tempdir().unwrap();
        let path = dir.path().join("profiles-local.zz");
        let kek = save_set_zz_with_config(&set, TEST_PASSPHRASE, &path, &FAST_KDF).unwrap();
        let s = AgentState::new(Duration::from_millis(2000), path);
        s.unlock(set, kek, "a".into(), None);
        sleep(Duration::from_millis(200));
        let _ = s.get_active_profile_renewing_ttl();
        sleep(Duration::from_millis(200));
        assert!(!s.check_ttl_and_lock());
        assert!(s.is_unlocked());
    }

    #[test]
    fn touch_resets_idle_counter() {
        let dir = tempdir().unwrap();
        let s = AgentState::new(
            Duration::from_secs(600),
            dir.path().join("profiles-local.zz"),
        );
        sleep(Duration::from_millis(40));
        s.touch();
        assert!(s.idle_for() < Duration::from_millis(20));
    }

    #[test]
    fn exit_flag() {
        let dir = tempdir().unwrap();
        let s = AgentState::new(
            Duration::from_secs(600),
            dir.path().join("profiles-local.zz"),
        );
        assert!(!s.should_exit());
        s.request_exit();
        assert!(s.should_exit());
    }

    // ---- SACS list cache integration --------------------------------

    #[test]
    fn list_remote_when_locked_returns_not_unlocked() {
        let dir = tempdir().unwrap();
        let s = AgentState::new(
            Duration::from_secs(600),
            dir.path().join("profiles-local.zz"),
        );
        let res = s.list_remote(None, EntryKindFilter::Both, 200);
        assert!(matches!(res, Err(ListError::NotUnlocked)));
    }

    #[test]
    fn lock_drops_the_list_cache() {
        let set = sample_set_with(&["a"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        s.test_inject_list_cache_entry(None, EntryKindFilter::Both);
        s.test_inject_list_cache_entry(Some("docs"), EntryKindFilter::File);
        assert_eq!(s.list_cache_len(), 2);

        s.lock();

        assert_eq!(s.list_cache_len(), 0);
    }

    #[test]
    fn ttl_auto_lock_drops_the_list_cache() {
        let set = sample_set_with(&["a"]);
        let dir = tempdir().unwrap();
        let path = dir.path().join("profiles-local.zz");
        let kek = save_set_zz_with_config(&set, TEST_PASSPHRASE, &path, &FAST_KDF).unwrap();
        let s = AgentState::new(Duration::from_millis(40), path);
        s.unlock(set, kek, "a".into(), None);
        s.test_inject_list_cache_entry(None, EntryKindFilter::Both);
        assert_eq!(s.list_cache_len(), 1);

        sleep(Duration::from_millis(80));
        assert!(s.check_ttl_and_lock());

        assert_eq!(s.list_cache_len(), 0);
    }

    #[test]
    fn set_active_alias_drops_the_list_cache() {
        let set = sample_set_with(&["a", "b"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        s.test_inject_list_cache_entry(None, EntryKindFilter::Both);
        assert_eq!(s.list_cache_len(), 1);

        s.set_active_alias("b").unwrap();

        assert_eq!(s.list_cache_len(), 0);
    }

    #[test]
    fn update_profile_for_active_alias_drops_the_list_cache() {
        let set = sample_set_with(&["a"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        s.test_inject_list_cache_entry(None, EntryKindFilter::Both);
        assert_eq!(s.list_cache_len(), 1);

        let mut p = sample_profile("a");
        p.default_target = "renamed".into();
        s.update_profile(p).unwrap();

        assert_eq!(s.list_cache_len(), 0);
    }

    #[test]
    fn update_profile_for_non_active_alias_keeps_the_list_cache() {
        // Active alias is `a`; updating `b` does NOT change "what
        // the active provider sees", so the list cache remains
        // valid. Avoids a wasteful cache miss on every CLI call
        // that touches a non-active inner profile.
        let set = sample_set_with(&["a", "b"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        s.test_inject_list_cache_entry(None, EntryKindFilter::Both);
        assert_eq!(s.list_cache_len(), 1);

        let mut p = sample_profile("b");
        p.default_target = "renamed".into();
        s.update_profile(p).unwrap();

        assert_eq!(s.list_cache_len(), 1);
    }

    #[test]
    fn update_profile_set_drops_the_list_cache() {
        let set1 = sample_set_with(&["a"]);
        let (_dir, s) = fresh_state_with(&set1, "a");
        s.test_inject_list_cache_entry(None, EntryKindFilter::Both);
        assert_eq!(s.list_cache_len(), 1);

        let set2 = sample_set_with(&["a", "b"]);
        s.update_profile_set(set2).unwrap();

        assert_eq!(s.list_cache_len(), 0);
    }

    #[test]
    fn invalidate_remote_prefix_walks_to_root() {
        let set = sample_set_with(&["a"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        s.test_inject_list_cache_entry(Some("backup/snap"), EntryKindFilter::Both);
        s.test_inject_list_cache_entry(Some("backup"), EntryKindFilter::File);
        s.test_inject_list_cache_entry(None, EntryKindFilter::Directory);
        s.test_inject_list_cache_entry(Some("docs"), EntryKindFilter::Both);
        assert_eq!(s.list_cache_len(), 4);

        s.invalidate_remote_prefix(Some("backup/snap"));

        // backup/snap, backup, root → all 3 dropped (kind_filter
        // ignored). docs is unrelated.
        assert_eq!(s.list_cache_len(), 1);
    }

    #[test]
    fn invalidate_remote_prefix_with_root_only_drops_root_keys() {
        let set = sample_set_with(&["a"]);
        let (_dir, s) = fresh_state_with(&set, "a");
        s.test_inject_list_cache_entry(None, EntryKindFilter::Both);
        s.test_inject_list_cache_entry(Some("docs"), EntryKindFilter::Both);
        assert_eq!(s.list_cache_len(), 2);

        s.invalidate_remote_prefix(None);

        assert_eq!(s.list_cache_len(), 1);
    }
}
