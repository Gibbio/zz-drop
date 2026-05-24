//! `zz z [local|remote]` — orchestrate container unlock then picker.
//!
//! Flow for `zz z local`:
//!   1. read sidecar `last-default-local` if present (defensive
//!      parsing per `sidecars` rules)
//!   2. read `profiles-local.zz` from disk
//!   3. prompt passphrase (the prompt label tells the operator which
//!      file is being unlocked)
//!   4. decrypt → `(ProfileSet, ProfileKek)`
//!   5. picker: numbered list, default = sidecar alias if it still
//!      resolves to an inner profile
//!   6. spawn agent if not running, connect
//!   7. send `Unlock { profile_set, kek, active_alias, ttl }`
//!   8. write sidecar with the chosen alias (best-effort)
//!
//! `zz z` (no args) reads the local sidecar first; if a default
//! resolves, the picker honours it. If neither container exists, the
//! operator is told to run `zz c`.
//!
//! `zz z remote` is gated by the `remote` feature flag (TASK 46) and
//! is not built into the default v1 binary. Today it surfaces a
//! clear "remote not available in this build" message.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use zeroize::Zeroizing;

use zz_drop_core::AgentResponse;
use zz_drop_core::config::Paths;
use zz_drop_core::diag_log;
use zz_drop_core::scriptable::Reason;
use zz_drop_core::{
    POLICY_V1, ProfileCryptoError, ProfileKek, ProfileSet, decrypt_set, rotate_set_if_needed,
};

use crate::agent::{AGENT_MODE_ENV, AgentClient, ClientError};
use crate::cli::ContainerSource;
use crate::commands::{
    EXIT_AGENT_UNREACHABLE, EXIT_DECRYPT_FAILED, EXIT_OK, EXIT_PASSPHRASE_FILE_INSECURE,
    EXIT_PROFILE_MISSING, EXIT_USAGE,
};
#[cfg(not(feature = "remote"))]
use crate::commands::EXIT_NOT_IMPLEMENTED;
use crate::output;
use crate::passphrase as pp;
use crate::picker::{PickError, pick_alias};
use crate::runtime::{self, OutputMode};
use zz_drop_core::sidecars;

const UNLOCK_TTL_SECS: u64 = 600;

pub fn run(paths: &Paths, which: Option<ContainerSource>) -> i32 {
    // Container source precedence: explicit positional (`zz z
    // local|remote`) → global flag/env (`--local`/`--remote`/
    // `ZZ_CONTAINER`) → automatic discovery.
    let resolved = match which.or(runtime::flags().container) {
        Some(s) => s,
        None => match resolve_default_source(paths) {
            Ok(s) => s,
            Err(code) => return code,
        },
    };

    match resolved {
        ContainerSource::Local => unlock_local(paths),
        ContainerSource::Remote => unlock_remote(paths),
    }
}

/// Whether the current invocation is in a scriptable mode where
/// interactive prompts and ambiguity resolution are forbidden.
fn scriptable() -> bool {
    matches!(
        runtime::flags().output,
        OutputMode::Json | OutputMode::Quiet
    )
}

/// Read the passphrase: from `--passphrase-file`/`ZZ_PASSPHRASE_FILE`
/// when supplied, otherwise prompt interactively. In scriptable
/// mode a missing flag is a hard error — we never prompt under
/// `--json`/`--quiet`.
fn obtain_passphrase(label: &str) -> Result<Zeroizing<String>, i32> {
    if let Some(path) = runtime::flags().passphrase_file.clone() {
        let uid = crate::config::current_uid();
        match pp::read_passphrase_file(&path, uid) {
            Ok(s) => return Ok(Zeroizing::new(s)),
            Err(e) => {
                let exit = if e.is_insecure() {
                    EXIT_PASSPHRASE_FILE_INSECURE
                } else {
                    EXIT_USAGE
                };
                let reason = if e.is_insecure() {
                    Reason::PassphraseFilePermissions
                } else {
                    Reason::Usage
                };
                output::emit_failed_bare(reason, Some(&format!("{e}")));
                return Err(exit);
            }
        }
    }

    if scriptable() {
        output::emit_failed_bare(
            Reason::InteractiveRequired,
            Some(
                "passphrase prompt would block in scriptable mode — \
                 pass `--passphrase-file <path>` or set ZZ_PASSPHRASE_FILE",
            ),
        );
        return Err(EXIT_USAGE);
    }

    match prompt_passphrase(label) {
        Ok(p) => Ok(Zeroizing::new(p)),
        Err(e) => {
            output::emit_failed_bare(Reason::Usage, Some(&format!("could not read passphrase: {e}")));
            Err(EXIT_USAGE)
        }
    }
}

/// Pick the active alias from the container's alias list. In
/// scriptable mode the picker never runs: we honour the
/// `--alias`/`ZZ_ALIAS` override first, then the sidecar cache,
/// then the single-alias short-circuit, and finally fail with
/// `alias_ambiguous` carrying the candidate set.
fn choose_alias(aliases: &[&str], cached_alias: Option<&str>) -> Result<String, i32> {
    if scriptable() {
        if let Some(flag) = runtime::flags().alias.as_deref() {
            if aliases.iter().any(|a| *a == flag) {
                return Ok(flag.to_string());
            }
            // The operator named an alias that doesn't exist in
            // this container. Surface it the same way as
            // alias_ambiguous so scripts get a single failure
            // shape to handle.
            output::emit_failed_alias_ambiguous(aliases.to_vec());
            return Err(EXIT_USAGE);
        }
        if let Some(c) = cached_alias {
            return Ok(c.to_string());
        }
        if aliases.len() == 1 {
            return Ok(aliases[0].to_string());
        }
        output::emit_failed_alias_ambiguous(aliases.to_vec());
        return Err(EXIT_USAGE);
    }

    match pick_alias(aliases, cached_alias) {
        Ok(a) => Ok(a),
        Err(PickError::EmptyList) => {
            output::emit_failed_bare(Reason::DecryptFailed, Some("profile container is empty"));
            Err(EXIT_DECRYPT_FAILED)
        }
        Err(PickError::NotInteractive) => {
            output::emit_failed_bare(
                Reason::InteractiveRequired,
                Some("no cached default and stdin is not a terminal"),
            );
            Err(EXIT_USAGE)
        }
        Err(PickError::InvalidIndex) => {
            output::emit_failed_bare(Reason::Usage, Some("invalid selection"));
            Err(EXIT_USAGE)
        }
        Err(PickError::Stdin) => {
            output::emit_failed_bare(Reason::Usage, Some("could not read selection"));
            Err(EXIT_USAGE)
        }
    }
}

#[cfg(not(feature = "remote"))]
fn unlock_remote(_paths: &Paths) -> i32 {
    // The remote container flow lives behind the `remote` feature
    // flag (TASK 46). The default v1 binary does not ship it; we
    // surface a clear message rather than silently failing.
    output::err_line(
        "remote container not available in this build (v1 ships local-only; rebuild with `--features remote`)",
    );
    EXIT_NOT_IMPLEMENTED
}

#[cfg(feature = "remote")]
fn unlock_remote(paths: &Paths) -> i32 {
    // Mirror image of `unlock_local` against the remote container
    // file + sidecar. Kept as a near-copy rather than a refactor so
    // the local-only default build doesn't carry remote-specific
    // branches it can never execute. A unifying helper can land
    // when both flows are stable enough to share.
    if !paths.profiles_remote_file.exists() {
        output::err_line(&format!(
            "no remote container at {}; run `zz z <email>` to fetch one",
            paths.profiles_remote_file.display()
        ));
        return EXIT_PROFILE_MISSING;
    }

    let envelope = match std::fs::read_to_string(&paths.profiles_remote_file) {
        Ok(s) => s,
        Err(e) => {
            output::err_line(&format!("could not read remote container: {e}"));
            return EXIT_PROFILE_MISSING;
        }
    };

    let label = paths
        .profiles_remote_file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("profiles-remote.zz")
        .to_string();
    let passphrase = match prompt_passphrase(&label) {
        Ok(p) => p,
        Err(e) => {
            output::err_line(&format!("could not read passphrase: {e}"));
            return EXIT_USAGE;
        }
    };

    let (profile_set, kek) = match decrypt_set(&envelope, &passphrase) {
        Ok(pair) => pair,
        Err(ProfileCryptoError::Aead) => {
            output::err_line("decryption failed (wrong passphrase or corrupted container)");
            return EXIT_DECRYPT_FAILED;
        }
        Err(ProfileCryptoError::LegacyFormat) => {
            output::err_line(
                "legacy single-profile blob detected (no migration in dev): run `zz w` and re-set up",
            );
            return EXIT_DECRYPT_FAILED;
        }
        Err(e) => {
            output::err_line(&format!("decryption failed: {e}"));
            return EXIT_DECRYPT_FAILED;
        }
    };

    let kek = maybe_rotate_kek(
        &profile_set,
        kek,
        &passphrase,
        &paths.profiles_remote_file,
    );

    if profile_set.is_empty() {
        output::err_line("remote profile container is empty");
        return EXIT_DECRYPT_FAILED;
    }

    let cached = sidecars::read_remote_default(&paths.last_default_remote_file).ok();
    let cached_alias = cached
        .as_ref()
        .and_then(|d| d.alias.as_deref())
        .filter(|a| profile_set.contains_alias(a));
    let aliases: Vec<&str> = profile_set.aliases();

    let active_alias = match pick_alias(&aliases, cached_alias) {
        Ok(a) => a,
        Err(PickError::EmptyList) => {
            output::err_line("remote profile container is empty");
            return EXIT_DECRYPT_FAILED;
        }
        Err(PickError::NotInteractive) => {
            output::err_line(
                "no cached default and stdin is not a terminal; run `zz z remote` interactively first",
            );
            return EXIT_USAGE;
        }
        Err(PickError::InvalidIndex) => {
            output::err_line("invalid selection");
            return EXIT_USAGE;
        }
        Err(PickError::Stdin) => {
            output::err_line("could not read selection");
            return EXIT_USAGE;
        }
    };

    let active_profile = profile_set
        .find_by_alias(&active_alias)
        .expect("alias was just chosen from the set");
    let target = output::profile_target(active_profile);

    let _ = crate::agent::lock::check_for_stale_agent(
        &paths.runtime_dir,
        &paths.agent_socket,
        &paths.token_file,
    );

    if !paths.agent_socket.exists() {
        if let Err(e) = spawn_agent() {
            output::err_line(&format!("could not start agent: {e}"));
            return EXIT_AGENT_UNREACHABLE;
        }
        if !wait_for_socket(&paths.agent_socket, Duration::from_secs(2)) {
            output::err_line("agent did not come up in time");
            return EXIT_AGENT_UNREACHABLE;
        }
    }

    let mut client = match AgentClient::connect(&paths.agent_socket, &paths.token_file) {
        Ok(c) => c,
        Err(e) => {
            output::err_line(&format!("could not connect to agent: {e}"));
            return EXIT_AGENT_UNREACHABLE;
        }
    };

    match client.unlock(profile_set, &kek, &active_alias, Some(UNLOCK_TTL_SECS)) {
        Ok(AgentResponse::Unlocked) => {
            output::line(&format!("unlocked · {active_alias} · {target}"));
            EXIT_OK
        }
        Ok(other) => {
            output::err_line(&format!("unexpected agent response: {other:?}"));
            EXIT_AGENT_UNREACHABLE
        }
        Err(ClientError::HandshakeFailed) => {
            output::err_line("agent handshake failed (token mismatch)");
            EXIT_AGENT_UNREACHABLE
        }
        Err(e) => {
            output::err_line(&format!("agent error: {e}"));
            EXIT_AGENT_UNREACHABLE
        }
    }
}

/// Pick local vs remote when the operator ran `zz z` with no args
/// and supplied no `--local`/`--remote`/`ZZ_CONTAINER` override.
fn resolve_default_source(paths: &Paths) -> Result<ContainerSource, i32> {
    let local_present = paths.profiles_local_file.exists();
    let remote_present = paths.profiles_remote_file.exists();

    match (local_present, remote_present) {
        (false, false) => {
            output::emit_failed_bare(
                Reason::ProfileMissing,
                Some(&format!(
                    "no profile container at {} or {}; run `zz c` to configure one",
                    paths.profiles_local_file.display(),
                    paths.profiles_remote_file.display()
                )),
            );
            Err(EXIT_PROFILE_MISSING)
        }
        (true, false) => Ok(ContainerSource::Local),
        (false, true) => Ok(ContainerSource::Remote),
        (true, true) => {
            // Both exist. In scriptable mode the operator must
            // pick explicitly — silently defaulting to local in
            // a script would mask user intent.
            if scriptable() {
                output::emit_failed_bare(
                    Reason::ContainerAmbiguous,
                    Some("two containers present — pass `--local` or `--remote`"),
                );
                return Err(EXIT_USAGE);
            }
            // Interactive: prefer whichever sidecar carries a
            // cached default, else fall back to local.
            let local_has_default =
                sidecars::read_local_default(&paths.last_default_local_file).is_ok();
            let remote_has_default =
                sidecars::read_remote_default(&paths.last_default_remote_file).is_ok();
            match (local_has_default, remote_has_default) {
                (true, false) => Ok(ContainerSource::Local),
                (false, true) => Ok(ContainerSource::Remote),
                _ => Ok(ContainerSource::Local),
            }
        }
    }
}

fn unlock_local(paths: &Paths) -> i32 {
    if !paths.profiles_local_file.exists() {
        output::emit_failed_bare(
            Reason::ProfileMissing,
            Some(&format!(
                "no local container at {}; run `zz c` to configure one",
                paths.profiles_local_file.display()
            )),
        );
        return EXIT_PROFILE_MISSING;
    }

    let envelope = match std::fs::read_to_string(&paths.profiles_local_file) {
        Ok(s) => s,
        Err(e) => {
            output::emit_failed_bare(
                Reason::ProfileMissing,
                Some(&format!("could not read profile container: {e}")),
            );
            diag_log::log(&format!(
                "unlock_local read_err path={} err={e}",
                paths.profiles_local_file.display()
            ));
            return EXIT_PROFILE_MISSING;
        }
    };
    let envelope_fnv = diag_log::fnv64(envelope.as_bytes());
    let envelope_mtime_secs = std::fs::metadata(&paths.profiles_local_file)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(-1);
    diag_log::log(&format!(
        "unlock_local read path={} envelope_len={} envelope_fnv={:016x} mtime_unix={}",
        paths.profiles_local_file.display(),
        envelope.len(),
        envelope_fnv,
        envelope_mtime_secs,
    ));

    let label = paths
        .profiles_local_file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("profiles-local.zz")
        .to_string();
    let passphrase = match obtain_passphrase(&label) {
        Ok(p) => p,
        Err(code) => return code,
    };

    let (profile_set, kek) = match decrypt_set(&envelope, &passphrase) {
        Ok(pair) => pair,
        Err(ProfileCryptoError::Aead) => {
            output::emit_failed_bare(
                Reason::DecryptFailed,
                Some("decryption failed (wrong passphrase or corrupted container)"),
            );
            diag_log::log(&format!(
                "unlock_local decrypt_fail kind=Aead envelope_fnv={envelope_fnv:016x}"
            ));
            return EXIT_DECRYPT_FAILED;
        }
        Err(ProfileCryptoError::LegacyFormat) => {
            output::emit_failed_bare(
                Reason::DecryptFailed,
                Some(
                    "legacy single-profile blob detected — no in-place migration; run `zz w` and re-set up",
                ),
            );
            diag_log::log("unlock_local decrypt_fail kind=Legacy");
            return EXIT_DECRYPT_FAILED;
        }
        Err(e) => {
            output::emit_failed_bare(Reason::DecryptFailed, Some(&format!("decryption failed: {e}")));
            diag_log::log(&format!("unlock_local decrypt_fail kind=other detail={e}"));
            return EXIT_DECRYPT_FAILED;
        }
    };
    // No KEK fingerprint is logged: even a non-reversible FNV of the
    // 32-byte key partially exfiltrates secret material. The salt
    // fingerprint + KDF params below are enough for the everyday
    // "did the on-disk file change?" diagnostic.
    diag_log::log(&format!(
        "unlock_local decrypt_ok profiles={} kdf_m={} kdf_t={} kdf_p={} salt_fnv={:016x}",
        profile_set.profiles.len(),
        kek.kdf_config().memory_kib,
        kek.kdf_config().iterations,
        kek.kdf_config().parallelism,
        diag_log::fnv64(kek.salt()),
    ));

    let kek = maybe_rotate_kek(
        &profile_set,
        kek,
        &passphrase,
        &paths.profiles_local_file,
    );

    if profile_set.is_empty() {
        output::emit_failed_bare(
            Reason::DecryptFailed,
            Some("profile container is empty; run `zz c` to add a profile"),
        );
        return EXIT_DECRYPT_FAILED;
    }

    // Picker — honour the sidecar default if it still resolves to an
    // inner profile in the just-decrypted container.
    let cached = sidecars::read_local_default(&paths.last_default_local_file).ok();
    let cached_alias = cached
        .as_ref()
        .map(|d| d.alias.as_str())
        .filter(|a| profile_set.contains_alias(a));
    let aliases: Vec<&str> = profile_set.aliases();

    let active_alias = match choose_alias(&aliases, cached_alias) {
        Ok(a) => a,
        Err(code) => return code,
    };

    let active_profile = profile_set
        .find_by_alias(&active_alias)
        .expect("alias was just chosen from the set");
    let target = output::profile_target(active_profile);

    // Stale-agent eviction: if a process from an older build is
    // still listening, SIGTERM it (the lock module already
    // wipes socket/token/lock) so the spawn below brings up a
    // fresh agent from the current binary.
    let stale = crate::agent::lock::check_for_stale_agent(
        &paths.runtime_dir,
        &paths.agent_socket,
        &paths.token_file,
    );
    diag_log::log(&format!("unlock_local stale_check={stale:?}"));

    if !paths.agent_socket.exists() {
        diag_log::log("unlock_local agent spawn");
        if let Err(e) = spawn_agent() {
            output::emit_failed_bare(
                Reason::AgentUnreachable,
                Some(&format!("could not start agent: {e}")),
            );
            diag_log::log(&format!("unlock_local agent spawn_err err={e}"));
            return EXIT_AGENT_UNREACHABLE;
        }
        if !wait_for_socket(&paths.agent_socket, Duration::from_secs(2)) {
            output::emit_failed_bare(
                Reason::AgentUnreachable,
                Some("agent did not come up in time"),
            );
            diag_log::log("unlock_local agent wait_socket_timeout");
            return EXIT_AGENT_UNREACHABLE;
        }
    }

    let mut client = match AgentClient::connect(&paths.agent_socket, &paths.token_file) {
        Ok(c) => c,
        Err(e) => {
            output::emit_failed_bare(
                Reason::AgentUnreachable,
                Some(&format!("could not connect to agent: {e}")),
            );
            diag_log::log(&format!("unlock_local agent connect_err err={e}"));
            return EXIT_AGENT_UNREACHABLE;
        }
    };

    match client.unlock(profile_set, &kek, &active_alias, Some(UNLOCK_TTL_SECS)) {
        Ok(AgentResponse::Unlocked) => {
            // Best-effort: persist the chosen alias so a future
            // `zz z` no-args bypasses the picker.
            let _ = sidecars::write_local_default(
                &paths.last_default_local_file,
                &active_alias,
            );
            output::emit_unlocked(&active_alias, &target);
            diag_log::log(&format!(
                "unlock_local agent_ok alias={active_alias}"
            ));
            EXIT_OK
        }
        Ok(other) => {
            output::emit_failed_bare(
                Reason::AgentUnreachable,
                Some(&format!("unexpected agent response: {other:?}")),
            );
            diag_log::log(&format!("unlock_local agent_unexpected resp={other:?}"));
            EXIT_AGENT_UNREACHABLE
        }
        Err(ClientError::HandshakeFailed) => {
            output::emit_failed_bare(
                Reason::AgentUnreachable,
                Some("agent handshake failed (token mismatch)"),
            );
            diag_log::log("unlock_local agent_handshake_fail");
            EXIT_AGENT_UNREACHABLE
        }
        Err(e) => {
            output::emit_failed_bare(Reason::AgentUnreachable, Some(&format!("agent error: {e}")));
            diag_log::log(&format!("unlock_local agent_err {e}"));
            EXIT_AGENT_UNREACHABLE
        }
    }
}

fn prompt_passphrase(label: &str) -> std::io::Result<String> {
    rpassword::prompt_password(&format!("profile passphrase ({label}): "))
}

/// Re-encrypt the container with current policy params if the
/// on-disk envelope used weaker ones, returning the post-rotation
/// `ProfileKek` for the agent handoff. Failures here are non-fatal:
/// the operator's unlock is already valid, so we log a warning and
/// fall back to the existing KEK — rotation retries on the next
/// unlock.
fn maybe_rotate_kek(
    profile_set: &ProfileSet,
    kek: ProfileKek,
    passphrase: &str,
    path: &Path,
) -> ProfileKek {
    match rotate_set_if_needed(profile_set, &kek, passphrase, path, &POLICY_V1) {
        Ok(Some(new_kek)) => {
            output::line("unlock: rotated KDF parameters to v1 policy");
            diag_log::log(&format!(
                "unlock rotate_ok kdf_m={} kdf_t={} kdf_p={}",
                new_kek.kdf_config().memory_kib,
                new_kek.kdf_config().iterations,
                new_kek.kdf_config().parallelism,
            ));
            new_kek
        }
        Ok(None) => kek,
        Err(e) => {
            output::err_line(&format!(
                "unlock: KDF rotation skipped: {e} (will retry on next unlock)"
            ));
            diag_log::log(&format!("unlock rotate_skip err={e}"));
            kek
        }
    }
}

fn spawn_agent() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    Command::new(exe)
        .env(AGENT_MODE_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(())
}

fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    path.exists()
}
