pub mod batch;
pub mod doctor;
pub mod download;
pub mod open_tui;
pub mod q_lock;
pub mod remote_fs;
pub mod upload;
pub mod w_wipe;
pub mod walk;
pub mod z_remote;
pub mod z_unlock;

use std::path::{Path, PathBuf};

use zz_drop_core::config::Paths;
use zz_drop_core::scriptable::Reason;
use zz_drop_core::{AgentResponse, PlainProfile, ProviderProfile};

use crate::agent::AgentClient;
use crate::cli::Command;
use crate::color::ColorPolicy;
use crate::config;
use crate::output;
use crate::runtime::{self, OutputMode};
use zz_drop_core::providers::dropbox::DropboxClient;
use zz_drop_core::providers::google_drive::GoogleDriveClient;
use zz_drop_core::providers::nextcloud::NextcloudClient;
use zz_drop_core::providers::onedrive::OneDriveClient;

use remote_fs::{AnyRemote, DropboxRemoteFs, GoogleDriveRemoteFs, NextcloudRemoteFs, OneDriveRemoteFs};

// Exit code table — public surface; codes are stable once 1.0
// ships. Must stay in sync with the `reason` codes in
// `zz_drop_core::scriptable::schema::Reason` (1:1 mapping) and
// with the public spec in `docs/scriptable.md` + `docs/commands.md`.
pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_NOT_IMPLEMENTED: i32 = 3;
pub const EXIT_AGENT_UNREACHABLE: i32 = 5;
pub const EXIT_PROFILE_MISSING: i32 = 6;
pub const EXIT_DECRYPT_FAILED: i32 = 7;
pub const EXIT_WIPE_CANCELLED: i32 = 8;
pub const EXIT_PROVIDER_ERROR: i32 = 9;
/// Agent reachable but the profile is locked, and `--json` mode
/// forbids the auto-unlock the human flow would normally do.
/// Scripts react by calling `zz x --json --passphrase-file …`.
pub const EXIT_AGENT_LOCKED: i32 = 10;
/// `--passphrase-file` / `ZZ_PASSPHRASE_FILE` points at a file
/// whose mode is > 0600 or whose owner differs from the current
/// UID. Refuses to read the file at all.
pub const EXIT_PASSPHRASE_FILE_INSECURE: i32 = 11;
/// `--setup-completions` couldn't write the completion file or the
/// rc-file block (permission denied, disk full, read-only fs).
/// Maps to [`zz_drop_core::scriptable::Reason::CompletionsInstallFailed`].
pub const EXIT_COMPLETIONS_FAILED: i32 = 12;

pub fn dispatch(cmd: &Command) -> i32 {
    match cmd {
        Command::Upload { files, compress, dest_remote } => {
            with_remote_invalidating(Some(dest_remote.as_deref()), |_paths, profile, remote, color| {
                upload::run_upload(
                    remote,
                    files,
                    profile,
                    color,
                    *compress,
                    dest_remote.as_deref(),
                )
            })
        }
        Command::SaveAll { compress, dir, dest_remote } => {
            with_remote_invalidating(Some(dest_remote.as_deref()), |_paths, profile, remote, color| {
                upload::run_save_all(
                    remote,
                    dir,
                    false,
                    profile,
                    color,
                    *compress,
                    dest_remote.as_deref(),
                )
            })
        }
        Command::SaveAllRecursive { compress, dir, dest_remote } => {
            with_remote_invalidating(Some(dest_remote.as_deref()), |_paths, profile, remote, color| {
                upload::run_save_all(
                    remote,
                    dir,
                    true,
                    profile,
                    color,
                    *compress,
                    dest_remote.as_deref(),
                )
            })
        }
        Command::Download { files, decompress, dest_local } => {
            with_remote(|_paths, profile, remote, color| {
                let cwd_default;
                let dest: &Path = match dest_local {
                    Some(p) => p.as_path(),
                    None => {
                        cwd_default = std::env::current_dir()
                            .unwrap_or_else(|_| PathBuf::from("."));
                        cwd_default.as_path()
                    }
                };
                download::run_download(remote, files, dest, profile, color, *decompress)
            })
        }
        Command::DownloadAll { decompress, dest_local, src_remote } => {
            with_remote(|_paths, profile, remote, color| {
                let cwd_default;
                let dest: &Path = match dest_local {
                    Some(p) => p.as_path(),
                    None => {
                        cwd_default = std::env::current_dir()
                            .unwrap_or_else(|_| PathBuf::from("."));
                        cwd_default.as_path()
                    }
                };
                download::run_download_all(
                    remote,
                    dest,
                    false,
                    profile,
                    color,
                    *decompress,
                    src_remote.as_deref(),
                )
            })
        }
        Command::DownloadAllRecursive { decompress, dest_local, src_remote } => {
            with_remote(|_paths, profile, remote, color| {
                let cwd_default;
                let dest: &Path = match dest_local {
                    Some(p) => p.as_path(),
                    None => {
                        cwd_default = std::env::current_dir()
                            .unwrap_or_else(|_| PathBuf::from("."));
                        cwd_default.as_path()
                    }
                };
                download::run_download_all(
                    remote,
                    dest,
                    true,
                    profile,
                    color,
                    *decompress,
                    src_remote.as_deref(),
                )
            })
        }
        Command::ContainerUnlock { which } => with_paths(|p| z_unlock::run(p, *which)),
        Command::RemoteUnlock { selector } => with_paths(|p| z_remote::run(p, selector)),
        Command::Lock => with_paths(q_lock::run),
        Command::Wipe => with_paths(w_wipe::run),
        Command::OpenTui => open_tui::run(),
        Command::Doctor => doctor::run(),
    }
}

fn with_paths<F: FnOnce(&Paths) -> i32>(f: F) -> i32 {
    match config::discover() {
        Ok(paths) => {
            let _ = config::ensure_dirs(&paths);
            f(&paths)
        }
        Err(e) => {
            output::err_line(&format!("could not resolve paths: {e}"));
            EXIT_USAGE
        }
    }
}

fn with_remote<F>(f: F) -> i32
where
    F: FnOnce(&Paths, &PlainProfile, &AnyRemote, &ColorPolicy) -> i32,
{
    with_remote_invalidating(None, f)
}

/// Variant of [`with_remote`] that asks the agent to drop SACS
/// list-cache entries for `prefix` (and every parent up to root)
/// **after** a successful upload. Best-effort: the operation's
/// exit code wins and any invalidate failure is dropped on the
/// floor, same posture as the post-op `update_profile` push.
///
/// Argument shape: outer `None` → no invalidate at all (caller is
/// not an upload). Outer `Some(None)` → invalidate the root
/// (upload landed under `<remote_root>/` with no sub-prefix).
/// Outer `Some(Some(p))` → invalidate `p` and walk to root.
fn with_remote_invalidating<F>(invalidate_prefix: Option<Option<&str>>, f: F) -> i32
where
    F: FnOnce(&Paths, &PlainProfile, &AnyRemote, &ColorPolicy) -> i32,
{
    let paths = match config::discover() {
        Ok(p) => p,
        Err(e) => {
            output::err_line(&format!("could not resolve paths: {e}"));
            return EXIT_USAGE;
        }
    };

    // Build-aware stale-agent check: a long-lived agent from a
    // previous build of this binary will silently mis-decode the
    // new wire schema. SIGTERM it and fall through to the
    // "agent locked" branch, prompting the operator to re-unlock.
    if let crate::agent::lock::StaleCheck::KilledStale =
        crate::agent::lock::check_for_stale_agent(
            &paths.runtime_dir,
            &paths.agent_socket,
            &paths.token_file,
        )
    {
        match runtime::flags().output {
            OutputMode::Text | OutputMode::Quiet => {
                output::err_line(
                    "agent from a previous build was still running and has been stopped.",
                );
                output::err_line(&output::render_hint("zz z"));
            }
            OutputMode::Json => output::emit_failed_bare(
                Reason::AgentUnreachable,
                Some("stale agent from a previous build was stopped — run `zz z` again"),
            ),
        }
        return EXIT_AGENT_UNREACHABLE;
    }

    // Scriptable modes never auto-unlock and never spawn the
    // agent — that would silently prompt the operator or worse,
    // hang on a closed stdin. Distinguish "locked" (exit 10, the
    // script should call `zz z` explicitly) from "unreachable"
    // (exit 5, something is wrong with the socket itself).
    let scriptable = matches!(
        runtime::flags().output,
        OutputMode::Json | OutputMode::Quiet
    );

    if !paths.agent_socket.exists() {
        if scriptable {
            output::emit_failed_bare(
                Reason::AgentLocked,
                Some("profile locked — run `zz z --passphrase-file <path>` first"),
            );
            return EXIT_AGENT_LOCKED;
        }
        output::err_line(&output::render_failed("(agent)", "locked", None, &ColorPolicy::detect()));
        output::err_line(&output::render_hint("zz z"));
        return EXIT_AGENT_UNREACHABLE;
    }

    let mut client = match AgentClient::connect(&paths.agent_socket, &paths.token_file) {
        Ok(c) => c,
        Err(_) => {
            if scriptable {
                output::emit_failed_bare(
                    Reason::AgentUnreachable,
                    Some("agent socket present but not accepting connections"),
                );
            } else {
                output::err_line(&output::render_failed(
                    "(agent)",
                    "unreachable",
                    None,
                    &ColorPolicy::detect(),
                ));
            }
            return EXIT_AGENT_UNREACHABLE;
        }
    };

    let profile = match client.get_profile() {
        Ok(AgentResponse::Profile(p)) => p,
        Ok(AgentResponse::Error(_)) | Ok(_) => {
            if scriptable {
                output::emit_failed_bare(
                    Reason::AgentLocked,
                    Some("agent up but profile locked — run `zz z --passphrase-file <path>` first"),
                );
                return EXIT_AGENT_LOCKED;
            }
            output::err_line(&output::render_failed(
                "(agent)",
                "locked",
                None,
                &ColorPolicy::detect(),
            ));
            output::err_line(&output::render_hint("zz z"));
            return EXIT_AGENT_UNREACHABLE;
        }
        Err(_) => {
            if scriptable {
                output::emit_failed_bare(
                    Reason::AgentUnreachable,
                    Some("agent rpc failed during get_profile"),
                );
            } else {
                output::err_line(&output::render_failed(
                    "(agent)",
                    "unreachable",
                    None,
                    &ColorPolicy::detect(),
                ));
            }
            return EXIT_AGENT_UNREACHABLE;
        }
    };

    let remote = match build_remote(&profile) {
        Ok(r) => r,
        Err(diag) => {
            output::emit_failed_bare(
                Reason::ProviderError,
                Some(&format!("provider init failed: {diag}")),
            );
            return EXIT_PROVIDER_ERROR;
        }
    };

    let color = ColorPolicy::detect();
    let exit = f(&paths, &profile, &remote, &color);

    // After the operation: if the active provider mutated its
    // persisted state (OAuth refresh, cached folder id), push the
    // updated profile back to the agent so the next `zz` invocation
    // doesn't redo the same round-trip. Best-effort — failures here
    // never mask the operation's exit code.
    if let Some(updated_provider) = remote.pending_provider_update() {
        let mut updated = profile.clone();
        for p in updated.providers.iter_mut() {
            if std::mem::discriminant(p) == std::mem::discriminant(&updated_provider) {
                *p = updated_provider;
                break;
            }
        }
        let _ = client.update_profile(updated);
    }

    // Successful upload paths drop the SACS list cache for the
    // touched prefix so the next TAB reflects the new file. The
    // agent walks `prefix → root` itself; we only forward the
    // leaf. Skipped on failure to avoid invalidating after a
    // no-op.
    if exit == EXIT_OK {
        if let Some(prefix_opt) = invalidate_prefix {
            let _ = client.invalidate_remote(prefix_opt);
        }
    }

    exit
}

/// Build a provider-agnostic `RemoteFs` from the first provider
/// declared in the profile. Profiles list at most one provider in
/// v1; the iteration order picks Nextcloud or Google Drive depending
/// on what the user configured at setup.
pub(crate) fn build_remote(profile: &PlainProfile) -> Result<AnyRemote, &'static str> {
    let first = profile
        .providers
        .first()
        .ok_or("no provider configured in profile")?;
    match first {
        ProviderProfile::Nextcloud(nc) => {
            let client = NextcloudClient::from_profile(nc)
                .map_err(|e| zz_drop_core::providers::nextcloud::diagnose(&e))?;
            Ok(AnyRemote::Nextcloud(NextcloudRemoteFs::new(client)))
        }
        ProviderProfile::GoogleDrive(gd) => {
            let client = GoogleDriveClient::from_profile(gd.clone())
                .map_err(|e| zz_drop_core::providers::google_drive::diagnose(&e))?;
            Ok(AnyRemote::GoogleDrive(GoogleDriveRemoteFs::new(client)))
        }
        ProviderProfile::OneDrive(od) => {
            let client = OneDriveClient::from_profile(od.clone())
                .map_err(|e| zz_drop_core::providers::onedrive::diagnose(&e))?;
            Ok(AnyRemote::OneDrive(OneDriveRemoteFs::new(client)))
        }
        ProviderProfile::Dropbox(db) => {
            let client = DropboxClient::from_profile(db.clone())
                .map_err(|e| zz_drop_core::providers::dropbox::diagnose(&e))?;
            Ok(AnyRemote::Dropbox(DropboxRemoteFs::new(client)))
        }
        ProviderProfile::Unknown(_) => Err(zz_drop_core::providers::UnknownProvider::diagnose()),
    }
}
