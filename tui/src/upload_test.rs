use std::io::Write;
use std::path::PathBuf;

use zz_drop_core::CollisionPolicy;
use zz_drop_core::providers::dropbox::{
    self, DropboxAuth, DropboxClient, DropboxProfile, diagnose as dropbox_diagnose,
};
use zz_drop_core::providers::google_drive::{
    self, GoogleDriveAuth, GoogleDriveClient, GoogleDriveProfile,
    diagnose as gdrive_diagnose,
};
use zz_drop_core::providers::nextcloud::{
    NextcloudClient, NextcloudError, diagnose_full,
    login_flow::{LoginFlowClient, LoginFlowError, LoginFlowResult, PollInfo},
    types::{NextcloudAuth, NextcloudProfile},
};
use zz_drop_core::providers::onedrive::{
    self, OneDriveAuth, OneDriveClient, OneDriveProfile,
    diagnose as onedrive_diagnose,
};

use crate::wizard::{
    DropboxSetupState, GoogleDriveSetupState, OneDriveSetupState, ProviderKind, WizardState,
};

pub enum LoginFlowInitOutcome {
    Ok {
        login_url: String,
        token: String,
        endpoint: String,
    },
    Failed(String),
}

pub fn run_login_flow_init(server_url: &str) -> LoginFlowInitOutcome {
    let client = LoginFlowClient::new();
    match client.initiate(server_url) {
        Ok(init) => LoginFlowInitOutcome::Ok {
            login_url: init.login,
            token: init.poll.token,
            endpoint: init.poll.endpoint,
        },
        Err(e) => LoginFlowInitOutcome::Failed(login_flow_diag(&e).to_string()),
    }
}

pub enum LoginFlowPollOutcome {
    Pending,
    Done {
        login_name: String,
        app_password: String,
    },
    Failed(String),
}

pub fn run_login_flow_poll(token: &str, endpoint: &str) -> LoginFlowPollOutcome {
    let client = LoginFlowClient::new();
    let poll = PollInfo {
        token: token.to_string(),
        endpoint: endpoint.to_string(),
    };
    match client.poll_once(&poll) {
        Ok(Some(LoginFlowResult {
            login_name,
            app_password,
            ..
        })) => LoginFlowPollOutcome::Done {
            login_name,
            app_password,
        },
        Ok(None) => LoginFlowPollOutcome::Pending,
        Err(e) => LoginFlowPollOutcome::Failed(login_flow_diag(&e).to_string()),
    }
}

fn login_flow_diag(e: &LoginFlowError) -> &'static str {
    match e {
        LoginFlowError::BadUrl => "invalid server url",
        LoginFlowError::Network => "network error",
        LoginFlowError::TlsTrustFailed(hint) => hint,
        LoginFlowError::ServerError { .. } => "server error",
        LoginFlowError::Decode => "bad response",
    }
}

const MARKER_BASENAME: &str = "Halvdan_was_here";
const MARKER_BODY: &[u8] =
    b"Halvdan was here. zz-drop set up successfully. You can delete this file.\n";
const TEST_FILE_BASENAME_PREFIX: &str = "zz-drop-test-";
const TEST_FILE_BODY: &[u8] = b"zz-drop test upload\n";

/// Resources held between the four probe stages so `main.rs` can
/// redraw the TUI between each step without rebuilding the underlying
/// provider client.
pub enum ProbeContext {
    Nextcloud(NextcloudProbeContext),
    GoogleDrive(GoogleDriveProbeContext),
    OneDrive(OneDriveProbeContext),
    Dropbox(DropboxProbeContext),
}

pub struct NextcloudProbeContext {
    client: NextcloudClient,
    marker_tmp: PathBuf,
    test_tmp: PathBuf,
    test_basename: String,
}

pub struct GoogleDriveProbeContext {
    client: GoogleDriveClient,
    marker_tmp: PathBuf,
    test_tmp: PathBuf,
    test_basename: String,
}

pub struct OneDriveProbeContext {
    client: OneDriveClient,
    marker_tmp: PathBuf,
    test_tmp: PathBuf,
    test_basename: String,
}

pub struct DropboxProbeContext {
    client: DropboxClient,
    marker_tmp: PathBuf,
    test_tmp: PathBuf,
    test_basename: String,
}

pub enum ProbeEnsureOutcome {
    Ok(ProbeContext),
    Failed(String),
}

/// Stage 1: build the provider client and ensure the remote root
/// folder exists. Also writes the local temp file so stage 2 has
/// nothing to set up.
pub fn run_probe_ensure(
    state: &WizardState,
    gdrive_setup: &GoogleDriveSetupState,
    onedrive_setup: &OneDriveSetupState,
    dropbox_setup: &DropboxSetupState,
) -> ProbeEnsureOutcome {
    match state.provider_kind {
        ProviderKind::Nextcloud => run_probe_ensure_nextcloud(state),
        ProviderKind::GoogleDrive => run_probe_ensure_gdrive(gdrive_setup),
        ProviderKind::OneDrive => run_probe_ensure_onedrive(onedrive_setup),
        ProviderKind::Dropbox => run_probe_ensure_dropbox(dropbox_setup),
    }
}

fn run_probe_ensure_nextcloud(state: &WizardState) -> ProbeEnsureOutcome {
    // Both auth methods produce an app password the WebDAV client can use.
    let _ = state.auth_kind;
    let auth = NextcloudAuth::AppPassword {
        secret: state.auth_secret.clone(),
    };

    let profile = NextcloudProfile {
        server_url: state.server_url.clone(),
        username: state.username.clone(),
        auth,
        remote_root: state.remote_folder.clone(),
    };

    let client = match NextcloudClient::from_profile(&profile) {
        Ok(c) => c,
        Err(e) => return ProbeEnsureOutcome::Failed(diagnose_full(&e)),
    };

    if let Err(e) = client.ensure_remote_root() {
        return ProbeEnsureOutcome::Failed(format!("ensure folder: {}", diagnose_full(&e)));
    }

    let nonce = make_nonce();
    let test_basename = format!("{TEST_FILE_BASENAME_PREFIX}{nonce}.txt");

    let marker_tmp = match write_local_temp(MARKER_BODY) {
        Ok(p) => p,
        Err(_) => return ProbeEnsureOutcome::Failed("local file error".into()),
    };
    let test_tmp = match write_local_temp(TEST_FILE_BODY) {
        Ok(p) => p,
        Err(_) => {
            let _ = std::fs::remove_file(&marker_tmp);
            return ProbeEnsureOutcome::Failed("local file error".into());
        }
    };

    ProbeEnsureOutcome::Ok(ProbeContext::Nextcloud(NextcloudProbeContext {
        client,
        marker_tmp,
        test_tmp,
        test_basename,
    }))
}

fn run_probe_ensure_gdrive(gdrive_setup: &GoogleDriveSetupState) -> ProbeEnsureOutcome {
    let profile = match gdrive_profile_from_setup(gdrive_setup) {
        Some(p) => p,
        None => return ProbeEnsureOutcome::Failed("oauth tokens missing".into()),
    };

    let client = match GoogleDriveClient::from_profile(profile) {
        Ok(c) => c,
        Err(e) => return ProbeEnsureOutcome::Failed(gdrive_diagnose(&e).to_string()),
    };

    if let Err(e) = client.ensure_root_folder() {
        return ProbeEnsureOutcome::Failed(format!("ensure folder: {}", gdrive_diagnose(&e)));
    }

    let nonce = make_nonce();
    let test_basename = format!("{TEST_FILE_BASENAME_PREFIX}{nonce}.txt");

    let marker_tmp = match write_local_temp(MARKER_BODY) {
        Ok(p) => p,
        Err(_) => return ProbeEnsureOutcome::Failed("local file error".into()),
    };
    let test_tmp = match write_local_temp(TEST_FILE_BODY) {
        Ok(p) => p,
        Err(_) => {
            let _ = std::fs::remove_file(&marker_tmp);
            return ProbeEnsureOutcome::Failed("local file error".into());
        }
    };

    ProbeEnsureOutcome::Ok(ProbeContext::GoogleDrive(GoogleDriveProbeContext {
        client,
        marker_tmp,
        test_tmp,
        test_basename,
    }))
}

fn run_probe_ensure_onedrive(onedrive_setup: &OneDriveSetupState) -> ProbeEnsureOutcome {
    let profile = match onedrive_profile_from_setup(onedrive_setup) {
        Some(p) => p,
        None => return ProbeEnsureOutcome::Failed("oauth tokens missing".into()),
    };

    let client = match OneDriveClient::from_profile(profile) {
        Ok(c) => c,
        Err(e) => return ProbeEnsureOutcome::Failed(onedrive_diagnose(&e).to_string()),
    };

    if let Err(e) = client.ensure_root_folder() {
        return ProbeEnsureOutcome::Failed(format!(
            "ensure folder: {}",
            onedrive_diagnose(&e)
        ));
    }

    let nonce = make_nonce();
    let test_basename = format!("{TEST_FILE_BASENAME_PREFIX}{nonce}.txt");

    let marker_tmp = match write_local_temp(MARKER_BODY) {
        Ok(p) => p,
        Err(_) => return ProbeEnsureOutcome::Failed("local file error".into()),
    };
    let test_tmp = match write_local_temp(TEST_FILE_BODY) {
        Ok(p) => p,
        Err(_) => {
            let _ = std::fs::remove_file(&marker_tmp);
            return ProbeEnsureOutcome::Failed("local file error".into());
        }
    };

    ProbeEnsureOutcome::Ok(ProbeContext::OneDrive(OneDriveProbeContext {
        client,
        marker_tmp,
        test_tmp,
        test_basename,
    }))
}

fn run_probe_ensure_dropbox(dropbox_setup: &DropboxSetupState) -> ProbeEnsureOutcome {
    let profile = match dropbox_profile_from_setup(dropbox_setup) {
        Some(p) => p,
        None => return ProbeEnsureOutcome::Failed("oauth tokens missing".into()),
    };

    let client = match DropboxClient::from_profile(profile) {
        Ok(c) => c,
        Err(e) => return ProbeEnsureOutcome::Failed(dropbox_diagnose(&e).to_string()),
    };

    if let Err(e) = client.ensure_root_folder() {
        return ProbeEnsureOutcome::Failed(format!(
            "ensure folder: {}",
            dropbox_diagnose(&e)
        ));
    }

    let nonce = make_nonce();
    let test_basename = format!("{TEST_FILE_BASENAME_PREFIX}{nonce}.txt");

    let marker_tmp = match write_local_temp(MARKER_BODY) {
        Ok(p) => p,
        Err(_) => return ProbeEnsureOutcome::Failed("local file error".into()),
    };
    let test_tmp = match write_local_temp(TEST_FILE_BODY) {
        Ok(p) => p,
        Err(_) => {
            let _ = std::fs::remove_file(&marker_tmp);
            return ProbeEnsureOutcome::Failed("local file error".into());
        }
    };

    ProbeEnsureOutcome::Ok(ProbeContext::Dropbox(DropboxProbeContext {
        client,
        marker_tmp,
        test_tmp,
        test_basename,
    }))
}

pub enum ProbeStepOutcome {
    Ok(ProbeContext),
    Failed(String),
}

/// Stage 2: write the persistent `Halvdan_was_here` marker. The
/// operator deletes it manually when the configuration no longer
/// needs proof. Repeated probes overwrite it in place.
pub fn run_probe_marker(ctx: ProbeContext) -> ProbeStepOutcome {
    match ctx {
        ProbeContext::Nextcloud(c) => run_probe_marker_nextcloud(c),
        ProbeContext::GoogleDrive(c) => run_probe_marker_gdrive(c),
        ProbeContext::OneDrive(c) => run_probe_marker_onedrive(c),
        ProbeContext::Dropbox(c) => run_probe_marker_dropbox(c),
    }
}

fn run_probe_marker_nextcloud(ctx: NextcloudProbeContext) -> ProbeStepOutcome {
    let result = ctx
        .client
        .upload(&ctx.marker_tmp, MARKER_BASENAME, CollisionPolicy::Overwrite);
    let _ = std::fs::remove_file(&ctx.marker_tmp);
    match result {
        Ok(_) => ProbeStepOutcome::Ok(ProbeContext::Nextcloud(NextcloudProbeContext {
            marker_tmp: PathBuf::new(),
            ..ctx
        })),
        Err(e) => ProbeStepOutcome::Failed(format!("marker: {}", diagnose_full(&e))),
    }
}

fn run_probe_marker_gdrive(ctx: GoogleDriveProbeContext) -> ProbeStepOutcome {
    let result = ctx.client.upload_to(
        &ctx.marker_tmp,
        &[MARKER_BASENAME],
        CollisionPolicy::Overwrite,
    );
    let _ = std::fs::remove_file(&ctx.marker_tmp);
    match result {
        Ok(_) => ProbeStepOutcome::Ok(ProbeContext::GoogleDrive(GoogleDriveProbeContext {
            marker_tmp: PathBuf::new(),
            ..ctx
        })),
        Err(e) => ProbeStepOutcome::Failed(format!("marker: {}", gdrive_diagnose(&e))),
    }
}

fn run_probe_marker_onedrive(ctx: OneDriveProbeContext) -> ProbeStepOutcome {
    let result = ctx.client.upload_to(
        &ctx.marker_tmp,
        &[MARKER_BASENAME],
        CollisionPolicy::Overwrite,
    );
    let _ = std::fs::remove_file(&ctx.marker_tmp);
    match result {
        Ok(_) => ProbeStepOutcome::Ok(ProbeContext::OneDrive(OneDriveProbeContext {
            marker_tmp: PathBuf::new(),
            ..ctx
        })),
        Err(e) => ProbeStepOutcome::Failed(format!("marker: {}", onedrive_diagnose(&e))),
    }
}

fn run_probe_marker_dropbox(ctx: DropboxProbeContext) -> ProbeStepOutcome {
    let result = ctx.client.upload_to(
        &ctx.marker_tmp,
        &[MARKER_BASENAME],
        CollisionPolicy::Overwrite,
    );
    let _ = std::fs::remove_file(&ctx.marker_tmp);
    match result {
        Ok(_) => ProbeStepOutcome::Ok(ProbeContext::Dropbox(DropboxProbeContext {
            marker_tmp: PathBuf::new(),
            ..ctx
        })),
        Err(e) => ProbeStepOutcome::Failed(format!("marker: {}", dropbox_diagnose(&e))),
    }
}

/// Stage 3: upload the disposable test file. Used only to confirm the
/// upload path works end-to-end; stage 4 deletes it.
pub fn run_probe_upload(ctx: ProbeContext) -> ProbeStepOutcome {
    match ctx {
        ProbeContext::Nextcloud(c) => run_probe_upload_nextcloud(c),
        ProbeContext::GoogleDrive(c) => run_probe_upload_gdrive(c),
        ProbeContext::OneDrive(c) => run_probe_upload_onedrive(c),
        ProbeContext::Dropbox(c) => run_probe_upload_dropbox(c),
    }
}

fn run_probe_upload_nextcloud(ctx: NextcloudProbeContext) -> ProbeStepOutcome {
    let result = ctx
        .client
        .upload(&ctx.test_tmp, &ctx.test_basename, CollisionPolicy::Overwrite);
    let _ = std::fs::remove_file(&ctx.test_tmp);
    match result {
        Ok(_) => ProbeStepOutcome::Ok(ProbeContext::Nextcloud(NextcloudProbeContext {
            test_tmp: PathBuf::new(),
            ..ctx
        })),
        Err(e) => ProbeStepOutcome::Failed(diagnose_for_user(&e)),
    }
}

fn run_probe_upload_gdrive(ctx: GoogleDriveProbeContext) -> ProbeStepOutcome {
    let result =
        ctx.client
            .upload_to(&ctx.test_tmp, &[&ctx.test_basename], CollisionPolicy::Overwrite);
    let _ = std::fs::remove_file(&ctx.test_tmp);
    match result {
        Ok(_) => ProbeStepOutcome::Ok(ProbeContext::GoogleDrive(GoogleDriveProbeContext {
            test_tmp: PathBuf::new(),
            ..ctx
        })),
        Err(e) => ProbeStepOutcome::Failed(format!("upload: {}", gdrive_diagnose(&e))),
    }
}

fn run_probe_upload_onedrive(ctx: OneDriveProbeContext) -> ProbeStepOutcome {
    let result =
        ctx.client
            .upload_to(&ctx.test_tmp, &[&ctx.test_basename], CollisionPolicy::Overwrite);
    let _ = std::fs::remove_file(&ctx.test_tmp);
    match result {
        Ok(_) => ProbeStepOutcome::Ok(ProbeContext::OneDrive(OneDriveProbeContext {
            test_tmp: PathBuf::new(),
            ..ctx
        })),
        Err(e) => ProbeStepOutcome::Failed(format!("upload: {}", onedrive_diagnose(&e))),
    }
}

fn run_probe_upload_dropbox(ctx: DropboxProbeContext) -> ProbeStepOutcome {
    let result =
        ctx.client
            .upload_to(&ctx.test_tmp, &[&ctx.test_basename], CollisionPolicy::Overwrite);
    let _ = std::fs::remove_file(&ctx.test_tmp);
    match result {
        Ok(_) => ProbeStepOutcome::Ok(ProbeContext::Dropbox(DropboxProbeContext {
            test_tmp: PathBuf::new(),
            ..ctx
        })),
        Err(e) => ProbeStepOutcome::Failed(format!("upload: {}", dropbox_diagnose(&e))),
    }
}

pub enum ProbeCleanupOutcome {
    Ok,
    Failed(String),
}

/// Stage 4: delete the disposable test file. Confirms the provider
/// also exposes a working DELETE path; the marker file is left in
/// place.
pub fn run_probe_cleanup(ctx: ProbeContext) -> ProbeCleanupOutcome {
    match ctx {
        ProbeContext::Nextcloud(c) => match c.client.delete_at(&[&c.test_basename]) {
            Ok(()) => ProbeCleanupOutcome::Ok,
            Err(e) => ProbeCleanupOutcome::Failed(format!("delete: {}", diagnose_full(&e))),
        },
        ProbeContext::GoogleDrive(c) => match c.client.delete_at(&[&c.test_basename], true) {
            Ok(()) => ProbeCleanupOutcome::Ok,
            Err(e) => ProbeCleanupOutcome::Failed(format!("delete: {}", gdrive_diagnose(&e))),
        },
        ProbeContext::OneDrive(c) => match c.client.delete_at(&[&c.test_basename], true) {
            Ok(()) => ProbeCleanupOutcome::Ok,
            Err(e) => ProbeCleanupOutcome::Failed(format!("delete: {}", onedrive_diagnose(&e))),
        },
        ProbeContext::Dropbox(c) => match c.client.delete_at(&[&c.test_basename], true) {
            Ok(()) => ProbeCleanupOutcome::Ok,
            Err(e) => ProbeCleanupOutcome::Failed(format!("delete: {}", dropbox_diagnose(&e))),
        },
    }
}

fn diagnose_for_user(e: &NextcloudError) -> String {
    format!("upload: {}", diagnose_full(e))
}

/// Build a `GoogleDriveProfile` from the live wizard setup state.
/// Returns `None` if any required token field is empty (which means
/// the operator advanced past the screen without finishing the OAuth
/// flow — defensive guard, the UI should prevent this).
fn gdrive_profile_from_setup(s: &GoogleDriveSetupState) -> Option<GoogleDriveProfile> {
    if s.access_token.is_empty() || s.refresh_token.is_empty() {
        return None;
    }
    Some(GoogleDriveProfile {
        root_folder: if s.root_folder.is_empty() {
            google_drive::GDRIVE_DEFAULT_ROOT.to_string()
        } else {
            s.root_folder.clone()
        },
        user_email: s.user_email.clone(),
        root_folder_id: None,
        auth: GoogleDriveAuth {
            access_token: s.access_token.clone(),
            refresh_token: s.refresh_token.clone(),
            token_type: s.token_type.clone(),
            expires_at: s.access_expires_at,
            scope: s.scope.clone(),
        },
    })
}

/// Build a `OneDriveProfile` from the live wizard setup state.
/// Same defensive contract as the Google Drive sibling: returns
/// `None` when either token is empty so the screen flow cannot
/// commit a half-completed device-flow run to disk.
fn onedrive_profile_from_setup(s: &OneDriveSetupState) -> Option<OneDriveProfile> {
    if s.access_token.is_empty() || s.refresh_token.is_empty() {
        return None;
    }
    Some(OneDriveProfile {
        root_folder: if s.root_folder.is_empty() {
            onedrive::ONEDRIVE_DEFAULT_ROOT.to_string()
        } else {
            s.root_folder.clone()
        },
        user_email: s.user_email.clone(),
        root_folder_id: None,
        auth: OneDriveAuth {
            access_token: s.access_token.clone(),
            refresh_token: s.refresh_token.clone(),
            token_type: s.token_type.clone(),
            expires_at: s.access_expires_at,
            scope: s.scope.clone(),
        },
    })
}

/// Build a `DropboxProfile` from the live wizard setup state. Same
/// defensive contract: returns `None` when either token is empty so
/// the screen flow cannot commit a half-completed paste-code run
/// to disk.
fn dropbox_profile_from_setup(s: &DropboxSetupState) -> Option<DropboxProfile> {
    if s.access_token.is_empty() || s.refresh_token.is_empty() {
        return None;
    }
    Some(DropboxProfile {
        root_folder: if s.root_folder.is_empty() {
            dropbox::DROPBOX_DEFAULT_ROOT.to_string()
        } else {
            s.root_folder.clone()
        },
        user_email: s.user_email.clone(),
        auth: DropboxAuth {
            access_token: s.access_token.clone(),
            refresh_token: s.refresh_token.clone(),
            token_type: s.token_type.clone(),
            expires_at: s.access_expires_at,
            scope: s.scope.clone(),
        },
    })
}

fn make_nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{n:016x}")
}

fn write_local_temp(body: &[u8]) -> std::io::Result<PathBuf> {
    let mut p = std::env::temp_dir();
    p.push(format!("zz-drop-test-{}.tmp", make_nonce()));
    let mut f = std::fs::File::create(&p)?;
    f.write_all(body)?;
    Ok(p)
}

pub enum SaveProfileOutcome {
    Ok { path: String },
    Failed(String),
}

/// Build a `PlainProfile` from the wizard state, encrypt it with
/// `passphrase`, and write `profile-local.zz` under the user's config
/// dir. The wizard always saves to the local-only slot; if the
/// operator later pushes to a server, the blob is re-encrypted with
/// the picked alias before being uploaded (see
/// `save_profile_with_alias`).
pub fn run_save_profile(
    state: &WizardState,
    gdrive_setup: &GoogleDriveSetupState,
    onedrive_setup: &OneDriveSetupState,
    dropbox_setup: &DropboxSetupState,
    passphrase: &str,
) -> SaveProfileOutcome {
    let path = match config_profile_path() {
        Some(p) => p,
        None => return SaveProfileOutcome::Failed("could not resolve config dir".into()),
    };
    run_save_profile_at(
        state,
        gdrive_setup,
        onedrive_setup,
        dropbox_setup,
        passphrase,
        &path,
    )
}

/// Same as [`run_save_profile`] but writes to an explicit path.
/// Used by integration tests so they cannot clobber the operator's
/// real `profiles-local.zz` — see the docstring on
/// [`save_profile_with_alias_at`] for the full rationale.
pub fn run_save_profile_at(
    state: &WizardState,
    gdrive_setup: &GoogleDriveSetupState,
    onedrive_setup: &OneDriveSetupState,
    dropbox_setup: &DropboxSetupState,
    passphrase: &str,
    path: &std::path::Path,
) -> SaveProfileOutcome {
    // Pre-push placeholder alias depends on the provider:
    // Nextcloud uses the WebDAV username; OAuth providers use the
    // local-part of the account email so the wizard pill has
    // something readable to show before the operator picks the
    // server alias.
    // If the wizard collected an explicit alias (always the case
    // for the OAuth providers in CreateLocal / CreateRemote mode
    // since chunk OneDrive landed; opt-in for Nextcloud), use it
    // as-is. Otherwise fall back to the per-provider placeholder.
    let alias = match state.alias_override.as_deref() {
        Some(a) if !a.is_empty() => a.to_string(),
        _ => match state.provider_kind {
            ProviderKind::Nextcloud => state.username.clone(),
            ProviderKind::GoogleDrive => gdrive_setup
                .user_email
                .split('@')
                .next()
                .unwrap_or("")
                .to_string(),
            ProviderKind::OneDrive => onedrive_setup
                .user_email
                .split('@')
                .next()
                .unwrap_or("")
                .to_string(),
            ProviderKind::Dropbox => dropbox_setup
                .user_email
                .split('@')
                .next()
                .unwrap_or("")
                .to_string(),
        },
    };
    save_profile_with_alias_at(
        state,
        gdrive_setup,
        onedrive_setup,
        dropbox_setup,
        passphrase,
        &alias,
        path,
    )
}

/// Build a `PlainProfile` from the wizard state with `alias` as the
/// canonical alias, encrypt with `passphrase`, and write to
/// `profile-local.zz`. Used by `run_save_profile` (placeholder alias
/// = username) and by the alias-picker rewrite step (real alias
/// chosen by the operator).
///
/// Production callers go through this entry point, which resolves
/// the destination path from the user's config dir. Tests must use
/// [`save_profile_with_alias_at`] instead with an explicit path
/// rooted in a `tempdir`, so they can never clobber the operator's
/// real `profiles-local.zz` (the `directories` crate ignores
/// `XDG_CONFIG_HOME` on macOS and falls back to
/// `~/Library/Application Support/`, which historically caused
/// `cargo test` runs to overwrite the maintainer's container).
pub fn save_profile_with_alias(
    state: &WizardState,
    gdrive_setup: &GoogleDriveSetupState,
    onedrive_setup: &OneDriveSetupState,
    dropbox_setup: &DropboxSetupState,
    passphrase: &str,
    alias: &str,
) -> SaveProfileOutcome {
    let path = match config_profile_path() {
        Some(p) => p,
        None => return SaveProfileOutcome::Failed("could not resolve config dir".into()),
    };
    save_profile_with_alias_at(
        state,
        gdrive_setup,
        onedrive_setup,
        dropbox_setup,
        passphrase,
        alias,
        &path,
    )
}

/// Same as [`save_profile_with_alias`] but writes to an explicit
/// path. Used by integration tests so they can isolate themselves
/// inside a `tempdir` without relying on `XDG_CONFIG_HOME` (which
/// `directories` ignores on macOS).
pub fn save_profile_with_alias_at(
    state: &WizardState,
    gdrive_setup: &GoogleDriveSetupState,
    onedrive_setup: &OneDriveSetupState,
    dropbox_setup: &DropboxSetupState,
    passphrase: &str,
    alias: &str,
    path: &std::path::Path,
) -> SaveProfileOutcome {
    use std::time::SystemTime;

    use zz_drop_core::profile::format::save_set_zz;
    use zz_drop_core::{PlainProfile, ProfileSet, ProfileSettings, ProviderProfile};

    let (providers, default_target) = match state.provider_kind {
        ProviderKind::Nextcloud => {
            let nc = NextcloudProfile {
                server_url: state.server_url.clone(),
                username: state.username.clone(),
                auth: NextcloudAuth::AppPassword {
                    secret: state.auth_secret.clone(),
                },
                remote_root: state.remote_folder.clone(),
            };
            (vec![ProviderProfile::Nextcloud(nc)], "nextcloud")
        }
        ProviderKind::GoogleDrive => match gdrive_profile_from_setup(gdrive_setup) {
            Some(gd) => (vec![ProviderProfile::GoogleDrive(gd)], "google_drive"),
            None => {
                return SaveProfileOutcome::Failed(
                    "google drive setup did not yield tokens".into(),
                );
            }
        },
        ProviderKind::OneDrive => match onedrive_profile_from_setup(onedrive_setup) {
            Some(od) => (vec![ProviderProfile::OneDrive(od)], "onedrive"),
            None => {
                return SaveProfileOutcome::Failed(
                    "onedrive setup did not yield tokens".into(),
                );
            }
        },
        ProviderKind::Dropbox => match dropbox_profile_from_setup(dropbox_setup) {
            Some(db) => (vec![ProviderProfile::Dropbox(db)], "dropbox"),
            None => {
                return SaveProfileOutcome::Failed(
                    "dropbox setup did not yield tokens".into(),
                );
            }
        },
    };

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timestamp = format!("epoch:{now}");

    let profile = PlainProfile {
        profile_version: 1,
        profile_id: format!("local-{now}"),
        alias: alias.to_string(),
        default_target: default_target.into(),
        providers,
        collision_policy: state.collision,
        settings: ProfileSettings::default(),
        created_at: timestamp.clone(),
        updated_at: timestamp,
    };

    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return SaveProfileOutcome::Failed("could not create config dir".into());
    }
    let set = ProfileSet::with_profile(profile);
    if save_set_zz(&set, passphrase, path).is_err() {
        return SaveProfileOutcome::Failed("could not encrypt or write profile blob".into());
    }

    SaveProfileOutcome::Ok {
        path: path.display().to_string(),
    }
}

fn config_profile_path() -> Option<std::path::PathBuf> {
    use zz_drop_core::config::{PathOverrides, discover_paths};
    let uid = rustix::process::geteuid().as_raw();
    discover_paths(uid, &PathOverrides::default())
        .ok()
        .map(|p| p.profiles_local_file)
}
