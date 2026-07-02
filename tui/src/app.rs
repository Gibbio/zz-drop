use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zz_drop_core::PlainProfile;

use crate::clipboard;
use crate::input::TextInput;
use crate::qr::GraphicsCtx;
use crate::screens::Screen;
use crate::screens::nextcloud_auth::AuthFocus;
use crate::tui_widgets::AgentPill;
use crate::wizard::{
    AccountFocus, AuthKind, CollisionChoice, DropboxSetupStage, DropboxSetupState,
    GoogleDriveSetupStage, GoogleDriveSetupState, LoginFlowStage, LoginFlowState, ManageStage,
    OneDriveSetupStage, OneDriveSetupState, PassphraseFocus, PassphraseStage, ProbeStepStatus,
    ProviderKind, PushFlowMode, PushFlowState, PushStage, TestOutcome, WelcomeItem, WizardMode,
    WizardState,
};

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub state: WizardState,
    pub server_input: TextInput,
    pub username_input: TextInput,
    pub secret_input: TextInput,
    pub remote_folder_input: TextInput,
    pub auth_focus: AuthFocus,
    pub collision: CollisionChoice,
    pub test_running: bool,
    pub test_request: bool,
    pub login_flow: LoginFlowState,
    pub login_flow_request_init: bool,
    pub login_flow_request_poll: bool,
    pub gdrive_setup: GoogleDriveSetupState,
    /// Edge-trigger flag set by the Provider picker when the operator
    /// confirms Google Drive: the next tick of the main loop will run
    /// the device-flow `initiate` call and clear this back to `false`.
    pub gdrive_request_init: bool,
    /// Edge-trigger flag set after the polling block stores the OAuth
    /// tokens: the next main-loop tick fetches the user's Google
    /// account email so the profile summary can show it.
    pub gdrive_request_email: bool,
    /// OneDrive shares the device-flow shape with Google Drive — the
    /// same state struct (aliased in `wizard.rs`) is reused but kept
    /// in a separate slot so the two flows don't trample each other
    /// when the user re-enters the Provider picker.
    pub onedrive_setup: OneDriveSetupState,
    pub onedrive_request_init: bool,
    pub onedrive_request_email: bool,
    /// Dropbox uses Authorization Code + PKCE paste-code, not device
    /// flow, so it gets its own state struct (`DropboxSetupState`)
    /// instead of aliasing the Google Drive one. Kept in a separate
    /// slot for the same reason as the OneDrive setup state.
    pub dropbox_setup: DropboxSetupState,
    /// Edge-trigger: build the authorize URL + PKCE verifier on the
    /// next main-loop tick.
    pub dropbox_request_init: bool,
    /// Edge-trigger: POST `code` + `code_verifier` to the Dropbox
    /// token endpoint on the next main-loop tick.
    pub dropbox_request_exchange: bool,
    /// Edge-trigger: fetch the Dropbox account email on the next
    /// main-loop tick after the exchange completes.
    pub dropbox_request_email: bool,
    pub graphics: Option<GraphicsCtx>,
    pub passphrase_input: TextInput,
    pub confirm_input: TextInput,
    pub passphrase_focus: PassphraseFocus,
    pub passphrase_stage: PassphraseStage,
    pub save_request: bool,
    pub saved_path: Option<String>,
    pub welcome_item: WelcomeItem,
    /// Tracks whether the Configure wizard is in CreateLocal mode
    /// (push prompt) or CreateRemote mode (auto-push, mirror to
    /// profile-remote.zz on success). Reset on every Welcome entry.
    pub wizard_mode: WizardMode,

    // ── push to zz-drop.net (TASK 20 Phase 2) ──────────────────────
    pub push_flow: PushFlowState,
    pub account_email_input: TextInput,
    pub account_password_input: TextInput,
    pub account_focus: AccountFocus,
    /// Inline feedback for the Account form when the local-only check
    /// rejects the email/password before any network request. Cleared
    /// on the next keystroke so the operator sees we're listening
    /// again as soon as they correct the input.
    pub account_validation_error: Option<&'static str>,
    pub totp_code_input: TextInput,
    pub push_alias_input: TextInput,
    /// The CLI's `ZZDROP_API_BASE` env var, captured once at startup
    /// (or fed by the test harness). The push flow uses it as the
    /// base URL for the `ApiClient`.
    pub api_base: String,
    /// Pretty-printed config directory for the welcome footnote, e.g.
    /// `~/Library/Application Support/zz-drop/` on macOS or
    /// `~/.config/zz-drop/` on Linux. Computed once at startup so the
    /// render path stays free of filesystem lookups.
    pub config_dir_display: String,
    pub push_request_login: bool,
    pub push_request_totp: bool,
    pub push_request_list: bool,
    pub push_request_send: bool,
    /// Set by the `PushProfile` Enter handler when running in
    /// `SignIn` mode. The main loop reads it, calls `get_blob`,
    /// writes the encrypted blob to `profile-remote.zz` and calls
    /// `apply_signin_done` / `apply_push_failed`.
    pub signin_request_download: bool,
    /// Set by the `PushProfile` Enter handler in wizard-push mode
    /// when the operator picks an alias different from the one the
    /// wizard saved into `profile-local.zz`. The main loop
    /// re-encrypts the blob with the picked alias and re-writes
    /// `profile-local.zz` *before* triggering the push, so file
    /// and server agree on the alias inside the blob.
    pub rewrite_blob_for_alias_request: bool,
    /// `Some(...)` after a successful push during this run. Drives
    /// the Done screen's "saved AND pushed" copy and turns off the
    /// `p · push` keybar fallback.
    pub pushed_summary: Option<PushedSummary>,

    // ── manage existing profile (TASK 22.5) ────────────────────────
    /// `true` when a local-only `profile-local.zz` exists at startup.
    pub local_exists: bool,
    /// `true` when a server-synced `profile-remote.zz` cache exists at
    /// startup.
    pub remote_exists: bool,
    /// Resolved path to `profile-local.zz`. `None` only on platforms
    /// where `directories::BaseDirs::new()` fails.
    pub profile_local_path: Option<std::path::PathBuf>,
    /// Resolved path to `profile-remote.zz`. `None` only on platforms
    /// where `directories::BaseDirs::new()` fails.
    pub profile_remote_path: Option<std::path::PathBuf>,
    /// Which slot the operator picked at Welcome (Local or Remote);
    /// drives `active_profile_path` and the labels on Unlock/Manage.
    pub unlock_source: ProfileSource,
    /// In-memory cache of the most recently unlocked profile. While
    /// the TUI session is alive, picking the same source again at
    /// Welcome skips the passphrase prompt; picking the *other*
    /// source clears the cache and re-prompts. Always cleared on
    /// wipe / save / sign-in / quit. Lives only in RAM.
    pub cached_source: Option<ProfileSource>,
    /// Server session token cached for the rest of this TUI session.
    /// Set after a successful Account / LoginTotp login. Re-used by
    /// SignIn, re-push and CreateRemote to skip the login screens
    /// when we've already authenticated. Cleared on wipe and on
    /// quit; never written to disk.
    pub cached_session_token: Option<String>,
    /// Where to route after a successful login. `None` → the default
    /// PushProfile alias picker. `Some(Screen::Provider)` → the
    /// Configure wizard (used by `Create remote profile` so the
    /// server is verified *before* the wizard runs).
    pub post_login_target: Option<Screen>,
    /// Passphrase prompt for the Open Existing flow. Separate from
    /// the wizard's `passphrase_input` so the two flows don't bleed.
    pub manage_passphrase_input: TextInput,
    /// Stage of the manage flow.
    pub manage_stage: ManageStage,
    /// Last unlock-attempt error message, displayed under the field.
    pub manage_unlock_error: Option<String>,
    /// Decrypted profile, set after a successful unlock. Cleared on
    /// `Esc` from `ProfileManage` and on wipe.
    pub unlocked_profile: Option<PlainProfile>,
    /// Full container of the unlocked session — the picker walks
    /// over its inner profiles. Cleared on lock/wipe/escape.
    pub unlocked_set: Option<zz_drop_core::ProfileSet>,
    /// KEK for the unlocked container, kept in `Zeroizing` storage.
    /// Used by add-inner-profile to re-encrypt without reprompt.
    pub unlocked_kek: Option<zz_drop_core::ProfileKek>,
    /// Selected row in the post-unlock container picker.
    pub picker_index: usize,
    /// Alias the sidecar suggested as default at unlock time.
    /// Renders in the picker as "(last used)".
    pub picker_default_alias: Option<String>,
    /// Text input for the InnerAlias screen.
    pub inner_alias_input: TextInput,
    /// State machine of the InnerAlias screen.
    pub inner_alias_state: crate::screens::inner_alias::InnerAliasState,
    /// Error to surface on the InnerAlias screen.
    pub inner_alias_error: Option<String>,
    /// Edge-trigger flag: the main loop builds the new inner profile,
    /// appends it, encrypts via cached KEK, writes to disk and pushes
    /// the new set to the agent.
    pub add_inner_request: bool,
    /// `true` while the operator has pressed `r` and wants to see
    /// the app password in clear text. Toggled by `r`.
    pub manage_show_secret: bool,
    /// Set by `Open existing profile` Enter; the main loop reads it,
    /// runs `load_profile_zz` synchronously and calls `apply_unlock_*`.
    pub unlock_request: bool,
    /// Set by the `WipeConfirm` `y` handler; the main loop reads it,
    /// removes the file synchronously and calls `apply_wipe_done` /
    /// `apply_wipe_failed`.
    pub wipe_request: bool,
    /// Set by the `DeleteInnerConfirm` `y` handler; the main loop
    /// reads it, removes the active inner profile from the unlocked
    /// container, re-encrypts with the cached KEK and writes
    /// atomically. Calls `apply_inner_deleted` /
    /// `apply_inner_delete_failed`.
    pub delete_inner_request: bool,
    /// Where to return when leaving the TestUpload screen. The
    /// re-test action from ProfileManage sets this to
    /// `Some(Screen::ProfileManage)` so Esc returns to manage.
    pub test_upload_back: Option<Screen>,
    /// Where to return when leaving the push sub-flow (Account /
    /// LoginTotp / PushProfile) via `Esc`. `Some(ProfileManage)` is
    /// set by the `p · re-push` action so the operator can bail
    /// out if the server is unreachable. `None` means the flow was
    /// entered via the wizard (auto-push after passphrase save) —
    /// in that case `Esc` is intentionally a no-op and the only
    /// way to exit is success or `Ctrl-C`.
    pub push_back: Option<Screen>,

    /// Live status of the SACS shell-completion install, surfaced on
    /// the Welcome screen. Refreshed on Welcome entry and after the
    /// `SetupCompletions` action runs. `None` means `$SHELL` is
    /// unset / unsupported and the row is a no-op.
    pub welcome_completions_status: Option<zz_drop_core::completions::Status>,
    /// One-shot result message shown below the Welcome menu after a
    /// `SetupCompletions` action. Cleared on next navigation away.
    pub welcome_completions_message: Option<String>,
}

/// Snapshot of a successful `PUT /profiles/{alias}/blob`. Held by
/// `App` so the Done screen can render it after the push sub-flow's
/// own state has been cleared.
#[derive(Clone, Debug)]
pub struct PushedSummary {
    pub alias: String,
    pub blob_size: u64,
    pub blob_version: u64,
}

/// Which profile blob the unlock flow is currently working on.
/// Picked up at Welcome time and consumed by `active_profile_path`
/// so the right file gets decrypted (and labelled in the UI).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProfileSource {
    /// `profile-local.zz` — local-only blob, never synced.
    #[default]
    Local,
    /// `profile-remote.zz` — local cache of a server alias.
    Remote,
}

/// Strip the URL scheme and any path suffix from `api_base` so the
/// UI can refer to the configured server compactly (e.g. show
/// `zz-drop.net` for `https://zz-drop.net`, `localhost:8080` for
/// `http://localhost:8080`).
pub fn server_label_for(api_base: &str) -> String {
    let s = api_base
        .strip_prefix("https://")
        .or_else(|| api_base.strip_prefix("http://"))
        .unwrap_or(api_base);
    s.split('/').next().unwrap_or(s).to_string()
}

/// Resolve the canonical pair of profile paths on this OS. Returns
/// `(profile_local.zz, profile_remote.zz)`. Both are `None` only when
/// `directories::BaseDirs::new()` can't find a home directory (e.g. a
/// sandbox without `$HOME`).
fn profile_paths() -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    use zz_drop_core::config::{PathOverrides, discover_paths};
    let uid = rustix::process::geteuid().as_raw();
    match discover_paths(uid, &PathOverrides::default()) {
        Ok(p) => (Some(p.profiles_local_file), Some(p.profiles_remote_file)),
        Err(_) => (None, None),
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let (local_path, remote_path) = profile_paths();
        let local_exists = local_path.as_ref().map(|p| p.exists()).unwrap_or(false);
        let remote_exists = remote_path.as_ref().map(|p| p.exists()).unwrap_or(false);
        // Default the menu cursor:
        // - with `remote` on: prefer remote (the primary recoverable
        //   state), fall back to local, then to the wizard entry;
        // - default build: never default to OpenRemote — the menu
        //   doesn't even surface that item.
        #[cfg(feature = "remote")]
        let welcome_item = if remote_exists {
            WelcomeItem::OpenRemote
        } else if local_exists {
            WelcomeItem::OpenLocal
        } else {
            WelcomeItem::Configure
        };
        #[cfg(not(feature = "remote"))]
        let welcome_item = if local_exists {
            WelcomeItem::OpenLocal
        } else {
            WelcomeItem::Configure
        };
        // Quiet the default-build warning that `remote_exists` is
        // unused.
        #[cfg(not(feature = "remote"))]
        let _ = remote_exists;
        let mut server_input = TextInput::new();
        // Pre-fill with `https://` so the user just types the host.
        server_input.set_value("https://");
        let mut app = Self {
            screen: Screen::Welcome,
            should_quit: false,
            state: WizardState::default(),
            server_input,
            username_input: TextInput::new(),
            secret_input: TextInput::masked(),
            remote_folder_input: TextInput::new(),
            auth_focus: AuthFocus::KindSelector,
            collision: CollisionChoice::Rename,
            test_running: false,
            test_request: false,
            login_flow: LoginFlowState::default(),
            login_flow_request_init: false,
            login_flow_request_poll: false,
            gdrive_setup: GoogleDriveSetupState::default(),
            gdrive_request_init: false,
            gdrive_request_email: false,
            onedrive_setup: OneDriveSetupState::default(),
            onedrive_request_init: false,
            onedrive_request_email: false,
            dropbox_setup: DropboxSetupState::default(),
            dropbox_request_init: false,
            dropbox_request_exchange: false,
            dropbox_request_email: false,
            graphics: None,
            passphrase_input: TextInput::masked(),
            confirm_input: TextInput::masked(),
            passphrase_focus: PassphraseFocus::Passphrase,
            passphrase_stage: PassphraseStage::Editing,
            save_request: false,
            saved_path: None,
            welcome_item,
            wizard_mode: WizardMode::default(),
            push_flow: PushFlowState::default(),
            account_email_input: TextInput::new(),
            account_password_input: TextInput::masked(),
            account_focus: AccountFocus::default(),
            account_validation_error: None,
            totp_code_input: TextInput::new(),
            push_alias_input: TextInput::new(),
            // Default base URL only ships in the `remote` build —
            // otherwise the string `https://zz-drop.net` would land
            // verbatim in the default binary, which the gating spec
            // forbids ("no zz-drop.net string statically referenced
            // in default binaries"). Default builds keep `api_base`
            // empty; the remote-only request handlers are also
            // cfg-gated, so it never gets read.
            #[cfg(feature = "remote")]
            api_base: std::env::var("ZZDROP_API_BASE")
                .unwrap_or_else(|_| "https://zz-drop.net".to_string()),
            #[cfg(not(feature = "remote"))]
            api_base: String::new(),
            config_dir_display: crate::wizard::config_dir_display(),
            push_request_login: false,
            push_request_totp: false,
            push_request_list: false,
            push_request_send: false,
            signin_request_download: false,
            rewrite_blob_for_alias_request: false,
            pushed_summary: None,
            local_exists,
            remote_exists,
            profile_local_path: local_path,
            profile_remote_path: remote_path,
            unlock_source: if remote_exists {
                ProfileSource::Remote
            } else {
                ProfileSource::Local
            },
            cached_source: None,
            cached_session_token: None,
            post_login_target: None,
            manage_passphrase_input: TextInput::masked(),
            manage_stage: ManageStage::default(),
            manage_unlock_error: None,
            unlocked_profile: None,
            unlocked_set: None,
            unlocked_kek: None,
            picker_index: 0,
            picker_default_alias: None,
            inner_alias_input: TextInput::new(),
            inner_alias_state: crate::screens::inner_alias::InnerAliasState::Editing,
            inner_alias_error: None,
            add_inner_request: false,
            manage_show_secret: false,
            unlock_request: false,
            wipe_request: false,
            delete_inner_request: false,
            test_upload_back: None,
            push_back: None,
            welcome_completions_status: None,
            welcome_completions_message: None,
        };
        app.refresh_welcome_completions_status();
        app
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        match self.screen {
            Screen::Welcome => self.handle_welcome(key),
            Screen::Provider => self.handle_provider(key),
            Screen::NextcloudServer => self.handle_server(key),
            Screen::NextcloudAuth => self.handle_auth(key),
            Screen::NextcloudLoginFlow => self.handle_login_flow(key),
            Screen::SetupGoogleDrive => self.handle_setup_google_drive(key),
            Screen::SetupOneDrive => self.handle_setup_onedrive(key),
            Screen::SetupDropbox => self.handle_setup_dropbox(key),
            Screen::RemoteFolder => self.handle_remote_folder(key),
            Screen::Collision => self.handle_collision(key),
            Screen::TestUpload => self.handle_test_upload(key),
            Screen::ProfilePassphrase => self.handle_passphrase(key),
            Screen::Done => self.handle_done(key),
            Screen::Account => self.handle_account(key),
            Screen::LoginTotp => self.handle_login_totp(key),
            Screen::PushProfile => self.handle_push_profile(key),
            Screen::ProfileUnlock => self.handle_profile_unlock(key),
            Screen::ProfileManage => self.handle_profile_manage(key),
            Screen::ContainerPicker => self.handle_container_picker(key),
            Screen::InnerAlias => self.handle_inner_alias(key),
        }
    }

    /// `true` when either a local-only or a server-synced profile blob
    /// is on disk. Drives the Welcome menu entry.
    pub fn profile_exists(&self) -> bool {
        self.local_exists || self.remote_exists
    }

    /// Compact, user-facing label for the configured server — strips
    /// the `https?://` prefix and any trailing path so the various
    /// screens can show `zz-drop.net` / `localhost:8080` instead of
    /// hardcoding a domain. Driven by `api_base` (which honours
    /// `ZZDROP_API_BASE`).
    pub fn server_label(&self) -> String {
        server_label_for(&self.api_base)
    }

    /// Enter the Account / LoginTotp / PushProfile sub-flow in the
    /// given mode (Push or SignIn), reusing `cached_session_token`
    /// when present so the operator doesn't re-type credentials in
    /// the same TUI session. `back` is the Esc destination from the
    /// push screens; `None` means the flow can only end via success
    /// or Ctrl-C (wizard mode).
    fn enter_push_flow_with_alias_list(
        &mut self,
        mode: PushFlowMode,
        back: Option<Screen>,
    ) {
        self.push_flow = PushFlowState::default();
        self.push_flow.mode = mode;
        self.push_alias_input = TextInput::new();
        self.push_back = back;
        self.post_login_target = None;
        if let Some(token) = self.cached_session_token.clone() {
            // Re-use existing session: skip Account/LoginTotp.
            self.push_flow.session_token = Some(token);
            self.push_flow.stage = PushStage::PushFetching;
            self.push_request_list = true;
            self.screen = Screen::PushProfile;
        } else {
            self.account_focus = AccountFocus::Email;
            self.account_email_input = TextInput::new();
            self.account_password_input = TextInput::masked();
            self.account_validation_error = None;
            self.totp_code_input = TextInput::new();
            self.screen = Screen::Account;
        }
    }

    /// Welcome → Open {Local,Remote}. Honours the in-memory cache:
    /// re-opening the same source skips the passphrase prompt; opening
    /// the *other* source clears the cache (so the previous decrypted
    /// profile is dropped from RAM) and re-prompts.
    fn open_profile(&mut self, target: ProfileSource) {
        self.unlock_source = target;
        self.manage_unlock_error = None;
        let cache_hit = self.cached_source == Some(target)
            && self.unlocked_set.is_some();
        if cache_hit {
            // Cache hit — skip the passphrase prompt and route to the
            // picker so the operator can choose any inner profile,
            // not just the last-active one. The cursor pre-selects
            // the previously-active alias if any (or the cached
            // sidecar default), so re-opening keeps muscle memory.
            self.manage_show_secret = false;
            if let (Some(set), Some(active)) =
                (self.unlocked_set.as_ref(), self.unlocked_profile.as_ref())
                && let Some(idx) =
                    set.profiles.iter().position(|p| p.alias == active.alias)
            {
                self.picker_index = idx;
            }
            self.unlocked_profile = None;
            self.manage_stage = ManageStage::Locked;
            self.screen = Screen::ContainerPicker;
        } else {
            // Cache miss or other source cached — drop any stale
            // decrypted profile from RAM and prompt for passphrase.
            self.unlocked_profile = None;
            self.unlocked_set = None;
            self.unlocked_kek = None;
            self.cached_source = None;
            self.manage_show_secret = false;
            self.manage_passphrase_input = TextInput::masked();
            self.manage_stage = ManageStage::Locked;
            self.screen = Screen::ProfileUnlock;
        }
    }

    /// Path to the profile blob the current Unlock/Manage flow is
    /// working on. Driven by `unlock_source`, which the Welcome
    /// dispatcher sets when the operator picks Open Local or Open
    /// Remote. Returns `None` if the chosen file is not on disk.
    pub fn active_profile_path(&self) -> Option<&std::path::Path> {
        match self.unlock_source {
            ProfileSource::Local if self.local_exists => self.profile_local_path.as_deref(),
            ProfileSource::Remote if self.remote_exists => self.profile_remote_path.as_deref(),
            // Fallback: the chosen slot is empty but the other isn't
            // — happen e.g. when the Welcome cursor was on `OpenLocal`
            // and only `profile-remote.zz` exists. Prefer remote.
            _ => {
                if self.remote_exists {
                    self.profile_remote_path.as_deref()
                } else if self.local_exists {
                    self.profile_local_path.as_deref()
                } else {
                    None
                }
            }
        }
    }

    fn handle_passphrase(&mut self, key: KeyEvent) {
        match &self.passphrase_stage {
            PassphraseStage::WeakWarning => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        self.passphrase_stage = PassphraseStage::Encrypting;
                        self.save_request = true;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        self.passphrase_stage = PassphraseStage::Editing;
                    }
                    _ => {}
                }
                return;
            }
            PassphraseStage::Encrypting => {
                // ignore keys while encrypting
                return;
            }
            PassphraseStage::Saved(_) => {
                // The blob is on disk as `profile-local.zz`. Pushing
                // it to a server is *optional* — the operator who
                // wants the file recoverable from any shell presses
                // `p`; the operator who wants a strictly local
                // profile presses Enter to land on Done with the
                // "no recovery" warning.
                match key.code {
                    KeyCode::Char('p') | KeyCode::Char('P') => {
                        self.push_flow = PushFlowState::default();
                        self.account_focus = AccountFocus::Email;
                        self.account_email_input = TextInput::new();
                        self.account_password_input = TextInput::masked();
                        self.account_validation_error = None;
                        self.totp_code_input = TextInput::new();
                        self.push_alias_input = TextInput::new();
                        self.push_back = None;
                        self.screen = Screen::Account;
                    }
                    KeyCode::Enter => {
                        // Skip the push: go straight to Done. The
                        // Done screen renders the local-only warning
                        // because `pushed_summary` is None.
                        self.screen = Screen::Done;
                    }
                    _ => {}
                }
                return;
            }
            PassphraseStage::Failed(_) => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                    self.passphrase_stage = PassphraseStage::Editing;
                }
                return;
            }
            PassphraseStage::Editing => {}
        }

        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::TestUpload;
            }
            KeyCode::Tab => {
                self.passphrase_focus = self.passphrase_focus.next();
            }
            KeyCode::BackTab => {
                self.passphrase_focus = self.passphrase_focus.next();
            }
            KeyCode::Enter => {
                self.try_save_profile();
            }
            KeyCode::Backspace => match self.passphrase_focus {
                PassphraseFocus::Passphrase => self.passphrase_input.backspace(),
                PassphraseFocus::Confirm => self.confirm_input.backspace(),
            },
            KeyCode::Char(c) => match self.passphrase_focus {
                PassphraseFocus::Passphrase => self.passphrase_input.push_char(c),
                PassphraseFocus::Confirm => self.confirm_input.push_char(c),
            },
            _ => {}
        }
    }

    fn try_save_profile(&mut self) {
        if self.passphrase_input.value().is_empty() {
            return;
        }
        if self.passphrase_input.value() != self.confirm_input.value() {
            return;
        }

        let strength = crate::strength::evaluate(self.passphrase_input.value());
        if strength.is_weak() {
            self.passphrase_stage = PassphraseStage::WeakWarning;
            return;
        }

        self.passphrase_stage = PassphraseStage::Encrypting;
        self.save_request = true;
    }

    pub fn apply_save_done(&mut self, path: String) {
        self.saved_path = Some(path.clone());
        // The wizard just (over)wrote `profile-local.zz`; any cached
        // local profile from a previous unlock in this session is
        // now stale.
        self.local_exists = true;
        if matches!(self.cached_source, Some(ProfileSource::Local)) {
            self.unlocked_profile = None;
            self.cached_source = None;
        }
        match self.wizard_mode {
            WizardMode::CreateLocal | WizardMode::AddInnerProfile => {
                // Park on the Saved stage; the operator decides
                // whether to push (`p`) or skip (`↵`).
                // (AddInnerProfile never reaches this branch in
                // practice — its save happens via the InnerAlias
                // screen — but cover it for exhaustiveness.)
                self.passphrase_stage = PassphraseStage::Saved(path);
            }
            WizardMode::CreateRemote => {
                // The operator logged in *before* the wizard, so the
                // cached session token sends us straight to the
                // alias picker. If the token has somehow vanished
                // (TUI bug, very long wizard, future-only feature),
                // fall through to a fresh login.
                self.passphrase_stage = PassphraseStage::Saved(path);
                self.enter_push_flow_with_alias_list(PushFlowMode::Push, None);
            }
        }
    }

    pub fn apply_save_failed(&mut self, reason: String) {
        self.passphrase_stage = PassphraseStage::Failed(reason);
    }

    fn handle_done(&mut self, key: KeyEvent) {
        // `q` exits the binary; `Enter` (or `b`) returns to Welcome
        // so the operator stays in the TUI to inspect the profile,
        // create another, sign in, etc. The profile they just saved
        // is now reachable via Open Local / Open Synced.
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('b') | KeyCode::Char('B') => {
                self.return_to_welcome_after_done();
            }
            _ => {}
        }
    }

    /// Reset the wizard's transient state and route back to Welcome
    /// from the Done screen. Keeps the in-RAM profile cache so the
    /// new file shows up under Open Local / Open Synced without
    /// re-typing the passphrase.
    fn return_to_welcome_after_done(&mut self) {
        self.passphrase_stage = PassphraseStage::Editing;
        self.passphrase_input = TextInput::masked();
        self.confirm_input = TextInput::masked();
        self.passphrase_focus = PassphraseFocus::Passphrase;
        self.saved_path = None;
        self.pushed_summary = None;
        self.push_flow = PushFlowState::default();
        // Drop the AddInnerProfile sticky mode now that the sub-flow
        // is fully closed. Subsequent Welcome picks set wizard_mode
        // explicitly anyway.
        self.wizard_mode = WizardMode::CreateLocal;
        // Move the menu cursor to the slot the just-saved profile
        // lives in, if any — that's the obvious next action.
        self.welcome_item = if self.remote_exists {
            WelcomeItem::OpenRemote
        } else if self.local_exists {
            WelcomeItem::OpenLocal
        } else {
            WelcomeItem::Configure
        };
        self.screen = Screen::Welcome;
    }

    // ── push sub-flow handlers (TASK 20 Phase 2) ───────────────────

    fn handle_account(&mut self, key: KeyEvent) {
        // No editing while a request is in flight.
        if matches!(self.push_flow.stage, PushStage::AccountSending) {
            return;
        }
        match key.code {
            // `Esc` exits the push flow when entered from
            // ProfileManage (re-push). In wizard auto-push mode
            // (`push_back == None`) it is normally a no-op so the
            // operator must finish the push or Ctrl-C — *except*
            // when the last login failed (server giù): in that
            // case we always allow an exit to Welcome so the user
            // is never trapped by an outage.
            KeyCode::Esc => {
                if let Some(back) = self.push_back.take() {
                    self.exit_push_flow_to(back);
                } else if matches!(self.push_flow.stage, PushStage::Failed(_)) {
                    self.exit_push_flow_to(Screen::Welcome);
                }
                return;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.account_focus = self.account_focus.next();
                return;
            }
            KeyCode::Enter => {
                match self.account_validate() {
                    Ok(()) => {
                        self.account_validation_error = None;
                        self.push_flow.stage = PushStage::AccountSending;
                        self.push_request_login = true;
                    }
                    Err(reason) => {
                        self.account_validation_error = Some(reason);
                    }
                }
                return;
            }
            _ => {}
        }
        // Any edit clears the inline validation hint so the user can
        // tell their fix has been registered.
        match self.account_focus {
            AccountFocus::Email => match key.code {
                KeyCode::Backspace => {
                    self.account_email_input.backspace();
                    self.account_validation_error = None;
                }
                KeyCode::Char(c) => {
                    self.account_email_input.push_char(c);
                    self.account_validation_error = None;
                }
                _ => {}
            },
            AccountFocus::Password => match key.code {
                KeyCode::Backspace => {
                    self.account_password_input.backspace();
                    self.account_validation_error = None;
                }
                KeyCode::Char(c) => {
                    self.account_password_input.push_char(c);
                    self.account_validation_error = None;
                }
                _ => {}
            },
        }
    }

    fn handle_login_totp(&mut self, key: KeyEvent) {
        if matches!(self.push_flow.stage, PushStage::TotpSending) {
            return;
        }
        match key.code {
            // `Esc` is a back-step here: returns to the Account form
            // so the operator can fix email/password if the TOTP
            // challenge is from a stale session.
            KeyCode::Esc => {
                self.screen = Screen::Account;
                self.push_flow.stage = PushStage::AccountForm;
                self.totp_code_input = TextInput::new();
            }
            KeyCode::Backspace => self.totp_code_input.backspace(),
            KeyCode::Enter => {
                if !self.totp_code_input.value().is_empty()
                    && self.push_flow.login_challenge.is_some()
                {
                    self.push_flow.stage = PushStage::TotpSending;
                    self.push_request_totp = true;
                }
            }
            KeyCode::Char(c) => self.totp_code_input.push_char(c),
            _ => {}
        }
    }

    fn handle_push_profile(&mut self, key: KeyEvent) {
        if matches!(
            self.push_flow.stage,
            PushStage::PushSending | PushStage::PushFetching
        ) {
            return;
        }
        if matches!(self.push_flow.stage, PushStage::Done) {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                // Re-push from ProfileManage: return there. Wizard
                // auto-push (no back-pointer): land on Done.
                let target = self.push_back.take().unwrap_or(Screen::Done);
                self.screen = target;
                self.push_flow = PushFlowState::default();
            }
            return;
        }
        if matches!(self.push_flow.stage, PushStage::Failed(_)) {
            // Network / server error: offer retry and an unconditional
            // back-out (Esc → Welcome even in wizard mode, so a server
            // outage doesn't trap the operator with no exit).
            match key.code {
                KeyCode::Esc => {
                    let target = self.push_back.unwrap_or(Screen::Welcome);
                    self.exit_push_flow_to(target);
                }
                KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => {
                    if self.push_flow.remote_aliases.is_empty() {
                        // List failed before we ever saw the picker
                        // — retry the alias list.
                        self.push_flow.stage = PushStage::PushFetching;
                        self.push_request_list = true;
                    } else {
                        // Picker was reached; the push or download
                        // itself failed — retry that.
                        self.push_flow.stage = PushStage::PushSending;
                        match self.push_flow.mode {
                            PushFlowMode::Push => self.push_request_send = true,
                            PushFlowMode::SignIn => self.signin_request_download = true,
                        }
                    }
                }
                _ => {}
            }
            return;
        }
        // `g` generates a fresh mnemonic alias suggestion
        // (`<adj>-<noun>-NN`) in the "new alias" field and switches
        // the picker out of selection mode so Enter targets the
        // typed value.
        if let KeyCode::Char('g') = key.code {
            let suggested = crate::alias_gen::suggest_alias();
            self.push_alias_input.set_value(&suggested);
            self.push_flow.picker_index = None;
            return;
        }
        match key.code {
            // `Esc` here only exits the push flow when entered from
            // ProfileManage (re-push). In wizard mode the only ways
            // forward are a successful push or Ctrl-C — failures
            // stay on this screen with a retry prompt.
            KeyCode::Esc => {
                if let Some(back) = self.push_back.take() {
                    self.exit_push_flow_to(back);
                }
                return;
            }
            KeyCode::Up => {
                if let Some(i) = self.push_flow.picker_index {
                    if i > 0 {
                        self.push_flow.picker_index = Some(i - 1);
                    }
                } else if !self.push_flow.remote_aliases.is_empty() {
                    self.push_flow.picker_index =
                        Some(self.push_flow.remote_aliases.len().saturating_sub(1));
                }
                return;
            }
            KeyCode::Down => {
                let n = self.push_flow.remote_aliases.len();
                if let Some(i) = self.push_flow.picker_index {
                    if i + 1 < n {
                        self.push_flow.picker_index = Some(i + 1);
                    } else {
                        self.push_flow.picker_index = None; // back to "type new"
                    }
                } else if n > 0 {
                    self.push_flow.picker_index = Some(0);
                }
                return;
            }
            KeyCode::Enter => {
                let alias = self
                    .push_flow
                    .picker_index
                    .and_then(|i| self.push_flow.remote_aliases.get(i).cloned())
                    .unwrap_or_else(|| self.push_alias_input.value().to_string());
                if alias.is_empty() {
                    return;
                }
                self.push_alias_input.set_value(&alias);
                self.push_flow.stage = PushStage::PushSending;
                match self.push_flow.mode {
                    PushFlowMode::Push => {
                        // Wizard push (push_back is None) and the
                        // alias differs from the wizard placeholder?
                        // Re-encrypt `profile-local.zz` with the
                        // chosen alias before pushing so file + server
                        // agree. (In re-push from ProfileManage the
                        // passphrase is no longer in RAM — we push
                        // the file as-is.)
                        let need_rewrite = self.push_back.is_none()
                            && alias != self.state.username
                            && !self.passphrase_input.value().is_empty();
                        if need_rewrite {
                            self.rewrite_blob_for_alias_request = true;
                        } else {
                            self.push_request_send = true;
                        }
                    }
                    PushFlowMode::SignIn => {
                        // Only allow downloading aliases the server
                        // actually has — typing a new one is a Push
                        // affordance that doesn't apply in SignIn.
                        if self.push_flow.remote_aliases.contains(&alias) {
                            self.signin_request_download = true;
                        } else {
                            self.push_flow.stage = PushStage::Failed(
                                "alias not on the server — pick one from the list".into(),
                            );
                        }
                    }
                }
                return;
            }
            _ => {}
        }
        // When typing into the "new alias" field, clear the picker
        // selection so Enter targets the typed value.
        if self.push_flow.picker_index.is_none() {
            match key.code {
                KeyCode::Backspace => self.push_alias_input.backspace(),
                KeyCode::Char(c) => self.push_alias_input.push_char(c),
                _ => {}
            }
        }
    }

    /// Reset the push sub-flow's transient state and route to
    /// `target`. Called by `Esc` on Account / PushProfile when the
    /// flow was entered with a back-pointer (re-push from
    /// ProfileManage).
    fn exit_push_flow_to(&mut self, target: Screen) {
        self.push_flow = PushFlowState::default();
        self.account_email_input = TextInput::new();
        self.account_password_input = TextInput::masked();
        self.account_validation_error = None;
        self.totp_code_input = TextInput::new();
        self.push_alias_input = TextInput::new();
        self.push_request_login = false;
        self.push_request_totp = false;
        self.push_request_list = false;
        self.push_request_send = false;
        self.signin_request_download = false;
        self.rewrite_blob_for_alias_request = false;
        self.screen = target;
    }

    /// Validate the Account form before any network round-trip. Order
    /// matters: when both fields are bad we surface the email reason
    /// first so the operator fixes the most-visible field first.
    fn account_validate(&self) -> Result<(), &'static str> {
        if !zz_drop_core::api::is_plausible_email(self.account_email_input.value()) {
            return Err("enter a valid email address");
        }
        if self.account_password_input.value().is_empty() {
            return Err("enter your password");
        }
        Ok(())
    }

    // Network outcome appliers — driven by main.rs after the sync
    // ureq call returns. They are public so the test harness can
    // simulate the network too.

    pub fn apply_login_session(&mut self, token: String) {
        self.cached_session_token = Some(token.clone());
        self.push_flow.session_token = Some(token);
        self.route_after_login();
    }

    pub fn apply_login_totp_required(&mut self, challenge: String) {
        self.push_flow.login_challenge = Some(challenge);
        self.push_flow.stage = PushStage::TotpForm;
        self.totp_code_input = TextInput::new();
        self.screen = Screen::LoginTotp;
    }

    pub fn apply_login_failed(&mut self, reason: String) {
        self.push_flow.stage = PushStage::Failed(reason);
    }

    pub fn apply_totp_session(&mut self, token: String) {
        self.cached_session_token = Some(token.clone());
        self.push_flow.session_token = Some(token);
        self.route_after_login();
    }

    /// Common post-login dispatch: honour `post_login_target`
    /// (CreateRemote → Provider) when set, otherwise fall through
    /// to the standard alias-picker (PushProfile).
    fn route_after_login(&mut self) {
        match self.post_login_target.take() {
            Some(target) => {
                // Login was a *prerequisite*, not the goal — go run
                // the wizard / whatever screen the caller wanted.
                // No alias-list fetch yet; that happens after save.
                self.push_flow.stage = PushStage::AccountForm;
                self.screen = target;
            }
            None => {
                self.push_flow.stage = PushStage::PushFetching;
                self.push_request_list = true;
                self.screen = Screen::PushProfile;
            }
        }
    }

    pub fn apply_totp_failed(&mut self, reason: String) {
        self.push_flow.stage = PushStage::Failed(reason);
    }

    pub fn apply_aliases_loaded(&mut self, aliases: Vec<String>) {
        self.push_flow.remote_aliases = aliases;
        self.push_flow.picker_index = if self.push_flow.remote_aliases.is_empty() {
            None
        } else {
            Some(0)
        };
        self.push_flow.stage = PushStage::PushForm;
    }

    pub fn apply_push_done(&mut self, alias: String, size: u64, version: u64) {
        self.push_flow.pushed_alias = Some(alias.clone());
        self.push_flow.pushed_size = size;
        self.push_flow.pushed_version = version;
        self.push_flow.stage = PushStage::Done;
        // Persist outside `push_flow` so the Done screen still has it
        // after `push_flow` is cleared on transition.
        self.pushed_summary = Some(PushedSummary {
            alias: alias.clone(),
            blob_size: size,
            blob_version: version,
        });
        // CreateRemote: mirror the encrypted blob into the remote
        // slot so the operator can use Open Synced from now on.
        // The blob is byte-identical (same encryption, same alias);
        // we just copy bytes — no extra encrypt round-trip.
        if matches!(self.wizard_mode, WizardMode::CreateRemote)
            && let (Some(local), Some(remote)) =
                (self.profile_local_path.as_ref(), self.profile_remote_path.as_ref())
            && let Ok(blob) = std::fs::read(local)
        {
            if let Some(parent) = remote.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(remote, &blob).is_ok() {
                self.remote_exists = true;
            }
        }
    }

    pub fn apply_push_failed(&mut self, reason: String) {
        self.push_flow.stage = PushStage::Failed(reason);
    }

    /// SignIn outcome: the encrypted blob has been written to
    /// `profile-remote.zz`. Clear the push sub-flow's transient
    /// state, mark the remote slot present, and route to
    /// `ProfileUnlock` so the operator can supply the passphrase.
    pub fn apply_signin_done(&mut self, alias: String) {
        self.remote_exists = true;
        self.unlock_source = ProfileSource::Remote;
        // SignIn just wrote a fresh `profile-remote.zz`; any cached
        // remote profile from earlier in the session is stale.
        if matches!(self.cached_source, Some(ProfileSource::Remote)) {
            self.unlocked_profile = None;
            self.cached_source = None;
        }
        self.manage_passphrase_input = TextInput::masked();
        self.manage_unlock_error = None;
        self.manage_stage = ManageStage::Locked;
        // Pretty side-effect: stash the alias on `pushed_summary` so
        // the unlock screen can mention "downloaded as <alias>".
        self.pushed_summary = Some(PushedSummary {
            alias,
            blob_size: 0,
            blob_version: 0,
        });
        self.push_flow = PushFlowState::default();
        self.account_email_input = TextInput::new();
        self.account_password_input = TextInput::masked();
        self.account_validation_error = None;
        self.totp_code_input = TextInput::new();
        self.push_alias_input = TextInput::new();
        self.push_back = None;
        self.screen = Screen::ProfileUnlock;
    }

    fn handle_login_flow(&mut self, key: KeyEvent) {
        // URL detail modal eats most keys.
        if self.login_flow.show_url_modal {
            if key.code == KeyCode::Esc {
                self.login_flow.show_url_modal = false;
            }
            return;
        }

        // `r` re-attempts the init when the previous one failed.
        if matches!(self.login_flow.stage, LoginFlowStage::Failed(_))
            && matches!(key.code, KeyCode::Char('r') | KeyCode::Char('R'))
        {
            self.login_flow = LoginFlowState::default();
            self.login_flow.stage = LoginFlowStage::Initiating;
            self.login_flow_request_init = true;
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.login_flow = LoginFlowState::default();
                self.screen = Screen::NextcloudAuth;
            }
            KeyCode::Char('q') => {
                if matches!(self.login_flow.stage, LoginFlowStage::Polling) {
                    self.login_flow.show_qr = !self.login_flow.show_qr;
                }
            }
            KeyCode::Char('i') => {
                // Toggle the inline-image renderer. Some terminals advertise
                // Kitty/iTerm/Sixel support via DA1 but leave the magic
                // bytes invisible — the user wants the half-block ASCII QR
                // in that case.
                if matches!(self.login_flow.stage, LoginFlowStage::Polling) {
                    self.login_flow.disable_inline_qr = !self.login_flow.disable_inline_qr;
                }
            }
            KeyCode::Char('c') => {
                if !self.login_flow.login_url.is_empty() {
                    let msg = match clipboard::copy_to_clipboard(&self.login_flow.login_url) {
                        Ok(()) => "copied",
                        Err(reason) => reason,
                    };
                    self.login_flow.clipboard_message = Some(msg);
                }
            }
            KeyCode::Char('o') => {
                if !self.login_flow.login_url.is_empty() {
                    let msg = match clipboard::open_in_browser(&self.login_flow.login_url) {
                        Ok(()) => "opened",
                        Err(reason) => reason,
                    };
                    self.login_flow.browser_message = Some(msg);
                }
            }
            KeyCode::Char('u') => {
                if !self.login_flow.login_url.is_empty() {
                    self.login_flow.show_url_modal = true;
                }
            }
            KeyCode::Enter => {
                if matches!(self.login_flow.stage, LoginFlowStage::Done) {
                    self.screen = Screen::RemoteFolder;
                }
            }
            _ => {}
        }
    }

    fn handle_welcome(&mut self, key: KeyEvent) {
        let items = self.welcome_items_active();
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => self.should_quit = true,
            KeyCode::Up | KeyCode::Char('k') => {
                self.welcome_item = self.welcome_item.previous_in(&items);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.welcome_item = self.welcome_item.next_in(&items);
            }
            KeyCode::Enter | KeyCode::Right => match self.welcome_item {
                WelcomeItem::OpenLocal => {
                    if self.local_exists {
                        self.open_profile(ProfileSource::Local);
                    }
                }
                WelcomeItem::OpenRemote => {
                    if self.remote_exists {
                        self.open_profile(ProfileSource::Remote);
                    }
                }
                WelcomeItem::Configure => {
                    if self.local_exists {
                        // The local container already exists: this
                        // entry now means "add a new connection to
                        // it" rather than "wipe and start over".
                        // Route through ProfileUnlock so the
                        // operator authenticates the existing
                        // container; `apply_unlock_set_done`
                        // detects `AddInnerProfile` mode and lands
                        // on the Provider screen instead of the
                        // picker/manage.
                        self.wizard_mode = WizardMode::AddInnerProfile;
                        self.unlock_source = ProfileSource::Local;
                        self.unlocked_profile = None;
                        self.cached_source = None;
                        self.manage_show_secret = false;
                        self.manage_passphrase_input = TextInput::masked();
                        self.manage_unlock_error = None;
                        self.manage_stage = ManageStage::Locked;
                        self.screen = Screen::ProfileUnlock;
                    } else {
                        // No container yet: classic "create local
                        // container" flow.
                        self.wizard_mode = WizardMode::CreateLocal;
                        self.screen = self.screen.next();
                    }
                }
                WelcomeItem::ConfigureRemote => {
                    self.wizard_mode = WizardMode::CreateRemote;
                    if let Some(token) = self.cached_session_token.clone() {
                        // Already authenticated in this session —
                        // skip Account/LoginTotp and go straight
                        // into the wizard. The token is parked on
                        // `push_flow` so the post-save push uses it.
                        self.push_flow = PushFlowState::default();
                        self.push_flow.session_token = Some(token);
                        self.post_login_target = None;
                        self.screen = Screen::Provider;
                    } else {
                        // Server login *first*, wizard *after* — so
                        // we never write `profile-local.zz` only to
                        // discover the server is unreachable.
                        self.push_flow = PushFlowState::default();
                        self.account_focus = AccountFocus::Email;
                        self.account_email_input = TextInput::new();
                        self.account_password_input = TextInput::masked();
                        self.account_validation_error = None;
                        self.totp_code_input = TextInput::new();
                        self.push_back = Some(Screen::Welcome);
                        self.post_login_target = Some(Screen::Provider);
                        self.screen = Screen::Account;
                    }
                }
                WelcomeItem::SignIn => {
                    // Reuse the push sub-flow (Account → LoginTotp →
                    // PushProfile) in SignIn mode. After the operator
                    // picks an alias, the main loop downloads the
                    // blob and saves it as `profile-remote.zz`.
                    self.enter_push_flow_with_alias_list(
                        PushFlowMode::SignIn,
                        Some(Screen::Welcome),
                    );
                }
                WelcomeItem::SetupCompletions => self.run_setup_completions(),
                WelcomeItem::Quit => self.should_quit = true,
            },
            _ => {}
        }
    }

    /// Items currently selectable on the Welcome menu, in display
    /// order. The menu is laid out in two sections — a LOCAL block
    /// (`OpenLocal` if the file exists, then `Configure`) and a
    /// REMOTE block (`OpenRemote` if the file exists, then
    /// `ConfigureRemote`, then `SignIn`) — followed by `Quit`.
    /// Up/Down walks through this same order.
    pub fn welcome_items_active(&self) -> Vec<WelcomeItem> {
        let mut v = Vec::with_capacity(7);
        if self.local_exists {
            v.push(WelcomeItem::OpenLocal);
        }
        v.push(WelcomeItem::Configure);
        // The REMOTE block is only reachable when the `remote`
        // feature is on. In default builds the operator stays in the
        // local-only flow; the menu has no entries that can't fire.
        #[cfg(feature = "remote")]
        {
            if self.remote_exists {
                v.push(WelcomeItem::OpenRemote);
            }
            v.push(WelcomeItem::ConfigureRemote);
            v.push(WelcomeItem::SignIn);
        }
        v.push(WelcomeItem::SetupCompletions);
        v.push(WelcomeItem::Quit);
        v
    }

    /// Build the InstallRequest from the operator's environment.
    /// Returns `None` when `$SHELL` is unset / unsupported or HOME
    /// can't be resolved — the welcome row then refuses to install
    /// and shows the reason as the status line.
    fn build_completions_request(
        shell: zz_drop_core::completions::Shell,
        script: &'static str,
    ) -> Option<zz_drop_core::completions::InstallRequest<'static>> {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from)?;
        Some(zz_drop_core::completions::InstallRequest {
            shell,
            script,
            home,
            xdg_data_home: std::env::var_os("XDG_DATA_HOME").map(std::path::PathBuf::from),
            zdotdir: std::env::var_os("ZDOTDIR").map(std::path::PathBuf::from),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(std::path::PathBuf::from),
        })
    }

    /// Refresh `welcome_completions_status` from the filesystem.
    /// Called on entry to the Welcome screen and after a successful
    /// install. Best-effort: errors collapse to "missing" so the
    /// menu suggests installing.
    pub fn refresh_welcome_completions_status(&mut self) {
        let Some(shell) = zz_drop_core::completions::Shell::detect_from_env() else {
            self.welcome_completions_status = None;
            return;
        };
        // status() doesn't read the script body, so the empty string
        // is harmless — it just needs the path-resolution fields.
        let Some(req) = Self::build_completions_request(shell, "") else {
            self.welcome_completions_status = None;
            return;
        };
        self.welcome_completions_status = Some(zz_drop_core::completions::status(&req));
    }

    fn run_setup_completions(&mut self) {
        let Some(shell) = zz_drop_core::completions::Shell::detect_from_env() else {
            self.welcome_completions_message =
                Some("$SHELL unset or unsupported (run `zz --setup-completions <shell>` from a shell).".into());
            return;
        };
        let script = zz_drop_core::completions::scripts::for_shell(shell);
        let Some(req) = Self::build_completions_request(shell, script) else {
            self.welcome_completions_message = Some("$HOME unset; can't install.".into());
            return;
        };
        match zz_drop_core::completions::install(&req) {
            Ok(outcome) => {
                let mut msg = format!(
                    "✓ {} completions installed → {}",
                    outcome.shell.as_str(),
                    outcome.completion_path.display()
                );
                if let Some(hint) = &outcome.hint {
                    msg.push_str(&format!(" ({hint})"));
                }
                self.welcome_completions_message = Some(msg);
            }
            Err(e) => {
                self.welcome_completions_message = Some(format!("install failed: {e}"));
            }
        }
        self.refresh_welcome_completions_status();
    }

    fn handle_profile_unlock(&mut self, key: KeyEvent) {
        if matches!(self.manage_stage, ManageStage::Unlocking) {
            return;
        }
        match key.code {
            KeyCode::Esc => {
                self.manage_passphrase_input = TextInput::masked();
                self.manage_unlock_error = None;
                self.screen = Screen::Welcome;
            }
            KeyCode::Backspace => self.manage_passphrase_input.backspace(),
            KeyCode::Enter => {
                if !self.manage_passphrase_input.value().is_empty() {
                    self.manage_stage = ManageStage::Unlocking;
                    self.manage_unlock_error = None;
                    self.unlock_request = true;
                }
            }
            KeyCode::Char(c) => self.manage_passphrase_input.push_char(c),
            _ => {}
        }
    }

    fn handle_profile_manage(&mut self, key: KeyEvent) {
        // Wipe confirmation sub-state.
        if matches!(self.manage_stage, ManageStage::WipeConfirm) {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.manage_stage = ManageStage::Wiping;
                    self.wipe_request = true;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.manage_stage = ManageStage::Viewing;
                }
                _ => {}
            }
            return;
        }
        if matches!(self.manage_stage, ManageStage::Wiping) {
            return; // request in flight
        }
        // Inner-profile delete confirmation sub-state.
        if matches!(self.manage_stage, ManageStage::DeleteInnerConfirm) {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.manage_stage = ManageStage::DeletingInner;
                    self.delete_inner_request = true;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.manage_stage = ManageStage::Viewing;
                    self.manage_unlock_error = None;
                }
                _ => {}
            }
            return;
        }
        if matches!(self.manage_stage, ManageStage::DeletingInner) {
            return; // request in flight
        }

        match key.code {
            KeyCode::Esc => {
                // Return to Welcome but keep the decrypted profile
                // in RAM (`cached_source` matches `unlock_source`).
                // If the operator picks the other source from
                // Welcome, `open_profile` will drop the cache and
                // re-prompt. If they pick the same source again,
                // they skip the passphrase. The cache lives only
                // for the current TUI session.
                self.manage_show_secret = false;
                self.manage_passphrase_input = TextInput::masked();
                self.manage_stage = ManageStage::Locked;
                self.screen = Screen::Welcome;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.manage_show_secret = !self.manage_show_secret;
            }
            KeyCode::Char('w') | KeyCode::Char('W') => {
                self.manage_stage = ManageStage::WipeConfirm;
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                // Re-push: blob is on disk, `saved_path` is set —
                // either re-use the cached session token or log in.
                // Esc from the push screens returns here.
                self.enter_push_flow_with_alias_list(
                    PushFlowMode::Push,
                    Some(Screen::ProfileManage),
                );
            }
            KeyCode::Char('t') | KeyCode::Char('T') => {
                // Re-test: jump to TestUpload with the unlocked
                // profile fields already populating `state`. Esc
                // from TestUpload returns to ProfileManage thanks
                // to `test_upload_back`.
                self.test_upload_back = Some(Screen::ProfileManage);
                self.screen = Screen::TestUpload;
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                // Add new connection: start a fresh wizard sub-flow
                // that ends in `InnerAlias`. The container's KEK is
                // cached (`unlocked_kek`), so the operator does not
                // re-enter the passphrase. Requires the container to
                // be unlocked (always true on this screen).
                if self.unlocked_kek.is_none() || self.unlocked_set.is_none() {
                    self.manage_unlock_error = Some(
                        "internal: no cached KEK; cannot add connection".into(),
                    );
                    return;
                }
                self.start_add_inner_profile();
            }
            // Uppercase-only `D` so it is impossible to delete an
            // inner profile by typo. Lowercase `w` already maps to
            // wipe-the-whole-container; `D` is the scoped variant.
            KeyCode::Char('D') => {
                if self.unlocked_kek.is_none() || self.unlocked_set.is_none() {
                    self.manage_unlock_error = Some(
                        "internal: no cached KEK; cannot delete connection".into(),
                    );
                    return;
                }
                let count = self
                    .unlocked_set
                    .as_ref()
                    .map(|s| s.profiles.len())
                    .unwrap_or(0);
                if count <= 1 {
                    // Refuse instead of leaving an empty container —
                    // the operator should use `w` to wipe the whole
                    // file (or add another profile first).
                    self.manage_unlock_error = Some(
                        "this is the last profile in the container — use `w` to wipe everything, or `a` to add another first".into(),
                    );
                    return;
                }
                self.manage_unlock_error = None;
                self.manage_stage = ManageStage::DeleteInnerConfirm;
            }
            _ => {}
        }
    }

    /// Reset the wizard state for a fresh provider-setup walk and
    /// route to `Screen::Provider`. The cached KEK / set in
    /// `unlocked_*` survive, so the save step can re-encrypt.
    fn start_add_inner_profile(&mut self) {
        self.state = WizardState::default();
        self.gdrive_setup = GoogleDriveSetupState::default();
        self.server_input.set_value("https://");
        self.username_input = TextInput::new();
        self.secret_input = TextInput::masked();
        self.remote_folder_input = TextInput::new();
        self.wizard_mode = WizardMode::AddInnerProfile;
        self.screen = Screen::Provider;
    }

    fn prepare_inner_alias_input(&mut self) {
        let suggestion = match self.state.provider_kind {
            ProviderKind::Nextcloud => {
                crate::alias_gen::suggest_alias_for(crate::alias_gen::ProviderPrefix::Nextcloud)
            }
            ProviderKind::GoogleDrive => crate::alias_gen::suggest_alias_for(
                crate::alias_gen::ProviderPrefix::GoogleDrive,
            ),
            ProviderKind::OneDrive => crate::alias_gen::suggest_alias_for(
                crate::alias_gen::ProviderPrefix::OneDrive,
            ),
            ProviderKind::Dropbox => {
                crate::alias_gen::suggest_alias_for(crate::alias_gen::ProviderPrefix::Dropbox)
            }
        };
        self.inner_alias_input.set_value(&suggestion);
        self.inner_alias_state = crate::screens::inner_alias::InnerAliasState::Editing;
        self.inner_alias_error = None;
    }

    fn handle_inner_alias(&mut self, key: KeyEvent) {
        use crate::screens::inner_alias::InnerAliasState as S;
        if matches!(self.inner_alias_state, S::Saving) {
            return;
        }
        match key.code {
            KeyCode::Esc => {
                self.inner_alias_input = TextInput::new();
                self.inner_alias_state = S::Editing;
                self.inner_alias_error = None;
                // Came from manage's "add another profile" → back to
                // manage. Came from welcome's "Add to local container"
                // before a profile was picked → unlocked_profile is
                // None, so route to the picker so the operator lands
                // somewhere useful instead of an empty manage.
                self.screen = if self.unlocked_profile.is_some() {
                    Screen::ProfileManage
                } else if self.unlocked_set.is_some() {
                    Screen::ContainerPicker
                } else {
                    Screen::Welcome
                };
            }
            KeyCode::Tab => {
                self.prepare_inner_alias_input();
            }
            KeyCode::Backspace => self.inner_alias_input.backspace(),
            KeyCode::Char(c) if !c.is_control() => {
                self.inner_alias_input.push_char(c);
            }
            KeyCode::Enter => {
                let alias = self.inner_alias_input.value().trim().to_string();
                if !zz_drop_core::sidecars::validate_alias(&alias) {
                    self.inner_alias_state = S::Failed;
                    self.inner_alias_error = Some("alias rejected (charset / length)".into());
                    return;
                }
                if self
                    .unlocked_set
                    .as_ref()
                    .is_some_and(|s| s.contains_alias(&alias))
                {
                    self.inner_alias_state = S::Failed;
                    self.inner_alias_error = Some(
                        "alias already exists in this container".into(),
                    );
                    return;
                }
                // First-setup branch (CreateLocal / CreateRemote):
                // the container does not exist yet, the agent
                // does not have a cached KEK, so we cannot append.
                // Stash the alias and advance to the passphrase
                // screen — `run_save_profile` will pick it up via
                // `state.alias_override`.
                if self.wizard_mode != WizardMode::AddInnerProfile {
                    self.state.alias_override = Some(alias);
                    self.inner_alias_input = TextInput::new();
                    self.inner_alias_state = S::Editing;
                    self.inner_alias_error = None;
                    self.screen = Screen::ProfilePassphrase;
                    return;
                }
                self.inner_alias_state = S::Saving;
                self.inner_alias_error = None;
                self.add_inner_request = true;
            }
            _ => {}
        }
    }

    /// main.rs flow result: container persisted, agent updated, the
    /// new inner profile is the active one. Routes to the Done
    /// screen (rendered in "connection added" mode) so the operator
    /// gets a clear confirmation step before being dropped back at
    /// Welcome — and the wizard stepper has a final "done" tick
    /// instead of vanishing the moment the alias is committed.
    pub fn apply_inner_added(
        &mut self,
        new_set: zz_drop_core::ProfileSet,
        active_alias: String,
    ) {
        // Pick the freshly added profile out of the new set.
        let profile = new_set
            .find_by_alias(&active_alias)
            .cloned()
            .expect("newly added alias must be present in the new set");
        self.unlocked_set = Some(new_set);
        self.hydrate_from_inner(&profile);
        self.unlocked_profile = Some(profile);
        self.inner_alias_input = TextInput::new();
        self.inner_alias_state = crate::screens::inner_alias::InnerAliasState::Editing;
        self.inner_alias_error = None;
        // `wizard_mode` stays at AddInnerProfile so the Done screen
        // and the stepper render the sub-flow's tail. It gets reset
        // to CreateLocal in `return_to_welcome_after_done`.
        if let Some(p) = self.active_profile_path() {
            self.saved_path = Some(p.display().to_string());
        }
        self.manage_stage = ManageStage::Viewing;
        self.screen = Screen::Done;
    }

    pub fn apply_inner_failed(&mut self, reason: String) {
        self.inner_alias_state = crate::screens::inner_alias::InnerAliasState::Failed;
        self.inner_alias_error = Some(reason);
    }

    /// main.rs flow result for the inner-profile delete: container
    /// re-encrypted on disk and the agent's RAM snapshot updated.
    /// Drops the just-deleted alias from `unlocked_profile`,
    /// refreshes `unlocked_set`, clears the cached default if it
    /// pointed at the removed alias, and routes to the picker so
    /// the operator chooses what to manage next.
    pub fn apply_inner_deleted(
        &mut self,
        new_set: zz_drop_core::ProfileSet,
        deleted_alias: String,
    ) {
        if self.picker_default_alias.as_deref() == Some(deleted_alias.as_str()) {
            self.picker_default_alias = None;
        }
        let default = self.picker_default_alias.as_deref();
        let default_idx = default
            .and_then(|d| new_set.profiles.iter().position(|p| p.alias == d))
            .unwrap_or(0);
        self.picker_index = default_idx;
        self.unlocked_set = Some(new_set);
        self.unlocked_profile = None;
        self.manage_unlock_error = None;
        self.manage_stage = ManageStage::Viewing;
        self.screen = Screen::ContainerPicker;
    }

    pub fn apply_inner_delete_failed(&mut self, reason: String) {
        self.manage_stage = ManageStage::Viewing;
        self.manage_unlock_error = Some(format!("delete failed: {reason}"));
    }

    /// Successful unlock from a container that holds exactly one
    /// inner profile (or pre-container legacy bridge). Hydrates the
    /// wizard `state` fields the re-test / re-push flows need and
    /// routes to the manage screen.
    pub fn apply_unlock_done(&mut self, profile: PlainProfile) {
        self.hydrate_from_inner(&profile);
        if let Some(p) = self.active_profile_path() {
            self.saved_path = Some(p.display().to_string());
        }
        self.unlocked_profile = Some(profile);
        self.cached_source = Some(self.unlock_source);
        self.manage_stage = ManageStage::Viewing;
        self.manage_unlock_error = None;
        self.screen = Screen::ProfileManage;
        self.manage_passphrase_input = TextInput::masked();
    }

    /// Successful unlock of a container with N≥1 inner profiles.
    /// With N==1, equivalent to `apply_unlock_done` on the single
    /// profile. With N>1, routes to the picker pre-selected on the
    /// sidecar default (or the first profile if no default).
    pub fn apply_unlock_set_done(
        &mut self,
        set: zz_drop_core::ProfileSet,
        kek: zz_drop_core::ProfileKek,
        default_alias: Option<String>,
    ) {
        // "Add to local container" path: the operator unlocked the
        // container only to append a new inner profile to it. Skip
        // the picker / manage screens and go straight to the
        // wizard's Provider screen with state reset.
        if self.wizard_mode == WizardMode::AddInnerProfile {
            self.unlocked_set = Some(set);
            self.unlocked_kek = Some(kek);
            self.picker_default_alias = default_alias;
            self.cached_source = Some(self.unlock_source);
            self.manage_passphrase_input = TextInput::masked();
            self.manage_unlock_error = None;
            self.start_add_inner_profile();
            return;
        }

        // Always present the picker post-unlock — even with a single
        // inner profile. The list confirms what the operator just
        // unlocked and gives muscle memory for the multi-profile
        // case. The cursor pre-selects the cached default (or the
        // first profile if no default).
        let default_idx = default_alias
            .as_deref()
            .and_then(|d| set.profiles.iter().position(|p| p.alias == d))
            .unwrap_or(0);

        self.picker_index = default_idx;
        self.picker_default_alias = default_alias;
        self.unlocked_set = Some(set);
        self.unlocked_kek = Some(kek);
        self.cached_source = Some(self.unlock_source);
        self.manage_stage = ManageStage::Viewing;
        self.manage_unlock_error = None;
        self.screen = Screen::ContainerPicker;
        self.manage_passphrase_input = TextInput::masked();
    }

    /// Common hydration path: populate the wizard `state` and field
    /// inputs from an inner profile.
    fn hydrate_from_inner(&mut self, profile: &PlainProfile) {
        self.state.collision = profile.collision_policy;
        if let Some(nc) = profile.providers.iter().find_map(|p| match p {
            zz_drop_core::ProviderProfile::Nextcloud(n) => Some(n),
            zz_drop_core::ProviderProfile::GoogleDrive(_) => None,
            zz_drop_core::ProviderProfile::OneDrive(_) => None,
            zz_drop_core::ProviderProfile::Dropbox(_) => None,
            zz_drop_core::ProviderProfile::Unknown(_) => None,
        }) {
            self.state.provider_kind = ProviderKind::Nextcloud;
            self.state.server_url = nc.server_url.clone();
            self.state.username = nc.username.clone();
            self.state.remote_folder = nc.remote_root.clone();
            let (kind, secret) = match &nc.auth {
                zz_drop_core::NextcloudAuth::AppPassword { secret } => {
                    (AuthKind::AppPassword, secret.clone())
                }
                zz_drop_core::NextcloudAuth::LoginFlowToken { secret } => {
                    (AuthKind::LoginFlow, secret.clone())
                }
            };
            self.state.auth_secret = secret;
            self.state.auth_kind = kind;
            self.username_input.set_value(&nc.username);
            self.secret_input.set_value(&self.state.auth_secret);
            self.server_input.set_value(&nc.server_url);
            self.remote_folder_input.set_value(&nc.remote_root);
        } else if let Some(gd) = profile.providers.iter().find_map(|p| match p {
            zz_drop_core::ProviderProfile::GoogleDrive(g) => Some(g),
            zz_drop_core::ProviderProfile::Nextcloud(_) => None,
            zz_drop_core::ProviderProfile::OneDrive(_) => None,
            zz_drop_core::ProviderProfile::Dropbox(_) => None,
            zz_drop_core::ProviderProfile::Unknown(_) => None,
        }) {
            self.state.provider_kind = ProviderKind::GoogleDrive;
            self.gdrive_setup = GoogleDriveSetupState::default();
            self.gdrive_setup.user_email = gd.user_email.clone();
            self.gdrive_setup.root_folder = gd.root_folder.clone();
            self.gdrive_setup.access_token = gd.auth.access_token.clone();
            self.gdrive_setup.refresh_token = gd.auth.refresh_token.clone();
            self.gdrive_setup.token_type = gd.auth.token_type.clone();
            self.gdrive_setup.access_expires_at = gd.auth.expires_at;
            self.gdrive_setup.scope = gd.auth.scope.clone();
            self.gdrive_setup.stage = GoogleDriveSetupStage::Done;
        } else if let Some(od) = profile.providers.iter().find_map(|p| match p {
            zz_drop_core::ProviderProfile::OneDrive(o) => Some(o),
            zz_drop_core::ProviderProfile::Nextcloud(_) => None,
            zz_drop_core::ProviderProfile::GoogleDrive(_) => None,
            zz_drop_core::ProviderProfile::Dropbox(_) => None,
            zz_drop_core::ProviderProfile::Unknown(_) => None,
        }) {
            self.state.provider_kind = ProviderKind::OneDrive;
            self.onedrive_setup = OneDriveSetupState::default();
            self.onedrive_setup.user_email = od.user_email.clone();
            self.onedrive_setup.root_folder = od.root_folder.clone();
            self.onedrive_setup.access_token = od.auth.access_token.clone();
            self.onedrive_setup.refresh_token = od.auth.refresh_token.clone();
            self.onedrive_setup.token_type = od.auth.token_type.clone();
            self.onedrive_setup.access_expires_at = od.auth.expires_at;
            self.onedrive_setup.scope = od.auth.scope.clone();
            self.onedrive_setup.stage = OneDriveSetupStage::Done;
        } else if let Some(db) = profile.providers.iter().find_map(|p| match p {
            zz_drop_core::ProviderProfile::Dropbox(d) => Some(d),
            zz_drop_core::ProviderProfile::Nextcloud(_) => None,
            zz_drop_core::ProviderProfile::GoogleDrive(_) => None,
            zz_drop_core::ProviderProfile::OneDrive(_) => None,
            zz_drop_core::ProviderProfile::Unknown(_) => None,
        }) {
            self.state.provider_kind = ProviderKind::Dropbox;
            self.dropbox_setup = DropboxSetupState::default();
            self.dropbox_setup.user_email = db.user_email.clone();
            self.dropbox_setup.root_folder = db.root_folder.clone();
            self.dropbox_setup.access_token = db.auth.access_token.clone();
            self.dropbox_setup.refresh_token = db.auth.refresh_token.clone();
            self.dropbox_setup.token_type = db.auth.token_type.clone();
            self.dropbox_setup.access_expires_at = db.auth.expires_at;
            self.dropbox_setup.scope = db.auth.scope.clone();
            self.dropbox_setup.stage = DropboxSetupStage::Done;
        }
    }

    /// Picker key handling: ↑/↓ navigate, Enter confirms, Esc locks.
    fn handle_container_picker(&mut self, key: KeyEvent) {
        let len = self
            .unlocked_set
            .as_ref()
            .map(|s| s.profiles.len())
            .unwrap_or(0);
        if len == 0 {
            // Defensive: shouldn't be reachable, but lock and bail.
            self.lock_picker_state();
            self.screen = Screen::Welcome;
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.picker_index == 0 {
                    self.picker_index = len - 1;
                } else {
                    self.picker_index -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.picker_index = (self.picker_index + 1) % len;
            }
            KeyCode::Enter => {
                self.confirm_picker_selection();
            }
            KeyCode::Esc => {
                // Esc from the picker locks the container, mirroring
                // CLI Esc semantics.
                self.lock_picker_state();
                self.screen = Screen::Welcome;
            }
            _ => {}
        }
    }

    /// Materialise the picker's current selection: hydrate state,
    /// store the active inner profile, route to manage.
    fn confirm_picker_selection(&mut self) {
        let Some(set) = self.unlocked_set.as_ref() else {
            return;
        };
        let Some(profile) = set.profiles.get(self.picker_index).cloned() else {
            return;
        };
        self.hydrate_from_inner(&profile);
        if let Some(p) = self.active_profile_path() {
            self.saved_path = Some(p.display().to_string());
        }
        self.unlocked_profile = Some(profile);
        self.manage_stage = ManageStage::Viewing;
        self.manage_unlock_error = None;
        self.screen = Screen::ProfileManage;
    }

    fn lock_picker_state(&mut self) {
        self.unlocked_set = None;
        self.unlocked_kek = None;
        self.picker_index = 0;
        self.picker_default_alias = None;
        self.unlocked_profile = None;
    }

    pub fn apply_unlock_failed(&mut self, reason: String) {
        self.manage_stage = ManageStage::Locked;
        self.manage_unlock_error = Some(reason);
    }

    pub fn apply_wipe_done(&mut self) {
        self.unlocked_profile = None;
        self.cached_source = None;
        self.cached_session_token = None;
        self.post_login_target = None;
        self.saved_path = None;
        self.local_exists = false;
        self.remote_exists = false;
        self.manage_show_secret = false;
        self.manage_stage = ManageStage::Locked;
        self.welcome_item = WelcomeItem::Configure;
        self.screen = Screen::Welcome;
    }

    pub fn apply_wipe_failed(&mut self, reason: String) {
        self.manage_stage = ManageStage::Viewing;
        self.manage_unlock_error = Some(format!("wipe failed: {reason}"));
    }

    fn handle_provider(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Left => {
                self.screen = self.screen.previous();
            }
            // Up/Down cycle through the four real providers
            // (Nextcloud → Google Drive → OneDrive → Dropbox).
            // The Proton entry is listed but disabled until a real
            // SDK lands; not selectable here.
            KeyCode::Up | KeyCode::Char('k') => {
                self.state.provider_kind = match self.state.provider_kind {
                    ProviderKind::Nextcloud => ProviderKind::Dropbox,
                    ProviderKind::GoogleDrive => ProviderKind::Nextcloud,
                    ProviderKind::OneDrive => ProviderKind::GoogleDrive,
                    ProviderKind::Dropbox => ProviderKind::OneDrive,
                };
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.state.provider_kind = match self.state.provider_kind {
                    ProviderKind::Nextcloud => ProviderKind::GoogleDrive,
                    ProviderKind::GoogleDrive => ProviderKind::OneDrive,
                    ProviderKind::OneDrive => ProviderKind::Dropbox,
                    ProviderKind::Dropbox => ProviderKind::Nextcloud,
                };
            }
            KeyCode::Enter | KeyCode::Char('n') | KeyCode::Right => {
                self.screen = match self.state.provider_kind {
                    ProviderKind::Nextcloud => Screen::NextcloudServer,
                    ProviderKind::GoogleDrive => {
                        // Reset any stale device-flow state from a
                        // previous attempt and trigger a fresh
                        // `initiate` on the next main-loop tick.
                        self.gdrive_setup = GoogleDriveSetupState::default();
                        self.gdrive_request_init = true;
                        Screen::SetupGoogleDrive
                    }
                    ProviderKind::OneDrive => {
                        self.onedrive_setup = OneDriveSetupState::default();
                        self.onedrive_request_init = true;
                        Screen::SetupOneDrive
                    }
                    ProviderKind::Dropbox => {
                        self.dropbox_setup = DropboxSetupState::default();
                        self.dropbox_request_init = true;
                        Screen::SetupDropbox
                    }
                };
            }
            _ => {}
        }
    }

    fn handle_setup_dropbox(&mut self, key: KeyEvent) {
        // Paste-code flow — distinct from device-flow handlers above:
        // there is no `Polling` stage to QR-toggle from, the only
        // editable input is `pasted_code`, and Enter triggers the
        // single-shot exchange instead of waiting for a poll loop.
        if self.dropbox_setup.show_url_modal {
            if key.code == KeyCode::Esc {
                self.dropbox_setup.show_url_modal = false;
            }
            return;
        }

        if matches!(self.dropbox_setup.stage, DropboxSetupStage::Failed(_))
            && matches!(key.code, KeyCode::Char('r') | KeyCode::Char('R'))
        {
            self.dropbox_setup = DropboxSetupState::default();
            self.dropbox_setup.stage = DropboxSetupStage::Initiating;
            self.dropbox_request_init = true;
            return;
        }

        // Editable input is gated to the AwaitingPaste stage.
        let editable = matches!(self.dropbox_setup.stage, DropboxSetupStage::AwaitingPaste);
        // Single-letter shortcuts (q / i / c / o / u) only fire
        // *before* the operator has started typing or pasting the
        // code. After that, every printable char must reach the
        // textbox — otherwise a code that happens to contain `q`
        // (toggle QR), `c`, `o`, etc. would silently mutate the
        // screen state instead of being entered. Once the field
        // has any content, only Enter / Backspace / Esc / Ctrl-V
        // are honoured, plus typing.
        let action_keys_active = editable && self.dropbox_setup.pasted_code.value().is_empty();

        match key.code {
            KeyCode::Esc => {
                self.dropbox_setup = DropboxSetupState::default();
                self.dropbox_request_init = false;
                self.dropbox_request_exchange = false;
                self.dropbox_request_email = false;
                self.screen = Screen::Provider;
            }
            KeyCode::Char('q') if action_keys_active => {
                self.dropbox_setup.show_qr = !self.dropbox_setup.show_qr;
            }
            KeyCode::Char('i') if action_keys_active => {
                self.dropbox_setup.disable_inline_qr = !self.dropbox_setup.disable_inline_qr;
            }
            KeyCode::Char('c') if action_keys_active => {
                let url = self.dropbox_setup.qr_url();
                if !url.is_empty() {
                    let msg = match clipboard::copy_to_clipboard(url) {
                        Ok(()) => "copied",
                        Err(reason) => reason,
                    };
                    self.dropbox_setup.clipboard_message = Some(msg);
                }
            }
            KeyCode::Char('o') if action_keys_active => {
                let url = self.dropbox_setup.qr_url();
                if !url.is_empty() {
                    let msg = match clipboard::open_in_browser(url) {
                        Ok(()) => "opened",
                        Err(reason) => reason,
                    };
                    self.dropbox_setup.browser_message = Some(msg);
                }
            }
            KeyCode::Char('u') if action_keys_active => {
                if !self.dropbox_setup.authorize_url.is_empty() {
                    self.dropbox_setup.show_url_modal = true;
                }
            }
            // Paste from clipboard via Ctrl+V (the screen accepts
            // bare alphanumeric input as the typed code below, so
            // `v` alone must not shadow the typed letter — the
            // paste binding is gated on the modifier).
            KeyCode::Char('v') if editable && key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Ok(contents) = clipboard::read_from_clipboard() {
                    let trimmed = contents.trim();
                    if !trimmed.is_empty() {
                        self.dropbox_setup.pasted_code.set_value(trimmed);
                        self.dropbox_setup.clipboard_message = Some("pasted");
                    }
                }
            }
            KeyCode::Backspace if editable => {
                self.dropbox_setup.pasted_code.backspace();
            }
            KeyCode::Char(c)
                if editable
                    && (c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    && self.dropbox_setup.pasted_code.value().len() < 200 =>
            {
                self.dropbox_setup.pasted_code.push_char(c);
            }
            KeyCode::Enter => {
                if editable && self.dropbox_setup.pasted_code_appears_valid() {
                    self.dropbox_setup.stage = DropboxSetupStage::Exchanging;
                    self.dropbox_request_exchange = true;
                } else if matches!(self.dropbox_setup.stage, DropboxSetupStage::Done) {
                    self.screen = Screen::Collision;
                }
            }
            _ => {}
        }
    }

    fn handle_setup_onedrive(&mut self, key: KeyEvent) {
        // Mirrors `handle_setup_google_drive`: same RFC 8628 device
        // flow, same UX (URL modal, retry, QR toggle, copy/open).
        // The only difference at runtime is the endpoints used by
        // the polling block in `main.rs`.
        if self.onedrive_setup.show_url_modal {
            if key.code == KeyCode::Esc {
                self.onedrive_setup.show_url_modal = false;
            }
            return;
        }

        if matches!(self.onedrive_setup.stage, OneDriveSetupStage::Failed(_))
            && matches!(key.code, KeyCode::Char('r') | KeyCode::Char('R'))
        {
            self.onedrive_setup = OneDriveSetupState::default();
            self.onedrive_setup.stage = OneDriveSetupStage::Initiating;
            self.onedrive_request_init = true;
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.onedrive_setup = OneDriveSetupState::default();
                self.onedrive_request_init = false;
                self.onedrive_request_email = false;
                self.screen = Screen::Provider;
            }
            KeyCode::Char('q') => {
                if matches!(self.onedrive_setup.stage, OneDriveSetupStage::Polling) {
                    self.onedrive_setup.show_qr = !self.onedrive_setup.show_qr;
                }
            }
            KeyCode::Char('i') => {
                if matches!(self.onedrive_setup.stage, OneDriveSetupStage::Polling) {
                    self.onedrive_setup.disable_inline_qr =
                        !self.onedrive_setup.disable_inline_qr;
                }
            }
            KeyCode::Char('c') => {
                let url = self.onedrive_setup.qr_url();
                if !url.is_empty() {
                    let msg = match clipboard::copy_to_clipboard(url) {
                        Ok(()) => "copied",
                        Err(reason) => reason,
                    };
                    self.onedrive_setup.clipboard_message = Some(msg);
                }
            }
            KeyCode::Char('o') => {
                let url = self.onedrive_setup.qr_url();
                if !url.is_empty() {
                    let msg = match clipboard::open_in_browser(url) {
                        Ok(()) => "opened",
                        Err(reason) => reason,
                    };
                    self.onedrive_setup.browser_message = Some(msg);
                }
            }
            KeyCode::Char('u') => {
                if !self.onedrive_setup.verification_uri.is_empty() {
                    self.onedrive_setup.show_url_modal = true;
                }
            }
            KeyCode::Enter => {
                if matches!(self.onedrive_setup.stage, OneDriveSetupStage::Done) {
                    self.screen = Screen::Collision;
                }
            }
            _ => {}
        }
    }

    fn handle_setup_google_drive(&mut self, key: KeyEvent) {
        // URL detail modal eats most keys, just like the Nextcloud flow.
        if self.gdrive_setup.show_url_modal {
            if key.code == KeyCode::Esc {
                self.gdrive_setup.show_url_modal = false;
            }
            return;
        }

        // `r` re-attempts the device flow when the previous one failed
        // (expired code, network glitch, denied consent, etc.).
        if matches!(self.gdrive_setup.stage, GoogleDriveSetupStage::Failed(_))
            && matches!(key.code, KeyCode::Char('r') | KeyCode::Char('R'))
        {
            self.gdrive_setup = GoogleDriveSetupState::default();
            self.gdrive_setup.stage = GoogleDriveSetupStage::Initiating;
            self.gdrive_request_init = true;
            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.gdrive_setup = GoogleDriveSetupState::default();
                self.gdrive_request_init = false;
                self.gdrive_request_email = false;
                self.screen = Screen::Provider;
            }
            KeyCode::Char('q') => {
                if matches!(self.gdrive_setup.stage, GoogleDriveSetupStage::Polling) {
                    self.gdrive_setup.show_qr = !self.gdrive_setup.show_qr;
                }
            }
            KeyCode::Char('i') => {
                if matches!(self.gdrive_setup.stage, GoogleDriveSetupStage::Polling) {
                    self.gdrive_setup.disable_inline_qr = !self.gdrive_setup.disable_inline_qr;
                }
            }
            KeyCode::Char('c') => {
                let url = self.gdrive_setup.qr_url();
                if !url.is_empty() {
                    let msg = match clipboard::copy_to_clipboard(url) {
                        Ok(()) => "copied",
                        Err(reason) => reason,
                    };
                    self.gdrive_setup.clipboard_message = Some(msg);
                }
            }
            KeyCode::Char('o') => {
                let url = self.gdrive_setup.qr_url();
                if !url.is_empty() {
                    let msg = match clipboard::open_in_browser(url) {
                        Ok(()) => "opened",
                        Err(reason) => reason,
                    };
                    self.gdrive_setup.browser_message = Some(msg);
                }
            }
            KeyCode::Char('u') => {
                if !self.gdrive_setup.verification_uri.is_empty() {
                    self.gdrive_setup.show_url_modal = true;
                }
            }
            KeyCode::Enter => {
                if matches!(self.gdrive_setup.stage, GoogleDriveSetupStage::Done) {
                    self.screen = Screen::Collision;
                }
            }
            _ => {}
        }
    }

    fn handle_server(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.screen = self.screen.previous();
            }
            KeyCode::Enter => {
                self.commit_server_url();
                if self.state.server_url_valid() {
                    self.screen = self.screen.next();
                }
            }
            KeyCode::Backspace => self.server_input.backspace(),
            // `?` is reserved for help; never let it leak into the URL.
            // Spaces are not legal in a URL either, so drop them silently.
            KeyCode::Char('?') | KeyCode::Char(' ') => {}
            KeyCode::Char(c) => self.server_input.push_char(c),
            _ => {}
        }
        self.commit_server_url();
    }

    fn handle_auth(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.screen = self.screen.previous();
                return;
            }
            KeyCode::Tab => {
                self.auth_focus = self.auth_focus.next();
                return;
            }
            KeyCode::BackTab => {
                self.auth_focus = self.auth_focus.previous();
                return;
            }
            KeyCode::Enter => {
                self.commit_auth();
                match self.state.auth_kind {
                    AuthKind::AppPassword => {
                        if self.auth_inputs_complete() {
                            self.screen = self.screen.next();
                        }
                    }
                    AuthKind::LoginFlow => {
                        if self.state.server_url_valid() {
                            self.login_flow = LoginFlowState::default();
                            self.login_flow.stage = LoginFlowStage::Initiating;
                            self.login_flow_request_init = true;
                            self.screen = Screen::NextcloudLoginFlow;
                        }
                    }
                }
                return;
            }
            _ => {}
        }

        match self.auth_focus {
            AuthFocus::KindSelector => {
                if matches!(
                    key.code,
                    KeyCode::Left
                        | KeyCode::Right
                        | KeyCode::Up
                        | KeyCode::Down
                        | KeyCode::Char(' ')
                ) {
                    self.state.auth_kind = self.state.auth_kind.next();
                }
            }
            AuthFocus::Username => match key.code {
                KeyCode::Backspace => self.username_input.backspace(),
                KeyCode::Char(c) => self.username_input.push_char(c),
                _ => {}
            },
            AuthFocus::Secret => match key.code {
                KeyCode::Backspace => self.secret_input.backspace(),
                KeyCode::Char(c) => self.secret_input.push_char(c),
                _ => {}
            },
        }
        self.commit_auth();
    }

    fn handle_remote_folder(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.screen = self.screen.previous();
            }
            KeyCode::Enter => {
                self.commit_remote_folder();
                if self.state.remote_folder_valid() {
                    self.screen = self.screen.next();
                }
            }
            KeyCode::Backspace => self.remote_folder_input.backspace(),
            KeyCode::Char(c) => self.remote_folder_input.push_char(c),
            _ => {}
        }
        self.commit_remote_folder();
    }

    fn handle_collision(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Left => {
                self.screen = self.screen.previous();
            }
            KeyCode::Up => self.collision = self.collision.previous(),
            KeyCode::Down => self.collision = self.collision.next(),
            KeyCode::Enter | KeyCode::Char('n') | KeyCode::Right => {
                self.state.collision = self.collision.to_policy();
                self.screen = self.screen.next();
            }
            _ => {}
        }
    }

    fn handle_test_upload(&mut self, key: KeyEvent) {
        if self.test_running {
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Left => {
                // Re-test from ProfileManage sets `test_upload_back`
                // to route back there instead of falling into the
                // wizard's previous step.
                if let Some(back) = self.test_upload_back.take() {
                    self.screen = back;
                } else {
                    self.screen = self.screen.previous();
                }
            }
            KeyCode::Enter => match &self.state.last_test_outcome {
                Some(TestOutcome::Ok) => {
                    // If we got here from ProfileManage (re-test),
                    // Enter returns there. Otherwise every flow —
                    // first-profile setup *and* add-inner — routes
                    // through InnerAlias so the operator always
                    // gets to pick (or accept) an explicit alias.
                    // Without this prompt the wizard silently
                    // inherits a placeholder (Nextcloud username
                    // or the OAuth email local-part) which the
                    // operator never confirmed.
                    if let Some(back) = self.test_upload_back.take() {
                        self.screen = back;
                    } else {
                        self.prepare_inner_alias_input();
                        self.screen = Screen::InnerAlias;
                    }
                }
                // None (never run) or Failed → (re)run the probe.
                _ => {
                    self.test_request = true;
                }
            },
            _ => {}
        }
    }

    fn commit_server_url(&mut self) {
        self.state.server_url = self.server_input.value().to_string();
    }

    fn commit_auth(&mut self) {
        self.state.username = self.username_input.value().to_string();
        self.state.auth_secret = self.secret_input.value().to_string();
    }

    fn commit_remote_folder(&mut self) {
        self.state.remote_folder = self.remote_folder_input.value().to_string();
    }

    fn auth_inputs_complete(&self) -> bool {
        match self.state.auth_kind {
            AuthKind::AppPassword => self.state.username_valid() && self.state.secret_valid(),
            AuthKind::LoginFlow => false,
        }
    }

    /// Compute the agent status pill shown in the title bar.
    /// Tells the operator at a glance whether they're operating on
    /// a local-only profile or a server-synced one — with the
    /// server label and the active alias when known.
    pub fn agent_pill(&self) -> AgentPill {
        // 1. A profile is unlocked in RAM (Open local/remote → Manage).
        if let Some(p) = self.unlocked_profile.as_ref() {
            let alias = p.alias.clone();
            return match self.unlock_source {
                ProfileSource::Local => AgentPill::Local { alias },
                ProfileSource::Remote => AgentPill::Remote {
                    server: self.server_label(),
                    alias,
                },
            };
        }
        // 1b. Add-inner-profile sub-flow: the container is unlocked
        // but no inner profile is "active" yet — the new one is
        // still being assembled across the wizard. Show "● local"
        // (or "● remote · server") without an alias instead of
        // falling through to the post-save branch, which would
        // leak `state.username` as the operator types it.
        if self.wizard_mode == WizardMode::AddInnerProfile && self.unlocked_set.is_some() {
            return match self.unlock_source {
                ProfileSource::Local => AgentPill::Local {
                    alias: String::new(),
                },
                ProfileSource::Remote => AgentPill::Remote {
                    server: self.server_label(),
                    alias: String::new(),
                },
            };
        }
        // 2. The wizard has saved a fresh profile in this session.
        // The alias is the one pushed to the server when present
        // (CreateRemote happy path), otherwise the username typed
        // in the Auth form (the wizard uses it as the profile alias).
        let post_save = self.saved_path.is_some()
            || matches!(self.passphrase_stage, PassphraseStage::Saved(_));
        if post_save {
            let alias = self
                .pushed_summary
                .as_ref()
                .map(|s| s.alias.clone())
                .unwrap_or_else(|| self.state.username.clone());
            return match self.wizard_mode {
                WizardMode::CreateLocal | WizardMode::AddInnerProfile => {
                    AgentPill::Local { alias }
                }
                WizardMode::CreateRemote => AgentPill::Remote {
                    server: self.server_label(),
                    alias,
                },
            };
        }
        AgentPill::NoProfile
    }

    /// Mark the start of a probe run: ensure goes Busy, the rest waits.
    /// Called by `main.rs` right before stage 1.
    pub fn start_probe(&mut self) {
        self.state.probe_progress.ensure = ProbeStepStatus::Busy;
        self.state.probe_progress.marker = ProbeStepStatus::Pending;
        self.state.probe_progress.upload = ProbeStepStatus::Pending;
        self.state.probe_progress.cleanup = ProbeStepStatus::Pending;
        self.state.last_test_outcome = None;
    }

    /// Stage 1 succeeded: ensure → Ok, marker starts Busy.
    pub fn mark_probe_ensure_ok(&mut self) {
        self.state.probe_progress.ensure = ProbeStepStatus::Ok;
        self.state.probe_progress.marker = ProbeStepStatus::Busy;
    }

    /// Stage 1 failed: ensure → Err, downstream skipped.
    pub fn fail_probe_ensure(&mut self, reason: String) {
        self.state.probe_progress.ensure = ProbeStepStatus::Err;
        self.state.probe_progress.marker = ProbeStepStatus::Skip;
        self.state.probe_progress.upload = ProbeStepStatus::Skip;
        self.state.probe_progress.cleanup = ProbeStepStatus::Skip;
        self.state.last_test_outcome = Some(TestOutcome::Failed(reason));
        self.test_running = false;
    }

    /// Stage 2 succeeded: marker → Ok, upload starts Busy.
    pub fn mark_probe_marker_ok(&mut self) {
        self.state.probe_progress.marker = ProbeStepStatus::Ok;
        self.state.probe_progress.upload = ProbeStepStatus::Busy;
    }

    /// Stage 2 failed: marker → Err, upload + cleanup skipped.
    pub fn fail_probe_marker(&mut self, reason: String) {
        self.state.probe_progress.marker = ProbeStepStatus::Err;
        self.state.probe_progress.upload = ProbeStepStatus::Skip;
        self.state.probe_progress.cleanup = ProbeStepStatus::Skip;
        self.state.last_test_outcome = Some(TestOutcome::Failed(reason));
        self.test_running = false;
    }

    /// Stage 3 succeeded: upload → Ok, cleanup starts Busy.
    pub fn mark_probe_upload_ok(&mut self) {
        self.state.probe_progress.upload = ProbeStepStatus::Ok;
        self.state.probe_progress.cleanup = ProbeStepStatus::Busy;
    }

    /// Stage 3 failed: upload → Err, cleanup skipped.
    pub fn fail_probe_upload(&mut self, reason: String) {
        self.state.probe_progress.upload = ProbeStepStatus::Err;
        self.state.probe_progress.cleanup = ProbeStepStatus::Skip;
        self.state.last_test_outcome = Some(TestOutcome::Failed(reason));
        self.test_running = false;
    }

    /// Stage 4 succeeded: cleanup → Ok, probe done with success.
    pub fn mark_probe_cleanup_ok(&mut self) {
        self.state.probe_progress.cleanup = ProbeStepStatus::Ok;
        self.state.last_test_outcome = Some(TestOutcome::Ok);
        self.test_running = false;
    }

    /// Stage 4 failed: cleanup → Err, probe done with failure.
    pub fn fail_probe_cleanup(&mut self, reason: String) {
        self.state.probe_progress.cleanup = ProbeStepStatus::Err;
        self.state.last_test_outcome = Some(TestOutcome::Failed(reason));
        self.test_running = false;
    }

    /// Test-only convenience: collapse a final outcome into a coherent
    /// `probe_progress`. Production code uses the per-stage helpers above.
    pub fn record_test_outcome(&mut self, outcome: TestOutcome) {
        match &outcome {
            TestOutcome::Ok => {
                self.state.probe_progress.ensure = ProbeStepStatus::Ok;
                self.state.probe_progress.marker = ProbeStepStatus::Ok;
                self.state.probe_progress.upload = ProbeStepStatus::Ok;
                self.state.probe_progress.cleanup = ProbeStepStatus::Ok;
            }
            TestOutcome::Failed(_) => {
                self.state.probe_progress.upload = ProbeStepStatus::Err;
            }
        }
        self.state.last_test_outcome = Some(outcome);
        self.test_running = false;
    }

    pub fn apply_login_flow_init(&mut self, login_url: String, token: String, endpoint: String) {
        self.login_flow.login_url = login_url;
        self.login_flow.poll_token = token;
        self.login_flow.poll_endpoint = endpoint;
        self.login_flow.stage = LoginFlowStage::Polling;
    }

    pub fn apply_login_flow_init_failed(&mut self, reason: String) {
        self.login_flow.stage = LoginFlowStage::Failed(reason);
    }

    pub fn apply_login_flow_done(&mut self, login_name: String, app_password: String) {
        self.login_flow.stage = LoginFlowStage::Done;
        self.username_input.set_value(&login_name);
        self.secret_input.set_value(&app_password);
        self.state.username = login_name;
        self.state.auth_secret = app_password;
        self.state.auth_kind = AuthKind::LoginFlow;
    }

    pub fn apply_login_flow_failed(&mut self, reason: String) {
        self.login_flow.stage = LoginFlowStage::Failed(reason);
    }

    // ── Google Drive Device Flow transitions ────────────────────────

    pub fn apply_gdrive_init(
        &mut self,
        user_code: String,
        verification_uri: String,
        verification_uri_complete: Option<String>,
        device_code: String,
        expires_in: u64,
        interval: u64,
    ) {
        let now = unix_now();
        self.gdrive_setup.user_code = user_code;
        self.gdrive_setup.verification_uri = verification_uri;
        self.gdrive_setup.verification_uri_complete = verification_uri_complete;
        self.gdrive_setup.device_code = device_code;
        self.gdrive_setup.expires_at = now + expires_in;
        self.gdrive_setup.interval_secs = interval.max(1);
        self.gdrive_setup.last_poll_at = now;
        self.gdrive_setup.stage = GoogleDriveSetupStage::Polling;
    }

    pub fn apply_gdrive_init_failed(&mut self, reason: String) {
        self.gdrive_setup.stage = GoogleDriveSetupStage::Failed(reason);
    }

    pub fn apply_gdrive_tokens(
        &mut self,
        access_token: String,
        refresh_token: Option<String>,
        token_type: String,
        expires_in: u64,
        scope: Option<String>,
    ) {
        let now = unix_now();
        self.gdrive_setup.access_token = access_token;
        if let Some(rt) = refresh_token {
            self.gdrive_setup.refresh_token = rt;
        }
        self.gdrive_setup.token_type = token_type;
        self.gdrive_setup.access_expires_at = now + expires_in;
        if let Some(s) = scope {
            self.gdrive_setup.scope = s;
        }
        self.gdrive_setup.stage = GoogleDriveSetupStage::Fetching;
        self.gdrive_request_email = true;
    }

    pub fn apply_gdrive_email(&mut self, email: String) {
        self.gdrive_setup.user_email = email;
        self.gdrive_setup.stage = GoogleDriveSetupStage::Done;
    }

    pub fn apply_gdrive_failed(&mut self, reason: String) {
        self.gdrive_setup.stage = GoogleDriveSetupStage::Failed(reason);
        self.gdrive_request_init = false;
        self.gdrive_request_email = false;
    }

    /// Server asked for a slower polling cadence — bump the interval
    /// by 5 s as RFC 8628 §3.5 prescribes.
    pub fn bump_gdrive_interval(&mut self) {
        self.gdrive_setup.interval_secs = self.gdrive_setup.interval_secs.saturating_add(5);
    }

    // ── OneDrive Device Flow transitions ────────────────────────────
    //
    // OneDrive shares the device-flow state struct with Google Drive
    // (`OneDriveSetupState` is a type alias on `GoogleDriveSetupState`).
    // The two flows live in separate slots so concurrent re-entries of
    // the Provider picker don't trample each other's user_code.

    pub fn apply_onedrive_init(
        &mut self,
        user_code: String,
        verification_uri: String,
        verification_uri_complete: Option<String>,
        device_code: String,
        expires_in: u64,
        interval: u64,
    ) {
        let now = unix_now();
        self.onedrive_setup.user_code = user_code;
        self.onedrive_setup.verification_uri = verification_uri;
        self.onedrive_setup.verification_uri_complete = verification_uri_complete;
        self.onedrive_setup.device_code = device_code;
        self.onedrive_setup.expires_at = now + expires_in;
        self.onedrive_setup.interval_secs = interval.max(1);
        self.onedrive_setup.last_poll_at = now;
        self.onedrive_setup.stage = OneDriveSetupStage::Polling;
    }

    pub fn apply_onedrive_init_failed(&mut self, reason: String) {
        self.onedrive_setup.stage = OneDriveSetupStage::Failed(reason);
    }

    pub fn apply_onedrive_tokens(
        &mut self,
        access_token: String,
        refresh_token: Option<String>,
        token_type: String,
        expires_in: u64,
        scope: Option<String>,
    ) {
        let now = unix_now();
        self.onedrive_setup.access_token = access_token;
        if let Some(rt) = refresh_token {
            self.onedrive_setup.refresh_token = rt;
        }
        self.onedrive_setup.token_type = token_type;
        self.onedrive_setup.access_expires_at = now + expires_in;
        if let Some(s) = scope {
            self.onedrive_setup.scope = s;
        }
        self.onedrive_setup.stage = OneDriveSetupStage::Fetching;
        self.onedrive_request_email = true;
    }

    pub fn apply_onedrive_email(&mut self, email: String) {
        self.onedrive_setup.user_email = email;
        self.onedrive_setup.stage = OneDriveSetupStage::Done;
    }

    pub fn apply_onedrive_failed(&mut self, reason: String) {
        self.onedrive_setup.stage = OneDriveSetupStage::Failed(reason);
        self.onedrive_request_init = false;
        self.onedrive_request_email = false;
    }

    pub fn bump_onedrive_interval(&mut self) {
        self.onedrive_setup.interval_secs = self.onedrive_setup.interval_secs.saturating_add(5);
    }

    /// Build phase complete: store the local PKCE secret + the
    /// authorize URL the operator must open. The screen flips to
    /// `AwaitingPaste` so the input field accepts characters.
    pub fn apply_dropbox_init(&mut self, authorize_url: String, code_verifier: String) {
        self.dropbox_setup.authorize_url = authorize_url;
        self.dropbox_setup.code_verifier = code_verifier;
        self.dropbox_setup.stage = DropboxSetupStage::AwaitingPaste;
    }

    pub fn apply_dropbox_init_failed(&mut self, reason: String) {
        self.dropbox_setup.stage = DropboxSetupStage::Failed(reason);
    }

    /// Token exchange completed: store the secrets, request the
    /// account email on the next tick.
    pub fn apply_dropbox_tokens(
        &mut self,
        access_token: String,
        refresh_token: Option<String>,
        token_type: String,
        expires_in: u64,
        scope: Option<String>,
    ) {
        let now = unix_now();
        self.dropbox_setup.access_token = access_token;
        if let Some(rt) = refresh_token {
            self.dropbox_setup.refresh_token = rt;
        }
        self.dropbox_setup.token_type = token_type;
        self.dropbox_setup.access_expires_at = now + expires_in;
        if let Some(s) = scope {
            self.dropbox_setup.scope = s;
        }
        // Clear the now-consumed paste-code state so a Failed/retry
        // cycle does not accidentally re-submit the same code.
        self.dropbox_setup.pasted_code.set_value("");
        self.dropbox_setup.code_verifier.clear();
        self.dropbox_setup.stage = DropboxSetupStage::Fetching;
        self.dropbox_request_email = true;
    }

    pub fn apply_dropbox_email(&mut self, email: String) {
        self.dropbox_setup.user_email = email;
        self.dropbox_setup.stage = DropboxSetupStage::Done;
    }

    pub fn apply_dropbox_failed(&mut self, reason: String) {
        self.dropbox_setup.stage = DropboxSetupStage::Failed(reason);
        self.dropbox_request_init = false;
        self.dropbox_request_exchange = false;
        self.dropbox_request_email = false;
    }
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn server_label_strips_scheme_and_path() {
        assert_eq!(server_label_for("https://zz-drop.net"), "zz-drop.net");
        assert_eq!(server_label_for("http://localhost:8080"), "localhost:8080");
        assert_eq!(
            server_label_for("https://api.example.org/v1"),
            "api.example.org"
        );
        // Non-URL falls through unchanged.
        assert_eq!(server_label_for("example.org"), "example.org");
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Reset App into the "no local profile.zz on disk" state so a
    /// test that exercises the wizard entry path is deterministic
    /// regardless of whether the dev machine actually has a profile.
    fn fresh_no_profile() -> App {
        let mut app = App::new();
        app.local_exists = false;
        app.remote_exists = false;
        app.welcome_item = WelcomeItem::Configure;
        app.unlocked_profile = None;
        app
    }

    #[test]
    fn welcome_to_provider_via_enter() {
        let mut app = fresh_no_profile();
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Provider);
    }

    #[cfg(feature = "remote")]
    #[test]
    fn welcome_arrow_down_walks_to_quit_then_enter_quits() {
        let mut app = fresh_no_profile();
        // Fresh menu (remote build): Configure → ConfigureRemote →
        // SignIn → SetupCompletions → Quit. Default build collapses
        // to Configure → SetupCompletions → Quit and is covered by
        // the sibling test below.
        assert_eq!(app.welcome_item, WelcomeItem::Configure);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.welcome_item, WelcomeItem::ConfigureRemote);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.welcome_item, WelcomeItem::SignIn);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.welcome_item, WelcomeItem::SetupCompletions);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.welcome_item, WelcomeItem::Quit);
        app.on_key(key(KeyCode::Enter));
        assert!(app.should_quit);
        assert_eq!(app.screen, Screen::Welcome);
    }

    #[cfg(not(feature = "remote"))]
    #[test]
    fn welcome_arrow_down_walks_to_quit_then_enter_quits_local_only() {
        // Default-build menu: Configure → SetupCompletions → Quit.
        let mut app = fresh_no_profile();
        assert_eq!(app.welcome_item, WelcomeItem::Configure);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.welcome_item, WelcomeItem::SetupCompletions);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.welcome_item, WelcomeItem::Quit);
        app.on_key(key(KeyCode::Enter));
        assert!(app.should_quit);
    }

    #[test]
    fn welcome_arrow_up_wraps_to_quit() {
        let mut app = fresh_no_profile();
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.welcome_item, WelcomeItem::Quit);
    }

    #[test]
    fn welcome_with_existing_local_profile_defaults_to_open_local() {
        let mut app = App::new();
        app.local_exists = true;
        app.welcome_item = WelcomeItem::OpenLocal;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::ProfileUnlock);
        assert_eq!(app.unlock_source, ProfileSource::Local);
    }

    #[test]
    fn welcome_with_existing_remote_profile_defaults_to_open_remote() {
        let mut app = App::new();
        app.remote_exists = true;
        app.welcome_item = WelcomeItem::OpenRemote;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::ProfileUnlock);
        assert_eq!(app.unlock_source, ProfileSource::Remote);
    }

    fn dummy_profile() -> PlainProfile {
        use zz_drop_core::providers::nextcloud::NextcloudAuth;
        use zz_drop_core::{
            CollisionPolicy, NextcloudProfile, ProfileSettings, ProviderProfile,
        };
        PlainProfile {
            profile_version: 1,
            profile_id: "test".into(),
            alias: "test".into(),
            default_target: "nextcloud".into(),
            providers: vec![ProviderProfile::Nextcloud(NextcloudProfile {
                server_url: "https://example.org".into(),
                username: "alice".into(),
                auth: NextcloudAuth::AppPassword {
                    secret: "x".into(),
                },
                remote_root: "/zz-drop".into(),
            })],
            collision_policy: CollisionPolicy::Rename,
            settings: ProfileSettings::default(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn reopening_same_source_is_a_cache_hit_and_skips_passphrase() {
        // First unlock (test sets up: cached_source + unlocked_set).
        let mut app = App::new();
        app.local_exists = true;
        app.unlock_source = ProfileSource::Local;
        app.apply_unlock_done(dummy_profile());
        // Bridge for the legacy single-profile `apply_unlock_done`
        // path: the new picker logic checks `unlocked_set`. A 1-set
        // is the natural shim.
        app.unlocked_set = Some(zz_drop_core::ProfileSet::with_profile(dummy_profile()));
        assert_eq!(app.cached_source, Some(ProfileSource::Local));
        // Esc back to Welcome — cache must survive.
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Welcome);
        assert!(app.unlocked_profile.is_some());
        assert_eq!(app.cached_source, Some(ProfileSource::Local));
        // Re-pick OpenLocal — must skip the passphrase prompt and
        // land on the picker (so the operator can choose any inner
        // profile, not just the previously-active one).
        app.welcome_item = WelcomeItem::OpenLocal;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::ContainerPicker);
    }

    #[test]
    fn opening_other_source_clears_cache_and_re_prompts() {
        let mut app = App::new();
        app.local_exists = true;
        app.remote_exists = true;
        app.unlock_source = ProfileSource::Remote;
        app.apply_unlock_done(dummy_profile());
        assert_eq!(app.cached_source, Some(ProfileSource::Remote));
        // Esc to Welcome, then pick the *other* source (Local).
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        app.on_key(key(KeyCode::Esc));
        app.welcome_item = WelcomeItem::OpenLocal;
        app.on_key(key(KeyCode::Enter));
        // Must clear the old cache and re-prompt for passphrase.
        assert_eq!(app.screen, Screen::ProfileUnlock);
        assert_eq!(app.unlock_source, ProfileSource::Local);
        assert!(app.unlocked_profile.is_none());
        assert_eq!(app.cached_source, None);
    }

    #[test]
    fn wipe_clears_cache() {
        let mut app = App::new();
        app.local_exists = true;
        app.unlock_source = ProfileSource::Local;
        app.apply_unlock_done(dummy_profile());
        assert!(app.unlocked_profile.is_some());
        app.apply_wipe_done();
        assert!(app.unlocked_profile.is_none());
        assert_eq!(app.cached_source, None);
    }

    #[cfg(feature = "remote")]
    #[test]
    fn welcome_signin_routes_to_account_with_signin_mode() {
        let mut app = fresh_no_profile();
        // step down past Configure → ConfigureRemote → SignIn
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.welcome_item, WelcomeItem::SignIn);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Account);
        assert_eq!(app.push_flow.mode, PushFlowMode::SignIn);
        assert_eq!(app.push_back, Some(Screen::Welcome));
    }

    #[test]
    fn welcome_configure_remote_without_session_logs_in_first() {
        // No cached token: must hit Account before the wizard.
        let mut app = fresh_no_profile();
        app.cached_session_token = None;
        app.welcome_item = WelcomeItem::ConfigureRemote;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.wizard_mode, WizardMode::CreateRemote);
        assert_eq!(app.screen, Screen::Account);
        assert_eq!(app.post_login_target, Some(Screen::Provider));
    }

    #[test]
    fn welcome_configure_remote_with_cached_token_skips_login() {
        // Same TUI session, already logged in — straight to wizard.
        let mut app = fresh_no_profile();
        app.cached_session_token = Some("tok".into());
        app.welcome_item = WelcomeItem::ConfigureRemote;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.wizard_mode, WizardMode::CreateRemote);
        assert_eq!(app.screen, Screen::Provider);
        assert_eq!(app.post_login_target, None);
        assert_eq!(app.push_flow.session_token.as_deref(), Some("tok"));
    }

    #[test]
    fn route_after_login_with_post_target_goes_to_provider() {
        let mut app = App::new();
        app.post_login_target = Some(Screen::Provider);
        app.apply_login_session("tok".into());
        assert_eq!(app.screen, Screen::Provider);
        assert!(!app.push_request_list);
        assert_eq!(app.cached_session_token.as_deref(), Some("tok"));
    }

    #[test]
    fn route_after_login_without_post_target_lists_aliases() {
        let mut app = App::new();
        app.post_login_target = None;
        app.apply_login_session("tok".into());
        assert_eq!(app.screen, Screen::PushProfile);
        assert!(app.push_request_list);
    }

    #[test]
    fn agent_pill_no_profile_by_default() {
        let app = fresh_no_profile();
        assert_eq!(app.agent_pill(), AgentPill::NoProfile);
    }

    #[test]
    fn agent_pill_local_when_local_unlocked() {
        let mut app = App::new();
        app.unlock_source = ProfileSource::Local;
        app.unlocked_profile = Some(dummy_profile());
        assert_eq!(
            app.agent_pill(),
            AgentPill::Local {
                alias: "test".into()
            }
        );
    }

    #[test]
    fn agent_pill_remote_with_server_when_remote_unlocked() {
        let mut app = App::new();
        app.unlock_source = ProfileSource::Remote;
        app.unlocked_profile = Some(dummy_profile());
        app.api_base = "https://example.org/api".into();
        assert_eq!(
            app.agent_pill(),
            AgentPill::Remote {
                server: "example.org".into(),
                alias: "test".into()
            }
        );
    }

    #[test]
    fn agent_pill_after_save_uses_wizard_mode_and_username() {
        let mut app = App::new();
        app.wizard_mode = WizardMode::CreateRemote;
        app.state.username = "casa-nc".into();
        app.saved_path = Some("/tmp/profiles-local.zz".into());
        let server = app.server_label();
        assert_eq!(
            app.agent_pill(),
            AgentPill::Remote {
                server,
                alias: "casa-nc".into()
            }
        );
    }

    #[test]
    fn picker_enter_with_new_alias_in_wizard_mode_triggers_rewrite() {
        // Wizard push: passphrase is still in RAM, alias differs
        // from the placeholder (state.username) → main loop should
        // re-encrypt before pushing.
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_flow.mode = PushFlowMode::Push;
        app.push_back = None; // wizard, not Manage re-push
        app.passphrase_input.set_value("hunter2hunter2");
        app.state.username = "alice".into();
        app.push_alias_input.set_value("casa-nc");
        app.on_key(key(KeyCode::Enter));
        assert!(app.rewrite_blob_for_alias_request);
        assert!(!app.push_request_send);
    }

    #[test]
    fn picker_enter_with_same_alias_skips_rewrite() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_flow.mode = PushFlowMode::Push;
        app.push_back = None;
        app.passphrase_input.set_value("hunter2hunter2");
        app.state.username = "casa-nc".into();
        app.push_alias_input.set_value("casa-nc");
        app.on_key(key(KeyCode::Enter));
        assert!(!app.rewrite_blob_for_alias_request);
        assert!(app.push_request_send);
    }

    #[test]
    fn push_failed_r_retries_list_when_aliases_empty() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_flow.mode = PushFlowMode::Push;
        app.push_flow.stage = PushStage::Failed("network error".into());
        // remote_aliases empty → retry should re-fetch the list
        app.on_key(key(KeyCode::Char('r')));
        assert!(app.push_request_list);
        assert_eq!(app.push_flow.stage, PushStage::PushFetching);
    }

    #[test]
    fn push_failed_r_retries_send_when_aliases_loaded() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_flow.mode = PushFlowMode::Push;
        app.push_flow.remote_aliases = vec!["casa-nc".into()];
        app.push_alias_input.set_value("casa-nc");
        app.push_flow.stage = PushStage::Failed("network error".into());
        app.on_key(key(KeyCode::Char('r')));
        assert!(app.push_request_send);
        assert_eq!(app.push_flow.stage, PushStage::PushSending);
    }

    #[test]
    fn signin_failed_r_retries_download() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_flow.mode = PushFlowMode::SignIn;
        app.push_flow.remote_aliases = vec!["casa-nc".into()];
        app.push_alias_input.set_value("casa-nc");
        app.push_flow.stage = PushStage::Failed("network error".into());
        app.on_key(key(KeyCode::Char('r')));
        assert!(app.signin_request_download);
    }

    #[test]
    fn push_failed_esc_exits_to_welcome_even_in_wizard_mode() {
        // Server outage during wizard auto-push: the operator must
        // have a way out, even though `push_back` is None.
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_flow.mode = PushFlowMode::Push;
        app.push_back = None;
        app.push_flow.stage = PushStage::Failed("network error".into());
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Welcome);
    }

    #[test]
    fn account_failed_esc_exits_to_welcome_in_wizard_mode() {
        // Server outage during ConfigureRemote login: Esc must let
        // the operator out, even though push_back is None.
        let mut app = App::new();
        app.screen = Screen::Account;
        app.push_back = None;
        app.push_flow.stage = PushStage::Failed("network error".into());
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Welcome);
    }

    #[test]
    fn account_form_esc_in_wizard_mode_still_blocks() {
        // Pre-failure (form stage) wizard mode keeps the no-op
        // behaviour so the operator commits to the flow.
        let mut app = App::new();
        app.screen = Screen::Account;
        app.push_back = None;
        app.push_flow.stage = PushStage::AccountForm;
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Account);
    }

    #[test]
    fn push_failed_esc_returns_to_back_pointer_when_set() {
        // Re-push from Manage, server fails: Esc returns to Manage.
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_flow.mode = PushFlowMode::Push;
        app.push_back = Some(Screen::ProfileManage);
        app.push_flow.stage = PushStage::Failed("network error".into());
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::ProfileManage);
    }

    #[test]
    fn picker_enter_in_manage_re_push_skips_rewrite() {
        // Re-push from Manage: passphrase is already cleared, so we
        // can't re-encrypt. Push the file as-is.
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_flow.mode = PushFlowMode::Push;
        app.push_back = Some(Screen::ProfileManage);
        app.state.username = "alice".into();
        app.push_alias_input.set_value("casa-nc");
        app.on_key(key(KeyCode::Enter));
        assert!(!app.rewrite_blob_for_alias_request);
        assert!(app.push_request_send);
    }

    #[test]
    fn agent_pill_after_push_prefers_pushed_alias() {
        let mut app = App::new();
        app.wizard_mode = WizardMode::CreateRemote;
        app.state.username = "username".into();
        app.saved_path = Some("/tmp/profiles-local.zz".into());
        app.pushed_summary = Some(PushedSummary {
            alias: "casa-nc".into(),
            blob_size: 0,
            blob_version: 0,
        });
        let server = app.server_label();
        assert_eq!(
            app.agent_pill(),
            AgentPill::Remote {
                server,
                alias: "casa-nc".into()
            }
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn signin_with_cached_token_skips_account_screen() {
        let mut app = fresh_no_profile();
        app.cached_session_token = Some("tok".into());
        // Walk to SignIn: Configure → ConfigureRemote → SignIn
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.welcome_item, WelcomeItem::SignIn);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::PushProfile);
        assert_eq!(app.push_flow.mode, PushFlowMode::SignIn);
        assert!(app.push_request_list);
    }

    #[test]
    fn welcome_configure_arms_create_local_mode() {
        let mut app = fresh_no_profile();
        app.welcome_item = WelcomeItem::Configure;
        // Pre-set the other mode to make sure Configure resets it.
        app.wizard_mode = WizardMode::CreateRemote;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Provider);
        assert_eq!(app.wizard_mode, WizardMode::CreateLocal);
    }

    #[test]
    fn apply_save_done_in_create_remote_auto_routes_to_account() {
        let mut app = App::new();
        app.wizard_mode = WizardMode::CreateRemote;
        app.apply_save_done("/tmp/profiles-local.zz".into());
        assert_eq!(app.screen, Screen::Account);
        assert_eq!(app.push_flow.mode, PushFlowMode::Push);
        assert!(app.push_back.is_none());
    }

    #[test]
    fn apply_save_done_in_create_local_stays_on_passphrase_for_prompt() {
        let mut app = App::new();
        app.wizard_mode = WizardMode::CreateLocal;
        app.screen = Screen::ProfilePassphrase;
        app.apply_save_done("/tmp/profiles-local.zz".into());
        // No auto-route — handle_passphrase Saved decides on key press.
        assert_eq!(app.screen, Screen::ProfilePassphrase);
        assert!(matches!(app.passphrase_stage, PassphraseStage::Saved(_)));
    }

    #[test]
    fn unlock_enter_with_passphrase_sets_request() {
        let mut app = App::new();
        app.screen = Screen::ProfileUnlock;
        app.manage_passphrase_input.set_value("hunter2hunter2");
        app.on_key(key(KeyCode::Enter));
        assert!(app.unlock_request);
        assert_eq!(app.manage_stage, ManageStage::Unlocking);
    }

    #[test]
    fn unlock_enter_with_empty_passphrase_does_nothing() {
        let mut app = App::new();
        app.screen = Screen::ProfileUnlock;
        app.on_key(key(KeyCode::Enter));
        assert!(!app.unlock_request);
    }

    #[test]
    fn manage_r_toggles_secret_reveal() {
        let mut app = App::new();
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        // Need a non-None unlocked_profile for the handler path,
        // but the handler itself doesn't deref it here, so a
        // dummy is unnecessary — the field flips regardless.
        assert!(!app.manage_show_secret);
        app.on_key(key(KeyCode::Char('r')));
        assert!(app.manage_show_secret);
        app.on_key(key(KeyCode::Char('r')));
        assert!(!app.manage_show_secret);
    }

    #[test]
    fn manage_w_enters_wipe_confirm_then_y_dispatches_request() {
        let mut app = App::new();
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        app.on_key(key(KeyCode::Char('w')));
        assert_eq!(app.manage_stage, ManageStage::WipeConfirm);
        app.on_key(key(KeyCode::Char('y')));
        assert!(app.wipe_request);
        assert_eq!(app.manage_stage, ManageStage::Wiping);
    }

    #[test]
    fn manage_w_then_n_cancels_back_to_viewing() {
        let mut app = App::new();
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        app.on_key(key(KeyCode::Char('w')));
        app.on_key(key(KeyCode::Char('n')));
        assert_eq!(app.manage_stage, ManageStage::Viewing);
        assert!(!app.wipe_request);
    }

    #[test]
    fn manage_p_routes_to_account_for_re_push() {
        let mut app = App::new();
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        app.on_key(key(KeyCode::Char('p')));
        assert_eq!(app.screen, Screen::Account);
        assert_eq!(app.push_flow.stage, PushStage::AccountForm);
    }

    #[test]
    fn manage_t_routes_to_test_upload_with_back_pointer() {
        let mut app = App::new();
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        app.on_key(key(KeyCode::Char('t')));
        assert_eq!(app.screen, Screen::TestUpload);
        assert_eq!(app.test_upload_back, Some(Screen::ProfileManage));
    }

    #[test]
    fn re_test_enter_on_ok_returns_to_manage_not_passphrase() {
        // From ProfileManage, the operator presses `t` → TestUpload.
        // After a successful probe, Enter must return to ProfileManage,
        // *not* advance to the wizard's ProfilePassphrase step.
        let mut app = App::new();
        app.screen = Screen::TestUpload;
        app.test_upload_back = Some(Screen::ProfileManage);
        app.state.last_test_outcome = Some(TestOutcome::Ok);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::ProfileManage);
        // Back pointer is consumed so re-entering via the wizard is
        // not affected.
        assert_eq!(app.test_upload_back, None);
    }

    #[test]
    fn wizard_test_enter_on_ok_routes_to_inner_alias_for_every_provider() {
        // First-profile setup must always route through InnerAlias so
        // the operator gets an explicit alias prompt regardless of
        // provider — Nextcloud included. Without this, Nextcloud
        // would inherit the WebDAV username verbatim and the OAuth
        // providers would inherit the email local-part, both
        // unconfirmed defaults.
        for provider in [
            ProviderKind::Nextcloud,
            ProviderKind::GoogleDrive,
            ProviderKind::OneDrive,
            ProviderKind::Dropbox,
        ] {
            let mut app = App::new();
            app.wizard_mode = WizardMode::CreateLocal;
            app.state.provider_kind = provider;
            app.screen = Screen::TestUpload;
            app.test_upload_back = None;
            app.state.last_test_outcome = Some(TestOutcome::Ok);
            app.on_key(key(KeyCode::Enter));
            assert_eq!(
                app.screen,
                Screen::InnerAlias,
                "provider {provider:?} did not route to InnerAlias",
            );
        }
    }

    #[test]
    fn add_inner_profile_test_enter_routes_to_inner_alias_not_passphrase() {
        // The add-inner-profile sub-flow must skip ProfilePassphrase
        // (the container's KEK is cached) and land on InnerAlias.
        // Hitting ProfilePassphrase here would let `save_request`
        // fire — which writes a fresh single-profile container,
        // overwriting the existing inner profiles.
        let mut app = App::new();
        app.wizard_mode = WizardMode::AddInnerProfile;
        app.screen = Screen::TestUpload;
        app.test_upload_back = None;
        app.state.last_test_outcome = Some(TestOutcome::Ok);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::InnerAlias);
        assert!(!app.save_request, "AddInnerProfile must not arm save_request");
    }

    #[test]
    fn open_local_after_cache_hit_routes_to_picker_not_manage() {
        // Cache hit (same source, container in RAM) must land on the
        // picker so the operator can choose any inner profile, not
        // jump straight back to the previously-active one.
        let mut app = App::new();
        app.local_exists = true;
        app.unlock_source = ProfileSource::Local;
        app.cached_source = Some(ProfileSource::Local);
        app.unlocked_set = Some(zz_drop_core::ProfileSet::with_profile(dummy_profile()));
        app.unlocked_profile = Some(dummy_profile());
        app.welcome_item = WelcomeItem::OpenLocal;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::ContainerPicker);
        // Picker takes over the active selection — the "stuck on
        // last alias" behavior is gone.
        assert!(app.unlocked_profile.is_none());
    }

    #[test]
    fn apply_inner_added_routes_to_done_in_add_inner_mode() {
        // After the alias is committed, the operator must land on
        // a "connection added" Done screen (not jump straight to
        // ProfileManage). This gives the wizard stepper a final
        // tick and a clear confirmation step before Welcome.
        let mut app = App::new();
        app.wizard_mode = WizardMode::AddInnerProfile;
        app.unlock_source = ProfileSource::Local;
        let mut set = zz_drop_core::ProfileSet::new();
        set.profiles.push({
            let mut p = dummy_profile();
            p.alias = "fresh".into();
            p
        });
        app.apply_inner_added(set, "fresh".into());
        assert_eq!(app.screen, Screen::Done);
        assert_eq!(app.wizard_mode, WizardMode::AddInnerProfile);
        assert_eq!(app.unlocked_profile.as_ref().map(|p| p.alias.as_str()), Some("fresh"));
        // Enter on Done returns to Welcome and resets the sticky
        // sub-flow mode.
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Welcome);
        assert_eq!(app.wizard_mode, WizardMode::CreateLocal);
    }

    #[test]
    fn manage_d_uppercase_arms_delete_confirm_when_n_above_one() {
        // From ProfileManage with an active inner profile and at
        // least one sibling, `D` (uppercase only) routes into the
        // confirm sub-state. Lowercase `d` is reserved for the
        // wizard "download" line in the future and must NOT trigger.
        let mut app = App::new();
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        app.unlock_source = ProfileSource::Local;
        app.unlocked_kek = Some(zz_drop_core::ProfileKek::from_parts(
            [0u8; 32],
            [0u8; 16],
            zz_drop_core::Argon2idConfig::DEFAULT,
        ));
        let mut set = zz_drop_core::ProfileSet::new();
        let mut a = dummy_profile();
        a.alias = "alpha".into();
        let mut b = dummy_profile();
        b.alias = "beta".into();
        b.profile_id = "p-beta".into();
        set.profiles.push(a);
        set.profiles.push(b);
        app.unlocked_set = Some(set);
        app.unlocked_profile = Some(dummy_profile());
        // Lowercase `d` does nothing.
        app.on_key(key(KeyCode::Char('d')));
        assert_eq!(app.manage_stage, ManageStage::Viewing);
        // Uppercase `D` arms confirm.
        app.on_key(key(KeyCode::Char('D')));
        assert_eq!(app.manage_stage, ManageStage::DeleteInnerConfirm);
        // `n` cancels.
        app.on_key(key(KeyCode::Char('n')));
        assert_eq!(app.manage_stage, ManageStage::Viewing);
        // `D` again, then `y` arms the request flag.
        app.on_key(key(KeyCode::Char('D')));
        app.on_key(key(KeyCode::Char('y')));
        assert_eq!(app.manage_stage, ManageStage::DeletingInner);
        assert!(app.delete_inner_request);
    }

    #[test]
    fn manage_d_with_only_one_inner_profile_refuses_with_error() {
        // The container would end up empty — the TUI refuses and
        // surfaces an inline error pointing at `w` (wipe everything).
        let mut app = App::new();
        app.screen = Screen::ProfileManage;
        app.manage_stage = ManageStage::Viewing;
        app.unlock_source = ProfileSource::Local;
        app.unlocked_kek = Some(zz_drop_core::ProfileKek::from_parts(
            [0u8; 32],
            [0u8; 16],
            zz_drop_core::Argon2idConfig::DEFAULT,
        ));
        let mut set = zz_drop_core::ProfileSet::new();
        set.profiles.push(dummy_profile());
        app.unlocked_set = Some(set);
        app.unlocked_profile = Some(dummy_profile());
        app.on_key(key(KeyCode::Char('D')));
        assert_eq!(app.manage_stage, ManageStage::Viewing);
        assert!(app.manage_unlock_error.is_some());
        let msg = app.manage_unlock_error.unwrap();
        assert!(msg.contains("last profile"));
        assert!(!app.delete_inner_request);
    }

    #[test]
    fn apply_inner_deleted_routes_to_picker_and_clears_default_when_match() {
        // After a delete succeeds the operator lands on the picker
        // (so they can choose what to manage next) and the cached
        // default-alias is cleared if it pointed at the just-deleted
        // alias.
        let mut app = App::new();
        let mut set = zz_drop_core::ProfileSet::new();
        let mut a = dummy_profile();
        a.alias = "alpha".into();
        set.profiles.push(a);
        app.unlocked_set = Some(zz_drop_core::ProfileSet::new()); // pre-state, will be replaced
        app.unlocked_profile = Some(dummy_profile());
        app.picker_default_alias = Some("beta".into());
        app.apply_inner_deleted(set, "beta".into());
        assert_eq!(app.screen, Screen::ContainerPicker);
        assert!(app.unlocked_profile.is_none());
        assert!(app.picker_default_alias.is_none());
        assert_eq!(app.unlocked_set.as_ref().unwrap().profiles.len(), 1);
    }

    #[test]
    fn agent_pill_in_add_inner_profile_drops_typed_username() {
        // During the AddInnerProfile wizard the operator is typing a
        // brand-new profile's fields. The pill must NOT echo
        // `state.username` — that leaked through the post-save fall-
        // back and made the pill flicker as the user typed.
        let mut app = App::new();
        app.wizard_mode = WizardMode::AddInnerProfile;
        app.unlock_source = ProfileSource::Local;
        app.unlocked_set = Some(zz_drop_core::ProfileSet::with_profile(dummy_profile()));
        // Stale post-save state from a previous flow in this session.
        app.saved_path = Some("/tmp/profiles-local.zz".into());
        app.state.username = "gibbio".into();
        assert_eq!(
            app.agent_pill(),
            AgentPill::Local {
                alias: String::new()
            }
        );
    }

    #[test]
    fn welcome_configure_with_local_existing_routes_to_unlock_in_add_mode() {
        let mut app = App::new();
        app.local_exists = true;
        app.welcome_item = WelcomeItem::Configure;
        app.on_key(key(KeyCode::Enter));
        // With local_exists=true, "Configure" must mean "add a new
        // inner profile to the existing container", NOT "create a
        // brand-new local container".
        assert_eq!(app.wizard_mode, WizardMode::AddInnerProfile);
        assert_eq!(app.screen, Screen::ProfileUnlock);
        assert_eq!(app.unlock_source, ProfileSource::Local);
    }

    #[test]
    fn welcome_add_to_local_then_unlock_preserves_existing_profiles_in_set() {
        use zz_drop_core::profile::set::ProfileKek;
        use zz_drop_core::{Argon2idConfig, ProfileSet};

        let mut existing = ProfileSet::new();
        existing.profiles.push(dummy_profile());
        let mut other = dummy_profile();
        other.alias = "other".into();
        other.profile_id = "other".into();
        existing.profiles.push(other);
        let kek = ProfileKek::from_parts([7u8; 32], [9u8; 16], Argon2idConfig::default());

        // 1. Welcome with local_exists=true and Configure focused →
        //    wizard_mode flips to AddInnerProfile and we land on
        //    ProfileUnlock without touching unlocked_set yet.
        let mut app = App::new();
        app.local_exists = true;
        app.welcome_item = WelcomeItem::Configure;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.wizard_mode, WizardMode::AddInnerProfile);
        assert_eq!(app.screen, Screen::ProfileUnlock);
        assert!(app.unlocked_set.is_none());

        // 2. Successful unlock with a 2-profile set: the AddInnerProfile
        //    branch in `apply_unlock_set_done` must store the set
        //    + KEK and route to Provider, *without* dropping any
        //    existing profile.
        app.apply_unlock_set_done(existing.clone(), kek, Some("test".into()));
        assert_eq!(app.wizard_mode, WizardMode::AddInnerProfile);
        assert_eq!(app.screen, Screen::Provider);
        assert!(app.unlocked_kek.is_some());
        let stored = app.unlocked_set.as_ref().expect("set stored after unlock");
        assert_eq!(stored.profiles.len(), 2);

        // 3. Walk the wizard end-to-end with stub state. The
        //    AddInnerProfile branch in TestUpload's Enter handler
        //    must route to InnerAlias (the alias prompt), never to
        //    ProfilePassphrase (which would arm save_request and
        //    overwrite the container with a single-profile set).
        app.state.server_url = "https://example.org".into();
        app.state.username = "alice".into();
        app.state.auth_secret = "x".into();
        app.state.remote_folder = "/zz-drop".into();
        app.screen = Screen::TestUpload;
        app.state.last_test_outcome = Some(TestOutcome::Ok);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::InnerAlias);
        assert!(!app.save_request);

        // 4. After typing an alias and pressing Enter on InnerAlias,
        //    only `add_inner_request` is armed — the container writer
        //    in main.rs reads `unlocked_set` (still 2 profiles) and
        //    appends a third before re-encrypting.
        app.inner_alias_input = TextInput::new();
        app.inner_alias_input.set_value("fresh");
        app.on_key(key(KeyCode::Enter));
        assert!(app.add_inner_request);
        assert!(!app.save_request);
        let still = app
            .unlocked_set
            .as_ref()
            .expect("set survives until main.rs re-encrypts");
        assert_eq!(
            still.profiles.len(),
            2,
            "main.rs must clone this 2-profile set and append the new one"
        );
    }

    #[test]
    fn apply_wipe_done_clears_state_and_returns_to_welcome() {
        let mut app = App::new();
        app.local_exists = true;
        app.remote_exists = true;
        app.saved_path = Some("/tmp/profiles-local.zz".into());
        app.apply_wipe_done();
        assert!(!app.profile_exists());
        assert!(app.saved_path.is_none());
        assert_eq!(app.screen, Screen::Welcome);
        assert_eq!(app.welcome_item, WelcomeItem::Configure);
    }

    #[test]
    fn provider_to_server_via_enter() {
        let mut app = App::new();
        app.screen = Screen::Provider;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::NextcloudServer);
    }

    #[test]
    fn provider_picker_arrow_down_then_enter_goes_to_gdrive_setup() {
        let mut app = App::new();
        app.screen = Screen::Provider;
        assert_eq!(app.state.provider_kind, ProviderKind::Nextcloud);

        app.on_key(key(KeyCode::Down));
        assert_eq!(app.state.provider_kind, ProviderKind::GoogleDrive);

        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::SetupGoogleDrive);
        assert!(
            app.gdrive_request_init,
            "entering SetupGoogleDrive should arm the device-flow init trigger"
        );
    }

    #[test]
    fn provider_picker_arrow_up_returns_to_nextcloud() {
        let mut app = App::new();
        app.screen = Screen::Provider;
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.state.provider_kind, ProviderKind::GoogleDrive);
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.state.provider_kind, ProviderKind::Nextcloud);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::NextcloudServer);
    }

    #[test]
    fn gdrive_setup_esc_returns_to_provider_and_clears_init_flag() {
        let mut app = App::new();
        app.screen = Screen::Provider;
        app.state.provider_kind = ProviderKind::GoogleDrive;
        app.on_key(key(KeyCode::Enter));
        assert!(app.gdrive_request_init);

        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Provider);
        assert!(!app.gdrive_request_init);
    }

    #[test]
    fn apply_gdrive_init_moves_to_polling_with_populated_state() {
        let mut app = App::new();
        app.screen = Screen::SetupGoogleDrive;
        app.apply_gdrive_init(
            "ABCD-EFGH".into(),
            "https://www.google.com/device".into(),
            Some("https://www.google.com/device?user_code=ABCD-EFGH".into()),
            "DEVCODE".into(),
            1800,
            5,
        );
        assert!(matches!(
            app.gdrive_setup.stage,
            GoogleDriveSetupStage::Polling
        ));
        assert_eq!(app.gdrive_setup.user_code, "ABCD-EFGH");
        assert_eq!(app.gdrive_setup.interval_secs, 5);
        assert!(app.gdrive_setup.expires_at > 0);
    }

    #[test]
    fn apply_gdrive_tokens_arms_email_request_and_moves_to_fetching() {
        let mut app = App::new();
        app.gdrive_setup.stage = GoogleDriveSetupStage::Polling;
        app.apply_gdrive_tokens(
            "AT".into(),
            Some("RT".into()),
            "Bearer".into(),
            3600,
            Some("https://www.googleapis.com/auth/drive.file".into()),
        );
        assert!(matches!(
            app.gdrive_setup.stage,
            GoogleDriveSetupStage::Fetching
        ));
        assert!(app.gdrive_request_email);
        assert_eq!(app.gdrive_setup.access_token, "AT");
        assert_eq!(app.gdrive_setup.refresh_token, "RT");
        assert!(app.gdrive_setup.access_expires_at > 0);
    }

    #[test]
    fn apply_gdrive_email_finalises_done_state() {
        let mut app = App::new();
        app.gdrive_setup.stage = GoogleDriveSetupStage::Fetching;
        app.apply_gdrive_email("alice@example.com".into());
        assert!(matches!(
            app.gdrive_setup.stage,
            GoogleDriveSetupStage::Done
        ));
        assert_eq!(app.gdrive_setup.user_email, "alice@example.com");
    }

    #[test]
    fn apply_gdrive_failed_clears_pending_triggers() {
        let mut app = App::new();
        app.gdrive_setup.stage = GoogleDriveSetupStage::Polling;
        app.gdrive_request_init = true;
        app.gdrive_request_email = true;
        app.apply_gdrive_failed("device code expired".into());
        assert!(matches!(
            app.gdrive_setup.stage,
            GoogleDriveSetupStage::Failed(_)
        ));
        assert!(!app.gdrive_request_init);
        assert!(!app.gdrive_request_email);
    }

    #[test]
    fn bump_gdrive_interval_adds_five_seconds() {
        let mut app = App::new();
        app.gdrive_setup.interval_secs = 5;
        app.bump_gdrive_interval();
        assert_eq!(app.gdrive_setup.interval_secs, 10);
        app.bump_gdrive_interval();
        assert_eq!(app.gdrive_setup.interval_secs, 15);
    }

    #[test]
    fn gdrive_setup_r_on_failed_rearms_init() {
        let mut app = App::new();
        app.screen = Screen::SetupGoogleDrive;
        app.gdrive_setup.stage = GoogleDriveSetupStage::Failed("expired".into());
        app.on_key(key(KeyCode::Char('r')));
        assert!(app.gdrive_request_init);
        assert!(matches!(
            app.gdrive_setup.stage,
            GoogleDriveSetupStage::Initiating
        ));
    }

    #[test]
    fn gdrive_setup_q_toggles_qr_only_when_polling() {
        let mut app = App::new();
        app.screen = Screen::SetupGoogleDrive;
        app.gdrive_setup.stage = GoogleDriveSetupStage::Initiating;
        let before = app.gdrive_setup.show_qr;
        app.on_key(key(KeyCode::Char('q')));
        assert_eq!(app.gdrive_setup.show_qr, before, "q must be a no-op outside Polling");

        app.gdrive_setup.stage = GoogleDriveSetupStage::Polling;
        app.on_key(key(KeyCode::Char('q')));
        assert_ne!(app.gdrive_setup.show_qr, before);
    }

    #[test]
    fn gdrive_setup_enter_on_done_advances_to_collision() {
        let mut app = App::new();
        app.screen = Screen::SetupGoogleDrive;
        app.gdrive_setup.stage = GoogleDriveSetupStage::Done;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Collision);
    }

    #[test]
    fn apply_unlock_done_hydrates_gdrive_provider_from_profile() {
        use zz_drop_core::providers::google_drive::{GoogleDriveAuth, GoogleDriveProfile};
        use zz_drop_core::{
            CollisionPolicy, PlainProfile, ProfileSettings, ProviderProfile,
        };

        let gd = GoogleDriveProfile {
            root_folder: "zz-drop".into(),
            user_email: "alice@example.com".into(),
            root_folder_id: Some("FOLDER_ID".into()),
            auth: GoogleDriveAuth {
                access_token: "AT".into(),
                refresh_token: "RT".into(),
                token_type: "Bearer".into(),
                expires_at: 1_700_000_000,
                scope: "https://www.googleapis.com/auth/drive.file".into(),
            },
        };
        let profile = PlainProfile {
            profile_version: 1,
            profile_id: "p".into(),
            alias: "alice".into(),
            default_target: "google_drive".into(),
            providers: vec![ProviderProfile::GoogleDrive(gd)],
            collision_policy: CollisionPolicy::Rename,
            settings: ProfileSettings::default(),
            created_at: "epoch:0".into(),
            updated_at: "epoch:0".into(),
        };

        let mut app = App::new();
        app.apply_unlock_done(profile);

        assert_eq!(app.state.provider_kind, ProviderKind::GoogleDrive);
        assert_eq!(app.gdrive_setup.user_email, "alice@example.com");
        assert_eq!(app.gdrive_setup.root_folder, "zz-drop");
        assert_eq!(app.gdrive_setup.access_token, "AT");
        assert_eq!(app.gdrive_setup.refresh_token, "RT");
        assert!(matches!(
            app.gdrive_setup.stage,
            GoogleDriveSetupStage::Done
        ));
        assert_eq!(app.screen, Screen::ProfileManage);
    }

    #[test]
    fn gdrive_setup_url_modal_eats_keys_and_esc_closes() {
        let mut app = App::new();
        app.screen = Screen::SetupGoogleDrive;
        app.gdrive_setup.stage = GoogleDriveSetupStage::Polling;
        app.gdrive_setup.show_url_modal = true;

        // Random key while modal is open — should NOT close it or
        // navigate; only `esc` does.
        app.on_key(key(KeyCode::Char('c')));
        assert!(app.gdrive_setup.show_url_modal);

        app.on_key(key(KeyCode::Esc));
        assert!(!app.gdrive_setup.show_url_modal);
        // The screen stays put; closing the modal is not "back".
        assert_eq!(app.screen, Screen::SetupGoogleDrive);
    }

    #[test]
    fn server_screen_starts_with_https_prefix() {
        let app = App::new();
        assert_eq!(app.server_input.value(), "https://");
    }

    #[test]
    fn server_screen_typed_chars_accumulate_in_state() {
        let mut app = App::new();
        app.screen = Screen::NextcloudServer;
        for c in "nc".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        // The default `https://` prefix is preserved.
        assert_eq!(app.state.server_url, "https://nc");
    }

    #[test]
    fn server_screen_q_is_typed_not_quit() {
        let mut app = App::new();
        app.screen = Screen::NextcloudServer;
        app.on_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        assert_eq!(app.state.server_url, "https://q");
    }

    #[test]
    fn server_screen_question_mark_is_ignored() {
        let mut app = App::new();
        app.screen = Screen::NextcloudServer;
        let before = app.server_input.value().to_string();
        app.on_key(key(KeyCode::Char('?')));
        assert_eq!(app.server_input.value(), before);
    }

    #[test]
    fn server_enter_advances_only_when_valid() {
        let mut app = App::new();
        app.screen = Screen::NextcloudServer;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::NextcloudServer);

        for c in "nc.example.org".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::NextcloudAuth);
    }

    #[test]
    fn auth_tab_cycles_focus() {
        let mut app = App::new();
        app.screen = Screen::NextcloudAuth;
        assert_eq!(app.auth_focus, AuthFocus::KindSelector);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.auth_focus, AuthFocus::Username);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.auth_focus, AuthFocus::Secret);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.auth_focus, AuthFocus::KindSelector);
    }

    #[test]
    fn auth_secret_chars_kept_in_state() {
        let mut app = App::new();
        app.screen = Screen::NextcloudAuth;
        app.auth_focus = AuthFocus::Secret;
        for c in "topsecret".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.state.auth_secret, "topsecret");
    }

    #[test]
    fn auth_login_flow_blocks_advance() {
        let mut app = App::new();
        app.screen = Screen::NextcloudAuth;
        app.state.auth_kind = AuthKind::LoginFlow;
        app.username_input.set_value("user");
        app.secret_input.set_value("xxx");
        app.commit_auth();
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::NextcloudAuth);
    }

    #[test]
    fn auth_app_password_advances_when_complete() {
        let mut app = App::new();
        app.screen = Screen::NextcloudAuth;
        app.state.auth_kind = AuthKind::AppPassword;
        app.username_input.set_value("user");
        app.secret_input.set_value("xxx");
        app.commit_auth();
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::RemoteFolder);
    }

    #[test]
    fn collision_arrows_cycle_choice() {
        let mut app = App::new();
        app.screen = Screen::Collision;
        assert_eq!(app.collision, CollisionChoice::Rename);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.collision, CollisionChoice::Overwrite);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.collision, CollisionChoice::Fail);
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.collision, CollisionChoice::Overwrite);
    }

    #[test]
    fn collision_enter_writes_state_and_advances() {
        let mut app = App::new();
        app.screen = Screen::Collision;
        app.collision = CollisionChoice::Overwrite;
        app.on_key(key(KeyCode::Enter));
        assert_eq!(
            app.state.collision,
            zz_drop_core::CollisionPolicy::Overwrite
        );
        assert_eq!(app.screen, Screen::TestUpload);
    }

    #[test]
    fn test_upload_enter_when_idle_runs_probe() {
        let mut app = App::new();
        app.screen = Screen::TestUpload;
        app.on_key(key(KeyCode::Enter));
        assert!(app.test_request);
        assert_eq!(app.screen, Screen::TestUpload);
    }

    #[test]
    fn test_upload_enter_after_ok_advances_to_inner_alias() {
        let mut app = App::new();
        app.screen = Screen::TestUpload;
        app.state.last_test_outcome = Some(TestOutcome::Ok);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::InnerAlias);
        assert!(!app.test_request);
    }

    #[test]
    fn test_upload_enter_after_failed_retries() {
        let mut app = App::new();
        app.screen = Screen::TestUpload;
        app.state.last_test_outcome = Some(TestOutcome::Failed("oops".into()));
        app.on_key(key(KeyCode::Enter));
        assert!(app.test_request);
        assert_eq!(app.screen, Screen::TestUpload);
    }

    #[test]
    fn test_upload_records_outcome() {
        let mut app = App::new();
        app.test_running = true;
        app.record_test_outcome(TestOutcome::Ok);
        assert_eq!(app.state.last_test_outcome, Some(TestOutcome::Ok));
        assert!(!app.test_running);
    }

    #[test]
    fn probe_per_step_transitions_busy_then_ok() {
        let mut app = App::new();
        app.test_running = true;
        app.start_probe();
        assert_eq!(app.state.probe_progress.ensure, ProbeStepStatus::Busy);
        assert_eq!(app.state.probe_progress.marker, ProbeStepStatus::Pending);
        assert_eq!(app.state.probe_progress.upload, ProbeStepStatus::Pending);
        assert_eq!(app.state.probe_progress.cleanup, ProbeStepStatus::Pending);

        app.mark_probe_ensure_ok();
        assert_eq!(app.state.probe_progress.ensure, ProbeStepStatus::Ok);
        assert_eq!(app.state.probe_progress.marker, ProbeStepStatus::Busy);
        assert!(app.test_running);

        app.mark_probe_marker_ok();
        assert_eq!(app.state.probe_progress.marker, ProbeStepStatus::Ok);
        assert_eq!(app.state.probe_progress.upload, ProbeStepStatus::Busy);
        assert!(app.test_running);

        app.mark_probe_upload_ok();
        assert_eq!(app.state.probe_progress.upload, ProbeStepStatus::Ok);
        assert_eq!(app.state.probe_progress.cleanup, ProbeStepStatus::Busy);
        // Probe still running until cleanup resolves.
        assert!(app.test_running);

        app.mark_probe_cleanup_ok();
        assert_eq!(app.state.probe_progress.cleanup, ProbeStepStatus::Ok);
        assert_eq!(app.state.last_test_outcome, Some(TestOutcome::Ok));
        assert!(!app.test_running);
    }

    #[test]
    fn probe_ensure_failure_stops_progress() {
        let mut app = App::new();
        app.test_running = true;
        app.start_probe();
        app.fail_probe_ensure("ensure folder: 401 unauthorized".into());
        assert_eq!(app.state.probe_progress.ensure, ProbeStepStatus::Err);
        // All downstream stages are skipped.
        assert_eq!(app.state.probe_progress.marker, ProbeStepStatus::Skip);
        assert_eq!(app.state.probe_progress.upload, ProbeStepStatus::Skip);
        assert_eq!(app.state.probe_progress.cleanup, ProbeStepStatus::Skip);
        assert!(matches!(
            app.state.last_test_outcome,
            Some(TestOutcome::Failed(_))
        ));
        assert!(!app.test_running);
    }

    #[test]
    fn probe_marker_failure_skips_upload_and_cleanup() {
        let mut app = App::new();
        app.test_running = true;
        app.start_probe();
        app.mark_probe_ensure_ok();
        app.fail_probe_marker("marker: write failed".into());
        assert_eq!(app.state.probe_progress.marker, ProbeStepStatus::Err);
        assert_eq!(app.state.probe_progress.upload, ProbeStepStatus::Skip);
        assert_eq!(app.state.probe_progress.cleanup, ProbeStepStatus::Skip);
        assert!(!app.test_running);
    }

    #[test]
    fn probe_upload_failure_skips_cleanup() {
        let mut app = App::new();
        app.test_running = true;
        app.start_probe();
        app.mark_probe_ensure_ok();
        app.mark_probe_marker_ok();
        app.fail_probe_upload("upload: 500 server error".into());
        assert_eq!(app.state.probe_progress.upload, ProbeStepStatus::Err);
        assert_eq!(app.state.probe_progress.cleanup, ProbeStepStatus::Skip);
        assert!(!app.test_running);
    }

    // ── push to zz-drop.net (TASK 20 Phase 2) ──────────────────

    #[test]
    fn done_q_quits() {
        let mut app = App::new();
        app.screen = Screen::Done;
        app.saved_path = Some("/tmp/profile.zz".into());
        app.on_key(key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    #[test]
    fn done_p_is_no_longer_a_shortcut() {
        // The push sub-flow used to be opt-in via `p` from Done. Now
        // it is part of the wizard automatically (after passphrase
        // save). `p` on Done is a no-op so the wording can stop
        // promising a shortcut that doesn't exist.
        let mut app = App::new();
        app.screen = Screen::Done;
        app.saved_path = Some("/tmp/profile.zz".into());
        app.on_key(key(KeyCode::Char('p')));
        assert_eq!(app.screen, Screen::Done);
        assert!(!app.should_quit);
    }

    #[test]
    fn passphrase_saved_enter_skips_push_and_lands_on_done() {
        // Push is optional after a Configure save: Enter on the
        // "saved" stage skips the push and lands on Done with the
        // local-only warning.
        let mut app = App::new();
        app.screen = Screen::ProfilePassphrase;
        app.passphrase_stage =
            PassphraseStage::Saved("/home/alice/.config/zz-drop/profiles-local.zz".into());
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Done);
        assert!(app.pushed_summary.is_none());
    }

    #[test]
    fn passphrase_saved_p_enters_push_flow() {
        // The operator who *does* want recovery presses `p` —
        // routes into the existing push sub-flow.
        let mut app = App::new();
        app.screen = Screen::ProfilePassphrase;
        app.passphrase_stage =
            PassphraseStage::Saved("/home/alice/.config/zz-drop/profiles-local.zz".into());
        app.on_key(key(KeyCode::Char('p')));
        assert_eq!(app.screen, Screen::Account);
        assert_eq!(app.push_flow.stage, PushStage::AccountForm);
        assert_eq!(app.push_flow.mode, PushFlowMode::Push);
        assert!(app.push_back.is_none());
    }

    #[test]
    fn account_esc_in_wizard_mode_is_noop() {
        // Wizard auto-push: `push_back` is None, so Esc must not
        // bail out — only success or Ctrl-C exit.
        let mut app = App::new();
        app.screen = Screen::Account;
        app.push_back = None;
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Account);
    }

    #[test]
    fn account_esc_in_repush_mode_returns_to_back_pointer() {
        // `p · re-push` from ProfileManage sets `push_back =
        // Some(ProfileManage)`. Esc on Account must consume the
        // back-pointer and return there. Useful when the API
        // server is unreachable and the operator wants to bail.
        let mut app = App::new();
        app.screen = Screen::Account;
        app.push_back = Some(Screen::ProfileManage);
        app.account_email_input.set_value("alice@example.org");
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::ProfileManage);
        assert_eq!(app.push_back, None);
        // Push state cleared so a re-entry starts fresh.
        assert_eq!(app.push_flow.stage, PushStage::AccountForm);
        assert_eq!(app.account_email_input.value(), "");
    }

    #[test]
    fn push_profile_esc_in_repush_mode_returns_to_back_pointer() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_back = Some(Screen::ProfileManage);
        app.apply_aliases_loaded(vec!["existing".into()]);
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::ProfileManage);
        assert_eq!(app.push_back, None);
    }

    #[test]
    fn push_profile_esc_in_wizard_mode_is_noop() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_back = None;
        app.apply_aliases_loaded(vec!["existing".into()]);
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::PushProfile);
    }

    #[test]
    fn re_push_done_enter_returns_to_back_pointer_not_done() {
        // Re-push from ProfileManage: after success, Enter must
        // return to ProfileManage, *not* to the wizard's Done
        // screen. The wizard's auto-push case is covered by the
        // existing `push_done_returns_to_done_screen_on_enter` test.
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.push_back = Some(Screen::ProfileManage);
        app.apply_push_done("asdasdasd".into(), 745, 7);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::ProfileManage);
        assert_eq!(app.push_back, None);
        assert_eq!(app.push_flow.stage, PushStage::AccountForm);
    }

    #[test]
    fn push_success_populates_pushed_summary_for_done_render() {
        let mut app = App::new();
        app.apply_push_done("casa-nc".into(), 4096, 3);
        {
            let s = app.pushed_summary.as_ref().expect("pushed_summary set");
            assert_eq!(s.alias, "casa-nc");
            assert_eq!(s.blob_size, 4096);
            assert_eq!(s.blob_version, 3);
        }
        // Survives a transition that would clear push_flow.
        app.push_flow = PushFlowState::default();
        assert!(app.pushed_summary.is_some());
    }

    #[test]
    fn account_enter_with_complete_inputs_sets_login_request() {
        let mut app = App::new();
        app.screen = Screen::Account;
        app.account_email_input.set_value("alice@example.org");
        app.account_password_input.set_value("hunter2hunter2");
        app.on_key(key(KeyCode::Enter));
        assert!(app.push_request_login);
        assert_eq!(app.push_flow.stage, PushStage::AccountSending);
    }

    #[test]
    fn account_enter_with_invalid_email_surfaces_validation_hint() {
        let mut app = App::new();
        app.screen = Screen::Account;
        app.account_email_input.set_value("noatsign");
        app.account_password_input.set_value("hunter2hunter2");
        app.on_key(key(KeyCode::Enter));
        assert!(!app.push_request_login);
        assert_eq!(
            app.account_validation_error,
            Some("enter a valid email address"),
        );
    }

    #[test]
    fn account_enter_with_empty_password_surfaces_validation_hint() {
        let mut app = App::new();
        app.screen = Screen::Account;
        app.account_email_input.set_value("alice@example.org");
        app.account_password_input.set_value("");
        app.on_key(key(KeyCode::Enter));
        assert!(!app.push_request_login);
        assert_eq!(app.account_validation_error, Some("enter your password"));
    }

    #[test]
    fn account_validation_hint_clears_on_next_keystroke() {
        let mut app = App::new();
        app.screen = Screen::Account;
        app.account_email_input.set_value("noatsign");
        app.account_password_input.set_value("hunter2hunter2");
        app.on_key(key(KeyCode::Enter));
        assert!(app.account_validation_error.is_some());
        // A character keystroke in the email field clears the hint.
        app.on_key(key(KeyCode::Char('@')));
        assert!(app.account_validation_error.is_none());
    }

    #[test]
    fn account_session_response_jumps_to_push_profile_and_lists() {
        let mut app = App::new();
        app.screen = Screen::Account;
        app.apply_login_session("session-token".into());
        assert_eq!(app.screen, Screen::PushProfile);
        assert_eq!(app.push_flow.stage, PushStage::PushFetching);
        assert!(app.push_request_list);
    }

    #[test]
    fn account_totp_required_response_jumps_to_login_totp() {
        let mut app = App::new();
        app.screen = Screen::Account;
        app.apply_login_totp_required("opaque-challenge".into());
        assert_eq!(app.screen, Screen::LoginTotp);
        assert_eq!(app.push_flow.stage, PushStage::TotpForm);
    }

    #[test]
    fn login_totp_enter_with_code_dispatches_verify() {
        let mut app = App::new();
        app.screen = Screen::LoginTotp;
        app.push_flow.login_challenge = Some("opaque".into());
        app.totp_code_input.set_value("123456");
        app.on_key(key(KeyCode::Enter));
        assert!(app.push_request_totp);
        assert_eq!(app.push_flow.stage, PushStage::TotpSending);
    }

    #[test]
    fn push_profile_picker_arrow_keys_walk_aliases() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.apply_aliases_loaded(vec!["a".into(), "b".into(), "c".into()]);
        assert_eq!(app.push_flow.picker_index, Some(0));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.push_flow.picker_index, Some(1));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.push_flow.picker_index, Some(2));
        // Stepping past the last alias goes to "type new" mode.
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.push_flow.picker_index, None);
    }

    #[test]
    fn push_profile_enter_on_picker_dispatches_send() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.apply_aliases_loaded(vec!["casa-nc".into()]);
        app.saved_path = Some("/tmp/profile.zz".into());
        app.on_key(key(KeyCode::Enter));
        assert!(app.push_request_send);
        assert_eq!(app.push_flow.stage, PushStage::PushSending);
    }

    #[test]
    fn push_done_returns_to_done_screen_on_enter() {
        let mut app = App::new();
        app.screen = Screen::PushProfile;
        app.apply_push_done("casa-nc".into(), 256, 1);
        assert_eq!(app.push_flow.stage, PushStage::Done);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Done);
        // Push state is cleared so a re-push starts clean.
        assert_eq!(app.push_flow.stage, PushStage::AccountForm);
    }

    #[test]
    fn push_failed_state_carries_reason() {
        let mut app = App::new();
        app.apply_push_failed("blob too large".into());
        assert!(matches!(
            app.push_flow.stage,
            PushStage::Failed(ref s) if s == "blob too large"
        ));
    }

    #[test]
    fn push_flow_debug_does_not_leak_token_or_challenge() {
        let mut app = App::new();
        app.push_flow.session_token = Some("super-secret-canary".into());
        app.push_flow.login_challenge = Some("challenge-canary".into());
        let d = format!("{:?}", app.push_flow);
        assert!(!d.contains("super-secret-canary"));
        assert!(!d.contains("challenge-canary"));
    }
}
