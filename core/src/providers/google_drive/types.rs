//! Persistent profile types for Google Drive.
//!
//! The `Debug` impls intentionally redact the entire structure rather
//! than printing field-by-field with `<redacted>` placeholders: there
//! is no useful non-secret content here that justifies a partial
//! `Debug`, and full redaction is harder to undo by mistake.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What zz-drop persists for a Google Drive provider inside the
/// encrypted `profile.zz` payload. Never written to disk in clear.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct GoogleDriveProfile {
    /// Folder name where zz-drop creates files. Default `"zz-drop"`.
    /// Only files created by the app are visible due to the
    /// `drive.file` scope, so this is a logical label more than an
    /// access boundary.
    pub root_folder: String,

    /// Display-only — the email address Google reported on the token
    /// exchange. Used by the CLI/TUI to confirm "you are uploading as
    /// alice@gmail.com". Not used for any auth decision.
    pub user_email: String,

    /// Cached identifier of the root folder on Drive, populated lazily
    /// by the operational client and kept here so subsequent runs
    /// avoid an extra search round-trip. `None` until first use.
    #[serde(default)]
    pub root_folder_id: Option<String>,

    pub auth: GoogleDriveAuth,
}

impl fmt::Debug for GoogleDriveProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GoogleDriveProfile { <redacted> }")
    }
}

/// OAuth tokens for Google Drive, plus enough metadata to know when to
/// refresh.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct GoogleDriveAuth {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    /// Unix timestamp (seconds) at which `access_token` expires.
    /// The operational client refreshes proactively when within
    /// `EXPIRY_SKEW_SECS` of this value.
    pub expires_at: u64,
    pub scope: String,
}

impl fmt::Debug for GoogleDriveAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GoogleDriveAuth { <redacted> }")
    }
}

/// Wipe the OAuth tokens from memory on drop (see security audit F2).
/// Fields stay `String`, so the on-disk CBOR format and call sites are
/// unchanged; only the freed buffers are zeroed.
impl Drop for GoogleDriveAuth {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// Refresh tokens before this many seconds remain on the access token,
/// to avoid edge-of-window 401s mid-upload.
pub const EXPIRY_SKEW_SECS: u64 = 60;
