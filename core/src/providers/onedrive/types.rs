//! Persistent profile types for Microsoft OneDrive.
//!
//! Mirrors the Google Drive layout: `OneDriveProfile` is the
//! container payload, `OneDriveAuth` holds the OAuth tokens. Both
//! `Debug` impls fully redact — there is no useful non-secret field
//! here that justifies a partial `Debug`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What zz-drop persists for a OneDrive provider inside the
/// encrypted `profile.zz` payload. Never written to disk in clear.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct OneDriveProfile {
    /// Folder name where zz-drop creates files, relative to the
    /// account's drive root. Default `"zz-drop"`. The path is
    /// resolved with Microsoft Graph's path-addressing
    /// (`/me/drive/root:/{root_folder}/...`).
    pub root_folder: String,

    /// Display-only — the user principal name (or `mail` field) the
    /// `/me` endpoint returned at setup. The CLI/TUI uses it to
    /// confirm "you are uploading as alice@outlook.com". Not used
    /// for any auth decision.
    pub user_email: String,

    /// Cached Graph item id of the root folder, populated lazily by
    /// the operational client. Lets subsequent runs skip a metadata
    /// lookup. `None` until first use.
    #[serde(default)]
    pub root_folder_id: Option<String>,

    pub auth: OneDriveAuth,
}

impl fmt::Debug for OneDriveProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OneDriveProfile { <redacted> }")
    }
}

/// OAuth tokens for OneDrive, plus enough metadata to know when to
/// refresh. Microsoft issues the refresh_token only when `scope`
/// included `offline_access`, which is enforced at setup time.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct OneDriveAuth {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    /// Unix timestamp (seconds) at which `access_token` expires.
    /// The operational client refreshes proactively when within
    /// `EXPIRY_SKEW_SECS` of this value.
    pub expires_at: u64,
    pub scope: String,
}

impl fmt::Debug for OneDriveAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OneDriveAuth { <redacted> }")
    }
}

/// Wipe the OAuth tokens from memory on drop (see security audit F2).
/// Fields stay `String`, so the on-disk CBOR format and call sites are
/// unchanged; only the freed buffers are zeroed.
impl Drop for OneDriveAuth {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// Refresh tokens before this many seconds remain on the access
/// token, to avoid edge-of-window 401s mid-upload.
pub const EXPIRY_SKEW_SECS: u64 = 60;
