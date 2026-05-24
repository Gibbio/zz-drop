//! Persistent profile types for Dropbox.
//!
//! Mirrors the OneDrive layout: [`DropboxProfile`] is the container
//! payload, [`DropboxAuth`] holds the OAuth tokens. Both `Debug`
//! impls fully redact — there is no useful non-secret field here
//! that justifies a partial `Debug`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What zz-drop persists for a Dropbox provider inside the encrypted
/// `profile.zz` payload. Never written to disk in clear.
///
/// The Dropbox app is registered as App-folder type, so paths sent
/// to the `/files/*` endpoints are *relative* to the app's sandbox.
/// Dropbox surfaces the same content to the user under
/// `Apps/zz-drop/{root_folder}/...`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DropboxProfile {
    /// Folder name where zz-drop creates files, relative to the
    /// app's sandbox. Default is the **empty string**, meaning
    /// "use the App folder sandbox root directly" — the user sees
    /// files under `Apps/zz-drop/...` with no extra subfolder.
    /// A non-empty value adds one nested folder
    /// (`Apps/zz-drop/{root_folder}/...`), preserved for
    /// backward compatibility with profiles persisted before the
    /// default flipped to empty.
    pub root_folder: String,

    /// Display-only — the email Dropbox returned from
    /// `/2/users/get_current_account` at setup. Used by the
    /// CLI/TUI to confirm "you upload as alice@example.com". Not
    /// used for any auth decision.
    pub user_email: String,

    pub auth: DropboxAuth,
}

impl fmt::Debug for DropboxProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DropboxProfile { <redacted> }")
    }
}

/// OAuth tokens for Dropbox, plus enough metadata to know when to
/// refresh. Dropbox issues the `refresh_token` only when the
/// authorize URL included `token_access_type=offline`, which is
/// enforced at setup time.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DropboxAuth {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    /// Unix timestamp (seconds) at which `access_token` expires.
    /// The operational client refreshes proactively when within
    /// `EXPIRY_SKEW_SECS` of this value.
    pub expires_at: u64,
    pub scope: String,
}

impl fmt::Debug for DropboxAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DropboxAuth { <redacted> }")
    }
}

/// Wipe the OAuth tokens from memory when this struct is dropped, so
/// that locking the agent (or dropping any transient clone of the
/// decrypted profile) does not leave token bytes lingering in freed
/// heap / swap. The fields stay `String` so the on-disk CBOR format and
/// every call site are unchanged. See security audit F2.
impl Drop for DropboxAuth {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// Refresh tokens before this many seconds remain on the access
/// token, to avoid edge-of-window 401s mid-upload.
pub const EXPIRY_SKEW_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard: the zeroize-on-drop `Drop` impl must coexist with the
    /// derived `Clone` / `PartialEq` and round-trip through CBOR
    /// unchanged (the on-disk format must not shift). Representative for
    /// all four `*Auth` types, which share the same pattern.
    #[test]
    fn auth_clone_eq_and_cbor_roundtrip_survive_drop_impl() {
        let a = DropboxAuth {
            access_token: "at".into(),
            refresh_token: "rt".into(),
            token_type: "bearer".into(),
            expires_at: 123,
            scope: "files".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);

        let mut buf = Vec::new();
        ciborium::into_writer(&a, &mut buf).unwrap();
        let back: DropboxAuth = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(a, back);
        // a, b, back all drop here → Drop (zeroize) runs without panic.
    }
}
