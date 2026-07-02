pub mod dropbox;
pub mod google_drive;
pub mod nextcloud;
pub mod oauth;
pub mod oauth_clients;
pub mod onedrive;

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use dropbox::{DropboxAuth, DropboxProfile};
pub use google_drive::{GoogleDriveAuth, GoogleDriveProfile};
pub use nextcloud::{NextcloudAuth, NextcloudProfile};
pub use onedrive::{OneDriveAuth, OneDriveProfile};

/// Serde tags of the provider variants this binary understands.
/// `profile::format` consults this list when decoding a container:
/// entries under any other tag are preserved as [`UnknownProvider`]
/// instead of failing the whole decode. Must stay in sync with the
/// [`ProviderProfile`] variants (guarded by a test in
/// `tests/types_serde.rs`).
pub const KNOWN_PROVIDER_TAGS: &[&str] = &["nextcloud", "google_drive", "one_drive", "dropbox"];

/// Reserved serde tag of [`ProviderProfile::Unknown`]. No real
/// provider may ever use this tag: a container written by a newer
/// zz-drop with a provider literally named `unknown` would collide
/// with the forward-compatibility carrier.
pub const UNKNOWN_PROVIDER_TAG: &str = "unknown";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProfile {
    Nextcloud(NextcloudProfile),
    GoogleDrive(GoogleDriveProfile),
    OneDrive(OneDriveProfile),
    Dropbox(DropboxProfile),
    /// Forward-compatibility carrier for a provider entry written by
    /// a newer zz-drop under a serde tag this binary does not know.
    /// Only the profile.zz decode boundary (`profile::format`)
    /// constructs it; on re-encrypt the entry is written back under
    /// its original tag with its original payload, byte-for-byte
    /// semantics preserved. Every operational path must treat it as
    /// "unsupported alias — upgrade zz-drop".
    Unknown(UnknownProvider),
}

/// Payload of [`ProviderProfile::Unknown`]: the foreign serde tag and
/// the raw CBOR bytes of the payload the newer binary wrote. The
/// bytes may contain that provider's secrets, so `Debug` never prints
/// them.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct UnknownProvider {
    pub tag: String,
    pub payload_cbor: Vec<u8>,
}

impl UnknownProvider {
    /// Static operator-facing diagnostic, shaped for
    /// `RemoteError::Diagnostic`.
    pub fn diagnose() -> &'static str {
        "this alias was set up by a newer zz-drop — upgrade zz-drop to use it"
    }
}

impl fmt::Debug for UnknownProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnknownProvider")
            .field("tag", &self.tag)
            .field(
                "payload_cbor",
                &format_args!("<{} bytes redacted>", self.payload_cbor.len()),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollisionPolicy {
    Rename,
    Overwrite,
    Fail,
}

impl Default for CollisionPolicy {
    fn default() -> Self {
        Self::Rename
    }
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("nextcloud: {0}")]
    Nextcloud(#[from] nextcloud::NextcloudError),

    #[error("google_drive: {0}")]
    GoogleDrive(#[from] google_drive::GoogleDriveError),

    #[error("onedrive: {0}")]
    OneDrive(#[from] onedrive::OneDriveError),

    #[error("dropbox: {0}")]
    Dropbox(#[from] dropbox::DropboxError),
}
