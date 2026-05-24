use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct NextcloudProfile {
    pub server_url: String,
    pub username: String,
    pub auth: NextcloudAuth,
    pub remote_root: String,
}

impl fmt::Debug for NextcloudProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NextcloudProfile { <redacted> }")
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextcloudAuth {
    AppPassword { secret: String },
    LoginFlowToken { secret: String },
}

impl fmt::Debug for NextcloudAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppPassword { .. } => f.write_str("AppPassword { secret: <redacted> }"),
            Self::LoginFlowToken { .. } => f.write_str("LoginFlowToken { secret: <redacted> }"),
        }
    }
}

/// Wipe the app-password / login-flow token from memory on drop (see
/// security audit F2). The field stays `String`, so the on-disk CBOR
/// format and call sites are unchanged; only the freed buffer is zeroed.
impl Drop for NextcloudAuth {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::AppPassword { secret } | Self::LoginFlowToken { secret } => secret.zeroize(),
        }
    }
}
