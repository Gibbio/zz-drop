//! REST client for Microsoft OneDrive over Microsoft Graph v1.0.
//!
//! Operations cover the surface needed by the `RemoteFs`-style
//! provider abstraction: ensure-folder, single-shot upload, download,
//! list, delete (recycle bin).
//!
//! Authentication uses the OAuth tokens stored in the profile.
//! `ensure_fresh_token` refreshes proactively when within
//! `EXPIRY_SKEW_SECS` of the access-token expiry, so callers can
//! issue operations without thinking about timing.
//!
//! Single-shot uploads cap at 4 MiB — Graph's small-upload limit.
//! Larger files require a `createUploadSession` resumable flow which
//! is intentionally not in scope for v1; the upload path returns
//! [`OneDriveError::ServerError { status: 413 }`] above the cap so
//! the operator gets a clear signal.

use std::cell::RefCell;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use ureq::Agent;
use ureq::http::Request;

use super::errors::OneDriveError;
use crate::http::{AgentOpts, build_agent};
use super::types::{EXPIRY_SKEW_SECS, OneDriveAuth, OneDriveProfile};
use crate::providers::CollisionPolicy;
use crate::providers::nextcloud::collision::rename_with_suffix;
use crate::providers::nextcloud::{RemoteEntry, RENAME_MAX_TRIES, UploadOutcome};
use crate::providers::oauth::{DeviceFlowClient, DeviceFlowError, TokenResponse};

const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";
const HTTP_TIMEOUT_SECS: u64 = 60;
/// Microsoft Graph's small-upload (single PUT) ceiling. Above this
/// the API rejects the body and the client must use a resumable
/// upload session — out of scope for v1.
const SMALL_UPLOAD_LIMIT_BYTES: u64 = 4 * 1024 * 1024;

pub struct OneDriveClient {
    profile: RefCell<OneDriveProfile>,
    profile_dirty: RefCell<bool>,
    agent: Agent,
}

impl OneDriveClient {
    pub fn from_profile(profile: OneDriveProfile) -> Result<Self, OneDriveError> {
        let trimmed = profile.root_folder.trim();
        if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('\0') {
            return Err(OneDriveError::BadRoot);
        }

        let agent: Agent = build_agent(AgentOpts {
            http_status_as_error: Some(false),
            ..AgentOpts::with_global_timeout(HTTP_TIMEOUT_SECS)
        });

        Ok(Self {
            profile: RefCell::new(profile),
            profile_dirty: RefCell::new(false),
            agent,
        })
    }

    pub fn current_profile(&self) -> OneDriveProfile {
        self.profile.borrow().clone()
    }

    pub fn dirty(&self) -> bool {
        *self.profile_dirty.borrow()
    }

    // ── Token lifecycle ─────────────────────────────────────────

    fn ensure_fresh_token(&self) -> Result<(), OneDriveError> {
        let now = unix_now();
        let needs_refresh = {
            let p = self.profile.borrow();
            now + EXPIRY_SKEW_SECS >= p.auth.expires_at
        };
        if !needs_refresh {
            return Ok(());
        }
        self.refresh_token_now()
    }

    fn refresh_token_now(&self) -> Result<(), OneDriveError> {
        let refresh = self.profile.borrow().auth.refresh_token.clone();
        let cfg = super::device_flow_config();
        let client = DeviceFlowClient::new(cfg);
        let tokens = client.refresh(&refresh).map_err(map_oauth)?;

        let mut p = self.profile.borrow_mut();
        apply_refresh(&mut p.auth, tokens);
        *self.profile_dirty.borrow_mut() = true;
        Ok(())
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.profile.borrow().auth.access_token)
    }

    // ── Folder resolution ───────────────────────────────────────

    pub fn ensure_root_folder(&self) -> Result<String, OneDriveError> {
        if let Some(id) = self.profile.borrow().root_folder_id.clone() {
            return Ok(id);
        }
        self.ensure_fresh_token()?;
        let name = self.profile.borrow().root_folder.clone();
        validate_filename(&name)?;
        let id = self.find_or_create_folder_at_root(&name)?;

        self.profile.borrow_mut().root_folder_id = Some(id.clone());
        *self.profile_dirty.borrow_mut() = true;
        Ok(id)
    }

    pub fn ensure_dir_segments(&self, segments: &[&str]) -> Result<String, OneDriveError> {
        for s in segments {
            validate_filename(s)?;
        }
        let mut current = self.ensure_root_folder()?;
        for seg in segments {
            current = self.find_or_create_folder_under(&current, seg)?;
        }
        Ok(current)
    }

    fn find_or_create_folder_at_root(&self, name: &str) -> Result<String, OneDriveError> {
        // Path-addressing: GET /me/drive/root:/{name}
        let path = format!("{GRAPH_BASE}/me/drive/root:/{}", url_path_escape(name));
        let (status, body) = self.json_request("GET", &path, None)?;
        if status == 404 {
            return self.create_folder_at_root(name);
        }
        if !is_success(status) {
            return Err(classify_status(status));
        }
        let parsed: DriveItem = serde_json::from_slice(&body).map_err(|_| OneDriveError::Decode)?;
        if parsed.is_folder() {
            Ok(parsed.id)
        } else {
            Err(OneDriveError::Conflict)
        }
    }

    fn create_folder_at_root(&self, name: &str) -> Result<String, OneDriveError> {
        self.ensure_fresh_token()?;
        let body = serde_json::json!({
            "name": name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "fail",
        })
        .to_string();
        let url = format!("{GRAPH_BASE}/me/drive/root/children");
        let (status, bytes) =
            self.json_request("POST", &url, Some(("application/json", body.into_bytes())))?;
        if !is_success(status) {
            return Err(classify_status(status));
        }
        let parsed: DriveItem =
            serde_json::from_slice(&bytes).map_err(|_| OneDriveError::Decode)?;
        Ok(parsed.id)
    }

    fn find_or_create_folder_under(
        &self,
        parent_id: &str,
        name: &str,
    ) -> Result<String, OneDriveError> {
        if let Some(item) = self.find_in_folder(parent_id, name)?
            && item.is_folder()
        {
            return Ok(item.id);
        }
        self.create_folder_under(parent_id, name)
    }

    fn create_folder_under(
        &self,
        parent_id: &str,
        name: &str,
    ) -> Result<String, OneDriveError> {
        self.ensure_fresh_token()?;
        let body = serde_json::json!({
            "name": name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "fail",
        })
        .to_string();
        let url = format!("{GRAPH_BASE}/me/drive/items/{parent_id}/children");
        let (status, bytes) =
            self.json_request("POST", &url, Some(("application/json", body.into_bytes())))?;
        if !is_success(status) {
            return Err(classify_status(status));
        }
        let parsed: DriveItem =
            serde_json::from_slice(&bytes).map_err(|_| OneDriveError::Decode)?;
        Ok(parsed.id)
    }

    // ── Lookups ─────────────────────────────────────────────────

    fn find_in_folder(
        &self,
        parent_id: &str,
        name: &str,
    ) -> Result<Option<DriveItem>, OneDriveError> {
        self.ensure_fresh_token()?;
        // GET /me/drive/items/{parent_id}:/{name}
        let url = format!(
            "{GRAPH_BASE}/me/drive/items/{parent_id}:/{}",
            url_path_escape(name)
        );
        let (status, bytes) = self.json_request("GET", &url, None)?;
        if status == 404 {
            return Ok(None);
        }
        if !is_success(status) {
            return Err(classify_status(status));
        }
        let parsed: DriveItem =
            serde_json::from_slice(&bytes).map_err(|_| OneDriveError::Decode)?;
        Ok(Some(parsed))
    }

    fn resolve_dir_segments(&self, segments: &[&str]) -> Result<String, OneDriveError> {
        let mut current = self.ensure_root_folder()?;
        for seg in segments {
            match self.find_in_folder(&current, seg)? {
                Some(it) if it.is_folder() => current = it.id,
                Some(_) => return Err(OneDriveError::Conflict),
                None => return Err(OneDriveError::NotFound),
            }
        }
        Ok(current)
    }

    fn resolve_file_path(&self, segments: &[&str]) -> Result<Option<DriveItem>, OneDriveError> {
        if segments.is_empty() {
            return Err(OneDriveError::NotFound);
        }
        for s in segments {
            validate_filename(s)?;
        }
        let last = segments.len() - 1;
        let parent_id = if last == 0 {
            self.ensure_root_folder()?
        } else {
            self.resolve_dir_segments(&segments[..last])?
        };
        self.find_in_folder(&parent_id, segments[last])
    }

    // ── Upload / download / list / delete ───────────────────────

    pub fn upload_to(
        &self,
        local: &Path,
        segments: &[&str],
        policy: CollisionPolicy,
    ) -> Result<UploadOutcome, OneDriveError> {
        if segments.is_empty() {
            return Err(OneDriveError::BadRoot);
        }
        for s in segments {
            validate_filename(s)?;
        }

        let last = segments.len() - 1;
        let leaf = segments[last];
        let parent_id = if last == 0 {
            self.ensure_root_folder()?
        } else {
            self.ensure_dir_segments(&segments[..last])?
        };

        let body = std::fs::read(local).map_err(|_| OneDriveError::LocalIo)?;
        let size = body.len() as u64;
        if size > SMALL_UPLOAD_LIMIT_BYTES {
            // Resumable upload session not implemented in v1.
            return Err(OneDriveError::ServerError { status: 413 });
        }

        match policy {
            CollisionPolicy::Overwrite => {
                self.put_file_content(&parent_id, leaf, &body, "replace")?;
                Ok(UploadOutcome {
                    final_name: leaf.to_string(),
                    size,
                    renamed: false,
                })
            }
            CollisionPolicy::Fail => {
                if self.find_in_folder(&parent_id, leaf)?.is_some() {
                    return Err(OneDriveError::Conflict);
                }
                self.put_file_content(&parent_id, leaf, &body, "fail")?;
                Ok(UploadOutcome {
                    final_name: leaf.to_string(),
                    size,
                    renamed: false,
                })
            }
            CollisionPolicy::Rename => {
                for n in 0..=RENAME_MAX_TRIES {
                    let candidate = rename_with_suffix(leaf, n);
                    if self.find_in_folder(&parent_id, &candidate)?.is_none() {
                        self.put_file_content(&parent_id, &candidate, &body, "fail")?;
                        return Ok(UploadOutcome {
                            final_name: candidate,
                            size,
                            renamed: n > 0,
                        });
                    }
                }
                Err(OneDriveError::Conflict)
            }
        }
    }

    fn put_file_content(
        &self,
        parent_id: &str,
        leaf: &str,
        bytes: &[u8],
        conflict_behavior: &str,
    ) -> Result<(), OneDriveError> {
        self.ensure_fresh_token()?;
        let url = format!(
            "{GRAPH_BASE}/me/drive/items/{parent_id}:/{}:/content?@microsoft.graph.conflictBehavior={conflict_behavior}",
            url_path_escape(leaf)
        );
        let (status, body) = self.binary_put(&url, bytes)?;
        if !is_success(status) {
            return Err(classify_status_with_body(status, &body));
        }
        Ok(())
    }

    pub fn download_from(
        &self,
        segments: &[&str],
        dest: &Path,
    ) -> Result<u64, OneDriveError> {
        let item = self
            .resolve_file_path(segments)?
            .ok_or(OneDriveError::NotFound)?;
        if item.is_folder() {
            return Err(OneDriveError::Conflict);
        }
        self.ensure_fresh_token()?;
        // /content returns 302 with a download URL; ureq follows it.
        let url = format!("{GRAPH_BASE}/me/drive/items/{}/content", item.id);
        let (status, body) = self.binary_get(&url)?;
        if !is_success(status) {
            return Err(classify_status(status));
        }
        std::fs::write(dest, &body).map_err(|_| OneDriveError::LocalIo)?;
        Ok(body.len() as u64)
    }

    pub fn list_at(&self, segments: &[&str]) -> Result<Vec<RemoteEntry>, OneDriveError> {
        self.ensure_fresh_token()?;
        let parent_id = if segments.is_empty() {
            self.ensure_root_folder()?
        } else {
            self.resolve_dir_segments(segments)?
        };

        let mut entries = Vec::new();
        let mut next_url = Some(format!("{GRAPH_BASE}/me/drive/items/{parent_id}/children"));
        while let Some(url) = next_url.take() {
            let (status, bytes) = self.json_request("GET", &url, None)?;
            if !is_success(status) {
                return Err(classify_status(status));
            }
            let page: ChildrenPage =
                serde_json::from_slice(&bytes).map_err(|_| OneDriveError::Decode)?;
            for it in page.value {
                let is_directory = it.is_folder();
                entries.push(RemoteEntry {
                    name: it.name,
                    size: it.size,
                    is_directory,
                });
            }
            next_url = page.next_link;
        }
        Ok(entries)
    }

    /// Move a file to the recycle bin. Microsoft Graph does not
    /// expose a permanent-delete on personal OneDrive, so `hard` is
    /// silently treated the same as the soft path. Items in the
    /// recycle bin clear after ~30 days.
    pub fn delete_at(&self, segments: &[&str], _hard: bool) -> Result<(), OneDriveError> {
        let item = self
            .resolve_file_path(segments)?
            .ok_or(OneDriveError::NotFound)?;
        self.ensure_fresh_token()?;
        let url = format!("{GRAPH_BASE}/me/drive/items/{}", item.id);
        let (status, _body) = self.json_request("DELETE", &url, None)?;
        if status != 204 && !is_success(status) {
            return Err(classify_status(status));
        }
        Ok(())
    }

    /// Fetch the email of the user who granted the OAuth consent.
    /// Personal Microsoft accounts often leave `mail` `null` and fill
    /// `userPrincipalName` instead, so we fall back to the latter.
    pub fn fetch_user_email(&self) -> Result<String, OneDriveError> {
        self.ensure_fresh_token()?;
        let url = format!("{GRAPH_BASE}/me?$select=mail,userPrincipalName");
        let (status, bytes) = self.json_request("GET", &url, None)?;
        if !is_success(status) {
            return Err(classify_status(status));
        }
        let parsed: MeResponse =
            serde_json::from_slice(&bytes).map_err(|_| OneDriveError::Decode)?;
        Ok(parsed.mail.or(parsed.user_principal_name).unwrap_or_default())
    }

    // ── Low-level HTTP helpers ──────────────────────────────────

    fn json_request(
        &self,
        method: &str,
        url: &str,
        body: Option<(&str, Vec<u8>)>,
    ) -> Result<(u16, Vec<u8>), OneDriveError> {
        let auth = self.auth_header();
        let mut builder = Request::builder()
            .method(method)
            .uri(url)
            .header("Authorization", auth)
            .header("User-Agent", "zz-drop")
            .header("Accept", "application/json");

        let final_body = if let Some((ct, b)) = body {
            builder = builder.header("Content-Type", ct);
            b
        } else {
            Vec::new()
        };

        let req = builder
            .body(final_body)
            .map_err(|_| OneDriveError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| OneDriveError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }

    fn binary_get(&self, url: &str) -> Result<(u16, Vec<u8>), OneDriveError> {
        let auth = self.auth_header();
        let req = Request::builder()
            .method("GET")
            .uri(url)
            .header("Authorization", auth)
            .header("User-Agent", "zz-drop")
            .body(Vec::<u8>::new())
            .map_err(|_| OneDriveError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| OneDriveError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }

    fn binary_put(&self, url: &str, body: &[u8]) -> Result<(u16, Vec<u8>), OneDriveError> {
        let auth = self.auth_header();
        let req = Request::builder()
            .method("PUT")
            .uri(url)
            .header("Authorization", auth)
            .header("User-Agent", "zz-drop")
            .header("Content-Type", "application/octet-stream")
            .body(body.to_vec())
            .map_err(|_| OneDriveError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| OneDriveError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }
}

fn read_body(
    mut resp: ureq::http::Response<ureq::Body>,
) -> Result<Vec<u8>, OneDriveError> {
    resp.body_mut()
        .read_to_vec()
        .map_err(|_| OneDriveError::Decode)
}

fn apply_refresh(auth: &mut OneDriveAuth, tokens: TokenResponse) {
    auth.access_token = tokens.access_token;
    auth.token_type = tokens.token_type;
    auth.expires_at = unix_now() + tokens.expires_in;
    if let Some(rt) = tokens.refresh_token {
        auth.refresh_token = rt;
    }
    if let Some(scope) = tokens.scope {
        auth.scope = scope;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn map_oauth(e: DeviceFlowError) -> OneDriveError {
    match e {
        DeviceFlowError::Network => OneDriveError::Network,
        DeviceFlowError::Decode => OneDriveError::Decode,
        DeviceFlowError::ServerError { status } => OneDriveError::ServerError { status },
        DeviceFlowError::InvalidClient
        | DeviceFlowError::InvalidGrant
        | DeviceFlowError::AccessDenied
        | DeviceFlowError::Expired => OneDriveError::TokenExpired,
        other => OneDriveError::Oauth(other),
    }
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn classify_status(status: u16) -> OneDriveError {
    match status {
        401 => OneDriveError::Unauthorized,
        403 => OneDriveError::Unauthorized,
        404 => OneDriveError::NotFound,
        409 => OneDriveError::Conflict,
        429 => OneDriveError::RateLimited,
        500..=599 => OneDriveError::ServerError { status },
        _ => OneDriveError::ServerError { status },
    }
}

/// Like `classify_status` but inspects the body for Graph's
/// `code: "quotaLimitReached"` shape, which arrives as a 507 or 403
/// depending on the violation.
fn classify_status_with_body(status: u16, body: &[u8]) -> OneDriveError {
    if status == 507 || body_mentions_quota(body) {
        return OneDriveError::ServerError { status };
    }
    classify_status(status)
}

fn body_mentions_quota(body: &[u8]) -> bool {
    let s = std::str::from_utf8(body).unwrap_or("");
    s.contains("quotaLimitReached") || s.contains("ResourceQuotaExceeded")
}

fn validate_filename(name: &str) -> Result<(), OneDriveError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(OneDriveError::BadRoot);
    }
    if name.contains('/') || name.contains('\0') {
        return Err(OneDriveError::BadRoot);
    }
    Ok(())
}

/// Percent-encode a single path segment for a Graph URL. Graph
/// accepts spaces and most printable ASCII unencoded but is strict
/// about `#`, `?`, `%`. Keep the set conservative.
fn url_path_escape(s: &str) -> String {
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
    const PATH: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'<')
        .add(b'>')
        .add(b'%')
        .add(b'?')
        .add(b'/')
        .add(b'+');
    utf8_percent_encode(s, PATH).to_string()
}

#[derive(Deserialize)]
struct DriveItem {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: Option<u64>,
    /// Present (as `{}` or with sub-fields) when the item is a folder.
    #[serde(default)]
    folder: Option<serde_json::Value>,
    /// Present when the item is a file. Kept for forward compat
    /// even though the discriminator currently uses `folder`.
    #[serde(default)]
    #[allow(dead_code)]
    file: Option<serde_json::Value>,
}

impl DriveItem {
    fn is_folder(&self) -> bool {
        self.folder.is_some()
    }
}

#[derive(Deserialize)]
struct ChildrenPage {
    #[serde(default)]
    value: Vec<DriveItem>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct MeResponse {
    #[serde(default)]
    mail: Option<String>,
    #[serde(default, rename = "userPrincipalName")]
    user_principal_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_path_escape_handles_spaces_and_specials() {
        assert_eq!(url_path_escape("plain"), "plain");
        assert_eq!(url_path_escape("a b"), "a%20b");
        assert_eq!(url_path_escape("a#b"), "a%23b");
        assert_eq!(url_path_escape("a/b"), "a%2Fb");
        assert_eq!(url_path_escape("a?b"), "a%3Fb");
    }

    #[test]
    fn validate_filename_rejects_problematic() {
        assert!(validate_filename("ok.txt").is_ok());
        assert!(validate_filename("").is_err());
        assert!(validate_filename(".").is_err());
        assert!(validate_filename("..").is_err());
        assert!(validate_filename("a/b").is_err());
        assert!(validate_filename("a\0b").is_err());
    }

    #[test]
    fn drive_item_folder_discriminator() {
        let json = r#"{"id":"i","name":"n","folder":{"childCount":0}}"#;
        let it: DriveItem = serde_json::from_str(json).unwrap();
        assert!(it.is_folder());

        let json = r#"{"id":"i","name":"f.txt","size":3,"file":{"mimeType":"text/plain"}}"#;
        let it: DriveItem = serde_json::from_str(json).unwrap();
        assert!(!it.is_folder());
        assert_eq!(it.size, Some(3));
    }

    #[test]
    fn children_page_parses_with_next_link() {
        let json = r#"{
            "value":[{"id":"a","name":"x","file":{}}],
            "@odata.nextLink":"https://graph/next"
        }"#;
        let p: ChildrenPage = serde_json::from_str(json).unwrap();
        assert_eq!(p.value.len(), 1);
        assert_eq!(p.next_link.as_deref(), Some("https://graph/next"));
    }

    #[test]
    fn me_response_falls_back_to_upn_when_mail_null() {
        let body = r#"{"mail":null,"userPrincipalName":"alice@outlook.com"}"#;
        let r: MeResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.user_principal_name.as_deref(), Some("alice@outlook.com"));
        assert!(r.mail.is_none());
    }

    #[test]
    fn classify_terminal_statuses() {
        assert!(matches!(classify_status(401), OneDriveError::Unauthorized));
        assert!(matches!(classify_status(403), OneDriveError::Unauthorized));
        assert!(matches!(classify_status(404), OneDriveError::NotFound));
        assert!(matches!(classify_status(409), OneDriveError::Conflict));
        assert!(matches!(classify_status(429), OneDriveError::RateLimited));
        assert!(matches!(
            classify_status(503),
            OneDriveError::ServerError { status: 503 }
        ));
    }

    #[test]
    fn classify_quota_body_distinguishes_quota_507() {
        let body = br#"{"error":{"code":"quotaLimitReached","message":"x"}}"#;
        assert!(matches!(
            classify_status_with_body(403, body),
            OneDriveError::ServerError { .. }
        ));
    }

    #[test]
    fn apply_refresh_keeps_existing_refresh_token_when_omitted() {
        let mut auth = OneDriveAuth {
            access_token: "OLD-AT".into(),
            refresh_token: "KEEP-RT".into(),
            token_type: "Bearer".into(),
            expires_at: 0,
            scope: "x".into(),
        };
        let tokens = TokenResponse {
            access_token: "NEW-AT".into(),
            refresh_token: None,
            expires_in: 3600,
            token_type: "Bearer".into(),
            scope: None,
        };
        apply_refresh(&mut auth, tokens);
        assert_eq!(auth.access_token, "NEW-AT");
        assert_eq!(auth.refresh_token, "KEEP-RT");
        assert!(auth.expires_at > 0);
    }

    #[test]
    fn apply_refresh_uses_new_refresh_token_when_present() {
        let mut auth = OneDriveAuth {
            access_token: "OLD".into(),
            refresh_token: "OLD-RT".into(),
            token_type: "Bearer".into(),
            expires_at: 0,
            scope: "x".into(),
        };
        let tokens = TokenResponse {
            access_token: "NEW".into(),
            refresh_token: Some("NEW-RT".into()),
            expires_in: 3600,
            token_type: "Bearer".into(),
            scope: Some("y".into()),
        };
        apply_refresh(&mut auth, tokens);
        assert_eq!(auth.refresh_token, "NEW-RT");
        assert_eq!(auth.scope, "y");
    }

    #[test]
    fn small_upload_limit_is_4_mib() {
        // The single-shot PUT only works under 4 MiB on Graph.
        // Document the constant so a future refactor doesn't drift.
        assert_eq!(SMALL_UPLOAD_LIMIT_BYTES, 4 * 1024 * 1024);
    }
}
