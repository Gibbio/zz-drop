//! REST client for Google Drive over the v3 API.
//!
//! Operations cover the surface needed by the `RemoteFs`-style
//! provider abstraction: ensure-folder, multipart upload, download,
//! list, delete (default = trash, opt-in = hard delete).
//!
//! Authentication uses the OAuth tokens stored in the profile.
//! `ensure_fresh_token` refreshes proactively when within
//! `EXPIRY_SKEW_SECS` of the access-token expiry, so callers can
//! issue operations without thinking about timing.
//!
//! Bytes are buffered in memory: this client targets small-to-medium
//! files, in line with v1 zz-drop's "single file at a time" model.
//! Streaming and resumable uploads can replace the multipart path
//! later without changing the public API.

use std::cell::RefCell;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use ureq::Agent;
use ureq::http::Request;

use super::errors::GoogleDriveError;
use crate::http::{AgentOpts, build_agent};
use super::types::{EXPIRY_SKEW_SECS, GoogleDriveAuth, GoogleDriveProfile};
use crate::providers::CollisionPolicy;
use crate::providers::nextcloud::collision::rename_with_suffix;
use crate::providers::nextcloud::{RemoteEntry, RENAME_MAX_TRIES, UploadOutcome};
use crate::providers::oauth::{DeviceFlowClient, DeviceFlowError, TokenResponse};

const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
const DEFAULT_FILE_MIME: &str = "application/octet-stream";
const DRIVE_API_BASE: &str = "https://www.googleapis.com/drive/v3";
const DRIVE_UPLOAD_BASE: &str = "https://www.googleapis.com/upload/drive/v3";
const ROOT_PARENT: &str = "root";
const PAGE_SIZE: u32 = 200;
const HTTP_TIMEOUT_SECS: u64 = 60;

pub struct GoogleDriveClient {
    profile: RefCell<GoogleDriveProfile>,
    profile_dirty: RefCell<bool>,
    agent: Agent,
}

impl GoogleDriveClient {
    pub fn from_profile(profile: GoogleDriveProfile) -> Result<Self, GoogleDriveError> {
        let trimmed = profile.root_folder.trim();
        if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('\0') {
            return Err(GoogleDriveError::BadRoot);
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

    /// Snapshot of the current profile, including any token refresh
    /// or `root_folder_id` cache mutation that has happened during
    /// this client's lifetime. Callers that care about persistence
    /// should compare with their last known profile and re-encrypt
    /// `profile.zz` if `dirty()` is `true`.
    pub fn current_profile(&self) -> GoogleDriveProfile {
        self.profile.borrow().clone()
    }

    pub fn dirty(&self) -> bool {
        *self.profile_dirty.borrow()
    }

    // ── Token lifecycle ─────────────────────────────────────────

    fn ensure_fresh_token(&self) -> Result<(), GoogleDriveError> {
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

    fn refresh_token_now(&self) -> Result<(), GoogleDriveError> {
        let refresh = self.profile.borrow().auth.refresh_token.clone();
        let cfg = super::device_flow_config();
        let client = DeviceFlowClient::new(cfg);
        let tokens = client.refresh(&refresh).map_err(map_oauth)?;

        let mut p = self.profile.borrow_mut();
        // refresh response usually omits a new refresh_token; keep
        // the existing one when absent.
        apply_refresh(&mut p.auth, tokens);
        *self.profile_dirty.borrow_mut() = true;
        Ok(())
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.profile.borrow().auth.access_token)
    }

    // ── Folder resolution ───────────────────────────────────────

    /// Resolve the cached root folder id, creating the folder under
    /// "My Drive" if it does not yet exist.
    pub fn ensure_root_folder(&self) -> Result<String, GoogleDriveError> {
        if let Some(id) = self.profile.borrow().root_folder_id.clone() {
            return Ok(id);
        }
        self.ensure_fresh_token()?;
        let name = self.profile.borrow().root_folder.clone();
        let id = self.find_or_create_folder_under(ROOT_PARENT, &name)?;

        self.profile.borrow_mut().root_folder_id = Some(id.clone());
        *self.profile_dirty.borrow_mut() = true;
        Ok(id)
    }

    /// Idempotently resolve / create a chain of subfolders under the
    /// configured root and return the final folder id. Used to mirror
    /// the multi-segment paths the CLI passes around.
    pub fn ensure_dir_segments(&self, segments: &[&str]) -> Result<String, GoogleDriveError> {
        for s in segments {
            validate_filename(s)?;
        }
        let mut current = self.ensure_root_folder()?;
        for seg in segments {
            current = self.find_or_create_folder_under(&current, seg)?;
        }
        Ok(current)
    }

    fn find_or_create_folder_under(
        &self,
        parent_id: &str,
        name: &str,
    ) -> Result<String, GoogleDriveError> {
        if let Some(file) = self.find_in_folder(parent_id, name, Some(FOLDER_MIME))? {
            return Ok(file.id);
        }
        self.create_folder_under(parent_id, name)
    }

    fn create_folder_under(
        &self,
        parent_id: &str,
        name: &str,
    ) -> Result<String, GoogleDriveError> {
        self.ensure_fresh_token()?;
        let body = serde_json::json!({
            "name": name,
            "mimeType": FOLDER_MIME,
            "parents": [parent_id],
        })
        .to_string();
        // Request only the `id` field — Drive returns just that
        // single property and a generic "kind" tag, so we parse with
        // a narrower struct to avoid a "missing field name" error.
        let url = format!("{DRIVE_API_BASE}/files?fields=id");
        let (status, bytes) =
            self.json_request("POST", &url, Some(("application/json", body.into_bytes())))?;
        if !is_success(status) {
            return Err(classify_status(status, &bytes));
        }
        let parsed: CreatedFile =
            serde_json::from_slice(&bytes).map_err(|_| GoogleDriveError::Decode)?;
        Ok(parsed.id)
    }

    // ── Lookups ─────────────────────────────────────────────────

    fn find_in_folder(
        &self,
        parent_id: &str,
        name: &str,
        mime: Option<&str>,
    ) -> Result<Option<DriveFile>, GoogleDriveError> {
        self.ensure_fresh_token()?;
        let mut q = format!(
            "'{}' in parents and name = '{}' and trashed = false",
            escape_q_literal(parent_id),
            escape_q_literal(name)
        );
        if let Some(m) = mime {
            q.push_str(&format!(" and mimeType = '{}'", escape_q_literal(m)));
        }
        let url = format!(
            "{DRIVE_API_BASE}/files?q={}&fields=files(id,name,size,mimeType)&pageSize=2&spaces=drive",
            url_query_escape(&q)
        );
        let (status, bytes) = self.json_request("GET", &url, None)?;
        if !is_success(status) {
            return Err(classify_status(status, &bytes));
        }
        let parsed: DriveFileList =
            serde_json::from_slice(&bytes).map_err(|_| GoogleDriveError::Decode)?;
        Ok(parsed.files.into_iter().next())
    }

    /// Resolve an absolute path (segments) to the file's Drive id.
    /// Returns `Ok(None)` when the path does not exist.
    fn resolve_file_path(
        &self,
        segments: &[&str],
    ) -> Result<Option<DriveFile>, GoogleDriveError> {
        if segments.is_empty() {
            return Err(GoogleDriveError::NotFound);
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
        self.find_in_folder(&parent_id, segments[last], None)
    }

    fn resolve_dir_segments(&self, segments: &[&str]) -> Result<String, GoogleDriveError> {
        let mut current = self.ensure_root_folder()?;
        for seg in segments {
            match self.find_in_folder(&current, seg, Some(FOLDER_MIME))? {
                Some(f) => current = f.id,
                None => return Err(GoogleDriveError::NotFound),
            }
        }
        Ok(current)
    }

    // ── Upload / download / list / delete ───────────────────────

    pub fn upload_to(
        &self,
        local: &Path,
        segments: &[&str],
        policy: CollisionPolicy,
    ) -> Result<UploadOutcome, GoogleDriveError> {
        if segments.is_empty() {
            return Err(GoogleDriveError::BadRoot);
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

        let body = std::fs::read(local).map_err(|_| GoogleDriveError::LocalIo)?;
        let size = body.len() as u64;

        match policy {
            CollisionPolicy::Overwrite => {
                if let Some(existing) = self.find_in_folder(&parent_id, leaf, None)? {
                    self.update_file_content(&existing.id, &body)?;
                    Ok(UploadOutcome {
                        final_name: leaf.to_string(),
                        size,
                        renamed: false,
                    })
                } else {
                    self.create_file(&parent_id, leaf, &body)?;
                    Ok(UploadOutcome {
                        final_name: leaf.to_string(),
                        size,
                        renamed: false,
                    })
                }
            }
            CollisionPolicy::Fail => {
                if self.find_in_folder(&parent_id, leaf, None)?.is_some() {
                    return Err(GoogleDriveError::Conflict);
                }
                self.create_file(&parent_id, leaf, &body)?;
                Ok(UploadOutcome {
                    final_name: leaf.to_string(),
                    size,
                    renamed: false,
                })
            }
            CollisionPolicy::Rename => {
                for n in 0..=RENAME_MAX_TRIES {
                    let candidate = rename_with_suffix(leaf, n);
                    if self
                        .find_in_folder(&parent_id, &candidate, None)?
                        .is_none()
                    {
                        self.create_file(&parent_id, &candidate, &body)?;
                        return Ok(UploadOutcome {
                            final_name: candidate,
                            size,
                            renamed: n > 0,
                        });
                    }
                }
                Err(GoogleDriveError::Conflict)
            }
        }
    }

    fn create_file(
        &self,
        parent_id: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<String, GoogleDriveError> {
        self.ensure_fresh_token()?;
        let metadata = serde_json::json!({
            "name": name,
            "parents": [parent_id],
        })
        .to_string();
        let boundary = make_boundary();
        let body =
            build_multipart_related(metadata.as_bytes(), bytes, DEFAULT_FILE_MIME, &boundary);
        let url = format!("{DRIVE_UPLOAD_BASE}/files?uploadType=multipart&fields=id");
        let content_type = format!("multipart/related; boundary={boundary}");
        let (status, resp_bytes) = self.json_request("POST", &url, Some((&content_type, body)))?;
        if !is_success(status) {
            return Err(classify_status(status, &resp_bytes));
        }
        let parsed: CreatedFile =
            serde_json::from_slice(&resp_bytes).map_err(|_| GoogleDriveError::Decode)?;
        Ok(parsed.id)
    }

    fn update_file_content(&self, file_id: &str, bytes: &[u8]) -> Result<(), GoogleDriveError> {
        self.ensure_fresh_token()?;
        let url = format!("{DRIVE_UPLOAD_BASE}/files/{file_id}?uploadType=media");
        let (status, resp) = self.json_request("PATCH", &url, Some((DEFAULT_FILE_MIME, bytes.to_vec())))?;
        if !is_success(status) {
            return Err(classify_status(status, &resp));
        }
        Ok(())
    }

    pub fn download_from(
        &self,
        segments: &[&str],
        dest: &Path,
    ) -> Result<u64, GoogleDriveError> {
        let file = self
            .resolve_file_path(segments)?
            .ok_or(GoogleDriveError::NotFound)?;
        self.ensure_fresh_token()?;
        let url = format!("{DRIVE_API_BASE}/files/{}?alt=media", file.id);
        let (status, body) = self.binary_request("GET", &url)?;
        if !is_success(status) {
            return Err(classify_status(status, &body));
        }
        std::fs::write(dest, &body).map_err(|_| GoogleDriveError::LocalIo)?;
        Ok(body.len() as u64)
    }

    pub fn list_at(&self, segments: &[&str]) -> Result<Vec<RemoteEntry>, GoogleDriveError> {
        self.ensure_fresh_token()?;
        let parent_id = if segments.is_empty() {
            self.ensure_root_folder()?
        } else {
            self.resolve_dir_segments(segments)?
        };

        let mut entries = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let q = format!(
                "'{}' in parents and trashed = false",
                escape_q_literal(&parent_id)
            );
            let mut url = format!(
                "{DRIVE_API_BASE}/files?q={}&fields=nextPageToken,files(id,name,size,mimeType)&pageSize={PAGE_SIZE}&spaces=drive",
                url_query_escape(&q)
            );
            if let Some(token) = &page_token {
                url.push_str(&format!("&pageToken={}", url_query_escape(token)));
            }
            let (status, bytes) = self.json_request("GET", &url, None)?;
            if !is_success(status) {
                return Err(classify_status(status, &bytes));
            }
            let page: DriveFileList =
                serde_json::from_slice(&bytes).map_err(|_| GoogleDriveError::Decode)?;
            for f in page.files {
                let size = f.size_as_u64();
                let is_directory = f.mime_type.as_deref() == Some(FOLDER_MIME);
                entries.push(RemoteEntry {
                    name: f.name,
                    size,
                    is_directory,
                });
            }
            match page.next_page_token {
                Some(t) => page_token = Some(t),
                None => break,
            }
        }
        Ok(entries)
    }

    /// Remove a file. `hard = false` moves to trash (recoverable
    /// from the user's Drive UI for ~30 days); `hard = true` deletes
    /// permanently.
    pub fn delete_at(&self, segments: &[&str], hard: bool) -> Result<(), GoogleDriveError> {
        let file = self
            .resolve_file_path(segments)?
            .ok_or(GoogleDriveError::NotFound)?;
        self.ensure_fresh_token()?;
        if hard {
            let url = format!("{DRIVE_API_BASE}/files/{}", file.id);
            let (status, body) = self.json_request("DELETE", &url, None)?;
            if !is_success(status) && status != 204 {
                return Err(classify_status(status, &body));
            }
        } else {
            let url = format!("{DRIVE_API_BASE}/files/{}", file.id);
            let payload = br#"{"trashed":true}"#.to_vec();
            let (status, body) = self.json_request("PATCH", &url, Some(("application/json", payload)))?;
            if !is_success(status) {
                return Err(classify_status(status, &body));
            }
        }
        Ok(())
    }

    /// Fetch the email of the user who granted the OAuth consent.
    /// Used by the setup flow to display "you are uploading as
    /// alice@gmail.com" without asking the user to type it.
    pub fn fetch_user_email(&self) -> Result<String, GoogleDriveError> {
        self.ensure_fresh_token()?;
        let url = format!("{DRIVE_API_BASE}/about?fields=user(emailAddress)");
        let (status, bytes) = self.json_request("GET", &url, None)?;
        if !is_success(status) {
            return Err(classify_status(status, &bytes));
        }
        #[derive(Deserialize)]
        struct AboutUser {
            #[serde(rename = "emailAddress")]
            email_address: String,
        }
        #[derive(Deserialize)]
        struct AboutResp {
            user: AboutUser,
        }
        let parsed: AboutResp =
            serde_json::from_slice(&bytes).map_err(|_| GoogleDriveError::Decode)?;
        Ok(parsed.user.email_address)
    }

    // ── Low-level HTTP helpers ──────────────────────────────────

    fn json_request(
        &self,
        method: &str,
        url: &str,
        body: Option<(&str, Vec<u8>)>,
    ) -> Result<(u16, Vec<u8>), GoogleDriveError> {
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
            .map_err(|_| GoogleDriveError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| GoogleDriveError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }

    fn binary_request(
        &self,
        method: &str,
        url: &str,
    ) -> Result<(u16, Vec<u8>), GoogleDriveError> {
        let auth = self.auth_header();
        let req = Request::builder()
            .method(method)
            .uri(url)
            .header("Authorization", auth)
            .header("User-Agent", "zz-drop")
            .body(Vec::<u8>::new())
            .map_err(|_| GoogleDriveError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| GoogleDriveError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }
}

fn read_body(
    mut resp: ureq::http::Response<ureq::Body>,
) -> Result<Vec<u8>, GoogleDriveError> {
    resp.body_mut()
        .read_to_vec()
        .map_err(|_| GoogleDriveError::Decode)
}

fn apply_refresh(auth: &mut GoogleDriveAuth, tokens: TokenResponse) {
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

fn map_oauth(e: DeviceFlowError) -> GoogleDriveError {
    match e {
        DeviceFlowError::Network => GoogleDriveError::Network,
        DeviceFlowError::Decode => GoogleDriveError::Decode,
        DeviceFlowError::ServerError { status } => GoogleDriveError::ServerError { status },
        DeviceFlowError::InvalidClient
        | DeviceFlowError::InvalidGrant
        | DeviceFlowError::AccessDenied
        | DeviceFlowError::Expired => GoogleDriveError::TokenExpired,
        other => GoogleDriveError::Oauth(other),
    }
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn classify_status(status: u16, body: &[u8]) -> GoogleDriveError {
    match status {
        401 => GoogleDriveError::Unauthorized,
        403 => {
            // Drive often returns 403 for both auth and rate-limit
            // (`userRateLimitExceeded` / `rateLimitExceeded`). When
            // the body says rate limit, surface that distinctly.
            if body_mentions_rate_limit(body) {
                GoogleDriveError::RateLimited
            } else {
                GoogleDriveError::Unauthorized
            }
        }
        404 => GoogleDriveError::NotFound,
        409 => GoogleDriveError::Conflict,
        429 => GoogleDriveError::RateLimited,
        500..=599 => GoogleDriveError::ServerError { status },
        _ => GoogleDriveError::ServerError { status },
    }
}

fn body_mentions_rate_limit(body: &[u8]) -> bool {
    let s = std::str::from_utf8(body).unwrap_or("");
    s.contains("userRateLimitExceeded") || s.contains("rateLimitExceeded")
}

fn validate_filename(name: &str) -> Result<(), GoogleDriveError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(GoogleDriveError::BadRoot);
    }
    if name.contains('/') || name.contains('\0') {
        return Err(GoogleDriveError::BadRoot);
    }
    Ok(())
}

fn make_boundary() -> String {
    let mut b = [0u8; 12];
    OsRng.fill_bytes(&mut b);
    let mut s = String::with_capacity(33);
    s.push_str("zzdrop_");
    for byte in b {
        use std::fmt::Write;
        let _ = write!(&mut s, "{byte:02x}");
    }
    s
}

fn build_multipart_related(
    metadata: &[u8],
    file_bytes: &[u8],
    file_mime: &str,
    boundary: &str,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(metadata.len() + file_bytes.len() + 256);
    write_part(&mut body, boundary, b"application/json; charset=UTF-8", metadata);
    write_part(&mut body, boundary, file_mime.as_bytes(), file_bytes);
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");
    body
}

fn write_part(body: &mut Vec<u8>, boundary: &str, content_type: &[u8], data: &[u8]) {
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"\r\nContent-Type: ");
    body.extend_from_slice(content_type);
    body.extend_from_slice(b"\r\n\r\n");
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n");
}

/// Escape a string literal for use inside a Drive API `q` filter.
/// The two characters that must be escaped are `\\` and `'`; we apply
/// both even when the input is unlikely to contain them, on the
/// principle that filenames may contain anything.
fn escape_q_literal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn url_query_escape(s: &str) -> String {
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
    // RFC 3986 query-component reserved set, conservative.
    const QUERY: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'<')
        .add(b'>')
        .add(b'%')
        .add(b'&')
        .add(b'+')
        .add(b'/')
        .add(b'?')
        .add(b'=')
        .add(b'\'');
    utf8_percent_encode(s, QUERY).to_string()
}

#[derive(Deserialize)]
struct DriveFile {
    id: String,
    name: String,
    #[serde(default)]
    size: Option<String>,
    #[serde(default, rename = "mimeType")]
    mime_type: Option<String>,
}

/// Minimal response shape for endpoints that respond with `fields=id`
/// only — chiefly folder/file creation. Keeping it separate from
/// [`DriveFile`] avoids a "missing field `name`" decode error when
/// the server omits everything but the id.
#[derive(Deserialize)]
struct CreatedFile {
    id: String,
}

impl DriveFile {
    fn size_as_u64(&self) -> Option<u64> {
        self.size.as_ref().and_then(|s| s.parse().ok())
    }
}

#[derive(Deserialize)]
struct DriveFileList {
    #[serde(default)]
    files: Vec<DriveFile>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_has_zzdrop_prefix_and_unique_tail() {
        let a = make_boundary();
        let b = make_boundary();
        assert!(a.starts_with("zzdrop_"));
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b);
    }

    #[test]
    fn multipart_body_contains_both_parts() {
        let body = build_multipart_related(
            br#"{"name":"x.txt"}"#,
            b"hello",
            DEFAULT_FILE_MIME,
            "BOUND",
        );
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("--BOUND\r\n"));
        assert!(s.contains("Content-Type: application/json; charset=UTF-8"));
        assert!(s.contains(r#"{"name":"x.txt"}"#));
        assert!(s.contains("Content-Type: application/octet-stream"));
        assert!(s.contains("hello"));
        assert!(s.ends_with("--BOUND--\r\n"));
    }

    #[test]
    fn escapes_q_literal_quotes_and_backslashes() {
        assert_eq!(escape_q_literal("plain"), "plain");
        assert_eq!(escape_q_literal("it's"), "it\\'s");
        assert_eq!(escape_q_literal("a\\b"), "a\\\\b");
        assert_eq!(escape_q_literal("a\\'b"), "a\\\\\\'b");
    }

    #[test]
    fn url_escape_handles_query_specials() {
        let s = url_query_escape("'parentId' in parents and name = 'a b'");
        assert!(s.contains("%27"));
        assert!(s.contains("%20"));
        assert!(!s.contains(' '));
        assert!(!s.contains('\''));
    }

    #[test]
    fn drive_file_parses_size_string() {
        let body = r#"{"id":"abc","name":"x.txt","size":"42","mimeType":"text/plain"}"#;
        let f: DriveFile = serde_json::from_str(body).unwrap();
        assert_eq!(f.size_as_u64(), Some(42));
        assert_eq!(f.mime_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn drive_file_list_parses_empty_page() {
        let body = r#"{"files":[]}"#;
        let l: DriveFileList = serde_json::from_str(body).unwrap();
        assert!(l.files.is_empty());
        assert!(l.next_page_token.is_none());
    }

    #[test]
    fn drive_file_list_parses_paged() {
        let body = r#"{"nextPageToken":"PAGE2","files":[{"id":"i","name":"n"}]}"#;
        let l: DriveFileList = serde_json::from_str(body).unwrap();
        assert_eq!(l.files.len(), 1);
        assert_eq!(l.next_page_token.as_deref(), Some("PAGE2"));
    }

    #[test]
    fn classify_403_with_rate_limit_body() {
        let body = br#"{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}"#;
        assert!(matches!(
            classify_status(403, body),
            GoogleDriveError::RateLimited
        ));
    }

    #[test]
    fn classify_403_without_rate_limit_is_unauthorized() {
        let body = br#"{"error":{"errors":[{"reason":"insufficientPermissions"}]}}"#;
        assert!(matches!(
            classify_status(403, body),
            GoogleDriveError::Unauthorized
        ));
    }

    #[test]
    fn classify_terminal_statuses() {
        assert!(matches!(
            classify_status(401, b""),
            GoogleDriveError::Unauthorized
        ));
        assert!(matches!(
            classify_status(404, b""),
            GoogleDriveError::NotFound
        ));
        assert!(matches!(
            classify_status(409, b""),
            GoogleDriveError::Conflict
        ));
        assert!(matches!(
            classify_status(429, b""),
            GoogleDriveError::RateLimited
        ));
        assert!(matches!(
            classify_status(503, b""),
            GoogleDriveError::ServerError { status: 503 }
        ));
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
    fn apply_refresh_keeps_existing_refresh_token_when_omitted() {
        let mut auth = GoogleDriveAuth {
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
        let mut auth = GoogleDriveAuth {
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
}
