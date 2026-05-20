//! REST client for Dropbox API v2.
//!
//! Operations cover the surface needed by the `RemoteFs`-style
//! provider abstraction: ensure-folder, single-shot upload,
//! download, list, delete (move to trash).
//!
//! Authentication uses the OAuth tokens stored in the profile.
//! [`DropboxClient::ensure_fresh_token`] refreshes proactively when
//! within [`EXPIRY_SKEW_SECS`] of the access-token expiry, so
//! callers can issue operations without thinking about timing.
//!
//! Single-shot uploads cap at 150 MiB — the Dropbox `/files/upload`
//! ceiling. Larger files require `/files/upload_session/start` +
//! `/append_v2` + `/finish` resumable flow which is intentionally
//! not in scope for v1; the upload path returns
//! [`DropboxError::ServerError { status: 413 }`] above the cap so
//! the operator gets a clear signal.
//!
//! All paths sent to the Dropbox API are *relative to the app's
//! sandbox* (the app is registered as App-folder). The user sees
//! the same files surfaced under `Apps/zz-drop/{root_folder}/...`
//! in their personal Dropbox.

use std::cell::RefCell;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use ureq::Agent;
use ureq::http::Request;

use super::errors::DropboxError;
use crate::http::{AgentOpts, build_agent};
use super::types::{DropboxAuth, DropboxProfile, EXPIRY_SKEW_SECS};
use crate::providers::CollisionPolicy;
use crate::providers::nextcloud::collision::rename_with_suffix;
use crate::providers::nextcloud::{RENAME_MAX_TRIES, RemoteEntry, UploadOutcome};
use crate::providers::oauth::{PasteCodeError, PasteCodeFlow, TokenResponse};

const API_BASE: &str = "https://api.dropboxapi.com/2";
const CONTENT_BASE: &str = "https://content.dropboxapi.com/2";
const HTTP_TIMEOUT_SECS: u64 = 60;
/// Dropbox `/files/upload` single-shot ceiling. Above this the API
/// rejects the body and the client must use a resumable upload
/// session — out of scope for v1.
const SINGLE_SHOT_UPLOAD_LIMIT_BYTES: u64 = 150 * 1024 * 1024;

pub struct DropboxClient {
    profile: RefCell<DropboxProfile>,
    profile_dirty: RefCell<bool>,
    agent: Agent,
}

impl DropboxClient {
    pub fn from_profile(profile: DropboxProfile) -> Result<Self, DropboxError> {
        validate_root_folder(profile.root_folder.trim())?;

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

    pub fn current_profile(&self) -> DropboxProfile {
        self.profile.borrow().clone()
    }

    pub fn dirty(&self) -> bool {
        *self.profile_dirty.borrow()
    }

    // ── Token lifecycle ─────────────────────────────────────────

    fn ensure_fresh_token(&self) -> Result<(), DropboxError> {
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

    fn refresh_token_now(&self) -> Result<(), DropboxError> {
        let refresh = self.profile.borrow().auth.refresh_token.clone();
        let cfg = super::paste_code_config();
        let flow = PasteCodeFlow::new(cfg);
        let tokens = flow.refresh(&refresh).map_err(map_oauth)?;

        let mut p = self.profile.borrow_mut();
        apply_refresh(&mut p.auth, tokens);
        *self.profile_dirty.borrow_mut() = true;
        Ok(())
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.profile.borrow().auth.access_token)
    }

    // ── Folder resolution ───────────────────────────────────────

    pub fn ensure_root_folder(&self) -> Result<(), DropboxError> {
        self.ensure_fresh_token()?;
        let root = self.profile.borrow().root_folder.clone();
        validate_root_folder(&root)?;
        // Empty root means "use the App folder sandbox root
        // directly". Dropbox creates `Apps/zz-drop/` automatically
        // on the first authorize, so there is nothing to ensure
        // here — and trying to create_folder on `/` returns 400.
        if root.is_empty() {
            return Ok(());
        }
        let path = format!("/{root}");
        self.create_folder_idempotent(&path)
    }

    pub fn ensure_dir_segments(&self, segments: &[&str]) -> Result<(), DropboxError> {
        for s in segments {
            validate_filename(s)?;
        }
        self.ensure_root_folder()?;
        // Build progressively deeper paths; create_folder_v2 errors
        // with `path/conflict/folder` if it already exists, which we
        // treat as success.
        let mut path = self.root_prefix();
        for seg in segments {
            path.push('/');
            path.push_str(seg);
            self.create_folder_idempotent(&path)?;
        }
        Ok(())
    }

    fn create_folder_idempotent(&self, path: &str) -> Result<(), DropboxError> {
        self.ensure_fresh_token()?;
        let body = serde_json::json!({
            "path": path,
            "autorename": false,
        })
        .to_string();
        let url = format!("{API_BASE}/files/create_folder_v2");
        let (status, bytes) = self.json_post(&url, body.into_bytes())?;
        if is_success(status) {
            return Ok(());
        }
        // 409 with `path/conflict/folder` means the folder already
        // exists — that is the desired post-condition for an
        // idempotent ensure.
        if status == 409 && body_mentions(&bytes, "path/conflict") {
            return Ok(());
        }
        Err(classify_status_with_body(status, &bytes))
    }

    // ── Upload / download / list / delete ───────────────────────

    pub fn upload_to(
        &self,
        local: &Path,
        segments: &[&str],
        policy: CollisionPolicy,
    ) -> Result<UploadOutcome, DropboxError> {
        if segments.is_empty() {
            return Err(DropboxError::BadRoot);
        }
        for s in segments {
            validate_filename(s)?;
        }

        let last = segments.len() - 1;
        let leaf = segments[last];
        let parent_dir_segments = &segments[..last];
        if !parent_dir_segments.is_empty() {
            self.ensure_dir_segments(parent_dir_segments)?;
        } else {
            self.ensure_root_folder()?;
        }

        let body = std::fs::read(local).map_err(|_| DropboxError::LocalIo)?;
        let size = body.len() as u64;
        if size > SINGLE_SHOT_UPLOAD_LIMIT_BYTES {
            return Err(DropboxError::ServerError { status: 413 });
        }

        let parent_path = self.path_for_segments(parent_dir_segments);

        match policy {
            CollisionPolicy::Overwrite => {
                let path = join_path(&parent_path, leaf);
                self.upload_bytes(&path, &body, "overwrite")?;
                Ok(UploadOutcome {
                    final_name: leaf.to_string(),
                    size,
                    renamed: false,
                })
            }
            CollisionPolicy::Fail => {
                let path = join_path(&parent_path, leaf);
                if self.path_exists(&path)? {
                    return Err(DropboxError::Conflict);
                }
                self.upload_bytes(&path, &body, "add")?;
                Ok(UploadOutcome {
                    final_name: leaf.to_string(),
                    size,
                    renamed: false,
                })
            }
            CollisionPolicy::Rename => {
                for n in 0..=RENAME_MAX_TRIES {
                    let candidate = rename_with_suffix(leaf, n);
                    let path = join_path(&parent_path, &candidate);
                    if !self.path_exists(&path)? {
                        self.upload_bytes(&path, &body, "add")?;
                        return Ok(UploadOutcome {
                            final_name: candidate,
                            size,
                            renamed: n > 0,
                        });
                    }
                }
                Err(DropboxError::Conflict)
            }
        }
    }

    fn upload_bytes(
        &self,
        path: &str,
        bytes: &[u8],
        mode: &str,
    ) -> Result<(), DropboxError> {
        self.ensure_fresh_token()?;
        let arg = serde_json::json!({
            "path": path,
            "mode": mode,
            "autorename": false,
            "mute": true,
            "strict_conflict": false,
        });
        let arg = ascii_safe_json(&arg.to_string());
        let url = format!("{CONTENT_BASE}/files/upload");
        let (status, body) = self.binary_post(&url, &arg, bytes)?;
        if !is_success(status) {
            return Err(classify_status_with_body(status, &body));
        }
        Ok(())
    }

    pub fn download_from(
        &self,
        segments: &[&str],
        dest: &Path,
    ) -> Result<u64, DropboxError> {
        if segments.is_empty() {
            return Err(DropboxError::NotFound);
        }
        for s in segments {
            validate_filename(s)?;
        }
        self.ensure_fresh_token()?;
        let path = self.path_for_segments(segments);
        let arg = ascii_safe_json(&serde_json::json!({ "path": path }).to_string());
        let url = format!("{CONTENT_BASE}/files/download");
        let (status, body) = self.binary_post_no_body(&url, &arg)?;
        if !is_success(status) {
            return Err(classify_status_with_body(status, &body));
        }
        std::fs::write(dest, &body).map_err(|_| DropboxError::LocalIo)?;
        Ok(body.len() as u64)
    }

    pub fn list_at(&self, segments: &[&str]) -> Result<Vec<RemoteEntry>, DropboxError> {
        for s in segments {
            validate_filename(s)?;
        }
        self.ensure_fresh_token()?;
        let path = self.path_for_segments(segments);
        let url = format!("{API_BASE}/files/list_folder");
        let body = serde_json::json!({
            "path": path,
            "recursive": false,
            "include_deleted": false,
            "include_has_explicit_shared_members": false,
            "include_mounted_folders": true,
        })
        .to_string();
        let (status, bytes) = self.json_post(&url, body.into_bytes())?;
        if !is_success(status) {
            return Err(classify_status_with_body(status, &bytes));
        }
        let mut page: ListFolderPage =
            serde_json::from_slice(&bytes).map_err(|_| DropboxError::Decode)?;
        let mut entries = Vec::new();
        loop {
            absorb_entries(&page, &mut entries);
            if !page.has_more {
                break;
            }
            let cont_url = format!("{API_BASE}/files/list_folder/continue");
            let body = serde_json::json!({ "cursor": page.cursor }).to_string();
            let (status, bytes) = self.json_post(&cont_url, body.into_bytes())?;
            if !is_success(status) {
                return Err(classify_status_with_body(status, &bytes));
            }
            page = serde_json::from_slice(&bytes).map_err(|_| DropboxError::Decode)?;
        }
        Ok(entries)
    }

    /// Move a file to the trash. Dropbox personal accounts do not
    /// expose a permanent-delete on this API surface, so `hard` is
    /// silently treated the same as the soft path. Items in the
    /// trash clear after ~30 days.
    pub fn delete_at(&self, segments: &[&str], _hard: bool) -> Result<(), DropboxError> {
        if segments.is_empty() {
            return Err(DropboxError::NotFound);
        }
        for s in segments {
            validate_filename(s)?;
        }
        self.ensure_fresh_token()?;
        let path = self.path_for_segments(segments);
        let url = format!("{API_BASE}/files/delete_v2");
        let body = serde_json::json!({ "path": path }).to_string();
        let (status, bytes) = self.json_post(&url, body.into_bytes())?;
        if !is_success(status) {
            return Err(classify_status_with_body(status, &bytes));
        }
        Ok(())
    }

    fn path_exists(&self, path: &str) -> Result<bool, DropboxError> {
        self.ensure_fresh_token()?;
        let url = format!("{API_BASE}/files/get_metadata");
        let body = serde_json::json!({ "path": path }).to_string();
        let (status, bytes) = self.json_post(&url, body.into_bytes())?;
        if is_success(status) {
            return Ok(true);
        }
        // 409 with `path/not_found` is the canonical "doesn't exist".
        if status == 409 && body_mentions(&bytes, "not_found") {
            return Ok(false);
        }
        Err(classify_status_with_body(status, &bytes))
    }

    /// Fetch the email of the user who granted the OAuth consent.
    pub fn fetch_user_email(&self) -> Result<String, DropboxError> {
        self.ensure_fresh_token()?;
        // /users/get_current_account is a "no-arg" endpoint —
        // Content-Type must be unset and the body must be empty.
        let url = format!("{API_BASE}/users/get_current_account");
        let (status, bytes) = self.no_arg_post(&url)?;
        if !is_success(status) {
            return Err(classify_status_with_body(status, &bytes));
        }
        let parsed: AccountResponse =
            serde_json::from_slice(&bytes).map_err(|_| DropboxError::Decode)?;
        Ok(parsed.email.unwrap_or_default())
    }

    fn path_for_segments(&self, segments: &[&str]) -> String {
        let mut p = self.root_prefix();
        for s in segments {
            p.push('/');
            p.push_str(s);
        }
        p
    }

    /// Build the path prefix for this profile's `root_folder`.
    /// Empty root → empty prefix (the App folder sandbox root);
    /// non-empty root → `/<root>`. Callers append `/seg` to extend
    /// the path; the empty-prefix case yields `/seg` cleanly,
    /// matching Dropbox's convention that paths inside an App-folder
    /// app are rooted at the sandbox.
    fn root_prefix(&self) -> String {
        let root = self.profile.borrow().root_folder.clone();
        if root.is_empty() {
            String::new()
        } else {
            format!("/{root}")
        }
    }

    // ── Low-level HTTP helpers ──────────────────────────────────

    fn json_post(&self, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), DropboxError> {
        let auth = self.auth_header();
        let req = Request::builder()
            .method("POST")
            .uri(url)
            .header("Authorization", auth)
            .header("User-Agent", "zz-drop")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .map_err(|_| DropboxError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| DropboxError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }

    fn no_arg_post(&self, url: &str) -> Result<(u16, Vec<u8>), DropboxError> {
        let auth = self.auth_header();
        let req = Request::builder()
            .method("POST")
            .uri(url)
            .header("Authorization", auth)
            .header("User-Agent", "zz-drop")
            .header("Accept", "application/json")
            .body(Vec::<u8>::new())
            .map_err(|_| DropboxError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| DropboxError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }

    fn binary_post(
        &self,
        url: &str,
        arg_json_ascii: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), DropboxError> {
        let auth = self.auth_header();
        let req = Request::builder()
            .method("POST")
            .uri(url)
            .header("Authorization", auth)
            .header("User-Agent", "zz-drop")
            .header("Dropbox-API-Arg", arg_json_ascii)
            .header("Content-Type", "application/octet-stream")
            .body(body.to_vec())
            .map_err(|_| DropboxError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| DropboxError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }

    fn binary_post_no_body(
        &self,
        url: &str,
        arg_json_ascii: &str,
    ) -> Result<(u16, Vec<u8>), DropboxError> {
        let auth = self.auth_header();
        let req = Request::builder()
            .method("POST")
            .uri(url)
            .header("Authorization", auth)
            .header("User-Agent", "zz-drop")
            .header("Dropbox-API-Arg", arg_json_ascii)
            .body(Vec::<u8>::new())
            .map_err(|_| DropboxError::Network)?;
        let resp = self
            .agent
            .run(req)
            .map_err(|e| DropboxError::from_ureq_transport(&e))?;
        let status = resp.status().as_u16();
        let bytes = read_body(resp)?;
        Ok((status, bytes))
    }
}

fn read_body(
    mut resp: ureq::http::Response<ureq::Body>,
) -> Result<Vec<u8>, DropboxError> {
    resp.body_mut()
        .read_to_vec()
        .map_err(|_| DropboxError::Decode)
}

fn apply_refresh(auth: &mut DropboxAuth, tokens: TokenResponse) {
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

fn map_oauth(e: PasteCodeError) -> DropboxError {
    match e {
        PasteCodeError::Network => DropboxError::Network,
        PasteCodeError::Decode => DropboxError::Decode,
        PasteCodeError::ServerError { status } => DropboxError::ServerError { status },
        PasteCodeError::InvalidClient
        | PasteCodeError::InvalidGrant
        | PasteCodeError::AccessDenied
        | PasteCodeError::Expired => DropboxError::TokenExpired,
        other => DropboxError::Oauth(other),
    }
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn classify_status_with_body(status: u16, body: &[u8]) -> DropboxError {
    match status {
        401 => DropboxError::Unauthorized,
        403 => DropboxError::Unauthorized,
        409 => {
            if body_mentions(body, "not_found") {
                DropboxError::NotFound
            } else {
                DropboxError::Conflict
            }
        }
        429 => DropboxError::RateLimited,
        500..=599 => DropboxError::ServerError { status },
        _ => DropboxError::ServerError { status },
    }
}

fn body_mentions(body: &[u8], needle: &str) -> bool {
    std::str::from_utf8(body)
        .map(|s| s.contains(needle))
        .unwrap_or(false)
}

fn validate_filename(name: &str) -> Result<(), DropboxError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(DropboxError::BadRoot);
    }
    if name.contains('/') || name.contains('\0') {
        return Err(DropboxError::BadRoot);
    }
    Ok(())
}

/// Looser validation for the profile's `root_folder`. Empty is the
/// new default — it means "use the App folder sandbox root directly"
/// so the user's Dropbox shows files under `Apps/zz-drop/...` instead
/// of the redundant `Apps/zz-drop/zz-drop/...` we used to produce.
/// Existing profiles persisted with `root_folder = "zz-drop"` still
/// validate and keep their legacy folder layout.
fn validate_root_folder(name: &str) -> Result<(), DropboxError> {
    if name.is_empty() {
        return Ok(());
    }
    validate_filename(name)
}

fn join_path(parent_path: &str, leaf: &str) -> String {
    let mut out = String::with_capacity(parent_path.len() + 1 + leaf.len());
    out.push_str(parent_path);
    out.push('/');
    out.push_str(leaf);
    out
}

/// Re-encode a JSON string so every non-ASCII codepoint becomes
/// `\uXXXX` (with UTF-16 surrogate pairs for codepoints above
/// U+FFFF). Required by the Dropbox `Dropbox-API-Arg` header,
/// whose value must be US-ASCII.
fn ascii_safe_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let code = c as u32;
        if code < 0x80 {
            out.push(c);
        } else if code <= 0xFFFF {
            out.push_str(&format!("\\u{code:04x}"));
        } else {
            let off = code - 0x10000;
            let high = 0xD800 | (off >> 10);
            let low = 0xDC00 | (off & 0x3FF);
            out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
        }
    }
    out
}

#[derive(Deserialize)]
struct ListFolderPage {
    entries: Vec<ListEntry>,
    cursor: String,
    has_more: bool,
}

#[derive(Deserialize)]
struct ListEntry {
    #[serde(rename = ".tag")]
    tag: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: Option<u64>,
}

fn absorb_entries(page: &ListFolderPage, into: &mut Vec<RemoteEntry>) {
    for e in &page.entries {
        match e.tag.as_str() {
            "folder" => into.push(RemoteEntry {
                name: e.name.clone(),
                size: None,
                is_directory: true,
            }),
            "file" => into.push(RemoteEntry {
                name: e.name.clone(),
                size: e.size,
                is_directory: false,
            }),
            // "deleted" entries appear only when include_deleted is
            // true (we set it false). Skip defensively.
            _ => {}
        }
    }
}

#[derive(Deserialize)]
struct AccountResponse {
    #[serde(default)]
    email: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn validate_root_folder_accepts_empty_and_legacy() {
        // Empty root = new default (use App folder sandbox root);
        // a single segment is the legacy layout still accepted.
        assert!(validate_root_folder("").is_ok());
        assert!(validate_root_folder("zz-drop").is_ok());
        // Same defensive rules as filenames apply for non-empty
        // values — no slashes, no traversal, no NUL.
        assert!(validate_root_folder(".").is_err());
        assert!(validate_root_folder("..").is_err());
        assert!(validate_root_folder("a/b").is_err());
        assert!(validate_root_folder("a\0b").is_err());
    }

    #[test]
    fn ascii_safe_json_passes_ascii_through() {
        let s = r#"{"path":"/zz-drop/foo.txt"}"#;
        assert_eq!(ascii_safe_json(s), s);
    }

    #[test]
    fn ascii_safe_json_escapes_bmp_codepoints() {
        // "café" → "café"
        let s = "café";
        let escaped = ascii_safe_json(s);
        assert_eq!(escaped, "caf\\u00e9");
        assert!(escaped.is_ascii());
    }

    #[test]
    fn ascii_safe_json_escapes_supplementary_with_surrogate_pair() {
        // U+1F600 → 😀
        let s = "\u{1F600}";
        let escaped = ascii_safe_json(s);
        assert_eq!(escaped, "\\ud83d\\ude00");
        assert!(escaped.is_ascii());
    }

    #[test]
    fn join_path_appends_leaf_with_one_slash() {
        assert_eq!(join_path("/zz-drop", "file.txt"), "/zz-drop/file.txt");
        assert_eq!(join_path("/zz-drop/sub", "f.txt"), "/zz-drop/sub/f.txt");
    }

    #[test]
    fn classify_status_distinguishes_not_found_from_conflict() {
        let nf = br#"{"error_summary":"path/not_found/.","error":{".tag":"path","path":{".tag":"not_found"}}}"#;
        assert!(matches!(
            classify_status_with_body(409, nf),
            DropboxError::NotFound
        ));
        let conflict = br#"{"error_summary":"path/conflict/folder/.","error":{".tag":"path","path":{".tag":"conflict"}}}"#;
        assert!(matches!(
            classify_status_with_body(409, conflict),
            DropboxError::Conflict
        ));
    }

    #[test]
    fn classify_terminal_statuses() {
        assert!(matches!(
            classify_status_with_body(401, b""),
            DropboxError::Unauthorized
        ));
        assert!(matches!(
            classify_status_with_body(403, b""),
            DropboxError::Unauthorized
        ));
        assert!(matches!(
            classify_status_with_body(429, b""),
            DropboxError::RateLimited
        ));
        assert!(matches!(
            classify_status_with_body(503, b""),
            DropboxError::ServerError { status: 503 }
        ));
    }

    #[test]
    fn list_folder_page_deserialises_files_and_folders() {
        let body = r#"{
            "entries": [
                {".tag":"folder","name":"sub","path_lower":"/zz-drop/sub"},
                {".tag":"file","name":"a.txt","size":3,"path_lower":"/zz-drop/a.txt"},
                {".tag":"deleted","name":"old.bin"}
            ],
            "cursor": "C1",
            "has_more": false
        }"#;
        let page: ListFolderPage = serde_json::from_str(body).unwrap();
        let mut entries = Vec::new();
        absorb_entries(&page, &mut entries);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.is_directory && e.name == "sub"));
        assert!(entries
            .iter()
            .any(|e| !e.is_directory && e.name == "a.txt" && e.size == Some(3)));
    }

    #[test]
    fn account_response_extracts_email() {
        let body = r#"{"email":"alice@example.com","name":{"display_name":"Alice"}}"#;
        let r: AccountResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn apply_refresh_keeps_existing_refresh_token_when_omitted() {
        let mut auth = DropboxAuth {
            access_token: "OLD-AT".into(),
            refresh_token: "KEEP-RT".into(),
            token_type: "bearer".into(),
            expires_at: 0,
            scope: "x".into(),
        };
        let tokens = TokenResponse {
            access_token: "NEW-AT".into(),
            refresh_token: None,
            expires_in: 14_400,
            token_type: "bearer".into(),
            scope: None,
        };
        apply_refresh(&mut auth, tokens);
        assert_eq!(auth.access_token, "NEW-AT");
        assert_eq!(auth.refresh_token, "KEEP-RT");
        assert!(auth.expires_at > 0);
    }

    #[test]
    fn single_shot_upload_limit_is_150_mib() {
        // The single-shot POST only works under 150 MiB on Dropbox.
        // Document the constant so a future refactor doesn't drift.
        assert_eq!(SINGLE_SHOT_UPLOAD_LIMIT_BYTES, 150 * 1024 * 1024);
    }
}
