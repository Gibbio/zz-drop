//! Read / write / remove the delimited block in an rc file.
//!
//! The block is bracketed by the [`super::BLOCK_START`] and
//! [`super::BLOCK_END`] marker lines. Within the markers the
//! content is owned by `zz --setup-completions`; outside, the
//! file is left exactly as it was.

use super::{BLOCK_END, BLOCK_START, CompletionError, RcAction};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// Returns `true` when the rc file contains both markers in
/// order. Missing file → `Ok(false)`.
pub fn contains_block(rc: &Path) -> Result<bool, CompletionError> {
    let body = match fs::read_to_string(rc) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    Ok(find_block(&body).is_some())
}

/// Insert or update the delimited block. `body` is the lines to
/// place *between* the start/end markers; this function adds the
/// markers and the leading newline if the file doesn't already
/// end with one.
///
/// Returns:
/// - [`RcAction::Inserted`] when no block existed before
/// - [`RcAction::Updated`] when a block existed with different content
/// - [`RcAction::Unchanged`] when the block already had identical content
pub fn write_block(rc: &Path, body: &str) -> Result<RcAction, CompletionError> {
    let existing = read_or_empty(rc)?;
    let desired_block = render_block(body);

    if let Some(range) = find_block(&existing) {
        // `find_block` reports the range BLOCK_START..BLOCK_END
        // marker text (exclusive of trailing newline). `render_block`
        // appends a single `\n` after BLOCK_END for tidy formatting.
        // Compare both sides trimmed of trailing whitespace so an
        // identical block reads as Unchanged regardless of whether
        // the file preserved that newline.
        let on_disk = existing[range.clone()].trim_end();
        let desired_trimmed = desired_block.trim_end();
        if on_disk == desired_trimmed {
            return Ok(RcAction::Unchanged);
        }
        let mut next = String::with_capacity(existing.len() + desired_block.len());
        next.push_str(&existing[..range.start]);
        // Strip the trailing newline from desired_block when the
        // existing range didn't capture one — keeps the surrounding
        // file bytes unchanged.
        let replacement = if existing.as_bytes().get(range.end).copied() == Some(b'\n') {
            desired_trimmed
        } else {
            desired_block.as_str()
        };
        next.push_str(replacement);
        next.push_str(&existing[range.end..]);
        atomic_write(rc, &next)?;
        return Ok(RcAction::Updated);
    }

    let mut next = existing;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    if !next.is_empty() {
        next.push('\n');
    }
    next.push_str(&desired_block);
    atomic_write(rc, &next)?;
    Ok(RcAction::Inserted)
}

/// Strip the delimited block (and exactly one trailing newline
/// after it, if present). Returns `true` when something was
/// removed.
pub fn remove_block(rc: &Path) -> Result<bool, CompletionError> {
    let existing = match fs::read_to_string(rc) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let Some(range) = find_block(&existing) else {
        return Ok(false);
    };

    // Also consume the single blank line we may have inserted
    // *before* the block, and one trailing newline after it, so
    // an install + uninstall pair leaves the file byte-identical
    // (modulo final newline preservation).
    let mut start = range.start;
    let mut end = range.end;
    // Trailing newline immediately after the block.
    if existing.as_bytes().get(end) == Some(&b'\n') {
        end += 1;
    }
    // One blank line before the block (we inserted exactly one).
    if start >= 2 && &existing[start - 2..start] == "\n\n" {
        start -= 1;
    } else if start >= 1 && existing.as_bytes()[start - 1] == b'\n'
        && existing.as_bytes().get(start.saturating_sub(2)).copied() == Some(b'\n')
    {
        start -= 1;
    }

    let mut next = String::with_capacity(existing.len());
    next.push_str(&existing[..start]);
    next.push_str(&existing[end..]);
    atomic_write(rc, &next)?;
    Ok(true)
}

// --- internals ----------------------------------------------------------

fn read_or_empty(rc: &Path) -> Result<String, CompletionError> {
    match fs::read_to_string(rc) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

fn render_block(body: &str) -> String {
    let mut out = String::with_capacity(body.len() + BLOCK_START.len() + BLOCK_END.len() + 4);
    out.push_str(BLOCK_START);
    out.push('\n');
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(BLOCK_END);
    out.push('\n');
    out
}

/// Return the byte range of the block (markers included) inside
/// `body`, or `None` if either marker is missing or they are out
/// of order.
fn find_block(body: &str) -> Option<std::ops::Range<usize>> {
    let s = body.find(BLOCK_START)?;
    let after = s + BLOCK_START.len();
    let e_rel = body[after..].find(BLOCK_END)?;
    let e = after + e_rel + BLOCK_END.len();
    Some(s..e)
}

/// Write a file atomically: stage the new content next to the
/// target, then `rename` so a reader can never see a partial
/// rc file. Preserves the target's mode bits on Unix.
fn atomic_write(path: &Path, content: &str) -> Result<(), CompletionError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("zzdrop.tmp");
    fs::write(&tmp, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode();
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
        }
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_rc() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Monotonic counter, not just a nanosecond timestamp: parallel
        // tests collided on the same clock tick and shared one rc file,
        // causing flaky failures. The counter guarantees uniqueness.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = env::temp_dir().join(format!(
            "zz-rc-test-{}-{nanos}-{seq}.rc",
            std::process::id(),
        ));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn insert_into_empty_file() {
        let rc = tmp_rc();
        let action = write_block(&rc, "echo hi\n").unwrap();
        assert_eq!(action, RcAction::Inserted);
        let body = fs::read_to_string(&rc).unwrap();
        assert!(body.starts_with(BLOCK_START));
        assert!(body.contains("echo hi"));
        assert!(body.contains(BLOCK_END));
    }

    #[test]
    fn append_after_existing_content_with_blank_separator() {
        let rc = tmp_rc();
        fs::write(&rc, "alias ll='ls -la'\nexport FOO=1\n").unwrap();
        write_block(&rc, "echo hi\n").unwrap();
        let body = fs::read_to_string(&rc).unwrap();
        assert!(body.contains("alias ll='ls -la'"));
        assert!(body.contains("export FOO=1"));
        assert!(body.contains("\n\n# >>> zz-drop SACS >>>"));
    }

    #[test]
    fn second_write_same_content_is_unchanged() {
        let rc = tmp_rc();
        write_block(&rc, "x=1\n").unwrap();
        let action = write_block(&rc, "x=1\n").unwrap();
        assert_eq!(action, RcAction::Unchanged);
    }

    #[test]
    fn second_write_different_content_updates_in_place() {
        let rc = tmp_rc();
        fs::write(&rc, "PREFIX_LINE\n").unwrap();
        write_block(&rc, "v=1\n").unwrap();
        // Add a trailing line OUTSIDE the block to prove update
        // preserves both sides.
        let mut body = fs::read_to_string(&rc).unwrap();
        body.push_str("SUFFIX_LINE\n");
        fs::write(&rc, body).unwrap();

        let action = write_block(&rc, "v=2\n").unwrap();
        assert_eq!(action, RcAction::Updated);
        let body = fs::read_to_string(&rc).unwrap();
        assert!(body.contains("PREFIX_LINE"));
        assert!(body.contains("SUFFIX_LINE"));
        assert!(body.contains("v=2"));
        assert!(!body.contains("v=1\n"));
    }

    #[test]
    fn remove_block_strips_markers_and_blank_separator() {
        let rc = tmp_rc();
        fs::write(&rc, "alias ll='ls -la'\n").unwrap();
        write_block(&rc, "x=1\n").unwrap();
        let removed = remove_block(&rc).unwrap();
        assert!(removed);
        let body = fs::read_to_string(&rc).unwrap();
        assert_eq!(body, "alias ll='ls -la'\n");
    }

    #[test]
    fn remove_block_missing_is_noop() {
        let rc = tmp_rc();
        fs::write(&rc, "alias ll='ls -la'\n").unwrap();
        let removed = remove_block(&rc).unwrap();
        assert!(!removed);
        let body = fs::read_to_string(&rc).unwrap();
        assert_eq!(body, "alias ll='ls -la'\n");
    }

    #[test]
    fn contains_block_reports_correctly() {
        let rc = tmp_rc();
        assert!(!contains_block(&rc).unwrap());
        fs::write(&rc, "alias ll='ls -la'\n").unwrap();
        assert!(!contains_block(&rc).unwrap());
        write_block(&rc, "x=1\n").unwrap();
        assert!(contains_block(&rc).unwrap());
    }
}
