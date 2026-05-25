use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use zz_drop_core::scriptable::Reason;

use crate::commands::EXIT_USAGE;
use crate::output;
use crate::runtime::{self, OutputMode};

/// Name of the TUI binary on PATH. It is shipped as `zz-tui` by the
/// `zz-drop-tui` crate's `[[bin]]` entry; on Windows it lives next to
/// it as `zz-tui.exe`.
const TUI_BINARY: &str = "zz-tui";

/// UNIX convention: the shell returns 127 when a command is not found.
/// We mirror it here so scripts that wrap `zz c` see the same code.
pub const EXIT_TUI_NOT_FOUND: i32 = 127;

/// Resolve `zz-tui` and run it, propagating its exit code. Prints a
/// one-line diagnostic and returns 127 when the binary is missing, or
/// when launching it fails for any other reason.
///
/// Resolution prefers the `zz-tui` installed **next to this binary**
/// (the install dir, found via `current_exe()`): the installer always
/// places `zz-drop` and `zz-tui` together, and a sibling lookup can't be
/// redirected by a poisoned `$PATH` (F6). Only if no sibling exists do
/// we fall back to a `$PATH` search.
///
/// In scriptable modes (`--json` / `--quiet`) the TUI cannot run,
/// so the command fails fast with `interactive_only` and exit
/// `EXIT_USAGE` without ever attempting to launch `zz-tui`.
pub fn run() -> i32 {
    if matches!(
        runtime::flags().output,
        OutputMode::Json | OutputMode::Quiet
    ) {
        output::emit_failed_bare(
            Reason::InteractiveOnly,
            Some("`zz c` opens the configuration TUI and has no scriptable surface"),
        );
        return EXIT_USAGE;
    }
    if let Some(path) = sibling_tui_binary() {
        return launch(&path);
    }
    run_with_env(env::var_os("PATH").as_deref())
}

/// Locate `zz-tui` alongside the currently-running executable. Returns
/// `None` if `current_exe()` can't be resolved or no runnable `zz-tui`
/// sits next to it.
fn sibling_tui_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // Canonicalize so a `zz` symlink resolves to the real install dir.
    let exe = exe.canonicalize().ok()?;
    sibling_in_dir(exe.parent()?)
}

fn sibling_in_dir(dir: &Path) -> Option<PathBuf> {
    candidates(dir, TUI_BINARY).into_iter().find(|c| is_runnable(c))
}

/// Test seam: lets the integration tests inject a custom `PATH`
/// without poisoning the parent process's environment. Used as the
/// fallback when no sibling `zz-tui` is found.
pub fn run_with_env(path_var: Option<&OsStr>) -> i32 {
    let Some(path) = find_in_path(TUI_BINARY, path_var) else {
        output::line(&format!(
            "zz c: `{TUI_BINARY}` not found next to zz-drop or on PATH.\n\
             install the zz-drop package, or add the binary to PATH."
        ));
        return EXIT_TUI_NOT_FOUND;
    };
    launch(&path)
}

fn launch(path: &Path) -> i32 {
    match Command::new(path).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            output::line(&format!(
                "zz c: failed to launch `{}`: {e}",
                path.display()
            ));
            EXIT_TUI_NOT_FOUND
        }
    }
}

fn find_in_path(name: &str, path_var: Option<&OsStr>) -> Option<PathBuf> {
    let path_var = path_var?;
    for dir in env::split_paths(path_var) {
        for candidate in candidates(&dir, name) {
            if is_runnable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn candidates(dir: &Path, name: &str) -> Vec<PathBuf> {
    let mut out = vec![dir.join(name)];
    if cfg!(windows) {
        out.push(dir.join(format!("{name}.exe")));
    }
    out
}

#[cfg(unix)]
fn is_runnable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_runnable(path: &Path) -> bool {
    matches!(std::fs::metadata(path), Ok(m) if m.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn empty_path_means_not_found() {
        assert_eq!(run_with_env(Some(OsStr::new(""))), EXIT_TUI_NOT_FOUND);
    }

    #[test]
    fn missing_path_var_means_not_found() {
        assert_eq!(run_with_env(None), EXIT_TUI_NOT_FOUND);
    }

    #[cfg(unix)]
    #[test]
    fn sibling_in_dir_prefers_executable_zz_tui() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        // No sibling yet → None.
        assert!(sibling_in_dir(tmp.path()).is_none());
        // A non-executable file does not count.
        let p = tmp.path().join("zz-tui");
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(sibling_in_dir(tmp.path()).is_none());
        // Mark it runnable → found.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(sibling_in_dir(tmp.path()), Some(p));
    }

    #[test]
    fn finds_binary_in_supplied_path() {
        // Put a tempdir on PATH that does NOT contain zz-tui;
        // find_in_path should return None.
        let tmp = tempfile::tempdir().unwrap();
        let mut path = OsString::from(tmp.path());
        path.push(":/this/dir/does/not/exist");
        assert!(find_in_path("zz-tui", Some(path.as_os_str())).is_none());
    }
}
