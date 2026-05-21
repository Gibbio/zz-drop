//! Shell completions: install, status check, uninstall.
//!
//! Single source of truth for "wire SACS into the operator's
//! shell". Consumed by:
//!
//! - the CLI top-level flags `--setup-completions` and
//!   `--check-completions` (intercepted in `sacs::intercept`)
//! - the TUI welcome screen, which surfaces the status as a
//!   menu entry and runs `install` on selection
//! - the curl-installer post-install hook, which invokes
//!   `<bin> --setup-completions` instead of duplicating the
//!   wiring logic in POSIX sh
//!
//! The brew formula doesn't call this directly (brew may not
//! touch the operator's dotfiles), but its `caveats` block
//! points the user at the same command.
//!
//! # rc-file block
//!
//! When this module appends to `~/.zshrc` or `~/.bashrc`, the
//! addition is delimited by the constants [`BLOCK_START`] and
//! [`BLOCK_END`] — same convention used by conda, asdf, nvm and
//! LM Studio. On a second invocation the block is replaced
//! in-place; on uninstall it is removed cleanly. The two marker
//! strings are part of the frozen public surface for v1.

pub mod framework;
pub mod paths;
pub mod rc_block;
pub mod scripts;
pub mod shell;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use framework::Framework;
pub use shell::Shell;

/// Opening marker for the rc-file block. Stable across versions
/// so older blocks remain recognisable for update / uninstall.
pub const BLOCK_START: &str = "# >>> zz-drop SACS >>>";

/// Closing marker for the rc-file block. See [`BLOCK_START`].
pub const BLOCK_END: &str = "# <<< zz-drop SACS <<<";

/// What [`install`] needs from the caller.
#[derive(Clone, Debug)]
pub struct InstallRequest<'a> {
    /// Target shell. Use [`Shell::detect`] or pass the caller's
    /// explicit choice.
    pub shell: Shell,
    /// Completion script content for the target shell (the
    /// caller fetches the right one from `sacs::scripts` — keeps
    /// this crate free of include_str! payloads).
    pub script: &'a str,
    /// `$HOME` to use. Mostly `dirs::home_dir()`; the parameter
    /// exists so unit tests can point at a tmpdir.
    pub home: PathBuf,
    /// `$XDG_DATA_HOME` if set in the environment. None falls
    /// back to `$HOME/.local/share`.
    pub xdg_data_home: Option<PathBuf>,
    /// `$ZDOTDIR` if set. None falls back to `$HOME`.
    pub zdotdir: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME` if set. None falls back to
    /// `$HOME/.config`.
    pub xdg_config_home: Option<PathBuf>,
}

/// What [`install`] returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallOutcome {
    pub shell: Shell,
    pub framework: Framework,
    pub completion_path: PathBuf,
    pub completion_action: FileAction,
    pub rc_path: Option<PathBuf>,
    pub rc_action: RcAction,
    /// Optional human hint (e.g. "open a new terminal", or
    /// "install bash-completion via your package manager"). The
    /// CLI / TUI surfaces this verbatim; scriptable mode emits
    /// it as a `hint` field.
    pub hint: Option<String>,
}

/// What happened to the completion script file on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAction {
    /// File didn't exist; we wrote it.
    Created,
    /// File existed with different content; we overwrote it.
    Updated,
    /// File existed with identical content; we left it alone.
    Unchanged,
}

/// What happened to the rc file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcAction {
    /// No block existed; we appended one.
    Inserted,
    /// Block existed with different content; we replaced it.
    Updated,
    /// Block existed with identical content; we left it alone.
    Unchanged,
    /// No rc edit needed for this shell (fish, or bash with a
    /// system bash-completion framework that auto-loads the XDG
    /// path).
    NotNeeded,
}

/// What [`status`] returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Completion file is in place; rc file is wired (or no rc
    /// edit is needed for this shell). Future shells will load
    /// SACS automatically.
    Wired {
        shell: Shell,
        completion_path: PathBuf,
        rc_path: Option<PathBuf>,
    },
    /// Completion file is on disk but the rc block is missing
    /// (and would be needed for this shell). Run
    /// `zz --setup-completions` to fix.
    NeedsRcBlock {
        shell: Shell,
        completion_path: PathBuf,
        rc_path: PathBuf,
    },
    /// Completion file is missing. Setup never ran.
    Missing {
        shell: Shell,
        completion_path: PathBuf,
    },
}

impl Status {
    pub fn is_wired(&self) -> bool {
        matches!(self, Status::Wired { .. })
    }

    pub fn shell(&self) -> Shell {
        match self {
            Status::Wired { shell, .. }
            | Status::NeedsRcBlock { shell, .. }
            | Status::Missing { shell, .. } => *shell,
        }
    }
}

/// Errors from [`install`] / [`status`] / [`uninstall`].
#[derive(Debug, thiserror::Error)]
pub enum CompletionError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("rc file at {path} is not writable")]
    RcNotWritable { path: PathBuf },
    #[error("could not determine $HOME")]
    HomeUnknown,
}

/// Write the completion script + (when needed) wire the rc file.
///
/// Idempotent: a second call with the same script content is a
/// no-op for both filesystem ops. A call with different content
/// updates both in place.
///
/// Bash and fish lazy-load by command name, so the primary file
/// alone wouldn't serve `zz <TAB>` when the file is named
/// `zz-drop` (and vice versa). For those shells we also drop one
/// or more alias files next to the primary — symlink where the
/// platform supports it, copy as a fallback. See
/// `paths::completion_aliases`.
pub fn install(req: &InstallRequest<'_>) -> Result<InstallOutcome, CompletionError> {
    let env = paths::Env {
        xdg_data_home: req.xdg_data_home.clone(),
        zdotdir: req.zdotdir.clone(),
        xdg_config_home: req.xdg_config_home.clone(),
    };
    let completion_path = paths::completion_file(req.shell, &req.home, &env);

    let completion_action = write_completion_file(&completion_path, req.script)?;

    for alias in paths::completion_aliases(req.shell, &req.home, &env) {
        write_alias_file(&alias, &completion_path, req.script)?;
    }

    let framework = match req.shell {
        Shell::Zsh => framework::detect_zsh(&zshrc_path(&req.home, req.zdotdir.as_deref())),
        _ => Framework::None,
    };

    let (rc_path, rc_action, hint) = match req.shell {
        Shell::Fish => (None, RcAction::NotNeeded, None),
        Shell::Bash => bash_rc_update(req, &completion_path)?,
        Shell::Zsh => zsh_rc_update(req, &framework)?,
    };

    Ok(InstallOutcome {
        shell: req.shell,
        framework,
        completion_path,
        completion_action,
        rc_path,
        rc_action,
        hint,
    })
}

/// Inspect filesystem + rc file and report whether SACS is wired
/// for the given shell. Read-only; never modifies anything.
pub fn status(req: &InstallRequest<'_>) -> Status {
    let completion_path = paths::completion_file(req.shell, &req.home, &paths::Env {
        xdg_data_home: req.xdg_data_home.clone(),
        zdotdir: req.zdotdir.clone(),
        xdg_config_home: req.xdg_config_home.clone(),
    });

    if !completion_path.exists() {
        return Status::Missing {
            shell: req.shell,
            completion_path,
        };
    }

    match req.shell {
        Shell::Fish => Status::Wired {
            shell: req.shell,
            completion_path,
            rc_path: None,
        },
        Shell::Bash => {
            // bash with the bash-completion framework auto-loads
            // the XDG path → no rc block needed.
            if framework::bash_completion_loaded() {
                return Status::Wired {
                    shell: req.shell,
                    completion_path,
                    rc_path: None,
                };
            }
            let rc = bashrc_path(&req.home);
            if rc_block::contains_block(&rc).unwrap_or(false) {
                Status::Wired {
                    shell: req.shell,
                    completion_path,
                    rc_path: Some(rc),
                }
            } else {
                Status::NeedsRcBlock {
                    shell: req.shell,
                    completion_path,
                    rc_path: rc,
                }
            }
        }
        Shell::Zsh => {
            let rc = zshrc_path(&req.home, req.zdotdir.as_deref());
            if rc_block::contains_block(&rc).unwrap_or(false) {
                Status::Wired {
                    shell: req.shell,
                    completion_path,
                    rc_path: Some(rc),
                }
            } else {
                Status::NeedsRcBlock {
                    shell: req.shell,
                    completion_path,
                    rc_path: rc,
                }
            }
        }
    }
}

/// Reverse [`install`]: remove the rc-file block (cleanly,
/// preserving everything outside the markers) and delete the
/// completion script file. Either op is a no-op when its target
/// is already absent.
///
/// Also removes the bash/fish alias files written by `install`.
pub fn uninstall(req: &InstallRequest<'_>) -> Result<UninstallOutcome, CompletionError> {
    let env = paths::Env {
        xdg_data_home: req.xdg_data_home.clone(),
        zdotdir: req.zdotdir.clone(),
        xdg_config_home: req.xdg_config_home.clone(),
    };
    let completion_path = paths::completion_file(req.shell, &req.home, &env);

    let file_removed = if path_present(&completion_path) {
        fs::remove_file(&completion_path)?;
        true
    } else {
        false
    };

    for alias in paths::completion_aliases(req.shell, &req.home, &env) {
        if path_present(&alias) {
            fs::remove_file(&alias)?;
        }
    }

    let rc_path = match req.shell {
        Shell::Fish => None,
        Shell::Bash => Some(bashrc_path(&req.home)),
        Shell::Zsh => Some(zshrc_path(&req.home, req.zdotdir.as_deref())),
    };

    let rc_block_removed = match &rc_path {
        Some(rc) if rc.exists() => rc_block::remove_block(rc)?,
        _ => false,
    };

    Ok(UninstallOutcome {
        completion_path,
        file_removed,
        rc_path,
        rc_block_removed,
    })
}

/// What [`uninstall`] returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallOutcome {
    pub completion_path: PathBuf,
    pub file_removed: bool,
    pub rc_path: Option<PathBuf>,
    pub rc_block_removed: bool,
}

// --- internal helpers ---------------------------------------------------

fn write_completion_file(path: &Path, script: &str) -> Result<FileAction, CompletionError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let existing = fs::read_to_string(path)?;
        if existing == script {
            return Ok(FileAction::Unchanged);
        }
        fs::write(path, script)?;
        Ok(FileAction::Updated)
    } else {
        fs::write(path, script)?;
        Ok(FileAction::Created)
    }
}

/// Place an alias next to the primary completion file so the
/// shell's lazy-loader picks up the other command name. Tries a
/// relative symlink first (cheap, self-updating); falls back to a
/// plain copy of the script when symlinks aren't available
/// (Windows without dev-mode, exotic filesystems).
///
/// Idempotent: an existing symlink pointing at the correct target
/// is left alone; an existing file with the correct content is
/// left alone; anything else is replaced.
fn write_alias_file(
    alias: &Path,
    primary: &Path,
    script: &str,
) -> Result<(), CompletionError> {
    if let Some(parent) = alias.parent() {
        fs::create_dir_all(parent)?;
    }

    let primary_name = primary
        .file_name()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| primary.to_path_buf());

    if let Ok(existing_target) = fs::read_link(alias) {
        if existing_target == primary_name {
            return Ok(());
        }
        fs::remove_file(alias)?;
    } else if alias.exists() {
        let existing = fs::read_to_string(alias).unwrap_or_default();
        if existing == script {
            return Ok(());
        }
        fs::remove_file(alias)?;
    }

    #[cfg(unix)]
    {
        if std::os::unix::fs::symlink(&primary_name, alias).is_ok() {
            return Ok(());
        }
    }
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_file(&primary_name, alias).is_ok() {
            return Ok(());
        }
    }

    fs::write(alias, script)?;
    Ok(())
}

/// Treat a dangling symlink as "present" — `Path::exists` follows
/// symlinks and returns false when the target is missing, which
/// would leak stale alias files past uninstall on systems where
/// the primary was already gone.
fn path_present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn bashrc_path(home: &Path) -> PathBuf {
    home.join(".bashrc")
}

fn zshrc_path(home: &Path, zdotdir: Option<&Path>) -> PathBuf {
    zdotdir.unwrap_or(home).join(".zshrc")
}

fn bash_rc_update(
    req: &InstallRequest<'_>,
    completion_path: &Path,
) -> Result<(Option<PathBuf>, RcAction, Option<String>), CompletionError> {
    // If the bash-completion framework is installed, it auto-loads
    // the XDG path and no rc edit is needed.
    if framework::bash_completion_loaded() {
        return Ok((None, RcAction::NotNeeded, None));
    }

    let rc = bashrc_path(&req.home);
    let body = format!(
        "# Added by `zz --setup-completions` — to remove, delete this block.\n\
         [ -f {q} ] && . {q}\n",
        q = shell_quote(&completion_path.display().to_string()),
    );
    let action = rc_block::write_block(&rc, &body)?;
    let hint = Some(
        "bash-completion framework not detected; install it via your package manager \
         (apt / dnf / pacman / apk / brew install bash-completion) for nicer rendering. \
         The block we just added sources the file directly, so SACS works either way."
            .into(),
    );
    Ok((Some(rc), action, hint))
}

fn zsh_rc_update(
    req: &InstallRequest<'_>,
    framework: &Framework,
) -> Result<(Option<PathBuf>, RcAction, Option<String>), CompletionError> {
    let rc = zshrc_path(&req.home, req.zdotdir.as_deref());
    let zfunc = paths::zsh_zfunc_dir(&req.home, req.zdotdir.as_deref());

    let body = if framework.is_some() {
        format!(
            "# Added by `zz --setup-completions` — framework detected ({fw}).\n\
             # Compinit is handled by the framework; we only ensure ~/.zfunc is in fpath.\n\
             fpath=({zf} $fpath)\n",
            fw = framework.as_str(),
            zf = shell_quote(&zfunc.display().to_string()),
        )
    } else {
        format!(
            "# Added by `zz --setup-completions` — to remove, delete this block.\n\
             fpath=({zf} $fpath)\n\
             autoload -U compinit && compinit -i\n",
            zf = shell_quote(&zfunc.display().to_string()),
        )
    };
    let action = rc_block::write_block(&rc, &body)?;
    let hint = Some("open a new terminal (or run `exec zsh -l`) for completions to load.".into());
    Ok((Some(rc), action, hint))
}

/// Conservative shell-quoter for path strings written to rc files.
/// Always quotes with double quotes and escapes the few chars that
/// matter inside them. Sufficient for `$HOME`-rooted paths; the
/// rc files we write never see arbitrary user input.
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' | '$' | '`' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_home() -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "zz-completions-test-{}-{}",
            std::process::id(),
            uniq_suffix(),
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn uniq_suffix() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn req<'a>(shell: Shell, home: &Path, script: &'a str) -> InstallRequest<'a> {
        InstallRequest {
            shell,
            script,
            home: home.to_path_buf(),
            xdg_data_home: None,
            zdotdir: None,
            xdg_config_home: None,
        }
    }

    #[test]
    fn install_zsh_creates_file_and_rc_block() {
        let home = tmp_home();
        let req = req(Shell::Zsh, &home, "# zsh completion script\n");
        let out = install(&req).unwrap();
        assert_eq!(out.shell, Shell::Zsh);
        assert_eq!(out.completion_action, FileAction::Created);
        assert_eq!(out.rc_action, RcAction::Inserted);
        assert!(out.completion_path.exists());
        let rc = fs::read_to_string(out.rc_path.unwrap()).unwrap();
        assert!(rc.contains(BLOCK_START));
        assert!(rc.contains(BLOCK_END));
        assert!(rc.contains("autoload -U compinit"));
    }

    #[test]
    fn install_is_idempotent() {
        let home = tmp_home();
        let req = req(Shell::Zsh, &home, "# zsh script v1\n");
        let _ = install(&req).unwrap();
        let again = install(&req).unwrap();
        assert_eq!(again.completion_action, FileAction::Unchanged);
        assert_eq!(again.rc_action, RcAction::Unchanged);
    }

    #[test]
    fn install_updates_block_when_script_changes() {
        let home = tmp_home();
        let r1 = req(Shell::Zsh, &home, "# v1\n");
        let _ = install(&r1).unwrap();
        let r2 = req(Shell::Zsh, &home, "# v2\n");
        let out = install(&r2).unwrap();
        assert_eq!(out.completion_action, FileAction::Updated);
        // RC block content is the same (the block only references
        // the path, not the script content), so Unchanged is correct.
        assert_eq!(out.rc_action, RcAction::Unchanged);
    }

    #[test]
    fn install_zsh_with_framework_skips_compinit() {
        let home = tmp_home();
        // Pre-populate .zshrc with an oh-my-zsh hint so framework
        // detection fires.
        fs::write(home.join(".zshrc"), "# my zshrc\nplugin=oh-my-zsh\n").unwrap();
        let req = req(Shell::Zsh, &home, "# script\n");
        let out = install(&req).unwrap();
        assert_eq!(out.framework, Framework::OhMyZsh);
        let rc = fs::read_to_string(out.rc_path.unwrap()).unwrap();
        assert!(rc.contains("framework detected (oh-my-zsh)"));
        assert!(!rc.contains("compinit -i"));
    }

    #[test]
    fn install_fish_skips_rc() {
        let home = tmp_home();
        let req = req(Shell::Fish, &home, "# fish\n");
        let out = install(&req).unwrap();
        assert_eq!(out.rc_action, RcAction::NotNeeded);
        assert!(out.rc_path.is_none());
        assert!(out.completion_path.exists());
    }

    #[test]
    fn status_progression() {
        let home = tmp_home();
        let req = req(Shell::Zsh, &home, "# script\n");
        assert!(matches!(status(&req), Status::Missing { .. }));
        let _ = install(&req).unwrap();
        assert!(status(&req).is_wired());
    }

    #[test]
    fn uninstall_removes_file_and_block() {
        let home = tmp_home();
        let req = req(Shell::Zsh, &home, "# script\n");
        let _ = install(&req).unwrap();
        let out = uninstall(&req).unwrap();
        assert!(out.file_removed);
        assert!(out.rc_block_removed);
        assert!(matches!(status(&req), Status::Missing { .. }));
        let rc = fs::read_to_string(out.rc_path.unwrap()).unwrap();
        assert!(!rc.contains(BLOCK_START));
    }

    #[test]
    fn uninstall_preserves_surrounding_rc_lines() {
        let home = tmp_home();
        let rc = home.join(".zshrc");
        fs::write(&rc, "alias ll='ls -la'\nexport FOO=1\n").unwrap();
        let req = req(Shell::Zsh, &home, "# script\n");
        let _ = install(&req).unwrap();
        let _ = uninstall(&req).unwrap();
        let body = fs::read_to_string(&rc).unwrap();
        assert!(body.contains("alias ll='ls -la'"));
        assert!(body.contains("export FOO=1"));
        assert!(!body.contains(BLOCK_START));
    }

    #[test]
    fn shell_quote_escapes_dollar_and_quotes() {
        assert_eq!(shell_quote("/home/user/.zfunc"), "\"/home/user/.zfunc\"");
        assert_eq!(shell_quote("a$b"), "\"a\\$b\"");
        assert_eq!(shell_quote("with\"quote"), "\"with\\\"quote\"");
    }

    #[test]
    fn install_bash_creates_alias_for_zz() {
        let home = tmp_home();
        let req = req(Shell::Bash, &home, "# bash completion v1\n");
        let _ = install(&req).unwrap();

        let primary = home.join(".local/share/bash-completion/completions/zz-drop");
        let alias = home.join(".local/share/bash-completion/completions/zz");
        assert!(path_present(&primary), "primary not written: {primary:?}");
        assert!(path_present(&alias), "alias not written: {alias:?}");

        // Either a relative symlink or a copy is acceptable.
        if let Ok(target) = fs::read_link(&alias) {
            assert_eq!(target, PathBuf::from("zz-drop"));
        } else {
            let body = fs::read_to_string(&alias).unwrap();
            assert!(body.contains("bash completion v1"));
        }
    }

    #[test]
    fn install_fish_creates_alias_for_zz_drop() {
        let home = tmp_home();
        let req = req(Shell::Fish, &home, "# fish completion v1\n");
        let _ = install(&req).unwrap();

        let primary = home.join(".config/fish/completions/zz.fish");
        let alias = home.join(".config/fish/completions/zz-drop.fish");
        assert!(path_present(&primary));
        assert!(path_present(&alias));

        if let Ok(target) = fs::read_link(&alias) {
            assert_eq!(target, PathBuf::from("zz.fish"));
        } else {
            let body = fs::read_to_string(&alias).unwrap();
            assert!(body.contains("fish completion v1"));
        }
    }

    #[test]
    fn install_zsh_writes_no_alias_file() {
        let home = tmp_home();
        let req = req(Shell::Zsh, &home, "# zsh\n");
        let _ = install(&req).unwrap();
        // .zfunc/_zz handles both names via the script's #compdef.
        let listing: Vec<_> = fs::read_dir(home.join(".zfunc"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0], std::ffi::OsString::from("_zz"));
    }

    #[test]
    fn install_alias_is_idempotent_across_runs() {
        let home = tmp_home();
        let req = req(Shell::Bash, &home, "# bash v1\n");
        let _ = install(&req).unwrap();
        // Second run with identical content must not error and
        // must leave the alias in place.
        let _ = install(&req).unwrap();
        let alias = home.join(".local/share/bash-completion/completions/zz");
        assert!(path_present(&alias));
    }

    #[test]
    fn install_alias_recovers_from_stale_content() {
        let home = tmp_home();
        let alias = home.join(".local/share/bash-completion/completions/zz");
        fs::create_dir_all(alias.parent().unwrap()).unwrap();
        fs::write(&alias, "# stale unrelated content\n").unwrap();

        let req = req(Shell::Bash, &home, "# bash v1\n");
        let _ = install(&req).unwrap();

        // Stale plain-file content must be replaced so `zz <TAB>`
        // actually loads the new completer.
        if let Ok(target) = fs::read_link(&alias) {
            assert_eq!(target, PathBuf::from("zz-drop"));
        } else {
            let body = fs::read_to_string(&alias).unwrap();
            assert!(!body.contains("stale unrelated content"));
            assert!(body.contains("bash v1"));
        }
    }

    #[test]
    fn uninstall_removes_alias_too() {
        let home = tmp_home();
        let req = req(Shell::Bash, &home, "# bash\n");
        let _ = install(&req).unwrap();
        let alias = home.join(".local/share/bash-completion/completions/zz");
        assert!(path_present(&alias));

        let _ = uninstall(&req).unwrap();
        assert!(!path_present(&alias), "alias not removed on uninstall");
    }
}
