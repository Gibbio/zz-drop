//! Canonical filesystem paths for installed completion files.
//!
//! Mirrors the per-shell layout in `docs/sacs.md`:
//!
//! | bash | `${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/zz-drop` (+ alias `zz`) |
//! | zsh  | `${ZDOTDIR:-$HOME}/.zfunc/_zz` |
//! | fish | `${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/zz.fish` (+ alias `zz-drop.fish`) |
//!
//! All three are XDG-conformant when the relevant `$XDG_*` env
//! var is set; otherwise they fall back to the conventional
//! `$HOME` location.
//!
//! Bash and fish lazy-load their completion files by command name
//! (`bash-completion/completions/<cmd>`, `fish/completions/<cmd>.fish`).
//! With only `zz-drop` on disk, typing `zz <TAB>` from a fresh
//! shell would never trigger the loader. To make both names work,
//! `completion_aliases` returns the extra filename(s) that must
//! live next to the primary file as a symlink (or copy on
//! filesystems that don't support symlinks). Zsh's `#compdef`
//! handles both names without an alias file.

use super::Shell;
use std::path::{Path, PathBuf};

/// Optional environment overrides resolved by the caller. None
/// means "fall back to the default under `$HOME`".
#[derive(Clone, Debug, Default)]
pub struct Env {
    pub xdg_data_home: Option<PathBuf>,
    pub zdotdir: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
}

impl Env {
    /// Read the three relevant env vars from the current
    /// process. Use this in production; tests should construct
    /// `Env` literally so they don't depend on test-run env.
    pub fn from_process() -> Self {
        Self {
            xdg_data_home: std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
            zdotdir: std::env::var_os("ZDOTDIR").map(PathBuf::from),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        }
    }
}

/// Where the completion script file should land for the given
/// shell.
pub fn completion_file(shell: Shell, home: &Path, env: &Env) -> PathBuf {
    match shell {
        Shell::Bash => xdg_data(home, env)
            .join("bash-completion/completions/zz-drop"),
        Shell::Zsh => zsh_zfunc_dir(home, env.zdotdir.as_deref()).join("_zz"),
        Shell::Fish => xdg_config(home, env)
            .join("fish/completions/zz.fish"),
    }
}

/// Extra filenames that must live next to the primary completion
/// file so the lazy-loader picks up the other command name.
///
/// - bash: `<…>/bash-completion/completions/zz` alongside `zz-drop`
/// - fish: `<…>/fish/completions/zz-drop.fish` alongside `zz.fish`
/// - zsh: none — `#compdef zz zz-drop` covers both names via
///   `compinit`'s autoload index.
pub fn completion_aliases(shell: Shell, home: &Path, env: &Env) -> Vec<PathBuf> {
    match shell {
        Shell::Bash => vec![xdg_data(home, env)
            .join("bash-completion/completions/zz")],
        Shell::Fish => vec![xdg_config(home, env)
            .join("fish/completions/zz-drop.fish")],
        Shell::Zsh => Vec::new(),
    }
}

pub fn zsh_zfunc_dir(home: &Path, zdotdir: Option<&Path>) -> PathBuf {
    zdotdir.unwrap_or(home).join(".zfunc")
}

fn xdg_data(home: &Path, env: &Env) -> PathBuf {
    env.xdg_data_home
        .clone()
        .unwrap_or_else(|| home.join(".local/share"))
}

fn xdg_config(home: &Path, env: &Env) -> PathBuf {
    env.xdg_config_home
        .clone()
        .unwrap_or_else(|| home.join(".config"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_under_home() {
        let h = Path::new("/h");
        let e = Env::default();
        assert_eq!(
            completion_file(Shell::Bash, h, &e),
            PathBuf::from("/h/.local/share/bash-completion/completions/zz-drop")
        );
        assert_eq!(
            completion_file(Shell::Zsh, h, &e),
            PathBuf::from("/h/.zfunc/_zz")
        );
        assert_eq!(
            completion_file(Shell::Fish, h, &e),
            PathBuf::from("/h/.config/fish/completions/zz.fish")
        );
    }

    #[test]
    fn xdg_overrides_apply() {
        let h = Path::new("/h");
        let e = Env {
            xdg_data_home: Some(PathBuf::from("/x/data")),
            xdg_config_home: Some(PathBuf::from("/x/config")),
            zdotdir: Some(PathBuf::from("/x/zsh")),
        };
        assert_eq!(
            completion_file(Shell::Bash, h, &e),
            PathBuf::from("/x/data/bash-completion/completions/zz-drop")
        );
        assert_eq!(
            completion_file(Shell::Zsh, h, &e),
            PathBuf::from("/x/zsh/.zfunc/_zz")
        );
        assert_eq!(
            completion_file(Shell::Fish, h, &e),
            PathBuf::from("/x/config/fish/completions/zz.fish")
        );
    }

    #[test]
    fn bash_alias_lives_next_to_primary() {
        let h = Path::new("/h");
        let e = Env::default();
        let aliases = completion_aliases(Shell::Bash, h, &e);
        assert_eq!(
            aliases,
            vec![PathBuf::from(
                "/h/.local/share/bash-completion/completions/zz"
            )]
        );
    }

    #[test]
    fn fish_alias_lives_next_to_primary() {
        let h = Path::new("/h");
        let e = Env::default();
        let aliases = completion_aliases(Shell::Fish, h, &e);
        assert_eq!(
            aliases,
            vec![PathBuf::from("/h/.config/fish/completions/zz-drop.fish")]
        );
    }

    #[test]
    fn zsh_has_no_alias_file() {
        let h = Path::new("/h");
        let e = Env::default();
        assert!(completion_aliases(Shell::Zsh, h, &e).is_empty());
    }

    #[test]
    fn aliases_honour_xdg_overrides() {
        let h = Path::new("/h");
        let e = Env {
            xdg_data_home: Some(PathBuf::from("/x/data")),
            xdg_config_home: Some(PathBuf::from("/x/config")),
            zdotdir: Some(PathBuf::from("/x/zsh")),
        };
        assert_eq!(
            completion_aliases(Shell::Bash, h, &e),
            vec![PathBuf::from(
                "/x/data/bash-completion/completions/zz"
            )]
        );
        assert_eq!(
            completion_aliases(Shell::Fish, h, &e),
            vec![PathBuf::from("/x/config/fish/completions/zz-drop.fish")]
        );
    }
}
