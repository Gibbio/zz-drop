//! Detect installed zsh plugin frameworks + the bash-completion
//! framework, by grepping the rc file and checking known paths.
//!
//! When a zsh framework is detected we *don't* append `compinit`
//! to `.zshrc`: the framework owns initialisation and a second
//! `compinit` call usually emits a "compinit:13: insecure
//! directories" warning or breaks completion ordering.

use serde::Serialize;
use std::path::Path;

/// Known zsh plugin frameworks. Detection is grep-based on the
/// user's `.zshrc`. False positives are mostly harmless (we just
/// skip our own `compinit`); false negatives mean we emit an
/// extra `compinit` that the framework will tolerate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Framework {
    None,
    OhMyZsh,
    Prezto,
    Zinit,
    Antibody,
    Antidote,
    Znap,
    Zimfw,
    Zplug,
}

impl Framework {
    pub fn is_some(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Bare kebab-case form, matches the serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OhMyZsh => "oh-my-zsh",
            Self::Prezto => "prezto",
            Self::Zinit => "zinit",
            Self::Antibody => "antibody",
            Self::Antidote => "antidote",
            Self::Znap => "znap",
            Self::Zimfw => "zimfw",
            Self::Zplug => "zplug",
        }
    }
}

/// Inspect a `.zshrc` (if it exists) and pick the first known
/// framework string it mentions. Order is roughly "most popular
/// first" but stable so the same rc always classifies the same
/// way.
pub fn detect_zsh(zshrc: &Path) -> Framework {
    let Ok(body) = std::fs::read_to_string(zshrc) else {
        return Framework::None;
    };
    // Match in priority order so a file referencing both
    // `oh-my-zsh` and `zinit` classifies as oh-my-zsh.
    for (needle, fw) in [
        ("oh-my-zsh", Framework::OhMyZsh),
        ("ohmyzsh", Framework::OhMyZsh),
        ("prezto", Framework::Prezto),
        ("zinit", Framework::Zinit),
        ("antibody", Framework::Antibody),
        ("antidote", Framework::Antidote),
        ("znap", Framework::Znap),
        ("zimfw", Framework::Zimfw),
        ("zplug", Framework::Zplug),
    ] {
        if body.contains(needle) {
            return fw;
        }
    }
    Framework::None
}

/// Returns true if the bash-completion framework looks installed
/// on this host. Mirrors the POSIX `__zz_bash_completion_loaded`
/// probe from `patch-installer.yml` — same set of paths so the
/// two stay in sync.
pub fn bash_completion_loaded() -> bool {
    use std::path::PathBuf;
    let prefix = std::env::var("HOMEBREW_PREFIX").unwrap_or_else(|_| "/opt/homebrew".into());
    let probes: [PathBuf; 6] = [
        PathBuf::from("/usr/share/bash-completion/bash_completion"),
        PathBuf::from("/etc/bash_completion.d"),
        PathBuf::from("/etc/profile.d/bash_completion.sh"),
        PathBuf::from("/etc/bash_completion"),
        PathBuf::from(format!("{prefix}/etc/bash_completion")),
        PathBuf::from("/usr/local/etc/bash_completion"),
    ];
    probes.iter().any(|p| p.exists())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    fn tmp_file(content: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Monotonic counter, not just a nanosecond timestamp: parallel
        // framework tests collided on the same clock tick and wrote the
        // same file, so one test read another's content (flaky
        // `detects_*` failures). The counter guarantees uniqueness.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "zz-framework-test-{}-{nanos}-{seq}.zshrc",
            std::process::id(),
        ));
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn missing_file_is_none() {
        assert_eq!(detect_zsh(Path::new("/nonexistent/zzz")), Framework::None);
    }

    #[test]
    fn detects_oh_my_zsh() {
        let p = tmp_file("export ZSH=$HOME/.oh-my-zsh\nplugins=(git)\n");
        assert_eq!(detect_zsh(&p), Framework::OhMyZsh);
    }

    #[test]
    fn detects_prezto() {
        let p = tmp_file("source ~/.zprezto/init.zsh\n");
        assert_eq!(detect_zsh(&p), Framework::Prezto);
    }

    #[test]
    fn detects_zinit() {
        let p = tmp_file("source ~/.local/share/zinit/zinit.zsh\n");
        assert_eq!(detect_zsh(&p), Framework::Zinit);
    }

    #[test]
    fn priority_oh_my_zsh_wins_over_zinit() {
        let p = tmp_file("# was using zinit before\nsource ~/.oh-my-zsh/oh-my-zsh.sh\n");
        assert_eq!(detect_zsh(&p), Framework::OhMyZsh);
    }

    #[test]
    fn plain_rc_is_none() {
        let p = tmp_file("alias ll='ls -la'\nexport PATH=$HOME/bin:$PATH\n");
        assert_eq!(detect_zsh(&p), Framework::None);
    }
}
