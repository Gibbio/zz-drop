#![forbid(unsafe_code)]

use std::process::ExitCode;

use zz_drop::agent::{self, ServerConfig};
use zz_drop::commands::EXIT_USAGE;
use zz_drop::config;
use zz_drop::runtime;
use zz_drop::sacs;
use zz_drop::{cli, commands, output};

fn main() -> ExitCode {
    if agent::is_agent_mode() {
        return run_agent();
    }

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Tooling subcommands (`--help`, `--completions`, `__complete`)
    // are intercepted exactly as the first arg, before the grammar
    // parser sees them. Matching exact tokens keeps `parse_args`'
    // "treat unknown as path" invariant intact for legitimate
    // filenames that happen to start with `-` or `_`.
    if let sacs::Intercepted::Handled(code) = sacs::intercept(&args) {
        return ExitCode::from(u8::try_from(code).unwrap_or(255));
    }

    init_diag_log("zz");
    // Log only the argument count, never the raw argv: operands can be
    // filenames / paths / alias names the operator may consider private,
    // and the per-command emitters already record the verb + outcome.
    zz_drop_core::diag_log::log(&format!("invoke argc={}", args.len()));

    // Strip global flags (`--json`, `--quiet`, `--passphrase-file`,
    // `--alias`, `--local`, `--remote`, `--yes`) from the front of
    // argv and merge env-var overrides (`ZZ_OUTPUT`, …). Errors
    // here precede any structured output, so they always render as
    // plain stderr text — exit code EXIT_USAGE.
    let (flags, residual) = match runtime::parse_global(args) {
        Ok(pair) => pair,
        Err(err) => {
            output::err_line(&format!("{err}"));
            zz_drop_core::diag_log::log(&format!("flag_err exit={}", EXIT_USAGE));
            return ExitCode::from(EXIT_USAGE as u8);
        }
    };
    runtime::init(flags);

    let cmd = match cli::parse_args(residual) {
        Ok(cmd) => cmd,
        Err(err) => {
            output::err_line(&format!("{err}"));
            zz_drop_core::diag_log::log(&format!("usage_err exit={}", EXIT_USAGE));
            return ExitCode::from(EXIT_USAGE as u8);
        }
    };

    let code = commands::dispatch(&cmd);
    zz_drop_core::diag_log::log(&format!("dispatch_done exit={code}"));
    ExitCode::from(u8::try_from(code).unwrap_or(255))
}

/// Initialise the shared `zz-drop.log` for the calling binary. No-op
/// when `discover_paths` fails (e.g. no `$HOME`) — the log is
/// best-effort.
fn init_diag_log(binary: &'static str) {
    if let Ok(paths) = config::discover() {
        let _ = zz_drop_core::config::ensure_dir(&paths.cache_dir, 0o700);
        zz_drop_core::diag_log::init(paths.debug_log_file(), binary);
    }
}

fn run_agent() -> ExitCode {
    let paths = match config::discover() {
        Ok(p) => p,
        Err(_) => return ExitCode::from(1),
    };
    let config = ServerConfig::default_with_paths(paths);
    match agent::run(config) {
        Ok(()) => ExitCode::from(0),
        Err(_) => ExitCode::from(1),
    }
}
