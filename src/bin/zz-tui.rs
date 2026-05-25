//! Entry point for the `zz-tui` binary. The TUI implementation
//! lives in the `zz-drop-tui` crate (workspace member `tui/`);
//! this file is just the shim that turns it into a binary
//! shipped from the `zz-drop` crate's release tarball.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    zz_drop_tui::entry_point()
}
