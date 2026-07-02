//! `zz f` — health-check / diagnostics.
//!
//! Read-only inspection of the local zz-drop state. Prints a
//! short, scriptable report grouped by area:
//!
//! - paths the binary would use;
//! - container files on disk (size + modify time, no decrypt);
//! - agent socket / token / build-aware lock;
//! - SACS state classification;
//! - what each provider in the active container would do.
//!
//! Never decrypts the container, never mutates state, never
//! talks to a provider. Two cheap calls cross the agent socket:
//! a single `Status` to read the unlock flag + TTL, and a single
//! `GetProfile` (only if the agent reports unlocked) to surface
//! the active provider name in the summary.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use zz_drop_core::AgentResponse;
use zz_drop_core::ProviderProfile;
use zz_drop_core::config::Paths;

use crate::agent::{AgentClient, lock};
use crate::config;
use crate::output;
use crate::runtime::{self, OutputMode};
use crate::sacs::state::{SacsState, classify, detect_signals_from_paths, remote_feature_compiled_in};

use super::EXIT_OK;

pub fn run() -> i32 {
    let paths = match config::discover() {
        Ok(p) => p,
        Err(e) => {
            output::emit_failed_bare(
                zz_drop_core::scriptable::Reason::Usage,
                Some(&format!("could not resolve paths: {e}")),
            );
            return super::EXIT_USAGE;
        }
    };

    if matches!(
        runtime::flags().output,
        OutputMode::Json | OutputMode::Quiet
    ) {
        return run_scriptable(&paths);
    }

    output::line("zz-drop doctor");
    output::line("==============");

    section_paths(&paths);
    section_containers(&paths);
    let agent_unlocked = section_agent(&paths);
    section_sacs(&paths, agent_unlocked);
    section_build();

    EXIT_OK
}

/// Structured doctor for `--json` / `--quiet`. One `doctor_check`
/// per probe, terminated by `doctor_summary`. Probes are
/// read-only and tolerate failures: every probe ends up in the
/// stream either way, so consumers can grep on `name`.
fn run_scriptable(paths: &Paths) -> i32 {
    let mut failed: Vec<&'static str> = Vec::new();

    // ---- container presence ----------------------------------
    let local_present = paths.profiles_local_file.exists();
    output::emit_doctor_check("container_local", local_present, None);
    let remote_present = paths.profiles_remote_file.exists();
    output::emit_doctor_check("container_remote", remote_present, None);
    if !local_present && !remote_present {
        // Not strictly a failure — `zz c` hasn't run yet — but
        // surface it so scripts can branch on the boolean.
        // We do NOT add to `failed` because absence of a
        // container is a legitimate starting state.
    }

    // ---- agent socket + status -------------------------------
    let socket_present = paths.agent_socket.exists();
    output::emit_doctor_check("agent_socket", socket_present, None);

    let unlocked_probe: Option<bool> = if socket_present {
        match AgentClient::connect(&paths.agent_socket, &paths.token_file) {
            Ok(mut client) => match client.status() {
                Ok(AgentResponse::Status { unlocked, .. }) => {
                    output::emit_doctor_check("agent_unlocked", unlocked, None);
                    Some(unlocked)
                }
                Ok(_) => {
                    output::emit_doctor_check(
                        "agent_unlocked",
                        false,
                        Some("unexpected status response"),
                    );
                    failed.push("agent_unlocked");
                    None
                }
                Err(e) => {
                    let msg = format!("rpc: {e}");
                    output::emit_doctor_check("agent_unlocked", false, Some(&msg));
                    failed.push("agent_unlocked");
                    None
                }
            },
            Err(e) => {
                let msg = format!("connect: {e}");
                output::emit_doctor_check("agent_unlocked", false, Some(&msg));
                failed.push("agent_unlocked");
                None
            }
        }
    } else {
        output::emit_doctor_check("agent_unlocked", false, Some("no socket"));
        None
    };

    // ---- SACS classification ---------------------------------
    let mut signals = detect_signals_from_paths(
        &paths.profiles_local_file,
        &paths.profiles_remote_file,
        &paths.agent_socket,
    );
    signals.agent_unlocked = unlocked_probe;
    let state = classify(&signals);
    let state_name = match state {
        SacsState::S0Fresh => "S0",
        SacsState::S1Down => "S1",
        SacsState::S2Locked => "S2",
        SacsState::S3Ready => "S3",
        SacsState::S4ReadyDual => "S4",
    };
    let ready = matches!(state, SacsState::S3Ready | SacsState::S4ReadyDual);
    output::emit_doctor_check("sacs_state", ready, Some(state_name));

    // ---- build identity --------------------------------------
    match lock::current_build_id() {
        Some(id) => output::emit_doctor_check("build_id", true, Some(&id)),
        None => output::emit_doctor_check("build_id", false, Some("unavailable")),
    }

    let ok = failed.is_empty();
    output::emit_doctor_summary(ok, failed);
    EXIT_OK
}

fn section_paths(paths: &Paths) {
    output::line("");
    output::line("paths:");
    output::line(&format!("  config dir       {}", paths.config_dir.display()));
    output::line(&format!("  runtime dir      {}", paths.runtime_dir.display()));
    output::line(&format!(
        "  profiles-local   {}",
        paths.profiles_local_file.display()
    ));
    output::line(&format!(
        "  profiles-remote  {}",
        paths.profiles_remote_file.display()
    ));
    output::line(&format!("  agent socket     {}", paths.agent_socket.display()));
}

fn section_containers(paths: &Paths) {
    output::line("");
    output::line("containers:");
    report_container("local ", &paths.profiles_local_file);
    report_container("remote", &paths.profiles_remote_file);
}

fn report_container(label: &str, path: &Path) {
    if !path.exists() {
        output::line(&format!("  {label}  absent"));
        return;
    }
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            output::line(&format!("  {label}  unreadable ({e})"));
            return;
        }
    };
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .map(format_unix_secs)
        .unwrap_or_else(|| "?".into());
    output::line(&format!("  {label}  present · {size} bytes · modified {mtime}"));
}

/// Returns the `unlocked` flag from the agent (when reachable),
/// so the SACS section downstream can classify against the real
/// agent state instead of falling back to the conservative S2.
fn section_agent(paths: &Paths) -> Option<bool> {
    output::line("");
    output::line("agent:");

    // Lock file inspection — surfaces stale-build situations
    // without making the doctor itself evict anything (read-only
    // contract). The eviction happens organically the next time
    // a client uses `with_remote` or `zz z`.
    let lock_path = lock::lock_path(&paths.runtime_dir);
    let socket_present = paths.agent_socket.exists();
    if lock_path.exists() {
        match std::fs::read_to_string(&lock_path) {
            Ok(raw) => {
                let mut lines = raw.lines();
                let pid = lines.next().unwrap_or("?");
                let recorded = lines.next().unwrap_or("?");
                let our = lock::current_build_id().unwrap_or_else(|| "?".into());
                let match_label = if recorded == our { "match" } else { "mismatch" };
                output::line(&format!("  lock        present · pid={pid} · build {match_label}"));
                if recorded != our {
                    output::line("              recorded build differs from current binary —");
                    output::line("              the next `zz z` will SIGTERM the stale agent.");
                }
            }
            Err(e) => output::line(&format!("  lock        unreadable ({e})")),
        }
    } else if socket_present {
        // The agent is up but no lock file is present. This means
        // it was spawned by a binary built *before* the lock-file
        // logic landed; perfectly fine on the wire, but the next
        // `zz z` after this binary's update will rotate it.
        output::line("  lock        absent (agent predates lock-file support)");
    } else {
        output::line("  lock        absent (no agent has ever run in this runtime dir)");
    }

    if !socket_present {
        output::line("  socket      absent (run `zz z` to spawn the agent)");
        return None;
    }
    output::line("  socket      present");

    let mut client = match AgentClient::connect(&paths.agent_socket, &paths.token_file) {
        Ok(c) => c,
        Err(e) => {
            output::line(&format!("  status      could not connect ({e})"));
            return None;
        }
    };
    match client.status() {
        Ok(AgentResponse::Status { unlocked: true, ttl_remaining_secs }) => {
            let ttl = ttl_remaining_secs
                .map(|s| format!("{s}s"))
                .unwrap_or_else(|| "?".into());
            output::line(&format!("  status      unlocked · ttl {ttl}"));
            if let Ok(AgentResponse::Profile(p)) = client.get_profile() {
                let providers = describe_providers(&p.providers);
                output::line(&format!("  active      {} · {providers}", p.alias));
            }
            Some(true)
        }
        Ok(AgentResponse::Status { unlocked: false, .. }) => {
            output::line("  status      locked (run `zz z`)");
            Some(false)
        }
        Ok(other) => {
            output::line(&format!("  status      unexpected response: {other:?}"));
            None
        }
        Err(e) => {
            output::line(&format!("  status      RPC failed ({e})"));
            None
        }
    }
}

fn describe_providers(providers: &[ProviderProfile]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for p in providers {
        let label = match p {
            ProviderProfile::Nextcloud(_) => "nextcloud",
            ProviderProfile::GoogleDrive(_) => "google-drive",
            ProviderProfile::OneDrive(_) => "onedrive",
            ProviderProfile::Dropbox(_) => "dropbox",
            ProviderProfile::Unknown(u) => {
                parts.push(format!("{} (unsupported — upgrade zz-drop)", u.tag));
                continue;
            }
        };
        parts.push(label.to_string());
    }
    if parts.is_empty() {
        "no provider configured".into()
    } else {
        parts.join(" + ")
    }
}

fn section_sacs(paths: &Paths, agent_unlocked: Option<bool>) {
    output::line("");
    output::line("sacs:");
    let mut signals = detect_signals_from_paths(
        &paths.profiles_local_file,
        &paths.profiles_remote_file,
        &paths.agent_socket,
    );
    // Feed the live `Status` flag into the classifier so the
    // doctor reports S3 (ready) when the agent is unlocked
    // instead of falling back to the conservative S2.
    signals.agent_unlocked = agent_unlocked;
    let state = classify(&signals);
    let label = match state {
        SacsState::S0Fresh => "S0 (fresh — no usable container)",
        SacsState::S1Down => "S1 (container present, agent down)",
        SacsState::S2Locked => "S2 (locked, or status not probed)",
        SacsState::S3Ready => "S3 (ready, single container)",
        SacsState::S4ReadyDual => "S4 (ready, two containers)",
    };
    output::line(&format!("  state       {label}"));
    let feat = if remote_feature_compiled_in() {
        "compiled in"
    } else {
        "default build (off)"
    };
    output::line(&format!("  remote feat {feat}"));
    output::line(&format!(
        "  install     `zz --completions $SHELL` to install shell completion"
    ));
}

fn section_build() {
    output::line("");
    output::line("build:");
    let id = lock::current_build_id().unwrap_or_else(|| "(unavailable)".into());
    output::line(&format!("  id          {id}"));
    output::line(&format!(
        "  binary      {}",
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".into())
    ));
}

fn format_unix_secs(secs: u64) -> String {
    // Lightweight ISO-8601 basic UTC, mirroring the helper used
    // by the Nextcloud rename-with-suffix algorithm but inlined
    // here to avoid pulling a `chrono` dep into doctor.
    let s = (secs % 60) as u32;
    let mi = ((secs / 60) % 60) as u32;
    let h = ((secs / 3600) % 24) as u32;
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y_anchor = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y_anchor + 1 } else { y_anchor };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tail of the function: epoch 0 must serialise to the unix
    /// epoch in ISO basic. Smoke check against the date math.
    #[test]
    fn format_unix_secs_at_epoch() {
        assert_eq!(format_unix_secs(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_unix_secs_round_number() {
        // 1700000000 → 2023-11-14T22:13:20Z (verified externally).
        assert_eq!(format_unix_secs(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn describe_providers_empty_is_clear() {
        assert_eq!(describe_providers(&[]), "no provider configured");
    }
}

// Silence unused-import warning when rustc walks the test module
// list — `SystemTime` is referenced through doc comments only.
const _: () = {
    let _ = SystemTime::UNIX_EPOCH;
};
