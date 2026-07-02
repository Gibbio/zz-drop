# Changelog

All notable changes to the `zz-drop`, `zz-drop-core`, and
`zz-drop-tui` crates are recorded here. The three crate
versions move together; this file is the single source of
truth for the workspace.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/);
the 0.x line is the pre-1.0 stabilisation track. The public
surfaces frozen on the road to 1.0 are listed in
[`AGENTS.md`](AGENTS.md).

## [Unreleased]

### Added

- **`profile.zz` forward compatibility.** A container holding a
  provider entry written by a newer zz-drop (unknown serde tag) no
  longer fails to decode as a whole. The foreign entry is preserved
  internally under the reserved `unknown` carrier tag: every other
  alias keeps working, operations on the foreign alias fail with a
  clear "upgrade zz-drop" diagnostic (`zz doctor` labels it), and
  re-encrypting the container writes the entry back under its
  original tag (payload semantically preserved; CBOR re-encoded).
  On-disk bytes for known providers are unchanged; no schema bump;
  agent protocol untouched.

## [0.9.7] — 2026-05-25

Security hardening release from a deep audit of the CLI, local agent,
and core crypto. Every change is backward-compatible: no change to the
command grammar, exit codes, `--json` schema, `profile.zz` format, or
agent protocol.

### Security

- **Mutual agent authentication.** The CLI now verifies the agent's
  peer UID and that the runtime dir is a private, owner-only `0700`
  directory before sending the token or unlocking — closing a path for
  a different local user to impersonate the agent via the world-writable
  `/tmp` runtime dir on macOS / XDG-less Linux. (The agent already
  checked the client's UID; the check is now mutual.)
- **No secret logging.** Removed the `ZZ_DROP_DECRYPT_DEBUG` branch that
  printed the passphrase and a key fingerprint. The shared diagnostic
  log is now **off by default** (opt in with `ZZ_DROP_DEBUG_LOG=1`) and
  no longer records the raw argv or the passphrase length — the
  "no log file" guarantee now holds by default.
- **Secrets zeroized.** OAuth tokens and Nextcloud app-passwords are
  wiped from memory when dropped (e.g. on lock); the unlock passphrase
  is held in zeroizing storage. On-disk format unchanged.
- **Untrusted-input limits.** Argon2 parameters read from the envelope
  header are range-checked (no OOM / CPU time-bomb on a hostile
  container); `zz dx` caps zstd decompression size (no decompression
  bomb); bulk download validates server-supplied filenames before
  building local paths and strips control/ANSI bytes from names printed
  to the terminal.
- **TLS / process hygiene.** `SSL_CERT_FILE` now fails closed when set
  but unusable (no silent fallback to the system trust store); provider
  clients gained connect/resolve timeouts; the process disables core
  dumps (and is non-dumpable on Linux) to keep the in-RAM key off disk.
- **Install integrity documented.** `SECURITY.md`/README now state
  plainly that `curl|sh` and brew verify a TLS-fetched SHA-256, not the
  minisign signature (which remains a manual, optional check).

### Changed

- Secret files (profile, token, lock) and the agent socket are created
  `0600` in a single step (no brief world-readable window).
- `zz c` resolves `zz-tui` next to the running binary first, then
  `$PATH`, so a poisoned `$PATH` can't redirect it.
- `#![forbid(unsafe_code)]` now also on the binary crate roots
  (workspace remains free of first-party `unsafe`).

### Fixed

- Removed a parallel-test flake in the completions suite (temp files
  were named from a nanosecond timestamp only and could collide).

## [0.9.6] — 2026-05-21

Fix release on the 0.9.x stabilisation track. Restores
`zz <TAB>` completion on bash and fish systems where the
shell's completion framework lazy-loads files by command name
— previously only `zz-drop <TAB>` actually triggered SACS.
Symmetric brew-side patch lands in the tap formula via the
release workflow.

### Fixed

- `zz <TAB>` now triggers SACS from a fresh shell on bash
  systems with the `bash-completion` framework loaded. The
  framework lazy-loads completion files by command name, and
  only the `zz-drop` file existed on disk, so the
  `complete -F … zz` binding inside it was never registered
  for the `zz` alias. `--setup-completions` now also drops a
  `zz` alias next to `zz-drop` (relative symlink where
  supported, copy otherwise); the symmetric fix lands for fish
  (`zz-drop.fish` alongside `zz.fish`). Zsh was already correct
  via `#compdef zz zz-drop`. `--setup-completions --uninstall`
  removes the alias too.
- **Homebrew formula** carries the same alias pair in the
  cellar: `share/bash-completion/completions/zz → zz-drop` and
  `share/fish/vendor_completions.d/zz.fish → zz-drop.fish`.
  Injected post-publish by the `patch-formula` workflow next to
  the existing `generate_completions_from_executable` call.
  `brew uninstall` reverses both.

## [0.9.5] — 2026-05-20

Maintenance release on the 0.9.x stabilisation track. No new
user-facing surface, no behavioural changes. Catches up on the
first batch of dependabot bumps after F3 went live, plus three
fixes to the install-smoke CI tooling that had silently drifted
out of sync with the binary's actual behaviour.

### Internal

- **`quick-xml` 0.39.2 → 0.40.1** (used by the Nextcloud WebDAV
  PROPFIND parser). Minor release, full test suite green.
- **`tar` 0.4.45 → 0.4.46** (used by the upload bundle path for
  `zz sar` / `zz sarx`). Patch release.
- **`ratatui-image` 10.0.8 → 11.0.2**. v11 changed
  `Picker::new_protocol` to take a `Size` instead of `Rect`;
  two callsites in `tui/src/qr.rs` and `tui/examples/qr_inline.rs`
  updated to `area.into()`.
- **`actions/checkout` v4 → v6** in the hand-managed workflows
  (`build.yml`, `patch-installer.yml`, `smoke-installer.yml`).
  `release.yml` was already at v6 (cargo-dist-managed).
- **Dependabot `ignore` rule** for `actions/upload-artifact` and
  `actions/download-artifact`: `release.yml` is auto-generated by
  cargo-dist with specific versions pinned, so manual bumps fail
  the `plan` step. Those two actions are owned by cargo-dist and
  bump when the cargo-dist version itself does.

### Fixed

- **`scripts/smoke-installer.sh` — three latent bugs surfaced when
  dependabot started running CI:**
  - Version resolution selected `prerelease==true` only, returning
    nothing once the project went stable from `0.9.0` onward; now
    uses `releases/latest`.
  - The framework-detection grep looked for `"framework detected:
    oh-my-zsh"` (the stdout rendering); the rc-block actually
    writes `"framework detected (oh-my-zsh)"` with parentheses.
  - The "no `$SHELL`" scenario predated the 0.9.2 unconditional
    bash-completion install: its assertions said bash completion
    should be absent, contradicting the fix that ensures it lands
    in containers / cron / non-login SSH. Rewritten to assert the
    actual 0.9.2+ contract (bash unconditional, zsh and fish gate
    on `$SHELL`).

## [0.9.4] — 2026-05-20

Polish release on the 0.9.x stabilisation track. One focused
change: zz-drop's outbound HTTPS now uses the operating system
trust store, so the CLI works behind corporate TLS-inspection
proxies and against self-hosted providers whose chain ends at a
system-installed CA. Landed pre-G1 so the trust-set claim on the
public security page lines up with the binary at 1.0.0.

### Changed

- **TLS trust set: operating system trust store, not the embedded
  Mozilla bundle.** Outbound HTTPS in `zz-drop-core` (every
  provider client + the API client + WebDAV + OAuth flows) now
  goes through `rustls` with
  [`rustls-platform-verifier`](https://docs.rs/rustls-platform-verifier/0.7.0/)
  via ureq's `platform-verifier` feature. On macOS this is
  Security.framework, on Windows SChannel, on Linux the system
  CA bundle. Practical effect: zz-drop works behind corporate
  TLS-inspection proxies and against self-hosted Nextcloud
  instances whose certificate chain ends at a CA the operator
  has installed system-wide. There is no `--insecure` flag; an
  unverifiable certificate is still a hard failure.
- **`SSL_CERT_FILE` is honored** as the standard OpenSSL escape
  valve. When set to a readable PEM, *only* the certificates in
  that file are trusted for the duration of the run — useful
  when a corporate CA is shipped as a `.pem` but cannot be
  installed system-wide.
- **Centralized HTTP agent factory.** Every `ureq::Agent` in
  `zz-drop-core` is built through `zz_drop_core::http::build_agent`,
  ensuring a uniform trust set and timeout policy across the
  crate. New `zz_drop_core::http::tls_error::tls_trust_hint`
  recognises rustls "invalid peer certificate" failures and
  yields a one-line operator hint pointing at the env var
  override.
- **Provider errors now distinguish TLS trust failures from
  generic network errors.** `OneDriveError`, `DropboxError`,
  `GoogleDriveError`, `LoginFlowError`, `DeviceFlowError`, and
  `PasteCodeError` gain a `TlsTrustFailed(&'static str)` variant
  that carries the operator hint and is produced by their
  `from_ureq_transport` helper when the underlying ureq error
  is a certificate rejection. The WebDAV client and
  `ApiClient` (which already carried `String` payloads for
  transport errors) append the hint inline via
  `zz_drop_core::http::tls_error::transport_message`. End users
  see a clear "TLS verification failed — set `SSL_CERT_FILE` or
  ask your administrator to install the corp CA…" message
  instead of a generic "network error".

### Security

- Trust-set change: see the entry above. The set of issuers
  zz-drop will accept is now whatever the operating system
  already accepts — same as the browser, `curl`, `ssh`,
  package managers. No silent expansion: only CAs the OS
  already trusts. Documented in
  [`SECURITY.md`](SECURITY.md),
  [`docs/security-model.md`](docs/security-model.md), and on
  the public security page at `zz-drop.net/security`.

## [0.9.3] — 2026-05-18

Unified shell-completion install path. One command everywhere
(`zz --setup-completions`), one source of truth in
`zz_drop_core::completions`, one delimited block (`# >>> zz-drop
SACS >>>` … `# <<< zz-drop SACS <<<`) in the rc file. Closes the
fragmentation that left brew users with the file installed but
the shell unable to find it, and the TUI's done-screen with
copy-paste hints that lied to 99% of operators.

### Added

- **`zz --setup-completions [bash|zsh|fish]`** — auto-detects
  `$SHELL`, writes the completion script to its canonical XDG
  path, and appends an idempotent delimited block to `~/.zshrc`
  or `~/.bashrc`. Framework-aware (oh-my-zsh, prezto, zinit,
  antibody, antidote, znap, zimfw, zplug — when a framework is
  detected, `compinit` is left to it). `--uninstall` reverses
  everything cleanly. Idempotent: re-running with identical
  content is a no-op; changed script content updates in place.
- **`zz --check-completions [bash|zsh|fish]`** — read-only
  status report: `wired` / `needs_rc_block` / `missing`. Exits
  0 when wired, 12 (`EXIT_COMPLETIONS_FAILED`) otherwise.
- **`completions_setup` and `completions_status` NDJSON events**
  with closed-enum fields for `shell`, `framework`,
  `completion_action`, `rc_action`, `status`. Full schema in
  [`docs/scriptable.md`](docs/scriptable.md) +
  [`docs/scriptable/zz-drop-output.v1.json`](docs/scriptable/zz-drop-output.v1.json).
- **`Reason::CompletionsInstallFailed`** (serialised as
  `completions_install_failed`) for I/O failures.
- **`EXIT_COMPLETIONS_FAILED = 12`** — new exit code (additive,
  doesn't bump the schema).
- **TUI welcome screen: Shell completions row** — shows live
  status (`✓ active`, `not wired`, `not installed`) for the
  detected shell. Enter installs / reinstalls.
- **Stable block markers** — the `# >>> zz-drop SACS >>>` and
  `# <<< zz-drop SACS <<<` strings are now part of the v1
  public surface so older blocks remain recognisable for
  update / uninstall across versions.

### Changed

- **Brew formula `def caveats`** — patched in by
  `patch-formula.yml`. Tells the operator the two one-liners
  they need (`brew shellenv` + `autoload compinit`) for the
  cellar-installed completions to actually load on Apple
  Silicon, and points at `zz --setup-completions` for the
  one-shot equivalent.
- **`curl | sh` installer** — the post-install completion hook
  shrinks from ~130 lines of POSIX sh to ~10. The wiring logic
  (shell detection, framework detection, idempotent rc block)
  now lives in `zz_drop_core::completions` and is shared with
  the TUI and the new CLI flags.
- **TUI "done" screen** — replaces ~20 lines of stale per-shell
  copy-paste hints with a single line pointing at
  `zz --setup-completions` for operators who installed via
  paths that don't auto-wire (cargo install, source build).
- **`docs/sacs.md` Installation section** — rewritten around
  `zz --setup-completions`. README + `docs/build.md` similarly
  updated.

### Internal

- Crates bumped from `0.9.2` to `0.9.3`.
- New module `zz-drop-core::completions` with public types
  `Shell`, `Framework`, `Status`, `InstallRequest`,
  `InstallOutcome`, `FileAction`, `RcAction`, plus
  `install()`, `status()`, `uninstall()` and the rc-block
  primitives. Tests cover idempotency, framework detection,
  install/uninstall round-trip preserving surrounding rc lines,
  and the path-resolution matrix across `$XDG_*` overrides.
- SACS shell script templates (`bash.sh`, `zsh.sh`,
  `fish.fish`) moved from `src/sacs/scripts/` to
  `core/src/completions/scripts/` so the TUI can install them
  without duplication. The root crate's `src/sacs/scripts/mod.rs`
  is now a thin re-export.

## [0.9.2] — 2026-05-17

Polish release ahead of the 1.0 freeze. No new public surface,
no breaking changes.

### Fixed

- **bash completion: no trailing space on directory candidates**
  — `zz s et<TAB>` now resolves to `zz s etc/` with the cursor
  positioned for the next path segment, instead of `zz s etc/ `
  with a trailing space that forced a backspace before typing
  the inner filename. The bash script now sets `compopt -o
  nospace` whenever every candidate in `COMPREPLY` ends with
  `/`, matching the zsh script's `compadd -S ''` behaviour.

### Changed

- **`curl | sh` installer auto-wires bash completion regardless
  of `$SHELL`** — the previous logic gated on `$SHELL`, so
  containers, cron jobs and SSH non-login sessions where
  `$SHELL` is unset got no bash completion installed. The
  installer now writes
  `${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions/zz-drop`
  unconditionally (bash is dominant on Linux/WSL, the XDG path
  is harmless for non-bash users). If the bash-completion
  framework isn't detected on the system, the installer prints
  a one-line hint pointing at the package manager.
- **README hero pass.** Project logo added; Homebrew tap badge
  alongside build / release / license; provider matrix promoted
  to a proper table with `auth method` + `status` columns; new
  "How it compares" table vs `rclone` / `croc` / `scp`; three
  static TUI screenshots above the existing walkthrough GIF;
  third install one-liner (`cargo install --git ... --locked
  zz-drop`) under a "from source via Rust toolchain" framing.
- **`COMMANDS.md` / `docs/commands.md` split.** The
  user-facing manual (`COMMANDS.md`) and the canonical grammar
  spec (`docs/commands.md`) no longer duplicate the verb table;
  the cheatsheet lives in `docs/commands.md` only.

## [0.9.1] — 2026-05-16

### Fixed

- **Global flags after the verb** — `--json`, `--quiet`,
  `--passphrase-file`, `--alias`, `--local`, `--remote`,
  `--yes` are now consumed wherever they appear on the
  command line (e.g. `zz f --json`, `zz d note.txt --json`).
  Previously the pre-pass stopped at the first positional, so
  flags placed after the verb were forwarded to the verb
  parser and rejected. The `--` terminator still freezes any
  remaining flags as positionals.
- **`zz dx` bundle extraction** — recognises GNU tar magic
  (`ustar ` at offset 257) in addition to POSIX `ustar\0`, so
  bundles produced by GNU tar are detected and unpacked
  instead of being treated as opaque blobs.

## [0.9.0] — 2026-05-16

First release on the 0.9 stabilisation track. Adds the
scriptable contract and graduates the version from the
`0.0.1-pre.N` development series.

### Added

- **Scriptable mode** — `--json` emits one NDJSON event per
  result on stdout with a stable `v: "1"` schema; `--quiet`
  emits one minimal text line per result. Full contract in
  [`docs/scriptable.md`](docs/scriptable.md); machine-checkable
  JSON Schema in
  [`docs/scriptable/zz-drop-output.v1.json`](docs/scriptable/zz-drop-output.v1.json).
- **Global flags** parsed before the verb: `--json`,
  `--quiet`, `--passphrase-file`, `--alias`, `--local`,
  `--remote`, `--yes`. `--quiet` and `--json` are mutually
  exclusive.
- **Environment overrides** (flag > env > default):
  `ZZ_OUTPUT`, `ZZ_PASSPHRASE_FILE`, `ZZ_ALIAS`,
  `ZZ_CONTAINER`. `ZZ_CONFIG_DIR=<absolute>` redirects the
  whole state tree to `<root>/{config,cache,runtime}`.
- **New exit codes**: `10` (`agent_locked` — scriptable mode
  never auto-unlocks), `11` (`passphrase_file_permissions`).
- **Passphrase-file reader** with strict checks: regular file
  only (no symlinks), owner = current UID, mode ≤ 0600, size
  cap 4 KiB, no embedded NUL, exactly one trailing `\n` stripped.
- **`docs/usage.md`** — scenario cookbook with worked examples
  for every verb.
- **Universal lint test** (`tests/scriptable_universal.rs`)
  asserts every verb either emits ≥ 1 well-formed NDJSON
  record under `--json` or fails with a documented `reason`.

### Changed

- **Doctor (`zz f`) in scriptable mode** now streams one
  `doctor_check` per probe followed by a final
  `doctor_summary` instead of the verbose human output.
- **`zz w`** in `--json` / `--quiet` requires `--yes` (or the
  legacy `ZZ_DROP_CONFIRM_WIPE=yes` env). Refuses with
  `interactive_required` otherwise.
- **`zz c`** in `--json` / `--quiet` fails fast with
  `interactive_only` and exits `2` without launching the TUI.
- **Container resolution**: when both `profiles-local.zz` and
  `profiles-remote.zz` exist and no override was provided,
  scriptable mode fails with `container_ambiguous` instead of
  silently defaulting to local.
- **Alias resolution** in scriptable mode is deterministic
  (flag/env → cached default → single-alias short-circuit →
  `alias_ambiguous` with candidate list). The numbered picker
  never runs under `--json` / `--quiet`.

### Fixed

- **`zz dx`** now correctly extracts tar bundles produced by
  `zz sax` / `zz sarx`. The Rust `tar` crate's default writer
  emits the GNU magic (`ustar `, with trailing space); a
  strict POSIX-only check left the `.tar` on disk un-untar'd.
  `is_tar_ustar` now accepts both POSIX and GNU magic.

### Internal

- Crates bumped from `0.0.1-pre.11` to `0.9.0`.
- `zz-drop-core` adds `scriptable::Reason`,
  `output::json::{Uploaded, Downloaded, Failed, BatchSummary,
  Unlocked, Locked, Wiped, DoctorCheck, DoctorSummary}`, and
  the RFC 3339 helper `now_rfc3339`.
- `zz-drop` (root) adds `runtime` (global-flag pre-pass +
  env merge), `passphrase` (file reader), and the
  `output::emit_*` family that routes results by mode.
- `serde_json = "1"` added as a dev-dependency for the
  integration tests.
