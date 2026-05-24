# Security policy — zz-drop

## Reporting a vulnerability

Please use **GitHub Security Advisories** (the "Security" tab of
this repository) to file a private vulnerability report. Do not
open public issues, pull requests, or discussion threads for
security problems, and please don't disclose details on social
media or chat platforms before the maintainers have responded.

Acknowledgement target: **7 days**. Fix-or-workaround target for
high-severity issues: **30 days**. Reporters are credited in the
release notes unless they ask otherwise.

For non-vulnerability questions about the security model, regular
GitHub issues are fine.

## What this repository ships

`zz-drop` is the **CLI binary + local agent** in the same
executable. It does not run an HTTP server. v1 connects only to
the configured cloud provider (Nextcloud via WebDAV, Google Drive
via OAuth 2.0 device flow).

This repository's contribution to the project's security posture:

- Argon2id-derived KEK + XChaCha20-Poly1305 AEAD for the
  `profiles-local.zz` container (the encryption pipeline lives
  in `zz-drop-core`).
- KEK held by the agent in `Zeroizing<[u8; 32]>`; re-encrypts the
  container with a fresh nonce on every write (inner-profile
  append, OAuth token refresh) so KEK + nonce reuse is impossible
  by construction.
- per-user Unix domain socket with peer-UID check **before** the
  token frame (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS)
  + 32-byte token in a `0600` file, compared with
  `subtle::ConstantTimeEq`.
- 10-minute TTL auto-lock + 5-minute locked-idle exit.
- no log file by default; the agent never opens stdout/stderr. An
  opt-in diagnostic log (no secrets — paths/lengths/FNV fingerprints
  only) is written under the cache dir only when `ZZ_DROP_DEBUG_LOG=1`
  is set.
- no telemetry, no analytics, no usage pings.
- HTTPS to providers and to `zz-drop.net` uses **rustls with the
  operating system trust store** (Security.framework on macOS,
  SChannel on Windows, the system CA bundle on Linux). Any
  certificate the OS already trusts — including a CA your
  administrator installed for a corporate TLS-inspection proxy —
  is honored. There is no `--insecure` flag. To pin a specific
  bundle of roots and ignore everything else, set
  `SSL_CERT_FILE=/path/to/roots.pem` before invoking zz-drop;
  only the PEM certificates in that file will be trusted for the
  duration of the run. If that variable is set but the file cannot
  be read or contains no certificate, zz-drop **fails closed** (it
  trusts nothing and every connection fails) rather than falling
  back to the OS trust store.

## What you should know before deploying

- **The user account on the local machine is trusted.** zz-drop
  does not defend against another process running under your UID.
- **`config.toml` never contains secrets.** Provider credentials
  live encrypted inside `profiles-local.zz`. Session tokens live
  in the agent's RAM only.
- **No recovery if the container passphrase is lost.** Pick a
  passphrase you can remember; the only way back from a lost one
  is `zz w` and a fresh setup.

## Scriptable mode and the passphrase file

`zz z --passphrase-file <path>` (or the matching
`ZZ_PASSPHRASE_FILE` env var) is the only supported way to feed
the profile passphrase to a script. The reader applies these
checks on every invocation; any one of them refuses the file:

- the path must resolve to a **regular file** — symlinks,
  directories, FIFOs, sockets and devices are rejected without
  following them
- the file owner must equal the current process UID — a file
  owned by root or any other user is refused even when the
  current process has read permission
- file mode must be `≤ 0600` (group and others bits must be 0);
  `0400` is also accepted
- file size capped at 4 KiB
- content must be valid UTF-8 with no embedded NUL byte; exactly
  one trailing `\n` is stripped, anything else (leading spaces,
  embedded newlines) is preserved verbatim

Permission / ownership failures exit with code `11` and emit
`failed reason=passphrase_file_permissions` in `--json` mode.
Other failures (missing file, too large, NUL inside) exit `2`.

What is **explicitly not supported**, by design:

- `ZZ_PASSPHRASE=<value>` — env values leak via
  `/proc/<pid>/environ`, `ps eww`, container debug snapshots
- `--passphrase-stdin` — deferred; revisit only if a real
  vault-piped flow surfaces

In scriptable mode (`--json` / `--quiet`) zz-drop **never** auto-
unlocks. A daily command against a locked agent fails with
`reason=agent_locked` (exit `10`) — the script must call
`zz z --passphrase-file <path>` explicitly first.

## Pre-alpha hardening pass

A v1 hardening pass against the project's internal checklist
(`cargo audit`, secret-logging grep, agent socket / token review,
container crypto review, wire-protocol Debug redaction) ran on
**2026-05-03**. Outcome: no critical or high findings; two
RustSec advisories on unmaintained transitive dependencies
(`atomic-polyfill 1.0.3` via `postcard`, `paste 1.0.15` via
`image → rav1e`) were reviewed and accepted as known.

Reproduce locally with:

```sh
cargo audit
```

## Cross-references

- [`docs/security.md`](docs/security.md) — what the server sees /
  does not see, honest non-goals, threat model
- [`docs/agent.md`](docs/agent.md) — local agent details: lifecycle,
  socket auth, memory model
- [`SECURITY.md`](SECURITY.md) —
  project-wide security policy
- [`docs/security-model.md`](docs/security-model.md)
  — canonical security model document
