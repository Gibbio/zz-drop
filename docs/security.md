# Security

This page describes what `zz-drop` does to protect your data, what it
**does not** try to protect against, and how to report a vulnerability.
The wording is deliberately conservative: we describe the design,
not absolutes.

## Threat model in one sentence

The cloud provider (Nextcloud over WebDAV, Google Drive over OAuth
device flow, OneDrive over OAuth device flow, Dropbox over OAuth
paste-code + PKCE, others as they land) **must not** be able to
read the decrypted container, the container passphrase, or the
per-provider credentials inside. The local user's account on their
own machine is trusted: zz-drop does not defend against another
process running under your UID.

## What zz-drop does locally

- The `profiles-local.zz` container is encrypted with **Argon2id-
  derived KEK + XChaCha20-Poly1305 AEAD**. Salt is 16 random bytes
  per envelope; the AEAD nonce is 24 random bytes per encrypt —
  re-encrypting the container after appending an inner profile or
  refreshing an OAuth token always uses a fresh nonce.
- **KDF rotation**: when zz-drop raises the Argon2id baseline in a
  future release, your container is **auto-upgraded** on the next
  unlock — one extra Argon2id derive that one time, then back to
  normal. Stronger-than-baseline containers are never downgraded.
  Rotation never asks you anything and never fails the unlock; if
  the write step fails it just retries next time. See
  [profile-format.md → KDF rotation](profile-format.md#kdf-rotation).
- The KEK is held by the agent in `Zeroizing<[u8; 32]>` and zeroed
  on lock / TTL expiry / process exit.
- The decrypted container lives only in the **local agent's RAM**,
  behind a `Mutex`, with a TTL of 10 minutes (auto-lock) and an
  idle-exit of 5 minutes (process terminates).
- The agent uses a **per-user Unix domain socket** with peer-UID
  check **before** the token frame (`SO_PEERCRED` on Linux,
  `LOCAL_PEERCRED` on macOS) and a 32-byte token in a `0600` file,
  compared with `subtle::ConstantTimeEq`.
- `config.toml` is plain TOML and **never** contains secrets.
- There is **no log file by default**. The agent never opens
  stdout/stderr. A diagnostic log containing **no secrets** (paths,
  lengths, KDF params, FNV fingerprints, request discriminants) is
  written under the cache dir only when you opt in with
  `ZZ_DROP_DEBUG_LOG=1`.

## What the daily commands write to disk

| Command | What it writes |
|---|---|
| `zz <file>` | the file goes to the cloud provider, no local copy |
| `zz d <file>` | the file is downloaded to the current directory |
| `zz z` | the agent socket and a 32-byte token (`0600`); writes the cached "default alias" sidecar (`last-default-local`) when picked |
| `zz q` | nothing |
| `zz w` | nothing — only deletes (`profiles-local.zz`, the sidecars, `config.toml`, the runtime dir) |

No telemetry, no analytics, no usage pings.

## Honest non-goals

zz-drop does **not** try to:

- hide the **filenames** or directory structure from your cloud
  provider (`zz s readme.md` puts a file called `readme.md` in the
  configured remote folder; the provider sees that)
- hide your **traffic timing or volume** from the cloud provider or
  any network observer
- defend against **another process running under your UID** —
  including a malicious shell extension, a hostile language server,
  or a copy of zz-drop running with the same agent socket
- forensically erase data from your disk or your cloud account
- guarantee **"zero IP capture"** — the cloud provider and your
  ISP both see the IP that initiated each request. TLS and TCP
  still happen on the wire.

If any of these are dealbreakers for your threat model, zz-drop is
not the right tool.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security bugs.

Use **GitHub Security Advisories** on this repository's "Security"
tab to file a private report. We acknowledge within 7 days and aim
to publish a fix or workaround within 30 days for high-severity
issues. We will credit you in the release notes unless you ask
otherwise.

For non-vulnerability questions about the security model, regular
GitHub issues are fine.

## Cross-references

- [`docs/agent.md`](agent.md) — local agent details, lifecycle,
  socket auth.
- [`docs/commands.md`](commands.md) — full command grammar +
  exit codes.
- [`./profile-format.md`](./profile-format.md)
  — `profile.zz` envelope spec.
- [`./security-model.md`](./security-model.md)
  — project-wide security model.
