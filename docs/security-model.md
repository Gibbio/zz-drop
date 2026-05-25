# zz-drop security model

This document describes the security posture of zz-drop. It is part of
the public, shared specification and applies to every implementation
(CLI, agent, TUI).

## Security goals

- `profile.zz` is encrypted client-side.
- The profile decrypt passphrase never leaves the device.
- Provider credentials are stored only inside encrypted `profile.zz` and
  in RAM when the local agent is unlocked.
- The local agent holds the decrypted profile only in RAM.
- Secrets (passphrases, provider credentials, tokens, decrypted profile
  data) are never written to logs.

## Non-goals (v1)

- No forensic local-deletion guarantee.
- No opaque encrypted filename mapping at the provider.
- No provider-side metadata hiding.
- No sync security model.
- No team / organization access model.

## User-memorized secret

zz-drop has exactly one user-memorized secret in v1: the **profile
decrypt passphrase** used locally to decrypt `profile.zz`. It never
leaves the device.

## Local agent

- One agent per user. Same binary as the CLI in a hidden internal mode.
- Unix domain socket, primary at `$XDG_RUNTIME_DIR/zz-drop/agent.sock`,
  fallback at `/tmp/zz-drop-$UID/agent.sock`. Directory permissions 0700.
- Token file with 0600 permissions, 32 random bytes.
- Per-connection peer UID credential check (`SO_PEERCRED` on Linux,
  `getpeereid()` / `LOCAL_PEERCRED` on macOS/BSD). The check is
  **mutual**: the agent authenticates the client, and the client
  authenticates the agent (it verifies the agent's peer UID equals its
  own EUID, and that the runtime dir is a non-symlink directory owned by
  the current UID with mode 0700, before sending the token or any
  `Unlock`). This protects against a different local user squatting the
  socket path in the world-writable `/tmp/zz-drop-$UID` runtime dir used
  on macOS and XDG-less Linux.
- Decrypted `PlainProfile` lives in RAM only.
- `zz q` clears RAM immediately.
- Automatic lock after `unlock_ttl_secs = 600` (10 minutes).
- Locked-idle exit after `agent_idle_exit_secs = 300` (5 minutes).

See `agent-protocol.md` for the wire protocol.

## `profile.zz` envelope

- JSON envelope, version 1.
- Argon2id KDF; parameters stored in the envelope (`memory_kib =
  194_560 ≈ 190 MiB, iterations = 3, parallelism = 1`).
- XChaCha20-Poly1305 AEAD with a fresh 24-byte random nonce per
  encrypt; salt is 16 random bytes per envelope.
- Salt, nonce and ciphertext are base64-encoded.
- Encrypted payload format: CBOR.
- KDF target: ~500 ms – 1 s on an average machine.
- No recovery if the container passphrase is lost.

**Envelope header authentication (accepted limitation).** The AEAD
authenticates the CBOR ciphertext but *not* the surrounding JSON header
(version, KDF parameters, salt, nonce, algorithm names). This is
accepted rather than bound as AAD: the algorithm and version names are
checked against the only supported constants **before** key derivation,
the KDF parameters are range-checked (see
[`profile-format.md`](profile-format.md#kdf-parameter-bounds)), and any
header tampering that survives those checks produces a wrong key and a
failing Poly1305 tag. There is therefore no algorithm-downgrade or
silent-acceptance path; binding the header as AAD would change the tag
computation and break the frozen v1 envelope format for no additional
practical guarantee.

The payload is a `ProfileSet` — a container that holds N inner
profiles (one inner profile per "alias", e.g. `casa-nc`,
`gdrive-bright`). The agent caches the 32-byte KEK derived by
Argon2id in zeroizing storage and re-encrypts the container with
a fresh nonce when an inner profile is appended or an OAuth token
gets refreshed: same KEK, fresh nonce per write — no nonce reuse
is possible by construction.

See `profile-format.md` for the envelope schema.

## TLS trust set

Outbound HTTPS connections (cloud providers, `zz-drop.net` API)
go through `rustls` configured with the **operating system trust
store** via `rustls-platform-verifier`:

- macOS — Security.framework
- Windows — SChannel
- Linux — the system CA bundle (`/etc/ssl/certs` and friends)

There is no embedded Mozilla CA bundle to fall back to and no
`--insecure` flag to bypass verification. An unverifiable
certificate is a hard failure.

`SSL_CERT_FILE` is honored as the standard OpenSSL escape valve:
when it points at a readable PEM, the certificates in that file
become the **only** trusted roots for the run. This covers
environments where a corporate CA is shipped as a `.pem` but
cannot be installed system-wide.

If `SSL_CERT_FILE` is **set but unusable** (unreadable, or it contains
no certificate), zz-drop **fails closed**: it trusts an empty root set
so every TLS handshake fails, rather than silently reverting to the
system trust store the operator was trying to override. Unset the
variable to use the OS trust store.

## Logging rules

The following must never appear in logs:

- profile decrypt passphrases
- decrypted profile data
- plaintext `profile.zz` payload
- provider credentials (URL, username, app password, OAuth token)
- session tokens
- `Authorization` headers

## Disclosure policy

To report a security issue, open a **private security advisory** on
the repository's "Security" tab. Do not file public issues, pull
requests, or discussion threads for security problems, and do not
disclose details on social media or chat platforms before the
maintainers have responded.

Each repository's `SECURITY.md` carries the same disclosure policy
and points back to this document for the full model.

## Hardening passes

A pre-alpha hardening pass against the project's internal
checklist (`cargo audit`, secret-logging grep, agent socket /
token review, container crypto review, wire-protocol Debug
redaction) ran on **2026-05-03**. Outcome: no critical or high
findings; two RustSec advisories on unmaintained transitive
dependencies (`atomic-polyfill 1.0.3` via `postcard`,
`paste 1.0.15` via `image → rav1e`) were reviewed and accepted
as known, neither carries a vulnerability. The headline lives in
each repo's `SECURITY.md`; the redaction guarantees on wire
types and provider auth structs are locked in by canary tests
under `tests/`.

## Honest non-claims

zz-drop deliberately does **not** promise:

- "zero IP logging" — TLS and TCP still happen on the wire, every
  reverse proxy and ISP sees IPs that initiate requests. The
  invariant we hold is: **no persistent application-level IP /
  user-agent logs are intentionally associated with profiles**.
  That is enforceable; "absolute zero IP" is not.
- forensic erasure of local data
- hiding filenames or directory structure from the cloud provider
- protection against another process running under the same user
  ID on the same machine

If any of these are dealbreakers, zz-drop is not the right tool.
