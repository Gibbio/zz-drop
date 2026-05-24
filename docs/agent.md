# zz-drop local agent

The `zz-drop` binary doubles as a per-user local agent: it holds the
decrypted profile in RAM with a TTL, so subsequent commands don't need
to ask for the passphrase again. Same binary, two roles.

## How it starts

`zz z` (unlock) is the entry point.

1. The CLI prompts for the profile passphrase (no echo, via `rpassword`).
2. It reads `profile.zz`, decrypts it locally, and constructs a
   `PlainProfile`.
3. If the agent socket is missing, the CLI spawns the same binary with
   the env var `ZZ_DROP_AGENT_MODE=1`. The child detaches with
   `setsid()` and listens.
4. The CLI connects, performs the token handshake, and sends `Unlock`.
5. The CLI exits; the agent stays.

The `ZZ_DROP_AGENT_MODE=1` mode is intentionally hidden: it is not in
the public command grammar and is not surfaced by `zz f`.

## Wire access

The agent listens on a per-user Unix domain socket:

- Linux: `$XDG_RUNTIME_DIR/zz-drop/agent.sock` (fallback `/tmp/zz-drop-$UID/agent.sock`)
- macOS: `/tmp/zz-drop-$UID/agent.sock`

Each connection must pass two checks:

1. **Peer UID check** — the server retrieves the connecting peer's UID
   via `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` sockopt (macOS) and
   refuses any UID different from the agent's own EUID.
2. **Token handshake** — the first frame the client sends is the raw
   32-byte token loaded from `<runtime>/token` (mode `0600`). The
   server compares with `subtle::ConstantTimeEq`. Mismatch → connection
   closed before any protocol message is processed.

After both pass, the protocol from

### Mutual checks: the client also authenticates the agent

The socket lives in the runtime dir, which on macOS (and on Linux when
`$XDG_RUNTIME_DIR` is unset) sits under the world-writable, sticky
`/tmp`. To stop a *different* local user from pre-creating that directory
and standing up a rogue agent that would receive an `Unlock` (and with it
the KEK and the whole decrypted profile), the **client** performs two
checks of its own before any secret leaves the process:

1. **Runtime-dir validation** — the directory holding the socket + token
   must be a real directory (not a symlink), owned by the current UID,
   with mode `0700` (no group/other bits). Enforced by
   `zz_drop_core::config::verify_private_dir`, called by both the agent
   (before `bind`) and every client (before `connect` sends anything).
2. **Server peer-UID check** — after `connect`, the client reads the
   *agent's* peer UID (`SO_PEERCRED` / `LOCAL_PEERCRED`) and aborts unless
   it equals the client's own EUID. A cross-UID attacker cannot run a
   process under the victim's UID, so a foreign agent can never receive
   the token or the `Unlock` payload.

The peer-UID check is therefore **mutual**: server authenticates client,
and client authenticates server.

The protocol from
[`agent-protocol.md`](./agent-protocol.md)
is used: postcard payload, 4-byte big-endian length prefix, 1 MiB frame
limit, version `1`.

## Lifecycle

State machine:

```
Locked  --(Unlock OK)-->  Unlocked
Unlocked --(GetProfile)-> Unlocked  (TTL renewed)
Unlocked --(TTL elapsed)-> Locked  (auto-lock)
Unlocked --(Lock)-->      Locked
Locked   --(idle 300s)--> exit (process terminates)
Any      --(Exit)-->      exit
```

- `unlock_ttl_secs = 600` — auto-lock after this many seconds without
  a `GetProfile` (or unlock).
- `agent_idle_exit_secs = 300` — once locked, exit if no client
  activity for this many seconds.

The reference values are pinned in
`zz_drop::agent::server::{DEFAULT_TTL_SECS, DEFAULT_IDLE_EXIT_SECS}`.

## CLI surface

- `zz z` — unlock; spawns the agent if needed.
- `zz q` — lock; no-op (and exit 0) if no agent is running.
- `zz w` — wipe; asks the user to type "wipe" to confirm. In a
  non-interactive shell, requires the env var `ZZ_DROP_CONFIRM_WIPE=yes`.
  Removes the container files, sidecars, the runtime directory
  (socket + token), and the config directory if empty.

The agent itself never opens stdout / stderr (they are redirected to
`/dev/null` at spawn). It writes nothing to disk except the socket and
the token file. There is no log file by default; a diagnostic log
(no secrets) is written under the cache dir only when the operator sets
`ZZ_DROP_DEBUG_LOG=1`. Diagnostic output for users is the
responsibility of `zz f`, not of the agent.

## Memory model

The decrypted `PlainProfile` lives only in the agent process's RAM,
behind a `Mutex`. The agent never persists the profile. The provider
credentials (Nextcloud app password, OAuth token) are only present in
the encrypted `profile.zz` and in the agent's RAM when unlocked.

Note: in this milestone the in-RAM `PlainProfile` is a plain Rust
struct. Its `String` fields are not zeroized in place when the agent
locks: locking drops them and process exit returns the pages to the
OS. A future task may replace the affected fields with explicit
`Zeroizing` wrappers.

## SACS endpoints — `LIST_REMOTE` and `INVALIDATE_REMOTE`

The agent additionally serves two endpoints that exist purely to
support the shell completion engine
([`docs/sacs.md`](sacs.md)). They are additive variants of the
v1 protocol — older clients that don't know about them keep
working unchanged.

- `ListRemote { prefix, kind_filter, max_results }` returns one
  remote directory listing for the active inner profile. The
  agent caches the response keyed by `(prefix, kind_filter)`
  with a 60-second TTL. A miss triggers one network call to the
  provider; a hit returns from RAM.
- `InvalidateRemote { prefix }` drops the cached entries for
  `prefix` and every parent up to the root, ignoring
  `kind_filter`. Called by the CLI after a successful upload so
  the next TAB reflects the new file.

Drop policy. Both caches (the list cache and the warm provider
client) are wiped on every transition that could change "what
the active provider is":

- `Lock` and TTL-driven auto-lock
- `UpdateProfile` whose alias matches the active inner profile
- `UpdateProfileSet` (always — the whole container changed)
- `SetActiveAlias` (a different inner profile is now active)

Provider errors are **not** cached. A transient 503 from the
provider is returned to the CLI and dropped on the floor by the
completion code; the next TAB tries again immediately instead
of being poisoned for 60 s.

The agent loop is single-threaded by design (one accept at a
time). A `LIST_REMOTE` cache miss therefore blocks any
concurrent agent traffic for the duration of the provider's
list call (50–500 ms depending on backend). Documented in
`docs/sacs.md` "Latency".

## Development: rebuild gotcha

The three crates (`zz-drop`, `zz-drop-tui`, `zz-drop-core`) live
in separate cargo workspaces. Rebuilding one does **not** rebuild
the others. After a change that touches the wire types in
`zz-drop-core`, both consumers (`zz-drop` and `zz-drop-tui`) must
be rebuilt or one will speak the old layout while the other
speaks the new one — with a long-lived agent process from the old
binary, the failure mode is opaque ("frame truncated", "wrong
passphrase or corrupted container") because the agent silently
mis-decodes incoming requests.

Use `scripts/dev-rebuild.sh` from the project root to:

1. kill any running `zz-drop` agent (so the next `zz z`
   respawns one from the freshly-built binary);
2. build all three crates in dependency order.

```sh
/Users/.../zz-project/zz-drop/scripts/dev-rebuild.sh
# add --profile dev to use debug builds for faster iteration
```

A regression test (`core/tests/agent_proto::variant_discriminants_are_stable`)
locks the postcard discriminant byte for every existing variant
of `AgentRequest` and `AgentResponse`. New variants must be
appended at the bottom — inserting one between existing variants
shifts every later index and breaks every older agent or client
on the wire.

## Exit codes (CLI)

| Code | Meaning |
|---|---|
| `0` | success |
| `2` | usage error |
| `3` | recognised command not implemented yet |
| `5` | agent unreachable (socket missing, refused, handshake failed) |
| `6` | profile not found |
| `7` | decryption failed (wrong passphrase or corrupted profile) |
| `8` | wipe cancelled |
