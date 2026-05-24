# Local CLI ↔ agent protocol

## Transport

Unix domain socket:

- primary: `$XDG_RUNTIME_DIR/zz-drop/agent.sock`
- fallback: `/tmp/zz-drop-$UID/agent.sock`

Token file:

- primary: `$XDG_RUNTIME_DIR/zz-drop/token`
- fallback: `/tmp/zz-drop-$UID/token`
- 32 random bytes
- 0600 permissions

Directory permissions: 0700. The socket and token/lock files are
created with mode `0600` in a single `open` (no write-then-chmod
window); the socket is additionally `chmod`ed to `0600` after `bind`.

## Security

Each connection must pass:

1. peer UID credential check
   - Linux: `SO_PEERCRED`
   - macOS/BSD: `getpeereid()` / `LOCAL_PEERCRED`
2. token check

The check is **mutual**. Before sending the token, the client validates
the runtime dir (real directory, owned by the current UID, mode `0700`)
and reads the *agent's* peer UID, refusing to proceed unless it equals
its own EUID. This prevents a rogue agent — squatting the socket path in
a world-writable runtime dir (`/tmp/zz-drop-$UID` on macOS / XDG-less
Linux) under a different UID — from ever receiving the token or an
`Unlock` payload. See `docs/agent.md` → "Mutual checks".

## Framing

```text
[4 bytes length big-endian][payload postcard/bincode]
```

Initial frame limit: 1 MiB.

Protocol version: `u16 = 1`.

## Operations v1

Core operations:

- `Ping`
- `Unlock { profile_set: ProfileSet, kek: KekPayload, active_alias: String, ttl_secs: Option<u64> }`
- `GetProfile`
- `UpdateProfile { profile: PlainProfile }`
- `UpdateProfileSet { profile_set: ProfileSet }`
- `SetActiveAlias { alias: String }`
- `Lock`
- `Exit`
- `Status`

Shell-completion operations (additive, used by SACS — see
`zz-drop/docs/sacs.md`):

- `ListRemote { prefix: Option<String>, kind_filter: EntryKindFilter, max_results: u32 }`
- `InvalidateRemote { prefix: Option<String> }`

Responses gain a matching `RemoteList { entries, cached_at_secs,
truncated }` variant; both new requests reuse the existing
`Updated` / `Error(_)` variants for negative/positive
acknowledgements.

## Forward compatibility

Variants are added strictly **at the end** of the request and
response enums. The protocol version stays `1`. A client built
against a newer wire schema sending a new variant to an older
agent receives `FramingError::Decode(_)` (postcard fails to
deserialise the unknown discriminant); an older client talking
to a newer agent sees only the variants it knows. There is no
"speak v2 if both ends know it" negotiation in v1 — protocol
bumps require a major version of the binary, not a runtime
feature flag.

## Behavior

- CLI does upload/download/list of bytes.
- Agent provides the decrypted active inner profile, manages RAM
  state, and serves the SACS list cache.
- `GetProfile` renews the unlock TTL.
- `Lock`, TTL auto-lock, `UpdateProfile{Set}`, and
  `SetActiveAlias` all drop the SACS list cache and warm
  provider client.
- `Exit` clears RAM and exits.
- `zz q` = immediate lock.
- automatic lock after `unlock_ttl_secs = 600`.
- locked idle exit after `agent_idle_exit_secs = 300`.

`ListRemote` cache TTL is 60 s. Provider errors are not cached.
The agent enforces a `max_results = 200` hard cap before the
response leaves the agent. `InvalidateRemote` walks the prefix
chain from the supplied leaf up to the root, dropping every
cached entry along the way regardless of `kind_filter`.

## Implementation notes (zz-drop-core reference)

The reference implementation lives in `core/src/agent_proto/`,
exposed via `zz_drop_core::agent_proto::*`.

Wire format:

```
[ 4 bytes len, big-endian ][ postcard-encoded VersionedRequest|VersionedResponse ]
```

`len` is a `u32` and counts the bytes that follow (the postcard
payload). `len > FRAME_LIMIT` (1 048 576 = 1 MiB) is rejected
**before** any allocation.

Versioning:

```rust
struct VersionedRequest  { version: u16, request:  AgentRequest }
struct VersionedResponse { version: u16, response: AgentResponse }
```

`version` is the first field inside the postcard payload. The
reference decoders refuse any frame whose decoded `version` is not
exactly `PROTOCOL_VERSION` (= `1`) and surface
`FramingError::UnsupportedVersion { got, expected }`.

API:

```rust
pub const FRAME_LIMIT: usize = 1 << 20;
pub const PROTOCOL_VERSION: u16 = 1;

pub fn encode_request(req:  &AgentRequest)  -> Result<Vec<u8>, FramingError>;
pub fn encode_response(resp: &AgentResponse) -> Result<Vec<u8>, FramingError>;
pub fn decode_request(frame: &[u8]) -> Result<AgentRequest,  FramingError>;
pub fn decode_response(frame: &[u8]) -> Result<AgentResponse, FramingError>;

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), FramingError>;
pub fn read_frame <R: Read >(r: &mut R)                 -> Result<Vec<u8>, FramingError>;
```

`encode_*` / `decode_*` deal with the complete length-prefixed
frame. `write_frame` / `read_frame` are byte-level building blocks
for the agent server (TASK 07): they prepend / parse the 4-byte
length header on a `Read`/`Write` and never allocate beyond the
limit.

`FramingError` variants:

- `FrameTooLarge { size, limit }` — payload exceeds 1 MiB
- `Io(String)` — underlying transport error (other than EOF)
- `Encode(String)` — postcard serialization failure
- `Decode(String)` — postcard deserialization failure
- `UnsupportedVersion { got, expected }` — protocol mismatch
- `Truncated` — stream ended mid-frame, or input slice too short

`FramingError` is **not** serializable: it is a transport-level error
held locally. The protocol-level error model that travels on the wire
is `AgentError`, embedded in `AgentResponse::Error(_)`.

Underlying crates: `postcard = "1"` (binary serializer, schema-stable,
no `#[serde(tag = …)]` is used on protocol enums because postcard
does not support internally-tagged representations).
