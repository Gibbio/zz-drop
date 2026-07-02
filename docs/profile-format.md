# `profiles-local.zz` format

## File name

- `profiles-local.zz` — encrypted container kept only on this machine

A single file holds **N** inner profiles; daily commands operate on
the inner profile last selected by `zz z`.

The legacy single-profile shape (`profile.zz`) is recognised on read
for the sole purpose of refusing it with `LegacyFormat`. There is no
auto-migration.

## Envelope v1

JSON envelope with base64 salt/nonce/ciphertext. Same shape as before;
only the encrypted payload changed (was `PlainProfile` v1, now
`ProfileSet` v2).

```json
{
  "version": 1,
  "kdf": {
    "name": "argon2id",
    "memory_kib": 194560,
    "iterations": 3,
    "parallelism": 1,
    "salt": "base64..."
  },
  "cipher": {
    "name": "xchacha20poly1305",
    "nonce": "base64..."
  },
  "payload": {
    "format": "cbor",
    "ciphertext": "base64..."
  }
}
```

## Plain payload — `ProfileSet` schema v2

```cbor
{
  "schema_version": 2,
  "profiles": [ <PlainProfile>, <PlainProfile>, … ]
}
```

Each `PlainProfile` carries:

- `profile_version`
- `profile_id`
- `alias` — operator-chosen mnemonic, used both as the human label in
  the picker and as the persistence key in the `last-default-local`
  sidecar
- `default_target`
- one provider config (Nextcloud / Google Drive / OneDrive /
  Dropbox — or a preserved foreign entry, see "Forward
  compatibility" below)
- auth secret(s)
- collision policy
- agent settings
- created/updated timestamps

The `ProfileSet` does **not** carry a `default_alias` field. The
"last selected" alias lives only in the plaintext sidecar file
`last-default-local` (one line `<alias>\n`); the in-memory agent
caches it between operations within a session.

### Sidecar size + charset rules

- max 256 bytes
- chmod 0600
- alias: printable ASCII, no NUL, no `/`, no `..`, length 1–64
- any failure mode (missing, oversized, malformed) silently falls
  back to the interactive picker

### Capacity

- Local container: no count limit.

### Forward compatibility — unknown providers

Introduced 2026-07-02 on the 0.9.x track (post-0.9.7). The container
decode tolerates provider entries written by a newer zz-drop:

- An entry whose serde tag is not one this binary knows
  (`nextcloud`, `google_drive`, `one_drive`, `dropbox`) decodes as
  an internal carrier (`ProviderProfile::Unknown { tag,
  payload_cbor }`) instead of failing the whole container. Every
  other alias stays fully usable; operations on the foreign alias
  fail with a clear "upgrade zz-drop" diagnostic, and `zz doctor`
  labels it.
- On re-encrypt (agent token refresh, TUI add-inner) the carrier is
  written back under its **original tag with a semantically
  identical payload** (the CBOR is re-encoded, so non-canonical
  encodings are normalised): a downgrade-then-upgrade cycle does not
  lose the foreign alias.
- Tolerance covers map-shaped entries (serde struct/newtype
  variants — the shape every current provider uses). A future
  dataless unit-variant provider would not be protected.
- The tag `unknown` is **reserved forever** for the carrier; no real
  provider may ever use it.
- Bytes on disk for known providers are unchanged and there is no
  `schema_version` bump. Binaries older than this change still fail
  the whole container ("payload decode failed") when a foreign
  entry is present — tolerance protects forward from the release
  that ships it.
- A known tag with a corrupt payload still fails the decode loudly;
  tolerance never masks corruption.

Implementation: shield/restore at the CBOR boundary in
`core/src/profile/format.rs`. The agent protocol's postcard encoding
of the same types is deliberately untouched (postcard is not
self-describing); the carrier rides it as a regular enum variant.

## Crypto

- Argon2id target: ~500 ms–1 s on average machine.
- XChaCha20-Poly1305 AEAD.
- KDF parameters stored in envelope.
- No recovery if profile decrypt passphrase is lost.

### KDF parameter bounds

The KDF parameters live in the cleartext envelope header (outside the
AEAD), so on a supplied or server-served container they are
attacker-controlled. Before deriving a key, zz-drop rejects parameters
outside a sane band so a hostile header cannot trigger a multi-GB
allocation (OOM) or a runaway iteration count (CPU time-bomb):

- `memory_kib` ≤ 2 GiB (`Argon2idConfig::MAX_MEMORY_KIB`)
- `iterations` ∈ `[1, 16]`
- `parallelism` ∈ `[1, 8]`

There is intentionally **no lower bound on `memory_kib`**: a legitimately
weak older container must still decrypt so KDF rotation can upgrade it.
Out-of-band parameters fail fast with `ProfileCryptoError::Kdf`,
independent of the passphrase (no decrypt oracle).

## KDF rotation

The envelope stores the Argon2id parameters that were used to
derive the key. When a future zz-drop release raises the policy
baseline (`POLICY_V1` in `core/src/profile/policy.rs`), every
container created under the old, weaker parameters is
auto-upgraded on the next successful unlock:

1. The CLI decrypts with the envelope's stored params (one
   Argon2id derive).
2. If any stored param is below `POLICY_V1`, it re-derives with
   the policy params and a fresh salt, re-encrypts the
   container, and atomically replaces the on-disk file
   (`<path>.tmp` + `rename`).
3. The post-rotation `ProfileKek` is what the agent receives —
   subsequent inner mutations (`encrypt_set_with_kek`) write the
   new params back to disk.
4. Failures are non-fatal: the unlock already succeeded, so the
   operator continues with the old KEK and rotation retries on
   the next unlock.

For v1.0.0 the policy equals `Argon2idConfig::DEFAULT`, so no
container will rotate at first release. The mechanism exists so a
future v1.x can bump the floor without leaving v1.0 profiles
stuck on weaker parameters.

Stronger-than-policy containers are never downgraded.

## Profile passphrase

- minimum technical length: 1 character
- recommended: 12+ characters
- weak passphrase allowed only after strong warning

## Implementation notes (zz-drop-core reference)

The reference implementation lives in this crate, exposed as:

```rust
// Container API (current).
pub fn encrypt_set(set: &ProfileSet, passphrase: &str)
    -> Result<(String, ProfileKek), ProfileCryptoError>;

pub fn encrypt_set_with_config(
    set: &ProfileSet, passphrase: &str, config: &Argon2idConfig)
    -> Result<(String, ProfileKek), ProfileCryptoError>;

/// Re-encrypt without running Argon2id again. The agent uses this
/// when the in-RAM container mutates (inner-profile add, OAuth
/// refresh) so the operator does not re-prompt the passphrase.
pub fn encrypt_set_with_kek(set: &ProfileSet, kek: &ProfileKek)
    -> Result<String, ProfileCryptoError>;

pub fn decrypt_set(envelope: &str, passphrase: &str)
    -> Result<(ProfileSet, ProfileKek), ProfileCryptoError>;

// Single-profile API (legacy, used only to recognise legacy blobs
// and report `LegacyFormat`).
pub fn encrypt_profile(profile: &PlainProfile, passphrase: &str)
    -> Result<String, ProfileCryptoError>;
pub fn decrypt_profile(profile_zz: &str, passphrase: &str)
    -> Result<PlainProfile, ProfileCryptoError>;
```

`ProfileKek` carries the derived key, salt and Argon2id parameters
used to derive it. The agent persists it in `Zeroizing` storage for
the duration of the unlocked session and uses it to re-encrypt the
container after any inner mutation.

Default Argon2id parameters (`Argon2idConfig::DEFAULT`):

- `memory_kib = 194_560` (≈ 190 MiB)
- `iterations = 3`
- `parallelism = 1`
- output key length: 32 bytes

Field sizes:

- salt: 16 bytes
- nonce: 24 bytes (XChaCha20)
- key: 32 bytes (zeroized on drop in the reference implementation)

Decrypt failure does **not** distinguish between MAC failure, wrong
passphrase, corrupted ciphertext or wrong nonce: every such case
returns the same error variant. This is deliberate — distinguishing
them would enable decrypt oracle attacks against the envelope.

Error variants visible to callers (`ProfileCryptoError`):
`UnsupportedVersion`, `UnsupportedKdf`, `UnsupportedCipher`,
`UnsupportedPayloadFormat`, `InvalidEnvelope`, `Base64Decode`,
`Kdf`, `Aead`, `PayloadDecode`, `PayloadEncode`, `InvalidLength`,
`Io`, `LegacyFormat`. None of these include the passphrase in their
`Display` or `Debug` output. `LegacyFormat` is surfaced when an
envelope decrypts to a single `PlainProfile` instead of a
`ProfileSet` v2 — the operator runs `zz w` and sets up again.

Underlying crates (RustCrypto where applicable):
`argon2 = "0.5"`, `chacha20poly1305 = "0.10"` (XChaCha20Poly1305),
`ciborium = "0.2"` for CBOR, `base64 = "0.22"`, `rand_core = "0.6"`
(`OsRng` for salt and nonce), `zeroize = "1"`.
