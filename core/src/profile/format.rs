use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::aead::{NONCE_LEN, SALT_LEN, aead_decrypt, aead_encrypt};
use crate::crypto::kdf::{Argon2idConfig, derive_key};
use crate::crypto::profile_envelope::{
    CIPHER_NAME_XCHACHA20POLY1305, CipherParams, ENVELOPE_VERSION_V1, KDF_NAME_ARGON2ID,
    KdfParams, PAYLOAD_FORMAT_CBOR, PayloadParams, ProfileEnvelope,
};
use crate::profile::set::{PROFILE_SET_SCHEMA_V2, ProfileKek, ProfileSet};
use crate::profile::types::PlainProfile;
use crate::providers::{
    KNOWN_PROVIDER_TAGS, ProviderProfile, UNKNOWN_PROVIDER_TAG, UnknownProvider,
};
use ciborium::value::Value;

#[derive(Debug, Error)]
pub enum ProfileCryptoError {
    #[error("unsupported envelope version (got {got}, expected {expected})")]
    UnsupportedVersion { got: u32, expected: u32 },

    #[error("unsupported KDF: {name}")]
    UnsupportedKdf { name: String },

    #[error("unsupported cipher: {name}")]
    UnsupportedCipher { name: String },

    #[error("unsupported payload format: {name}")]
    UnsupportedPayloadFormat { name: String },

    #[error("invalid envelope")]
    InvalidEnvelope,

    #[error("base64 decode failed")]
    Base64Decode,

    #[error("invalid kdf parameters: {0}")]
    Kdf(String),

    #[error("decryption failed")]
    Aead,

    #[error("payload decode failed")]
    PayloadDecode,

    #[error("payload encode failed")]
    PayloadEncode,

    #[error("invalid envelope field length")]
    InvalidLength,

    #[error("io error")]
    Io,

    /// The envelope decrypted to a single legacy `PlainProfile` rather
    /// than a `ProfileSet`. zz-drop is dev-only — there is no
    /// auto-migration path; the operator is expected to `zz w` and
    /// re-set up.
    #[error("legacy single-profile format detected (no migration in v1)")]
    LegacyFormat,
}

pub fn encrypt_profile(
    profile: &PlainProfile,
    passphrase: &str,
) -> Result<String, ProfileCryptoError> {
    encrypt_profile_with_config(profile, passphrase, &Argon2idConfig::DEFAULT)
}

pub fn encrypt_profile_with_config(
    profile: &PlainProfile,
    passphrase: &str,
    config: &Argon2idConfig,
) -> Result<String, ProfileCryptoError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt, config)?;

    let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(512));
    {
        let writer: &mut Vec<u8> = &mut plaintext;
        ciborium::into_writer(profile, writer)
            .map_err(|_| ProfileCryptoError::PayloadEncode)?;
    }

    let ciphertext = aead_encrypt(&key, &nonce, &plaintext)?;

    let envelope = ProfileEnvelope {
        version: ENVELOPE_VERSION_V1,
        kdf: KdfParams {
            name: KDF_NAME_ARGON2ID.into(),
            memory_kib: config.memory_kib,
            iterations: config.iterations,
            parallelism: config.parallelism,
            salt: B64.encode(salt),
        },
        cipher: CipherParams {
            name: CIPHER_NAME_XCHACHA20POLY1305.into(),
            nonce: B64.encode(nonce),
        },
        payload: PayloadParams {
            format: PAYLOAD_FORMAT_CBOR.into(),
            ciphertext: B64.encode(&ciphertext),
        },
    };

    serde_json::to_string(&envelope).map_err(|_| ProfileCryptoError::InvalidEnvelope)
}

pub fn decrypt_profile(
    profile_zz: &str,
    passphrase: &str,
) -> Result<PlainProfile, ProfileCryptoError> {
    let envelope: ProfileEnvelope =
        serde_json::from_str(profile_zz).map_err(|_| ProfileCryptoError::InvalidEnvelope)?;

    if envelope.version != ENVELOPE_VERSION_V1 {
        return Err(ProfileCryptoError::UnsupportedVersion {
            got: envelope.version,
            expected: ENVELOPE_VERSION_V1,
        });
    }

    if envelope.kdf.name != KDF_NAME_ARGON2ID {
        return Err(ProfileCryptoError::UnsupportedKdf {
            name: envelope.kdf.name,
        });
    }
    if envelope.cipher.name != CIPHER_NAME_XCHACHA20POLY1305 {
        return Err(ProfileCryptoError::UnsupportedCipher {
            name: envelope.cipher.name,
        });
    }
    if envelope.payload.format != PAYLOAD_FORMAT_CBOR {
        return Err(ProfileCryptoError::UnsupportedPayloadFormat {
            name: envelope.payload.format,
        });
    }

    let salt = B64
        .decode(&envelope.kdf.salt)
        .map_err(|_| ProfileCryptoError::Base64Decode)?;
    let nonce_bytes = B64
        .decode(&envelope.cipher.nonce)
        .map_err(|_| ProfileCryptoError::Base64Decode)?;
    let ciphertext = B64
        .decode(&envelope.payload.ciphertext)
        .map_err(|_| ProfileCryptoError::Base64Decode)?;

    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ProfileCryptoError::InvalidLength)?;

    let config = Argon2idConfig {
        memory_kib: envelope.kdf.memory_kib,
        iterations: envelope.kdf.iterations,
        parallelism: envelope.kdf.parallelism,
    };

    let key = derive_key(passphrase, &salt, &config)?;

    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(aead_decrypt(&key, &nonce, &ciphertext)?);

    let profile: PlainProfile = ciborium::from_reader(plaintext.as_slice())
        .map_err(|_| ProfileCryptoError::PayloadDecode)?;

    Ok(profile)
}

/// Encrypt `profile` with `passphrase` and write the JSON envelope to
/// `path`. Creates parent directories if missing. Sets file mode `0600`
/// on Unix.
pub fn save_profile_zz(
    profile: &PlainProfile,
    passphrase: &str,
    path: &Path,
) -> Result<(), ProfileCryptoError> {
    save_profile_zz_with_config(profile, passphrase, path, &Argon2idConfig::DEFAULT)
}

/// Same as [`save_profile_zz`] but with a custom KDF config (used in
/// tests to keep the suite fast).
pub fn save_profile_zz_with_config(
    profile: &PlainProfile,
    passphrase: &str,
    path: &Path,
    config: &Argon2idConfig,
) -> Result<(), ProfileCryptoError> {
    let envelope = encrypt_profile_with_config(profile, passphrase, config)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| ProfileCryptoError::Io)?;
    }
    write_private(path, envelope.as_bytes())
}

/// Read `profile.zz` from disk and decrypt it with `passphrase`.
pub fn load_profile_zz(path: &Path, passphrase: &str) -> Result<PlainProfile, ProfileCryptoError> {
    let envelope = std::fs::read_to_string(path).map_err(|_| ProfileCryptoError::Io)?;
    decrypt_profile(&envelope, passphrase)
}

// ── Container (`ProfileSet`) functions ────────────────────────────

/// Encrypt a `ProfileSet` with `passphrase`. Returns the JSON
/// envelope and the `ProfileKek` derived from the passphrase: callers
/// (the agent) keep the KEK in RAM to re-encrypt on subsequent inner
/// mutations without re-prompting.
pub fn encrypt_set(
    set: &ProfileSet,
    passphrase: &str,
) -> Result<(String, ProfileKek), ProfileCryptoError> {
    encrypt_set_with_config(set, passphrase, &Argon2idConfig::DEFAULT)
}

pub fn encrypt_set_with_config(
    set: &ProfileSet,
    passphrase: &str,
    config: &Argon2idConfig,
) -> Result<(String, ProfileKek), ProfileCryptoError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(passphrase, &salt, config)?;
    let kek = ProfileKek::new(key, salt, config.clone());

    let envelope = encrypt_set_with_kek(set, &kek)?;
    Ok((envelope, kek))
}

/// Re-encrypt without running Argon2id again. Used by the agent when
/// the in-RAM `ProfileSet` mutates (inner-profile add, OAuth token
/// refresh, cached folder id) — the KEK and salt are reused, only the
/// nonce is fresh.
pub fn encrypt_set_with_kek(
    set: &ProfileSet,
    kek: &ProfileKek,
) -> Result<String, ProfileCryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(1024));
    {
        let writer: &mut Vec<u8> = &mut plaintext;
        if set_holds_unknown_provider(set) {
            // Route through a raw CBOR value so `Unknown` carriers are
            // written back under their original serde tag with their
            // original payload — a container that came from a newer
            // zz-drop re-encrypts without losing the foreign entry.
            // The intermediate value tree is transient plain heap (not
            // zeroized); it exists only on this fallback path.
            let mut value = value_from(set)?;
            restore_unknown_providers(&mut value)?;
            ciborium::into_writer(&value, writer)
                .map_err(|_| ProfileCryptoError::PayloadEncode)?;
        } else {
            ciborium::into_writer(set, writer)
                .map_err(|_| ProfileCryptoError::PayloadEncode)?;
        }
    }

    let ciphertext = aead_encrypt(&kek.key, &nonce, &plaintext)?;

    let envelope = ProfileEnvelope {
        version: ENVELOPE_VERSION_V1,
        kdf: KdfParams {
            name: KDF_NAME_ARGON2ID.into(),
            memory_kib: kek.kdf_config.memory_kib,
            iterations: kek.kdf_config.iterations,
            parallelism: kek.kdf_config.parallelism,
            salt: B64.encode(kek.salt),
        },
        cipher: CipherParams {
            name: CIPHER_NAME_XCHACHA20POLY1305.into(),
            nonce: B64.encode(nonce),
        },
        payload: PayloadParams {
            format: PAYLOAD_FORMAT_CBOR.into(),
            ciphertext: B64.encode(&ciphertext),
        },
    };

    serde_json::to_string(&envelope).map_err(|_| ProfileCryptoError::InvalidEnvelope)
}

/// Decrypt a container envelope. Returns the decoded `ProfileSet`
/// and the `ProfileKek` so the caller can hand it off to the agent
/// without a second Argon2id round.
///
/// If the envelope decrypts but the payload turns out to be a
/// legacy single `PlainProfile`, returns
/// [`ProfileCryptoError::LegacyFormat`]. There is no auto-migration
/// path in dev-only v1.
pub fn decrypt_set(
    envelope: &str,
    passphrase: &str,
) -> Result<(ProfileSet, ProfileKek), ProfileCryptoError> {
    let parsed: ProfileEnvelope =
        serde_json::from_str(envelope).map_err(|_| ProfileCryptoError::InvalidEnvelope)?;

    if parsed.version != ENVELOPE_VERSION_V1 {
        return Err(ProfileCryptoError::UnsupportedVersion {
            got: parsed.version,
            expected: ENVELOPE_VERSION_V1,
        });
    }
    if parsed.kdf.name != KDF_NAME_ARGON2ID {
        return Err(ProfileCryptoError::UnsupportedKdf {
            name: parsed.kdf.name,
        });
    }
    if parsed.cipher.name != CIPHER_NAME_XCHACHA20POLY1305 {
        return Err(ProfileCryptoError::UnsupportedCipher {
            name: parsed.cipher.name,
        });
    }
    if parsed.payload.format != PAYLOAD_FORMAT_CBOR {
        return Err(ProfileCryptoError::UnsupportedPayloadFormat {
            name: parsed.payload.format,
        });
    }

    let salt_bytes = B64
        .decode(&parsed.kdf.salt)
        .map_err(|_| ProfileCryptoError::Base64Decode)?;
    let salt: [u8; SALT_LEN] = salt_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ProfileCryptoError::InvalidLength)?;
    let nonce_bytes = B64
        .decode(&parsed.cipher.nonce)
        .map_err(|_| ProfileCryptoError::Base64Decode)?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ProfileCryptoError::InvalidLength)?;
    let ciphertext = B64
        .decode(&parsed.payload.ciphertext)
        .map_err(|_| ProfileCryptoError::Base64Decode)?;

    let config = Argon2idConfig {
        memory_kib: parsed.kdf.memory_kib,
        iterations: parsed.kdf.iterations,
        parallelism: parsed.kdf.parallelism,
    };

    let key = derive_key(passphrase, &salt, &config)?;
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(aead_decrypt(&key, &nonce, &ciphertext)?);

    // Try to decode as ProfileSet (v2 schema). Schema v1 was an
    // implicit single PlainProfile; if that's what we get, surface it
    // as LegacyFormat rather than silently mapping.
    if let Ok(set) = ciborium::from_reader::<ProfileSet, _>(plaintext.as_slice()) {
        if set.schema_version >= PROFILE_SET_SCHEMA_V2 {
            let kek = ProfileKek::new(key, salt, config);
            return Ok((set, kek));
        }
    }
    // The typed decode fails on provider entries written by a newer
    // zz-drop (unknown serde tags). Retry through a raw CBOR value,
    // shielding foreign entries as `ProviderProfile::Unknown` so the
    // rest of the container stays usable. Known-tag entries are left
    // untouched: a corrupt known provider must still fail loudly
    // below. The value tree is transient plain heap (not zeroized);
    // it exists only on this fallback path.
    if let Ok(mut value) = ciborium::from_reader::<Value, _>(plaintext.as_slice())
        && shield_unknown_providers(&mut value).is_ok()
        && let Ok(set) = value_to::<ProfileSet>(&value)
        && set.schema_version >= PROFILE_SET_SCHEMA_V2
    {
        let kek = ProfileKek::new(key, salt, config);
        return Ok((set, kek));
    }
    if ciborium::from_reader::<PlainProfile, _>(plaintext.as_slice()).is_ok() {
        return Err(ProfileCryptoError::LegacyFormat);
    }
    Err(ProfileCryptoError::PayloadDecode)
}

// ── Unknown-provider tolerance ────────────────────────────────────
//
// `ProviderProfile` is an externally tagged serde enum. Its derived
// impls must not change: the agent protocol encodes the same types
// with postcard, which is not self-describing and relies on the
// derived variant encoding. Tolerance therefore lives entirely at
// this CBOR boundary: on decode, entries under a tag this binary
// does not know are rewritten into the reserved `unknown` carrier
// form before the typed decode; on encode, carriers are rewritten
// back to their original tag + payload. Bytes on disk for known
// providers are identical to what the derived impls produce.

fn set_holds_unknown_provider(set: &ProfileSet) -> bool {
    set.profiles
        .iter()
        .any(|p| p.providers.iter().any(|pr| matches!(pr, ProviderProfile::Unknown(_))))
}

fn value_from<T: serde::Serialize>(t: &T) -> Result<Value, ProfileCryptoError> {
    let mut buf = Vec::new();
    ciborium::into_writer(t, &mut buf).map_err(|_| ProfileCryptoError::PayloadEncode)?;
    ciborium::from_reader(buf.as_slice()).map_err(|_| ProfileCryptoError::PayloadEncode)
}

fn value_to<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, ProfileCryptoError> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).map_err(|_| ProfileCryptoError::PayloadDecode)?;
    ciborium::from_reader(buf.as_slice()).map_err(|_| ProfileCryptoError::PayloadDecode)
}

/// Walks `root` as a `ProfileSet` value and applies `rewrite` to each
/// entry of each profile's `providers` array. Unexpected shapes are
/// skipped, not errors: the typed decode after the walk is the
/// authority on validity.
fn for_each_provider_entry(
    root: &mut Value,
    rewrite: &mut dyn FnMut(&mut Value) -> Result<(), ProfileCryptoError>,
) -> Result<(), ProfileCryptoError> {
    let Value::Map(root_entries) = root else {
        return Ok(());
    };
    for (root_key, root_val) in root_entries.iter_mut() {
        if !matches!(root_key, Value::Text(k) if k == "profiles") {
            continue;
        }
        let Value::Array(profiles) = root_val else {
            continue;
        };
        for profile in profiles.iter_mut() {
            let Value::Map(fields) = profile else {
                continue;
            };
            for (field_key, field_val) in fields.iter_mut() {
                if !matches!(field_key, Value::Text(k) if k == "providers") {
                    continue;
                }
                let Value::Array(providers) = field_val else {
                    continue;
                };
                for entry in providers.iter_mut() {
                    rewrite(entry)?;
                }
            }
        }
    }
    Ok(())
}

/// Decode direction: rewrite `{<foreign-tag>: payload}` into the
/// reserved carrier form so the typed decode preserves it as
/// [`ProviderProfile::Unknown`].
fn shield_unknown_providers(root: &mut Value) -> Result<(), ProfileCryptoError> {
    for_each_provider_entry(root, &mut |entry| {
        let Value::Map(kv) = &*entry else {
            return Ok(());
        };
        if kv.len() != 1 {
            return Ok(());
        }
        let Value::Text(tag) = &kv[0].0 else {
            return Ok(());
        };
        if tag == UNKNOWN_PROVIDER_TAG || KNOWN_PROVIDER_TAGS.contains(&tag.as_str()) {
            return Ok(());
        }
        let mut payload = Vec::new();
        ciborium::into_writer(&kv[0].1, &mut payload)
            .map_err(|_| ProfileCryptoError::PayloadDecode)?;
        let carrier = ProviderProfile::Unknown(UnknownProvider {
            tag: tag.clone(),
            payload_cbor: payload,
        });
        *entry = value_from(&carrier).map_err(|_| ProfileCryptoError::PayloadDecode)?;
        Ok(())
    })
}

/// Encode direction: rewrite the reserved carrier form back into
/// `{<original-tag>: payload}` so the container on disk looks exactly
/// as the newer binary wrote it.
fn restore_unknown_providers(root: &mut Value) -> Result<(), ProfileCryptoError> {
    for_each_provider_entry(root, &mut |entry| {
        let Value::Map(kv) = &*entry else {
            return Ok(());
        };
        if kv.len() != 1 || !matches!(&kv[0].0, Value::Text(t) if t == UNKNOWN_PROVIDER_TAG) {
            return Ok(());
        }
        let ProviderProfile::Unknown(carrier) =
            value_to::<ProviderProfile>(entry).map_err(|_| ProfileCryptoError::PayloadEncode)?
        else {
            return Ok(());
        };
        // A carrier under a known or reserved tag can only come from
        // API misuse (shield never builds one); writing it would brick
        // the container at the next decode. Refuse loudly instead.
        if carrier.tag == UNKNOWN_PROVIDER_TAG
            || KNOWN_PROVIDER_TAGS.contains(&carrier.tag.as_str())
        {
            return Err(ProfileCryptoError::PayloadEncode);
        }
        let payload: Value = ciborium::from_reader(carrier.payload_cbor.as_slice())
            .map_err(|_| ProfileCryptoError::PayloadEncode)?;
        *entry = Value::Map(vec![(Value::Text(carrier.tag), payload)]);
        Ok(())
    })
}

/// Encrypt a `ProfileSet` with `passphrase` and write the JSON
/// envelope to `path`. Sets file mode `0600` on Unix.
pub fn save_set_zz(
    set: &ProfileSet,
    passphrase: &str,
    path: &Path,
) -> Result<ProfileKek, ProfileCryptoError> {
    save_set_zz_with_config(set, passphrase, path, &Argon2idConfig::DEFAULT)
}

pub fn save_set_zz_with_config(
    set: &ProfileSet,
    passphrase: &str,
    path: &Path,
    config: &Argon2idConfig,
) -> Result<ProfileKek, ProfileCryptoError> {
    let (envelope, kek) = encrypt_set_with_config(set, passphrase, config)?;
    write_envelope(path, &envelope)?;
    Ok(kek)
}

/// Read a container envelope from disk and decrypt it.
pub fn load_set_zz(
    path: &Path,
    passphrase: &str,
) -> Result<(ProfileSet, ProfileKek), ProfileCryptoError> {
    let envelope = std::fs::read_to_string(path).map_err(|_| ProfileCryptoError::Io)?;
    decrypt_set(&envelope, passphrase)
}

fn write_envelope(path: &Path, envelope: &str) -> Result<(), ProfileCryptoError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| ProfileCryptoError::Io)?;
    }
    write_private(path, envelope.as_bytes())
}

/// Write `data` to `path`, creating the file with mode `0600` in a
/// single `open` so it is never momentarily world-readable — closing
/// the write-then-chmod window (audit F4). A pre-existing file keeps its
/// inode but is re-tightened to `0600` as defense in depth.
fn write_private(path: &Path, data: &[u8]) -> Result<(), ProfileCryptoError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| ProfileCryptoError::Io)?;
        f.write_all(data).map_err(|_| ProfileCryptoError::Io)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| ProfileCryptoError::Io)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).map_err(|_| ProfileCryptoError::Io)
    }
}

#[cfg(test)]
mod tolerance_tests {
    use super::*;
    use crate::profile::types::ProfileSettings;
    use crate::providers::{CollisionPolicy, NextcloudAuth, NextcloudProfile};

    fn nextcloud_profile(alias: &str) -> PlainProfile {
        PlainProfile {
            profile_version: 1,
            profile_id: format!("p-{alias}"),
            alias: alias.into(),
            default_target: "nextcloud-1".into(),
            providers: vec![ProviderProfile::Nextcloud(NextcloudProfile {
                server_url: "https://example.org".into(),
                username: "user".into(),
                auth: NextcloudAuth::AppPassword {
                    secret: "topsecret".into(),
                },
                remote_root: "/zz-drop".into(),
            })],
            collision_policy: CollisionPolicy::Rename,
            settings: ProfileSettings::default(),
            created_at: "2026-07-02T08:00:00Z".into(),
            updated_at: "2026-07-02T08:00:00Z".into(),
        }
    }

    fn future_profile(alias: &str, tag: &str) -> PlainProfile {
        let mut payload = Vec::new();
        ciborium::into_writer(&Value::Text("future-payload".into()), &mut payload).unwrap();
        let mut p = nextcloud_profile(alias);
        p.providers = vec![ProviderProfile::Unknown(UnknownProvider {
            tag: tag.into(),
            payload_cbor: payload,
        })];
        p
    }

    fn provider_entries(root: &Value) -> Vec<&Value> {
        let Value::Map(entries) = root else {
            panic!("root is not a map")
        };
        let mut out = Vec::new();
        for (k, v) in entries {
            if !matches!(k, Value::Text(t) if t == "profiles") {
                continue;
            }
            let Value::Array(profiles) = v else { continue };
            for profile in profiles {
                let Value::Map(fields) = profile else { continue };
                for (fk, fv) in fields {
                    if !matches!(fk, Value::Text(t) if t == "providers") {
                        continue;
                    }
                    let Value::Array(providers) = fv else { continue };
                    out.extend(providers.iter());
                }
            }
        }
        out
    }

    fn entry_tag(entry: &Value) -> &str {
        let Value::Map(kv) = entry else {
            panic!("provider entry is not a map")
        };
        let Value::Text(tag) = &kv[0].0 else {
            panic!("provider tag is not text")
        };
        tag
    }

    fn direct_kek() -> ProfileKek {
        use crate::crypto::aead::KEY_LEN;
        ProfileKek::new(
            Zeroizing::new([7u8; KEY_LEN]),
            [9u8; SALT_LEN],
            Argon2idConfig::DEFAULT,
        )
    }

    fn decrypt_envelope_payload(envelope: &str, kek: &ProfileKek) -> Vec<u8> {
        let parsed: ProfileEnvelope = serde_json::from_str(envelope).unwrap();
        let nonce: [u8; NONCE_LEN] = B64
            .decode(&parsed.cipher.nonce)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let ciphertext = B64.decode(&parsed.payload.ciphertext).unwrap();
        aead_decrypt(&kek.key, &nonce, &ciphertext).unwrap()
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Regression armor for the write-back guarantee: struct-level
    /// roundtrips cannot distinguish carrier form from original-tag
    /// form on disk (both decode back to the same `Unknown`), so this
    /// decrypts the actual encrypted payload and scans the bytes.
    #[test]
    fn encrypted_payload_carries_the_foreign_tag_not_the_carrier() {
        let set = ProfileSet {
            schema_version: PROFILE_SET_SCHEMA_V2,
            profiles: vec![future_profile("fut", "proton")],
        };
        let kek = direct_kek();
        let envelope = encrypt_set_with_kek(&set, &kek).unwrap();
        let plaintext = decrypt_envelope_payload(&envelope, &kek);
        assert!(contains_bytes(&plaintext, b"proton"));
        assert!(!contains_bytes(&plaintext, b"payload_cbor"));
        assert!(!contains_bytes(&plaintext, b"unknown"));
    }

    /// A hand-built carrier under a known or reserved tag would write
    /// a container the next decode cannot read; the encode path must
    /// refuse it loudly instead of bricking the file.
    #[test]
    fn restore_refuses_known_or_reserved_carrier_tags() {
        for tag in ["nextcloud", "one_drive", "unknown"] {
            let set = ProfileSet {
                schema_version: PROFILE_SET_SCHEMA_V2,
                profiles: vec![future_profile("fut", tag)],
            };
            let err = encrypt_set_with_kek(&set, &direct_kek()).unwrap_err();
            assert!(
                matches!(err, ProfileCryptoError::PayloadEncode),
                "tag {tag}: got {err:?}"
            );
        }
    }

    #[test]
    fn restore_writes_original_tag_not_the_carrier_form() {
        let set = ProfileSet {
            schema_version: PROFILE_SET_SCHEMA_V2,
            profiles: vec![nextcloud_profile("nc"), future_profile("fut", "proton")],
        };
        let mut value = value_from(&set).unwrap();
        restore_unknown_providers(&mut value).unwrap();
        let tags: Vec<&str> = provider_entries(&value).iter().map(|e| entry_tag(e)).collect();
        assert_eq!(tags, vec!["nextcloud", "proton"]);
    }

    #[test]
    fn shield_then_typed_decode_round_trips_the_carrier() {
        let set = ProfileSet {
            schema_version: PROFILE_SET_SCHEMA_V2,
            profiles: vec![nextcloud_profile("nc"), future_profile("fut", "proton")],
        };
        let mut value = value_from(&set).unwrap();
        restore_unknown_providers(&mut value).unwrap();
        shield_unknown_providers(&mut value).unwrap();
        let restored: ProfileSet = value_to(&value).unwrap();
        assert!(restored == set);
    }

    #[test]
    fn shield_leaves_known_tags_untouched() {
        let set = ProfileSet {
            schema_version: PROFILE_SET_SCHEMA_V2,
            profiles: vec![nextcloud_profile("nc")],
        };
        let mut value = value_from(&set).unwrap();
        shield_unknown_providers(&mut value).unwrap();
        let restored: ProfileSet = value_to(&value).unwrap();
        assert!(restored == set);
    }

    #[test]
    fn corrupt_known_provider_still_fails_the_typed_decode() {
        let set = ProfileSet {
            schema_version: PROFILE_SET_SCHEMA_V2,
            profiles: vec![nextcloud_profile("nc")],
        };
        let mut value = value_from(&set).unwrap();
        // Corrupt the nextcloud payload: shielding must not hide it.
        {
            let Value::Map(entries) = &mut value else { panic!() };
            for (k, v) in entries.iter_mut() {
                if !matches!(k, Value::Text(t) if t == "profiles") {
                    continue;
                }
                let Value::Array(profiles) = v else { continue };
                let Value::Map(fields) = &mut profiles[0] else { panic!() };
                for (fk, fv) in fields.iter_mut() {
                    if !matches!(fk, Value::Text(t) if t == "providers") {
                        continue;
                    }
                    let Value::Array(providers) = fv else { continue };
                    let Value::Map(kv) = &mut providers[0] else { panic!() };
                    kv[0].1 = Value::Integer(42.into());
                }
            }
        }
        shield_unknown_providers(&mut value).unwrap();
        assert!(value_to::<ProfileSet>(&value).is_err());
    }
}
