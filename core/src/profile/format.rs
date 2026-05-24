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
    std::fs::write(path, envelope).map_err(|_| ProfileCryptoError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|_| ProfileCryptoError::Io)?;
    }

    Ok(())
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
        ciborium::into_writer(set, writer)
            .map_err(|_| ProfileCryptoError::PayloadEncode)?;
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
    if ciborium::from_reader::<PlainProfile, _>(plaintext.as_slice()).is_ok() {
        return Err(ProfileCryptoError::LegacyFormat);
    }
    Err(ProfileCryptoError::PayloadDecode)
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
    std::fs::write(path, envelope).map_err(|_| ProfileCryptoError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|_| ProfileCryptoError::Io)?;
    }
    Ok(())
}
