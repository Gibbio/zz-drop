use zz_drop_core::profile::format::{decrypt_profile, encrypt_profile_with_config};
use zz_drop_core::{
    Argon2idConfig, CollisionPolicy, NextcloudAuth, NextcloudProfile, PROFILE_SET_SCHEMA_V2,
    PlainProfile, ProfileCryptoError, ProfileSet, ProfileSettings, ProviderProfile, decrypt_set,
    encrypt_set_with_config, encrypt_set_with_kek, load_set_zz, save_set_zz_with_config,
};

const TEST_PASSPHRASE: &str = "correct horse battery staple";
const WRONG_PASSPHRASE: &str = "Tr0ub4dor&3";

const FAST_KDF: Argon2idConfig = Argon2idConfig {
    memory_kib: 8 * 1024,
    iterations: 1,
    parallelism: 1,
};

fn sample_profile(alias: &str) -> PlainProfile {
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
        created_at: "2026-04-25T22:00:00Z".into(),
        updated_at: "2026-04-25T22:00:00Z".into(),
    }
}

#[test]
fn round_trip_empty_set() {
    let set = ProfileSet::new();
    let (envelope, _kek) = encrypt_set_with_config(&set, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    let (restored, _kek) = decrypt_set(&envelope, TEST_PASSPHRASE).unwrap();
    assert_eq!(restored.schema_version, PROFILE_SET_SCHEMA_V2);
    assert!(restored.profiles.is_empty());
}

#[test]
fn round_trip_single_profile() {
    let set = ProfileSet::with_profile(sample_profile("casa-nc"));
    let (envelope, _kek) = encrypt_set_with_config(&set, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    let (restored, _kek) = decrypt_set(&envelope, TEST_PASSPHRASE).unwrap();
    assert_eq!(restored.profiles.len(), 1);
    assert_eq!(restored.profiles[0].alias, "casa-nc");
    assert!(set == restored);
}

#[test]
fn round_trip_n_profiles() {
    let mut set = ProfileSet::new();
    for alias in ["nc-home", "gdrive-work", "onedrive-school"] {
        set.profiles.push(sample_profile(alias));
    }
    let (envelope, _kek) = encrypt_set_with_config(&set, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    let (restored, _kek) = decrypt_set(&envelope, TEST_PASSPHRASE).unwrap();
    assert_eq!(restored.profiles.len(), 3);
    assert_eq!(restored.aliases(), vec!["nc-home", "gdrive-work", "onedrive-school"]);
}

#[test]
fn decrypt_with_wrong_passphrase_fails() {
    let set = ProfileSet::with_profile(sample_profile("a"));
    let (envelope, _) = encrypt_set_with_config(&set, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    let err = decrypt_set(&envelope, WRONG_PASSPHRASE).unwrap_err();
    assert!(matches!(err, ProfileCryptoError::Aead), "got {err:?}");
}

#[test]
fn encrypt_with_kek_skips_argon2_and_round_trips() {
    let set = ProfileSet::with_profile(sample_profile("a"));
    // First encrypt with Argon2 to get a KEK.
    let (_envelope1, kek) = encrypt_set_with_config(&set, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    // Re-encrypt without Argon2.
    let envelope2 = encrypt_set_with_kek(&set, &kek).unwrap();
    // Same passphrase decrypts the second envelope.
    let (restored, _kek2) = decrypt_set(&envelope2, TEST_PASSPHRASE).unwrap();
    assert!(set == restored);
}

#[test]
fn legacy_single_profile_payload_is_rejected() {
    // Encode a *PlainProfile* through the single-profile envelope
    // path, then attempt to decrypt as a set. Should surface
    // `LegacyFormat`.
    let profile = sample_profile("legacy");
    let envelope = encrypt_profile_with_config(&profile, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    // Sanity: the legacy path *can* still decrypt as a single profile.
    let _restored = decrypt_profile(&envelope, TEST_PASSPHRASE).unwrap();

    let err = decrypt_set(&envelope, TEST_PASSPHRASE).unwrap_err();
    assert!(
        matches!(err, ProfileCryptoError::LegacyFormat),
        "expected LegacyFormat, got {err:?}"
    );
}

#[test]
fn debug_redacts_profile_set_and_kek() {
    let set = ProfileSet::with_profile(sample_profile("canary-alias"));
    let dbg = format!("{set:?}");
    // Schema version is OK to expose; alias and inner secrets are not.
    assert!(dbg.contains("schema_version"));
    assert!(!dbg.contains("canary-alias"));
    assert!(!dbg.contains("topsecret"));
    assert!(dbg.contains("redacted"));

    let (_envelope, kek) = encrypt_set_with_config(&set, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    let dbg = format!("{kek:?}");
    assert!(dbg.contains("redacted"));
    // No raw key bytes in any form.
    let key_bytes = kek.key_bytes();
    let hex: String = key_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(!dbg.contains(&hex));
}

#[test]
fn save_and_load_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("profiles-local.zz");
    let set = ProfileSet::with_profile(sample_profile("disk-test"));
    save_set_zz_with_config(&set, TEST_PASSPHRASE, &path, &FAST_KDF).unwrap();

    let (loaded, _kek) = load_set_zz(&path, TEST_PASSPHRASE).unwrap();
    assert!(set == loaded);
}

/// End-to-end of the TUI's `perform_add_inner_profile`: save a 1-profile
/// container to disk, decrypt it, append a 2nd profile, re-encrypt
/// with the cached KEK, write atomically, reload — must end with 2
/// profiles (not 1).
#[test]
fn add_inner_profile_disk_roundtrip_does_not_overwrite() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("profiles-local.zz");

    let initial = ProfileSet::with_profile(sample_profile("first"));
    save_set_zz_with_config(&initial, TEST_PASSPHRASE, &path, &FAST_KDF).unwrap();

    let envelope = std::fs::read_to_string(&path).unwrap();
    let (loaded, kek) = decrypt_set(&envelope, TEST_PASSPHRASE).unwrap();
    assert_eq!(loaded.profiles.len(), 1);

    let mut updated = loaded.clone();
    updated.profiles.push(sample_profile("second"));
    let new_envelope = encrypt_set_with_kek(&updated, &kek).unwrap();
    let tmp_path = path.with_extension("zz.tmp");
    std::fs::write(&tmp_path, new_envelope).unwrap();
    std::fs::rename(&tmp_path, &path).unwrap();

    let (final_set, _kek2) = load_set_zz(&path, TEST_PASSPHRASE).unwrap();
    assert_eq!(final_set.profiles.len(), 2);
    assert_eq!(final_set.profiles[0].alias, "first");
    assert_eq!(final_set.profiles[1].alias, "second");
}

#[cfg(unix)]
#[test]
fn save_set_zz_sets_0600() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("profiles-local.zz");
    let set = ProfileSet::with_profile(sample_profile("perms"));
    save_set_zz_with_config(&set, TEST_PASSPHRASE, &path, &FAST_KDF).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn aliases_helper_lists_in_order() {
    let mut set = ProfileSet::new();
    set.profiles.push(sample_profile("alpha"));
    set.profiles.push(sample_profile("beta"));
    set.profiles.push(sample_profile("gamma"));
    assert_eq!(set.aliases(), vec!["alpha", "beta", "gamma"]);
    assert!(set.contains_alias("beta"));
    assert!(!set.contains_alias("delta"));
    assert_eq!(set.find_by_alias("gamma").unwrap().alias, "gamma");
}

#[test]
fn malformed_envelope_is_rejected() {
    let err = decrypt_set("not json", TEST_PASSPHRASE).unwrap_err();
    assert!(matches!(err, ProfileCryptoError::InvalidEnvelope), "got {err:?}");
}

// ── Unknown-provider tolerance ────────────────────────────────────

/// A profile whose provider carries a serde tag this binary does not
/// know — what a container written by a newer zz-drop looks like
/// after decode.
fn sample_future_profile(alias: &str, tag: &str) -> PlainProfile {
    let mut payload = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Text("FUTURE-PAYLOAD-CANARY".into()),
        &mut payload,
    )
    .unwrap();
    let mut profile = sample_profile(alias);
    profile.providers = vec![zz_drop_core::ProviderProfile::Unknown(
        zz_drop_core::UnknownProvider {
            tag: tag.into(),
            payload_cbor: payload,
        },
    )];
    profile
}

/// End-to-end tolerance: a container holding a foreign provider entry
/// (written on disk under its original tag, see the in-module
/// `tolerance_tests` in `profile::format`) decrypts with every alias
/// intact — the known one typed, the foreign one preserved.
#[test]
fn unknown_provider_survives_set_roundtrip() {
    let mut set = ProfileSet::new();
    set.profiles.push(sample_profile("nc-home"));
    set.profiles.push(sample_future_profile("proton-fut", "proton"));

    let (envelope, _kek) = encrypt_set_with_config(&set, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    let (restored, _kek) = decrypt_set(&envelope, TEST_PASSPHRASE).unwrap();
    assert!(set == restored);
    assert_eq!(restored.aliases(), vec!["nc-home", "proton-fut"]);
}

/// The write-back path must not destroy the foreign alias: decrypt,
/// mutate an unrelated profile, re-encrypt with the cached KEK (the
/// agent's token-refresh path), decrypt again.
#[test]
fn mutation_reencrypt_preserves_unknown_provider() {
    let mut set = ProfileSet::new();
    set.profiles.push(sample_profile("nc-home"));
    set.profiles.push(sample_future_profile("proton-fut", "proton"));

    let (envelope, kek) = encrypt_set_with_config(&set, TEST_PASSPHRASE, &FAST_KDF).unwrap();
    let (mut loaded, _) = decrypt_set(&envelope, TEST_PASSPHRASE).unwrap();

    loaded.profiles.push(sample_profile("nc-new"));
    let envelope2 = encrypt_set_with_kek(&loaded, &kek).unwrap();
    let (final_set, _) = decrypt_set(&envelope2, TEST_PASSPHRASE).unwrap();

    assert_eq!(final_set.aliases(), vec!["nc-home", "proton-fut", "nc-new"]);
    assert!(final_set.profiles[1] == set.profiles[1], "foreign alias must be byte-preserved");
}

#[test]
fn unknown_provider_survives_disk_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("profiles-local.zz");
    let set = ProfileSet::with_profile(sample_future_profile("proton-disk", "proton"));
    save_set_zz_with_config(&set, TEST_PASSPHRASE, &path, &FAST_KDF).unwrap();
    let (loaded, _kek) = load_set_zz(&path, TEST_PASSPHRASE).unwrap();
    assert!(set == loaded);
}
