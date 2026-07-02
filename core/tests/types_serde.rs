use zz_drop_core::agent_proto::KekPayload;
use zz_drop_core::{
    AgentError, AgentRequest, AgentResponse, Argon2idConfig, CollisionPolicy, DropboxAuth,
    DropboxProfile, NextcloudAuth, NextcloudProfile, PROTOCOL_VERSION, PlainProfile, ProfileSet,
    ProfileSettings, ProviderProfile, UnknownProvider,
};

fn sample_kek_payload() -> KekPayload {
    KekPayload {
        key: [0x42u8; 32],
        salt: [0x11u8; 16],
        kdf: Argon2idConfig::DEFAULT,
    }
}

fn sample_profile() -> PlainProfile {
    PlainProfile {
        profile_version: 1,
        profile_id: "p-0001".into(),
        alias: "casa-nc".into(),
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
fn protocol_version_is_one() {
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn profile_settings_defaults() {
    let s = ProfileSettings::default();
    assert_eq!(s.unlock_ttl_secs, 600);
    assert_eq!(s.agent_idle_exit_secs, 300);
}

#[test]
fn plain_profile_roundtrip() {
    let original = sample_profile();
    let json = serde_json::to_string(&original).unwrap();
    let restored: PlainProfile = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&restored).unwrap();
    assert_eq!(json, json2);
    assert!(original == restored);
}

#[test]
fn agent_request_unlock_roundtrip() {
    let req = AgentRequest::Unlock {
        profile_set: ProfileSet::with_profile(sample_profile()),
        kek: sample_kek_payload(),
        active_alias: "casa-nc".into(),
        ttl_secs: Some(600),
    };
    let json = serde_json::to_string(&req).unwrap();
    let restored: AgentRequest = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&restored).unwrap();
    assert_eq!(json, json2);
}

#[test]
fn agent_request_simple_variants_roundtrip() {
    for req in [
        AgentRequest::Ping,
        AgentRequest::GetProfile,
        AgentRequest::Lock,
        AgentRequest::Exit,
        AgentRequest::Status,
    ] {
        let json = serde_json::to_string(&req).unwrap();
        let restored: AgentRequest = serde_json::from_str(&json).unwrap();
        assert!(req == restored);
    }
}

#[test]
fn agent_response_profile_roundtrip() {
    let resp = AgentResponse::Profile(sample_profile());
    let json = serde_json::to_string(&resp).unwrap();
    let restored: AgentResponse = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&restored).unwrap();
    assert_eq!(json, json2);
}

#[test]
fn agent_response_status_roundtrip() {
    let resp = AgentResponse::Status {
        unlocked: true,
        ttl_remaining_secs: Some(420),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let restored: AgentResponse = serde_json::from_str(&json).unwrap();
    assert!(resp == restored);
}

#[test]
fn agent_error_roundtrip() {
    let cases = [
        AgentError::ProtocolMismatch {
            got: 0,
            expected: 1,
        },
        AgentError::NotUnlocked,
        AgentError::FrameTooLarge {
            size: 2_000_000,
            limit: 1_048_576,
        },
        AgentError::InvalidToken,
        AgentError::Io {
            message: "connection reset".into(),
        },
        AgentError::Decode {
            message: "bad frame".into(),
        },
    ];
    for err in cases {
        let json = serde_json::to_string(&err).unwrap();
        let restored: AgentError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }
}

#[test]
fn collision_policy_serialization() {
    assert_eq!(
        serde_json::to_string(&CollisionPolicy::Rename).unwrap(),
        "\"rename\""
    );
    assert_eq!(
        serde_json::to_string(&CollisionPolicy::Overwrite).unwrap(),
        "\"overwrite\""
    );
    assert_eq!(
        serde_json::to_string(&CollisionPolicy::Fail).unwrap(),
        "\"fail\""
    );
}

#[test]
fn debug_redacts_plain_profile() {
    let profile = sample_profile();
    let formatted = format!("{profile:?}");
    assert!(
        !formatted.contains("topsecret"),
        "PlainProfile Debug must redact provider secret: got `{formatted}`"
    );
    assert!(
        !formatted.contains("example.org"),
        "PlainProfile Debug must redact provider URL: got `{formatted}`"
    );
}

#[test]
fn debug_redacts_nextcloud_auth() {
    let auth = NextcloudAuth::AppPassword {
        secret: "topsecret".into(),
    };
    let formatted = format!("{auth:?}");
    assert!(
        !formatted.contains("topsecret"),
        "NextcloudAuth Debug must redact secret: got `{formatted}`"
    );

    let auth = NextcloudAuth::LoginFlowToken {
        secret: "lf-token".into(),
    };
    let formatted = format!("{auth:?}");
    assert!(
        !formatted.contains("lf-token"),
        "NextcloudAuth Debug must redact secret: got `{formatted}`"
    );
}

#[test]
fn debug_redacts_agent_request_unlock() {
    let req = AgentRequest::Unlock {
        profile_set: ProfileSet::with_profile(sample_profile()),
        kek: sample_kek_payload(),
        active_alias: "casa-nc".into(),
        ttl_secs: Some(600),
    };
    let formatted = format!("{req:?}");
    assert!(
        !formatted.contains("topsecret"),
        "AgentRequest::Unlock Debug must redact profile secret: got `{formatted}`"
    );
}

#[test]
fn debug_redacts_agent_response_profile() {
    let resp = AgentResponse::Profile(sample_profile());
    let formatted = format!("{resp:?}");
    assert!(
        !formatted.contains("topsecret"),
        "AgentResponse::Profile Debug must redact profile secret: got `{formatted}`"
    );
}

fn sample_dropbox_profile() -> PlainProfile {
    PlainProfile {
        profile_version: 1,
        profile_id: "p-0042".into(),
        alias: "dropbox-amber-brook-42".into(),
        default_target: "dropbox-1".into(),
        providers: vec![ProviderProfile::Dropbox(DropboxProfile {
            root_folder: "zz-drop".into(),
            user_email: "alice@example.com".into(),
            auth: DropboxAuth {
                access_token: "AT-DROPBOX-CANARY".into(),
                refresh_token: "RT-DROPBOX-CANARY".into(),
                token_type: "bearer".into(),
                expires_at: 9_999_999_999,
                scope: "files.content.write files.content.read files.metadata.read account_info.read".into(),
            },
        })],
        collision_policy: CollisionPolicy::Rename,
        settings: ProfileSettings::default(),
        created_at: "2026-05-09T22:00:00Z".into(),
        updated_at: "2026-05-09T22:00:00Z".into(),
    }
}

#[test]
fn plain_profile_dropbox_roundtrip() {
    let original = sample_dropbox_profile();
    let json = serde_json::to_string(&original).unwrap();
    let restored: PlainProfile = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&restored).unwrap();
    assert_eq!(json, json2);
    assert!(original == restored);
    // Variant tag uses snake_case ("dropbox") per the existing
    // ProviderProfile serde rename rule.
    assert!(json.contains("\"dropbox\""));
}

fn sample_unknown_profile() -> PlainProfile {
    let mut payload = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Text("UNKNOWN-PAYLOAD-CANARY".into()),
        &mut payload,
    )
    .unwrap();
    PlainProfile {
        profile_version: 1,
        profile_id: "p-0099".into(),
        alias: "proton-quiet-lake-7".into(),
        default_target: "proton-1".into(),
        providers: vec![ProviderProfile::Unknown(UnknownProvider {
            tag: "proton".into(),
            payload_cbor: payload,
        })],
        collision_policy: CollisionPolicy::Rename,
        settings: ProfileSettings::default(),
        created_at: "2026-07-02T08:00:00Z".into(),
        updated_at: "2026-07-02T08:00:00Z".into(),
    }
}

#[test]
fn plain_profile_unknown_roundtrip() {
    let original = sample_unknown_profile();
    let json = serde_json::to_string(&original).unwrap();
    let restored: PlainProfile = serde_json::from_str(&json).unwrap();
    assert!(original == restored);
    // The carrier serializes under the reserved tag.
    assert!(json.contains("\"unknown\""));
}

#[test]
fn debug_redacts_unknown_provider_payload() {
    let profile = sample_unknown_profile();
    let formatted = format!("{profile:?}");
    assert!(
        !formatted.contains("UNKNOWN-PAYLOAD-CANARY"),
        "PlainProfile Debug must redact unknown-provider payload: got `{formatted}`"
    );
    let ProviderProfile::Unknown(carrier) = &profile.providers[0] else {
        panic!("expected Unknown provider");
    };
    let formatted = format!("{carrier:?}");
    assert!(formatted.contains("proton"), "tag itself is not a secret");
    assert!(formatted.contains("redacted"));
    assert!(!formatted.contains("UNKNOWN-PAYLOAD-CANARY"));
}

/// The tag list `profile::format` uses to split known from foreign
/// providers must track the enum exactly: a variant added without
/// updating the const would get silently shielded as `Unknown` on
/// every decode. serde's unknown-variant error enumerates the
/// accepted tags, so parse them out and compare sets.
#[test]
fn known_provider_tags_stay_in_sync_with_enum() {
    use zz_drop_core::providers::{KNOWN_PROVIDER_TAGS, UNKNOWN_PROVIDER_TAG};

    let err = serde_json::from_str::<ProviderProfile>("{\"zz_not_a_provider\": null}")
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown variant"), "got `{err}`");
    let mut listed: Vec<String> = err
        .split('`')
        .skip(3) // skip past: unknown variant `zz_not_a_provider`, expected one of
        .step_by(2)
        .map(str::to_string)
        .collect();
    listed.retain(|t| t != UNKNOWN_PROVIDER_TAG);
    let mut expected: Vec<String> =
        KNOWN_PROVIDER_TAGS.iter().map(|t| t.to_string()).collect();
    listed.sort();
    expected.sort();
    assert_eq!(
        listed, expected,
        "KNOWN_PROVIDER_TAGS out of sync with ProviderProfile variants"
    );
}

/// The forward-compat carrier must survive the real agent wire
/// (postcard, not self-describing) — an unlock that carries a foreign
/// provider round-trips without loss.
#[test]
fn agent_unlock_with_unknown_provider_postcard_roundtrip() {
    use zz_drop_core::agent_proto::{decode_request_body, encode_request_body};

    let req = AgentRequest::Unlock {
        profile_set: ProfileSet::with_profile(sample_unknown_profile()),
        kek: sample_kek_payload(),
        active_alias: "proton-quiet-lake-7".into(),
        ttl_secs: Some(600),
    };
    let body = encode_request_body(&req).unwrap();
    let restored = decode_request_body(&body).unwrap();
    assert!(req == restored);
}

#[test]
fn debug_redacts_dropbox_profile() {
    let profile = sample_dropbox_profile();
    let formatted = format!("{profile:?}");
    assert!(
        !formatted.contains("AT-DROPBOX-CANARY"),
        "PlainProfile Debug must redact Dropbox access_token: got `{formatted}`"
    );
    assert!(
        !formatted.contains("RT-DROPBOX-CANARY"),
        "PlainProfile Debug must redact Dropbox refresh_token: got `{formatted}`"
    );
    assert!(
        !formatted.contains("alice@example.com"),
        "PlainProfile Debug must redact Dropbox user email: got `{formatted}`"
    );
}
