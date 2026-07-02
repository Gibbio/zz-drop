#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod agent_proto;
pub mod api;
pub mod completions;
pub mod config;
pub mod crypto;
pub mod diag_log;
pub mod errors;
pub mod http;
pub mod output;
pub mod profile;
pub mod providers;
pub mod scriptable;
pub mod sidecars;

pub use agent_proto::{AgentError, AgentRequest, AgentResponse, PROTOCOL_VERSION};
pub use config::{
    ConfigError, LocalConfig, PathError, PathOverrides, Paths, discover_paths, load_or_default,
};
pub use crypto::Argon2idConfig;
pub use errors::CoreError;
pub use profile::{
    POLICY_V1, PROFILE_SET_SCHEMA_V2, PROFILE_VERSION_V1, PlainProfile, ProfileCryptoError,
    ProfileKek, ProfileSet, ProfileSettings, decrypt_profile, decrypt_set, encrypt_profile,
    encrypt_profile_with_config, encrypt_set, encrypt_set_with_config, encrypt_set_with_kek,
    load_set_zz, needs_rotation, rotate_set_if_needed, save_set_zz, save_set_zz_with_config,
};
pub use providers::dropbox::{DropboxAuth, DropboxProfile};
pub use providers::google_drive::{GoogleDriveAuth, GoogleDriveProfile};
pub use providers::nextcloud::{NextcloudAuth, NextcloudProfile};
pub use providers::onedrive::{OneDriveAuth, OneDriveProfile};
pub use providers::{CollisionPolicy, ProviderProfile, UnknownProvider};
