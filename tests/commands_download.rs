use tempfile::tempdir;
use zz_drop_core::{
    CollisionPolicy, NextcloudAuth, NextcloudProfile, PlainProfile, ProfileSettings,
    ProviderProfile,
};

use zz_drop::color::{ColorPolicy, MockEnv};
use zz_drop::commands::download::{run_download, run_download_all};
use zz_drop::commands::remote_fs::FakeRemoteFs;
use zz_drop::commands::{EXIT_OK, EXIT_PROVIDER_ERROR};

fn sample_profile() -> PlainProfile {
    PlainProfile {
        profile_version: 1,
        profile_id: "p".into(),
        alias: "casa".into(),
        default_target: "nc".into(),
        providers: vec![ProviderProfile::Nextcloud(NextcloudProfile {
            server_url: "https://example.org".into(),
            username: "u".into(),
            auth: NextcloudAuth::AppPassword {
                secret: "secret".into(),
            },
            remote_root: "/".into(),
        })],
        collision_policy: CollisionPolicy::Rename,
        settings: ProfileSettings::default(),
        created_at: "2026-04-26T00:00:00Z".into(),
        updated_at: "2026-04-26T00:00:00Z".into(),
    }
}

fn no_color() -> ColorPolicy {
    ColorPolicy::from_parts(&MockEnv::empty(), false)
}

#[test]
fn run_download_single_file_round_trip() {
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["readme.md"], b"hello world".to_vec());

    let code = run_download(
        &remote,
        &["readme.md".to_string()],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    assert_eq!(code, EXIT_OK);
    let written = std::fs::read(tmp.path().join("readme.md")).unwrap();
    assert_eq!(written, b"hello world");
    assert_eq!(remote.download_count(), 1);
}

#[test]
fn run_download_missing_file_fails_but_continues() {
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["a.md"], b"a".to_vec());
    remote.put_file(&["b.md"], b"b".to_vec());

    let code = run_download(
        &remote,
        &[
            "a.md".to_string(),
            "missing.md".to_string(),
            "b.md".to_string(),
        ],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    assert_eq!(code, EXIT_PROVIDER_ERROR);
    assert!(tmp.path().join("a.md").is_file());
    assert!(!tmp.path().join("missing.md").exists());
    assert!(tmp.path().join("b.md").is_file());
    assert_eq!(remote.download_count(), 2);
}

#[test]
fn run_download_subdir_path_saves_with_basename() {
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["docs", "guide.md"], b"guide".to_vec());

    let code = run_download(
        &remote,
        &["docs/guide.md".to_string()],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    assert_eq!(code, EXIT_OK);
    // saved with basename in the destination dir
    assert!(tmp.path().join("guide.md").is_file());
    assert!(!tmp.path().join("docs").exists());
}

#[test]
fn run_download_all_top_level_only_non_recursive() {
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["top.md"], b"top".to_vec());
    remote.put_file(&["sub", "inner.md"], b"inner".to_vec());

    let code = run_download_all(&remote, tmp.path(), false, &sample_profile(), &no_color(), false, None);
    assert_eq!(code, EXIT_OK);
    assert!(tmp.path().join("top.md").is_file());
    assert!(!tmp.path().join("sub").exists());
}

#[test]
fn run_download_all_recursive_preserves_local_tree() {
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["top.md"], b"top".to_vec());
    remote.put_file(&["sub", "inner.md"], b"inner".to_vec());
    remote.put_file(&["sub", "deep", "leaf.md"], b"leaf".to_vec());

    let code = run_download_all(&remote, tmp.path(), true, &sample_profile(), &no_color(), false, None);
    assert_eq!(code, EXIT_OK);
    assert!(tmp.path().join("top.md").is_file());
    assert!(tmp.path().join("sub").join("inner.md").is_file());
    assert!(
        tmp.path()
            .join("sub")
            .join("deep")
            .join("leaf.md")
            .is_file()
    );
}

#[test]
fn run_download_rejects_traversal_path() {
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    let code = run_download(
        &remote,
        &["../etc/passwd".to_string()],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    assert_eq!(code, EXIT_PROVIDER_ERROR);
    assert_eq!(remote.download_count(), 0);
}

#[test]
fn run_download_all_skips_unsafe_server_names() {
    // A malicious server lists entries whose names would escape the
    // destination dir or drive the terminal. download_dir must skip
    // them and only fetch the safe one (D7/D8).
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["safe.md"], b"ok".to_vec());
    remote.put_file(&[".."], b"evil".to_vec()); // traversal
    remote.put_file(&["a/b"], b"evil".to_vec()); // embedded separator
    remote.put_file(&["x\u{1b}[2J"], b"evil".to_vec()); // ANSI escape

    let code = run_download_all(
        &remote,
        tmp.path(),
        false,
        &sample_profile(),
        &no_color(),
        false,
        None,
    );

    assert!(tmp.path().join("safe.md").is_file());
    assert_ne!(code, EXIT_OK, "unsafe entries must be recorded as failures");
    assert_eq!(
        remote.download_count(),
        1,
        "only the safe entry should be fetched"
    );
}

#[test]
fn empty_download_batch_succeeds() {
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    let code = run_download(&remote, &[], tmp.path(), &sample_profile(), &no_color(), false);
    assert_eq!(code, EXIT_OK);
}

#[test]
fn run_download_glob_expands_root_pattern() {
    // `zz d Q*` against a remote with three matching files and
    // some non-matching ones. All matches must be downloaded;
    // non-matches must be left alone.
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["QMulti_DL_CMD_V4.zip"], b"a".to_vec());
    remote.put_file(&["Quectel_FAQ.pdf"], b"bb".to_vec());
    remote.put_file(&["Quectel_Guide.pdf"], b"ccc".to_vec());
    remote.put_file(&["readme.md"], b"x".to_vec());

    let code = run_download(
        &remote,
        &["Q*".to_string()],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    assert_eq!(code, EXIT_OK);
    assert_eq!(remote.download_count(), 3);
    assert!(tmp.path().join("QMulti_DL_CMD_V4.zip").exists());
    assert!(tmp.path().join("Quectel_FAQ.pdf").exists());
    assert!(tmp.path().join("Quectel_Guide.pdf").exists());
    assert!(!tmp.path().join("readme.md").exists());
}

#[test]
fn run_download_glob_with_subdirectory() {
    // `zz d backup/*.pdf` lists only `backup/` and matches the
    // basename. Files outside `backup/` must not match even if
    // they have the same suffix.
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["backup", "guide.pdf"], b"a".to_vec());
    remote.put_file(&["backup", "manual.pdf"], b"bb".to_vec());
    remote.put_file(&["backup", "notes.txt"], b"x".to_vec());
    remote.put_file(&["other.pdf"], b"x".to_vec());

    let code = run_download(
        &remote,
        &["backup/*.pdf".to_string()],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    assert_eq!(code, EXIT_OK);
    assert_eq!(remote.download_count(), 2);
    assert!(tmp.path().join("guide.pdf").exists());
    assert!(tmp.path().join("manual.pdf").exists());
    assert!(!tmp.path().join("notes.txt").exists());
    assert!(!tmp.path().join("other.pdf").exists());
}

#[test]
fn run_download_glob_no_matches_fails() {
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["readme.md"], b"x".to_vec());

    let code = run_download(
        &remote,
        &["Z*".to_string()],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    // No matches → non-zero exit. The contract is "report
    // failure", consistent with how a non-existent literal
    // filename is handled today.
    assert_ne!(code, EXIT_OK);
    assert_eq!(remote.download_count(), 0);
}

#[test]
fn run_download_glob_skips_directories() {
    // `zz d *` at the root must not pick up directory entries —
    // only files. Otherwise we'd try to download a folder as a
    // file and emit a confusing error per dir.
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["alpha.md"], b"a".to_vec());
    remote.put_dir(&["beta_dir"]);
    remote.put_file(&["gamma.md"], b"c".to_vec());

    let code = run_download(
        &remote,
        &["*".to_string()],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    assert_eq!(code, EXIT_OK);
    assert_eq!(remote.download_count(), 2);
}

#[test]
fn run_download_literal_path_unaffected_by_glob_path() {
    // Plain (non-glob) arguments must keep going through the
    // direct download path — no spurious LIST round-trip.
    let tmp = tempdir().unwrap();
    let remote = FakeRemoteFs::new();
    remote.put_file(&["readme.md"], b"hello".to_vec());

    let code = run_download(
        &remote,
        &["readme.md".to_string()],
        tmp.path(),
        &sample_profile(),
        &no_color(),
        false,
    );
    assert_eq!(code, EXIT_OK);
    assert_eq!(remote.download_count(), 1);
}
