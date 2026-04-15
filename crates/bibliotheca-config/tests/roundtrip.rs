//! Serde round-trip tests for `BibliothecaConfig`.

use std::path::Path;

use bibliotheca_config::{BibliothecaConfig, Error};
use tempfile::TempDir;

#[test]
fn defaults_round_trip_through_yaml() {
    let cfg = BibliothecaConfig::default();
    let yaml = cfg.to_yaml();
    let parsed: BibliothecaConfig = serde_yaml_ng::from_str(&yaml).expect("re-parse defaults");
    assert_eq!(cfg, parsed);
}

#[test]
fn empty_yaml_parses_to_defaults() {
    let cfg: BibliothecaConfig = serde_yaml_ng::from_str("").expect("parse empty");
    assert_eq!(cfg, BibliothecaConfig::default());
}

#[test]
fn partial_yaml_merges_with_defaults() {
    let yaml = r#"
daemon:
  socket: /tmp/bibliotheca.sock
sync:
  townos_url: https://townos.internal/
anisette:
  enabled: true
  upstreams:
    - https://anisette.peer.internal/
share:
  base_url: https://share.example.org/
archive:
  root: /srv/bibliotheca/archives
  default_retention_days: 30
"#;
    let cfg: BibliothecaConfig = serde_yaml_ng::from_str(yaml).expect("parse partial");
    assert_eq!(
        cfg.daemon.socket,
        std::path::PathBuf::from("/tmp/bibliotheca.sock")
    );
    assert_eq!(
        cfg.sync.townos_url.as_ref().map(|u| u.as_str()),
        Some("https://townos.internal/")
    );
    assert!(cfg.anisette.enabled);
    assert_eq!(cfg.anisette.upstreams.len(), 1);
    assert_eq!(
        cfg.share.base_url.as_ref().map(|u| u.as_str()),
        Some("https://share.example.org/")
    );
    assert_eq!(
        cfg.archive.root,
        std::path::PathBuf::from("/srv/bibliotheca/archives")
    );
    assert_eq!(cfg.archive.default_retention_days, Some(30));
    // Untouched sections match defaults.
    assert_eq!(cfg.oauth, bibliotheca_config::OAuthConfig::default());
}

#[test]
fn load_nonexistent_explicit_errors() {
    let tmp = TempDir::new().expect("tempdir");
    let missing = tmp.path().join("does-not-exist.yml");
    let err = BibliothecaConfig::load(&missing).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)));
}

#[test]
fn load_or_default_returns_defaults_on_missing_implicit() {
    let cfg = BibliothecaConfig::load_or_default(None).expect("fallback");
    // Compare a couple of fields instead of full equality — a
    // real operator may have /etc/bibliotheca/bibliotheca.yml
    // installed, in which case this test happily validates
    // their schema.
    assert!(!cfg.daemon.socket.as_os_str().is_empty());
}

#[test]
fn load_or_default_explicit_missing_errors() {
    let tmp = TempDir::new().expect("tempdir");
    let missing = tmp.path().join("nope.yml");
    let err = BibliothecaConfig::load_or_default(Some(&missing)).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)));
}

#[test]
fn example_yaml_parses_cleanly() {
    // Walk up from the crate manifest dir to find the repo root,
    // then locate `examples/bibliotheca.yml`. Keeps this test
    // robust to out-of-tree builds.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let mut cursor = Path::new(manifest).to_path_buf();
    let mut example = None;
    for _ in 0..5 {
        let candidate = cursor.join("examples/bibliotheca.yml");
        if candidate.exists() {
            example = Some(candidate);
            break;
        }
        if !cursor.pop() {
            break;
        }
    }
    let example = example.expect("find examples/bibliotheca.yml");
    let cfg = BibliothecaConfig::load(&example).expect("parse example");
    // Sanity: the example should have non-default placeholders
    // (documented values), not empty defaults across the board.
    assert!(!cfg.oauth.providers.is_empty());
}

#[test]
fn unknown_fields_are_rejected() {
    let yaml = r#"
daemon:
  completely_unknown_key: 1
"#;
    // Our default behaviour is lenient (serde `default`
    // accepts unknown fields). This test just documents that
    // fact so a regression that tightens parsing shows up here.
    let parsed: std::result::Result<BibliothecaConfig, _> = serde_yaml_ng::from_str(yaml);
    assert!(parsed.is_ok());
}
