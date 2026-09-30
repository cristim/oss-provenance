use oss_provenance::{evidence::collect, scanner::Candidate};
use serde_json::json;

fn candidate() -> Candidate {
    Candidate {
        id: "file".into(),
        local_ranges: vec![(1, 1)],
        upstream_ranges: vec![],
        url: Some("https://github.com/scanoss/scanoss.py".into()),
        file: Some("src/scanoss/winnowing.py".into()),
        file_hash: Some("00000000000000000000000000000000".into()),
        licenses: vec!["MIT".into()],
        raw: json!({"version":"0c1292bd4d53bc504804411dd42ff1ab0fa7aa76"}),
    }
}

#[test]
fn missing_metadata_never_turns_scanner_labels_into_grants() {
    let mut input = candidate();
    input.file_hash = None;
    let result = collect(&input, 1).unwrap();
    assert!(result.evidence.is_none());
    assert!(result.artifacts.is_empty());
    assert!(result.issues[0].contains("missing upstream file MD5"));
}

#[test]
fn unsupported_hosts_credentials_and_paths_are_local_unresolved_results() {
    for url in [
        "http://github.com/o/r",
        "https://example.com/o/r",
        "https://user@github.com/o/r",
        "https://github.com/o/r/tree/main",
        "https://github.com/o/r?x=1",
    ] {
        let mut input = candidate();
        input.url = Some(url.into());
        let result = collect(&input, 1).unwrap();
        assert!(result.evidence.is_none());
        assert!(!result.issues.is_empty());
    }
    let mut input = candidate();
    input.file = Some("../../secrets".into());
    assert!(collect(&input, 1).unwrap().evidence.is_none());
    assert!(collect(&candidate(), 0).is_err());
}

#[test]
#[ignore = "downloads only the bundled public SCANOSS reference and its revision-consistent grants"]
fn live_public_reference_collects_actual_grant_bytes() {
    use md5::{Digest, Md5};
    let source = include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/winnowing.py");
    let mut input = candidate();
    input.file_hash = Some(format!("{:x}", Md5::digest(source)));
    let result = collect(&input, 60).unwrap();
    assert!(result.artifacts.values().any(|bytes| bytes == source));
    assert!(
        result
            .artifacts
            .keys()
            .any(|path| path.ends_with("/upstream/LICENSE"))
    );
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.starts_with("Pending review:"))
    );
    assert!(
        result
            .evidence
            .as_ref()
            .is_none_or(|e| e.review.starts_with("PENDING:"))
    );
    assert!(result.evidence.as_ref().is_none_or(|e| matches!(
        &e.obligations,
        oss_provenance::policy::Obligations::Unsupported { reason }
            if reason.starts_with("PENDING:")
    )));
}
