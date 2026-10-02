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
fn scancode_executable_and_pin_are_validated_before_downloads() {
    use oss_provenance::evidence::collect_with_scancode_executable;
    use std::path::Path;
    let directory = tempfile::tempdir().unwrap();
    for (path, version) in [
        (Path::new("scancode"), "32.4.1"),
        (directory.path(), "32.4.1"),
        (Path::new("/usr/bin/false"), ""),
    ] {
        assert!(collect_with_scancode_executable(&candidate(), 1, path, version).is_err());
    }
    let file = directory.path().join("not-executable");
    std::fs::write(&file, b"data").unwrap();
    assert!(collect_with_scancode_executable(&candidate(), 1, &file, "32.4.1").is_err());
}

#[test]
#[ignore = "requires explicit SCANCODE_EXECUTABLE and downloads only the pinned public MIT reference"]
fn live_scancode_collects_public_reference_as_pending_proposal() {
    use oss_provenance::evidence::collect_with_scancode_executable;
    let executable = std::env::var_os("SCANCODE_EXECUTABLE")
        .expect("set an absolute trusted SCANCODE_EXECUTABLE");
    let mut input = candidate();
    input.file_hash = Some("d58d9e6aad6a8574050df90430ed8ffc".into());
    let proposal =
        collect_with_scancode_executable(&input, 60, std::path::Path::new(&executable), "32.4.1")
            .unwrap();
    let report = proposal
        .artifacts
        .iter()
        .find(|(path, _)| path.ends_with("/scancode.json"))
        .unwrap()
        .1;
    let report: serde_json::Value = serde_json::from_slice(report).unwrap();
    assert_eq!(report["headers"][0]["tool_version"], "32.4.1");
    let evidence = proposal.evidence.unwrap();
    assert_eq!(evidence.license, "MIT");
    assert!(evidence.review.starts_with("PENDING:"));
    assert!(matches!(
        evidence.obligations,
        oss_provenance::policy::Obligations::Unsupported { .. }
    ));
    assert!(
        proposal
            .artifacts
            .values()
            .any(|bytes| bytes
                == include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/winnowing.py"))
    );
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

#[test]
#[ignore = "downloads only the pinned public GitLab LabKit source and its MIT grant"]
fn live_gitlab_collection_and_source_verification_use_pinned_bytes() {
    use oss_provenance::{
        evidence::verify_source,
        policy::{Evidence, Obligations, sha256},
    };
    let source = include_bytes!("../LICENSE-NOTICES/gitlab-labkit/fields.go");
    let license = include_bytes!("../LICENSE-NOTICES/gitlab-labkit/LICENSE");
    let revision = "f6a93079dd611ffeec26f9f599dc1f78397f41ba";
    let mut input = candidate();
    input.url = Some("https://gitlab.com/gitlab-org/labkit".into());
    input.file = Some("fields/fields.go".into());
    input.file_hash = Some("da966675939febb440609aeea0bac49b".into());
    input.raw = json!({"version": revision});
    let proposal = collect(&input, 60).unwrap();
    assert!(proposal.artifacts.values().any(|bytes| bytes == source));
    assert!(proposal.artifacts.values().any(|bytes| bytes == license));
    assert!(
        proposal
            .artifacts
            .keys()
            .any(|path| path.ends_with("/tree-9.json"))
    );
    assert!(proposal.evidence.is_none());
    let evidence = Evidence {
        file_md5: input.file_hash.unwrap(),
        source_sha256: sha256(source),
        repository: input.url.unwrap(),
        revision: revision.into(),
        path: input.file.unwrap(),
        license: "MIT".into(),
        selected_license: "MIT".into(),
        review: "Public fixture test only".into(),
        obligations: Obligations::ArtifactOnly {},
        artifacts: vec![],
    };
    assert_eq!(verify_source(&evidence, 30).unwrap(), source);
}
