use oss_provenance::git::{Blob, Scope, Snapshot};
use oss_provenance::notices::{self, MANIFEST_PATH, Manifest};
use oss_provenance::policy::{
    Artifact, Decision, Evidence, Obligations, Policy, Retirement, sha256,
};
use std::collections::BTreeMap;
use std::process::Command;

fn evidence() -> Evidence {
    Evidence {
        file_md5: "a".repeat(32),
        source_sha256: "b".repeat(64),
        repository: "https://example.org/upstream".into(),
        revision: "c".repeat(40),
        path: "source.rs".into(),
        license: "MIT".into(),
        selected_license: "MIT".into(),
        review: "Grant checked for this source; preserve copyright and license text.".into(),
        obligations: Obligations::ArtifactOnly {},
        artifacts: vec![Artifact {
            path: "LICENSE-NOTICES/upstream/LICENSE".into(),
            sha256: sha256(b"exact upstream license text\n"),
        }],
    }
}

fn policy() -> Policy {
    let mut policy = Policy::parse(oss_provenance::policy::EXAMPLE.as_bytes()).unwrap();
    policy.evidence.push(evidence());
    policy.allow.push("MIT".into());
    policy
}

fn blob(bytes: impl AsRef<[u8]>) -> Blob {
    Blob {
        mode: "100644".into(),
        oid: String::new(),
        bytes: bytes.as_ref().to_vec(),
    }
}

fn manifest() -> Manifest {
    let mut manifest = notices::load(&BTreeMap::new()).unwrap();
    notices::upsert(
        &mut manifest,
        &evidence(),
        "src/one.rs",
        2,
        2,
        b"original\nborrowed\n",
        "Human explanation of the reuse.",
    )
    .unwrap();
    manifest
}

fn files(manifest: &Manifest) -> BTreeMap<String, Blob> {
    let mut files: BTreeMap<_, _> = notices::proposed_files(manifest)
        .unwrap()
        .into_iter()
        .map(|(path, bytes)| (path, blob(bytes)))
        .collect();
    files.insert("src/one.rs".into(), blob(b"original\nborrowed\n"));
    files.insert(
        evidence().artifacts[0].path.clone(),
        blob(b"exact upstream license text\n"),
    );
    files
}

fn snapshot() -> (tempfile::TempDir, Snapshot) {
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    let output = command
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "init",
            "--initial-branch=main",
        ])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot = Snapshot::capture(directory.path(), Scope::Staged { all: false }).unwrap();
    (directory, snapshot)
}

#[test]
fn repeated_reuse_preserves_human_description_and_adds_uses() {
    let mut manifest = manifest();
    notices::upsert(
        &mut manifest,
        &evidence(),
        "src/one.rs",
        3,
        3,
        b"inserted\noriginal\nborrowed\n",
        "Replace my description",
    )
    .unwrap();
    notices::upsert(
        &mut manifest,
        &evidence(),
        "src/two.rs",
        1,
        1,
        b"borrowed\n",
        "Another use",
    )
    .unwrap();
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].uses.len(), 2);
    assert_eq!(manifest.entries[0].uses[0].start, 3);
    assert_eq!(
        manifest.entries[0].uses[0].description,
        "Human explanation of the reuse."
    );
    let (_directory, mut snapshot) = snapshot();
    snapshot.baseline = files(&self::manifest());
    snapshot.files = files(&manifest);
    snapshot
        .files
        .insert("src/one.rs".into(), blob(b"inserted\noriginal\nborrowed\n"));
    snapshot
        .files
        .insert("src/two.rs".into(), blob(b"borrowed\n"));
    assert!(notices::validate(&snapshot, &policy()).unwrap().is_empty());
}

#[test]
fn unchanged_snippet_can_move_without_silently_dropping_it() {
    let (_directory, mut snapshot) = snapshot();
    snapshot.files = files(&manifest());
    snapshot
        .files
        .insert("src/one.rs".into(), blob(b"inserted\noriginal\nborrowed\n"));
    assert!(notices::validate(&snapshot, &policy()).unwrap().is_empty());
    snapshot
        .files
        .insert("src/one.rs".into(), blob(b"original\nchanged\n"));
    let issues = notices::validate(&snapshot, &policy()).unwrap();
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("snippet is missing or changed"));
}

#[test]
fn reports_manifest_and_historical_entry_removal() {
    let (_directory, mut snapshot) = snapshot();
    snapshot.baseline = files(&manifest());
    let issues = notices::validate(&snapshot, &policy()).unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("manifest was removed"))
    );
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("historical notice entry was removed"))
    );
}

#[test]
fn reports_independent_artifact_use_and_readme_failures() {
    let manifest = manifest();
    let (_directory, mut snapshot) = snapshot();
    snapshot.files = files(&manifest);
    snapshot
        .files
        .get_mut(&evidence().artifacts[0].path)
        .unwrap()
        .bytes = b"altered license".to_vec();
    snapshot.files.remove("src/one.rs");
    snapshot
        .files
        .get_mut(&format!(
            "LICENSE-NOTICES/{}/README.md",
            manifest.entries[0].id
        ))
        .unwrap()
        .bytes = b"manual description must not be overwritten".to_vec();
    let issues = notices::validate(&snapshot, &policy()).unwrap();
    assert_eq!(issues.len(), 3, "{issues:?}");
    assert!(issues.iter().any(|issue| issue.contains("README")));
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("artifact differs"))
    );
    assert!(issues.iter().any(|issue| issue.contains("use is missing")));
}

#[test]
fn rejects_policy_tampering_and_historical_use_replacement() {
    let mut candidate = manifest();
    let (_directory, mut snapshot) = snapshot();
    snapshot.baseline = files(&candidate);
    candidate.entries[0].uses[0].snippet_sha256 = sha256(b"original\n");
    candidate.entries[0].uses[0].start = 1;
    candidate.entries[0].uses[0].end = 1;
    snapshot.files = files(&candidate);
    let issues = notices::validate(&snapshot, &policy()).unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("historical notice use"))
    );
    candidate.entries[0].evidence.review = "Changed admission".into();
    candidate.entries[0].id = notices::evidence_id(&candidate.entries[0].evidence).unwrap();
    snapshot.files = files(&candidate);
    let issues = notices::validate(&snapshot, &policy()).unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("not admitted by policy"))
    );
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("entry was removed"))
    );
}

#[test]
fn exact_bytes_and_trailing_newlines_define_snippet_hash() {
    let mut manifest = notices::load(&BTreeMap::new()).unwrap();
    for (start, end, bytes) in [
        (0, 1, &b"one\n"[..]),
        (2, 2, &b"one\n"[..]),
        (1, 1, &b""[..]),
        (2, 1, &b"one\ntwo"[..]),
    ] {
        assert!(
            notices::upsert(
                &mut manifest,
                &evidence(),
                "source.rs",
                start,
                end,
                bytes,
                ""
            )
            .is_err()
        );
    }
    notices::upsert(
        &mut manifest,
        &evidence(),
        "source.rs",
        2,
        2,
        b"one\r\ntwo",
        "",
    )
    .unwrap();
    assert_eq!(manifest.entries[0].uses[0].snippet_sha256, sha256(b"two"));
    notices::upsert(
        &mut manifest,
        &evidence(),
        "source.rs",
        1,
        1,
        b"one\r\ntwo",
        "",
    )
    .unwrap();
    assert_eq!(
        manifest.entries[0].uses[0].snippet_sha256,
        sha256(b"one\r\n")
    );
}

#[test]
fn rejects_unknown_fields_unsafe_paths_duplicate_entries_and_nonregular_manifests() {
    let mut files = files(&manifest());
    let mut value: serde_json::Value = serde_json::from_slice(&files[MANIFEST_PATH].bytes).unwrap();
    value["typo"] = true.into();
    files.get_mut(MANIFEST_PATH).unwrap().bytes = serde_json::to_vec(&value).unwrap();
    assert!(notices::load(&files).is_err());
    let mut manifest = manifest();
    assert!(notices::upsert(&mut manifest, &evidence(), "../escape", 1, 1, b"a", "").is_err());
    manifest.entries.push(manifest.entries[0].clone());
    assert!(notices::proposed_files(&manifest).is_err());
    files.get_mut(MANIFEST_PATH).unwrap().mode = "120000".into();
    assert!(
        notices::load(&files)
            .unwrap_err()
            .to_string()
            .contains("regular file")
    );
}

#[test]
fn generated_files_are_deterministic_and_contain_attribution() {
    let manifest = manifest();
    let generated = notices::proposed_files(&manifest).unwrap();
    assert_eq!(generated, notices::proposed_files(&manifest).unwrap());
    assert_eq!(generated.len(), 2);
    let readme = std::str::from_utf8(
        &generated[&format!("LICENSE-NOTICES/{}/README.md", manifest.entries[0].id)],
    )
    .unwrap();
    for required in [
        &evidence().repository,
        &evidence().revision,
        &evidence().artifacts[0].path,
        "Human explanation of the reuse.",
        "Selected license: MIT",
    ] {
        assert!(readme.contains(required));
    }
}

#[test]
fn committed_readme_drift_is_not_erased_by_regeneration() {
    let (_directory, mut snapshot) = snapshot();
    let manifest = manifest();
    snapshot.files = files(&manifest);
    snapshot.baseline = snapshot.files.clone();
    snapshot
        .baseline
        .get_mut(&format!(
            "LICENSE-NOTICES/{}/README.md",
            manifest.entries[0].id
        ))
        .unwrap()
        .bytes = b"Human additions".to_vec();
    let issues = notices::validate(&snapshot, &policy()).unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("baseline notice README"))
    );
}

#[test]
fn current_policy_rechecks_existing_uses() {
    let (_directory, mut snapshot) = snapshot();
    snapshot.files = files(&manifest());
    snapshot.baseline = snapshot.files.clone();
    let mut policy = policy();
    policy.allow.clear();
    let issues = notices::validate(&snapshot, &policy).unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("unresolved under current policy"))
    );
    policy.deny.push("MIT".into());
    let issues = notices::validate(&snapshot, &policy).unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("blocked by current policy"))
    );
}

#[test]
fn coverage_follows_actual_snippet_bytes_and_not_claimed_display_ranges() {
    let mut manifest = manifest();
    let usage = &mut manifest.entries[0].uses[0];
    assert!(notices::covers_usage(b"original\nborrowed\n", usage, 2, 2));
    assert!(!notices::covers_usage(b"original\nborrowed\n", usage, 1, 2));
    assert!(!notices::covers_usage(
        b"new content\noriginal\nborrowed\n",
        usage,
        2,
        2
    ));
    assert!(notices::covers_usage(
        b"new content\noriginal\nborrowed\n",
        usage,
        3,
        3
    ));
    usage.start = 100;
    usage.end = 100;
    assert!(notices::covers_usage(b"original\nborrowed\n", usage, 2, 2));
    assert!(!notices::covers_usage(
        b"original\nborrowed\n",
        usage,
        100,
        100
    ));
    usage.retired = true;
    assert!(!notices::covers_usage(b"original\nborrowed\n", usage, 2, 2));
}

#[test]
fn existing_readmes_are_checked_before_proposals_can_replace_them() {
    let manifest = manifest();
    let mut files = files(&manifest);
    assert!(
        notices::validate_existing_readmes(&files)
            .unwrap()
            .is_empty()
    );
    let path = format!("LICENSE-NOTICES/{}/README.md", manifest.entries[0].id);
    files.get_mut(&path).unwrap().bytes = b"Human edit".to_vec();
    assert_eq!(notices::validate_existing_readmes(&files).unwrap().len(), 1);
    files.remove(&path);
    assert!(
        notices::validate_existing_readmes(&files)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn explicit_retirement_keeps_history_and_artifacts_without_requiring_deleted_code() {
    let (_directory, mut snapshot) = snapshot();
    let mut manifest = manifest();
    snapshot.baseline = files(&manifest);
    let mut policy = policy();
    let entry = &manifest.entries[0];
    policy.retirements.push(Retirement {
        evidence_id: entry.id.clone(),
        path: entry.uses[0].path.clone(),
        snippet_sha256: entry.uses[0].snippet_sha256.clone(),
        reason: "Removed the reused implementation.".into(),
    });
    notices::reconcile_retirements(&mut manifest, &policy);
    assert!(manifest.entries[0].uses[0].retired);
    assert_eq!(
        manifest.entries[0].uses[0].description,
        "Human explanation of the reuse."
    );
    snapshot.files = files(&manifest);
    snapshot.files.remove("src/one.rs");
    policy.allow.clear();
    policy.deny.push("MIT".into());
    policy.evidence.clear();
    assert!(notices::validate(&snapshot, &policy).unwrap().is_empty());
    assert!(
        notices::upsert(
            &mut manifest,
            &evidence(),
            "src/one.rs",
            1,
            1,
            b"borrowed\n",
            "Revive"
        )
        .is_err()
    );
    snapshot
        .files
        .insert("src/one.rs".into(), blob(b"borrowed\n"));
    assert!(
        notices::validate(&snapshot, &policy)
            .unwrap()
            .iter()
            .any(|issue| issue.contains("retired notice snippet is still present"))
    );
    snapshot.files.remove("src/one.rs");
    snapshot.files.remove(&evidence().artifacts[0].path);
    assert!(
        notices::validate(&snapshot, &policy)
            .unwrap()
            .iter()
            .any(|issue| issue.contains("missing regular notice artifact"))
    );
    policy.retirements.clear();
    assert!(
        notices::validate(&snapshot, &policy)
            .unwrap()
            .iter()
            .any(|issue| issue.contains("retirement is not admitted"))
    );
}

#[test]
fn deleting_required_source_prefix_fails_without_any_added_lines() {
    let mut evidence = evidence();
    evidence.obligations = Obligations::SourcePrefix {
        text: "// Copyright upstream author\n".into(),
    };
    let mut manifest = notices::load(&BTreeMap::new()).unwrap();
    notices::upsert(
        &mut manifest,
        &evidence,
        "src/one.rs",
        2,
        2,
        b"// Copyright upstream author\nborrowed\n",
        "Keep the original source header.",
    )
    .unwrap();
    let mut policy = policy();
    policy.evidence = vec![evidence];
    let (_directory, mut snapshot) = snapshot();
    snapshot.files = files(&manifest);
    snapshot.files.insert(
        "src/one.rs".into(),
        blob(b"// Copyright upstream author\nborrowed\n"),
    );
    snapshot.baseline = snapshot.files.clone();
    assert!(notices::validate(&snapshot, &policy).unwrap().is_empty());
    snapshot
        .files
        .insert("src/one.rs".into(), blob(b"borrowed\n"));
    assert!(snapshot.added.is_empty());
    let issues = notices::validate(&snapshot, &policy).unwrap();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(issues[0].contains("required source prefix is missing or changed"));
}

#[test]
fn unsupported_obligations_never_pass_an_allowed_license() {
    let mut evidence = evidence();
    evidence.obligations = Obligations::Unsupported {
        reason: "Review copyleft distribution obligations.".into(),
    };
    let mut policy = policy();
    policy.evidence = vec![evidence.clone()];
    assert!(matches!(
        policy.decide(&evidence).unwrap(),
        Decision::Unresolved(reason) if reason.contains("unsupported source obligations")
    ));
    let mut manifest = notices::load(&BTreeMap::new()).unwrap();
    notices::upsert(
        &mut manifest,
        &evidence,
        "src/one.rs",
        2,
        2,
        b"original\nborrowed\n",
        "Fixture",
    )
    .unwrap();
    let (_directory, mut snapshot) = snapshot();
    snapshot.files = files(&manifest);
    snapshot.baseline = snapshot.files.clone();
    let issues = notices::validate(&snapshot, &policy).unwrap();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(issues[0].contains("unsupported source obligations"));
}

#[test]
fn obligation_admission_requires_explicit_kind_and_nonempty_parameters() {
    let mut value = serde_json::to_value(evidence()).unwrap();
    value.as_object_mut().unwrap().remove("obligations");
    assert!(serde_json::from_value::<Evidence>(value.clone()).is_err());
    for obligation in [
        serde_json::json!({"kind":"unrecognized"}),
        serde_json::json!({"kind":"artifact_only", "text":"ignored restriction"}),
    ] {
        value["obligations"] = obligation;
        assert!(serde_json::from_value::<Evidence>(value.clone()).is_err());
    }
    for obligations in [
        Obligations::SourcePrefix { text: " \n".into() },
        Obligations::Unsupported {
            reason: String::new(),
        },
    ] {
        let mut policy = policy();
        policy.evidence[0].obligations = obligations;
        assert!(Policy::parse(toml::to_string(&policy).unwrap().as_bytes()).is_err());
    }
    let mut policy = policy();
    policy.evidence[0].obligations = Obligations::SourcePrefix {
        text: "// Copyright upstream\n".into(),
    };
    let parsed = Policy::parse(toml::to_string(&policy).unwrap().as_bytes()).unwrap();
    assert_eq!(
        parsed.evidence[0].obligations,
        policy.evidence[0].obligations
    );
}
