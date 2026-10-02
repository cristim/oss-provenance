use oss_provenance::{evidence::collect, scanner::Candidate};
use serde_json::json;

fn isolated(mut command: std::process::Command) -> std::process::Command {
    let keys: Vec<_> = std::env::vars_os()
        .map(|(key, _)| key)
        .chain(command.get_envs().map(|(key, _)| key.to_owned()))
        .filter(|key| key.to_string_lossy().starts_with("GIT_"))
        .collect();
    for key in keys {
        command.env_remove(key);
    }
    command
}

#[test]
fn boundary_fixture_preserves_inherited_git_repository() {
    use std::{fs, process::Command};
    let sentinel = tempfile::tempdir().unwrap();
    assert!(
        isolated(Command::new("git"))
            .args(["init", "--quiet"])
            .arg(sentinel.path())
            .status()
            .unwrap()
            .success()
    );
    fs::write(sentinel.path().join("source.txt"), b"sentinel\n").unwrap();
    assert!(
        isolated(Command::new("git"))
            .arg("-C")
            .arg(sentinel.path())
            .args(["add", "source.txt"])
            .status()
            .unwrap()
            .success()
    );
    let metadata = ["config", "HEAD", "index"].map(|name| {
        let path = sentinel.path().join(".git").join(name);
        let bytes = fs::read(&path).unwrap();
        (path, bytes)
    });
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli_rejects_tools_inside_git_boundaries_before_reading_the_report",
            "--nocapture",
        ])
        .env("GIT_DIR", sentinel.path().join(".git"))
        .env("GIT_WORK_TREE", sentinel.path())
        .env("GIT_INDEX_FILE", sentinel.path().join(".git/index"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    for (path, bytes) in metadata {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn cli_rejects_tools_inside_git_boundaries_before_reading_the_report() {
    use std::{fs, process::Command};
    let directory = tempfile::tempdir().unwrap();
    let repo = directory.path().join("repo");
    let common = directory.path().join("git-data");
    assert!(
        isolated(Command::new("git"))
            .args(["init", "--quiet", "--separate-git-dir"])
            .arg(&common)
            .arg(&repo)
            .status()
            .unwrap()
            .success()
    );
    let subdir = repo.join("subdir");
    fs::create_dir(&subdir).unwrap();
    let sentinel = directory.path().join("executed");
    let script = format!(
        "#!/bin/sh\nprintf executed > '{}'\n",
        sentinel.to_str().unwrap().replace('\'', "'\\''")
    );
    let tool = repo.join("scancode");
    fs::write(&tool, &script).unwrap();
    let common_tool = common.join("scancode");
    fs::write(&common_tool, &script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&tool, &common_tool] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let mut paths = vec![
        tool.clone(),
        common_tool,
        std::path::PathBuf::from("relative-tool"),
    ];
    #[cfg(unix)]
    {
        let link = directory.path().join("external-link");
        std::os::unix::fs::symlink(&tool, &link).unwrap();
        paths.push(link);
    }
    for path in paths {
        let output_path = directory.path().join("proposal");
        let result = isolated(Command::new(env!("CARGO_BIN_EXE_oss-provenance")))
            .arg("--repo")
            .arg(&subdir)
            .args([
                "collect-evidence",
                "--report",
                "absent-report.json",
                "--output",
            ])
            .arg(&output_path)
            .arg("--scancode-executable")
            .arg(path)
            .args(["--scancode-version", "32.4.1"])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(error.contains("ScanCode executable must be"), "{error}");
        assert!(!output_path.exists());
        assert!(!sentinel.exists());
    }
}

#[test]
#[ignore = "requires explicit SCANCODE_EXECUTABLE and downloads only the pinned public MIT reference"]
fn live_cli_scancode_writes_a_pending_proposal() {
    use md5::{Digest, Md5};
    use std::{fs, process::Command};
    let executable = std::env::var_os("SCANCODE_EXECUTABLE")
        .expect("set an absolute trusted SCANCODE_EXECUTABLE");
    let mut input = candidate();
    input.file_hash = Some(format!(
        "{:x}",
        Md5::digest(include_bytes!(
            "../LICENSE-NOTICES/scanoss-winnowing/winnowing.py"
        ))
    ));
    let directory = tempfile::tempdir().unwrap();
    let report = directory.path().join("report.json");
    fs::write(
        &report,
        serde_json::to_vec(&json!({
            "files": [{"findings": [{"candidate": input}]}]
        }))
        .unwrap(),
    )
    .unwrap();
    let output = directory.path().join("proposal");
    let result = isolated(Command::new(env!("CARGO_BIN_EXE_oss-provenance")))
        .args([
            "--repo",
            env!("CARGO_MANIFEST_DIR"),
            "collect-evidence",
            "--report",
        ])
        .arg(&report)
        .arg("--output")
        .arg(&output)
        .arg("--scancode-executable")
        .arg(executable)
        .args(["--scancode-version", "32.4.1"])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let proposal: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("proposal.json")).unwrap()).unwrap();
    assert_eq!(proposal["evidence"]["license"], "MIT");
    assert!(
        proposal["evidence"]["review"]
            .as_str()
            .unwrap()
            .starts_with("PENDING:")
    );
    assert_eq!(proposal["evidence"]["obligations"]["kind"], "unsupported");
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("not admitted")
    );
}

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
