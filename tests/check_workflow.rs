use md5::{Digest, Md5};
use oss_provenance::{
    check::{self, Report},
    git::{Blob, Scope, Snapshot},
    notices,
    policy::{self, Artifact, Evidence, Obligations, Policy, ScannerConfig},
    scanner::{Candidate, ScanResult},
};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

const PUBLIC_SOURCE: &[u8] = include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/winnowing.py");
const PUBLIC_LICENSE: &[u8] = include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/LICENSE");
const GRANT: &str = "LICENSE-NOTICES/evidence/LICENSE";
const BINARY: &str = env!("CARGO_BIN_EXE_oss-provenance");

fn isolated(mut command: Command) -> Command {
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

struct Fixture {
    directory: TempDir,
    policy: Policy,
    policy_bytes: Vec<u8>,
    reference: String,
}

impl Fixture {
    fn new() -> Self {
        let evidence = Evidence {
            file_md5: format!("{:x}", Md5::digest(PUBLIC_SOURCE)),
            source_sha256: policy::sha256(PUBLIC_SOURCE),
            repository: "https://github.com/scanoss/scanoss.py".into(),
            revision: "0c1292bd4d53bc504804411dd42ff1ab0fa7aa76".into(),
            path: "src/scanoss/winnowing.py".into(),
            license: "MIT".into(),
            selected_license: "MIT".into(),
            obligations: Obligations::ArtifactOnly {},
            review: "Public pinned SCANOSS source and its bundled MIT grant; preserve copyright and permission notice.".into(),
            artifacts: vec![Artifact { path: GRANT.into(), sha256: policy::sha256(PUBLIC_LICENSE) }],
        };
        let policy = Policy {
            version: 1,
            project_license: "MIT".into(),
            use_context: "Distribute source with preserved upstream attribution".into(),
            scanner: ScannerConfig {
                endpoint: "https://api.osskb.org/scan/direct".into(),
                enabled: true,
                timeout_secs: 30,
            },
            allow: vec!["MIT".into()],
            deny: Vec::new(),
            exclude: vec![policy::POLICY_PATH.into(), "LICENSE-NOTICES/".into()],
            evidence: vec![evidence],
            retirements: Vec::new(),
        };
        let policy_bytes = toml::to_string(&policy).unwrap().into_bytes();
        Policy::parse(&policy_bytes).unwrap();
        let mut fixture = Self {
            directory: tempfile::tempdir().unwrap(),
            policy,
            policy_bytes,
            reference: String::new(),
        };
        fixture.git(&["init", "--initial-branch=main"]);
        fixture.git(&["config", "user.name", "Workflow Test"]);
        fixture.git(&["config", "user.email", "workflow@example.invalid"]);
        fixture.write(policy::POLICY_PATH, &fixture.policy_bytes);
        fixture.write(GRANT, PUBLIC_LICENSE);
        fixture.commit();
        fixture.reference = fixture.git(&["rev-parse", "HEAD"]);
        fixture
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn git(&self, args: &[&str]) -> String {
        let output = isolated(Command::new("git"))
            .arg("-C")
            .arg(self.path())
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.fsmonitor=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().into()
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn commit(&self) {
        self.git(&["add", "."]);
        self.git(&["commit", "-m", "fixture"]);
    }

    fn stage(&self, path: &str, bytes: &[u8]) {
        self.write(path, bytes);
        self.git(&["add", "--", path]);
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot::capture(self.path(), Scope::Staged { all: false }).unwrap()
    }

    fn candidate(&self, start: usize, end: usize) -> Candidate {
        let evidence = &self.policy.evidence[0];
        Candidate {
            id: "snippet".into(),
            local_ranges: vec![(start, end)],
            upstream_ranges: vec![(start, end)],
            url: Some(evidence.repository.clone()),
            file: Some(evidence.path.clone()),
            file_hash: Some(evidence.file_md5.clone()),
            licenses: vec!["MIT".into()],
            raw: serde_json::json!({"fixture":true}),
        }
    }

    fn assess(&self, snapshot: &Snapshot, candidates: Vec<Candidate>) -> Report {
        check::assess(
            snapshot,
            &self.policy,
            &self.reference,
            &self.policy_bytes,
            false,
            false,
            |_, _| {
                Ok(ScanResult {
                    fingerprintable: true,
                    candidates: candidates.clone(),
                })
            },
            |_| Ok(PUBLIC_SOURCE.to_vec()),
        )
        .unwrap()
    }

    fn cli(&self, args: &[&str]) -> Output {
        isolated(Command::new(BINARY))
            .arg("--repo")
            .arg(self.path())
            .args(args)
            .output()
            .unwrap()
    }

    fn cli_with_cache(&self, cache: &Path, args: &[&str]) -> Output {
        isolated(Command::new(BINARY))
            .arg("--repo")
            .arg(self.path())
            .args(args)
            .env("OSS_PROVENANCE_CACHE_DIR", cache)
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("NO_PROXY", "")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("https_proxy", "http://127.0.0.1:1")
            .env("all_proxy", "http://127.0.0.1:1")
            .env("no_proxy", "")
            .output()
            .unwrap()
    }
}

fn seed_cache(cache: &Path, parts: &[&[u8]], body: &[u8]) {
    let mut hash = Sha256::new();
    hash.update(b"oss-provenance-cache-v1");
    hash.update(env!("CARGO_PKG_VERSION").as_bytes());
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10;
    let mut record = b"OSSPCACHE\x01".to_vec();
    record.extend_from_slice(&stamp.to_be_bytes());
    record.extend_from_slice(body);
    fs::write(cache.join(format!("{:x}", hash.finalize())), record).unwrap();
}

fn cache_bytes(cache: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(cache)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn cached_check(fixture: &Fixture, cache: &Path) -> (i32, serde_json::Value) {
    let output = fixture.cli_with_cache(
        cache,
        &[
            "check",
            "--staged",
            "--policy-ref",
            &fixture.reference,
            "--format",
            "json",
        ],
    );
    let code = output.status.code().unwrap();
    assert!(
        matches!(code, 0 | 1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (code, serde_json::from_slice(&output.stdout).unwrap())
}

fn exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fixture_children_ignore_inherited_repository_environment() {
    let target = Fixture::new();
    let sentinel = Fixture::new();
    sentinel.stage("sentinel.bin", b"private sentinel\0");
    let paths = [
        ".git/HEAD",
        ".git/index",
        ".git/config",
        ".git/refs/heads/main",
    ];
    let before: Vec<_> = paths
        .iter()
        .map(|path| fs::read(sentinel.path().join(path)).unwrap())
        .collect();
    let contaminated = |program: &str| {
        let mut command = Command::new(program);
        command
            .env("GIT_DIR", sentinel.path().join(".git"))
            .env("GIT_WORK_TREE", sentinel.path())
            .env("GIT_INDEX_FILE", sentinel.path().join(".git/index"))
            .env("GIT_COMMON_DIR", sentinel.path().join(".git"))
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.bare")
            .env("GIT_CONFIG_VALUE_0", "true");
        isolated(command)
    };
    let output = contaminated("git")
        .arg("-C")
        .arg(target.path())
        .args(["config", "--local", "test.isolation", "verified"])
        .output()
        .unwrap();
    exit(&output, 0);
    assert_eq!(
        target.git(&["config", "--local", "--get", "test.isolation"]),
        "verified"
    );
    let output = contaminated(BINARY)
        .arg("--repo")
        .arg(target.path())
        .args(["check", "--staged", "--policy-ref", &target.reference])
        .output()
        .unwrap();
    exit(&output, 0);
    for (path, bytes) in paths.iter().zip(before) {
        assert_eq!(
            fs::read(sentinel.path().join(path)).unwrap(),
            bytes,
            "sentinel metadata changed: {path}"
        );
    }
}

fn source_status(report: &Report, path: &str) -> String {
    report
        .files
        .iter()
        .find(|file| file.path == path)
        .unwrap()
        .status
        .clone()
}

#[test]
fn missing_notice_then_deterministic_virtual_proposal_clears_admitted_match() {
    let fixture = Fixture::new();
    fixture.stage("source.py", PUBLIC_SOURCE);
    fixture.write("source.py", b"unstaged sentinel must not be read\n");
    let mut snapshot = fixture.snapshot();
    assert_eq!(snapshot.files["source.py"].bytes, PUBLIC_SOURCE);
    let candidate = fixture.candidate(1, 2);
    let report = fixture.assess(&snapshot, vec![candidate.clone()]);
    assert!(!report.passed());
    assert_eq!(report.files[0].findings[0].status, "notice_required");
    check::ensure_resolvable(&report).unwrap();
    let mut manifest = notices::load(&snapshot.files).unwrap();
    notices::upsert(
        &mut manifest,
        &fixture.policy.evidence[0],
        "source.py",
        1,
        2,
        PUBLIC_SOURCE,
        "Pinned public source reuse",
    )
    .unwrap();
    let proposed = notices::proposed_files(&manifest).unwrap();
    notices::upsert(
        &mut manifest,
        &fixture.policy.evidence[0],
        "source.py",
        1,
        2,
        PUBLIC_SOURCE,
        "Pinned public source reuse",
    )
    .unwrap();
    assert_eq!(proposed, notices::proposed_files(&manifest).unwrap());
    for (path, bytes) in proposed {
        snapshot.files.insert(
            path,
            Blob {
                mode: "100644".into(),
                oid: policy::sha256(&bytes),
                bytes,
            },
        );
    }
    assert!(fixture.assess(&snapshot, vec![candidate]).passed());
    assert_eq!(
        fs::read(fixture.path().join("source.py")).unwrap(),
        b"unstaged sentinel must not be read\n"
    );
}

#[test]
fn cli_cached_match_still_requires_notices_and_current_policy_permission() {
    let mut fixture = Fixture::new();
    fixture.policy.scanner.endpoint = "https://127.0.0.1:1/scan".into();
    fixture.policy.scanner.timeout_secs = 1;
    fixture.policy_bytes = toml::to_string(&fixture.policy).unwrap().into_bytes();
    fixture.stage(policy::POLICY_PATH, &fixture.policy_bytes);
    fixture.commit();
    fixture.reference = fixture.git(&["rev-parse", "HEAD"]);

    let cache = tempfile::tempdir().unwrap();
    let content_hash = Sha256::digest(PUBLIC_SOURCE);
    let wire_id = format!("source_{content_hash:x}");
    let evidence = &fixture.policy.evidence[0];
    let scan = serde_json::json!({wire_id: [{
        "id": "snippet",
        "lines": "1-2",
        "oss_lines": "1-2",
        "url": evidence.repository,
        "file": evidence.path,
        "file_hash": evidence.file_md5,
        "licenses": [{"name": "MIT"}]
    }]});
    seed_cache(
        cache.path(),
        &[
            b"scanner",
            fixture.policy.scanner.endpoint.as_bytes(),
            &content_hash,
        ],
        &serde_json::to_vec(&scan).unwrap(),
    );
    let raw_url = format!(
        "https://raw.githubusercontent.com/scanoss/scanoss.py/{}/{}",
        evidence.revision, evidence.path
    );
    seed_cache(
        cache.path(),
        &[
            b"source",
            raw_url.as_bytes(),
            evidence.source_sha256.as_bytes(),
            evidence.file_md5.as_bytes(),
        ],
        PUBLIC_SOURCE,
    );
    let seeded = cache_bytes(cache.path());
    assert_eq!(seeded.len(), 2);
    fixture.stage("source.py", PUBLIC_SOURCE);
    let (code, first) = cached_check(&fixture, cache.path());
    assert_eq!(code, 1);
    assert_eq!(
        first["files"][0]["findings"][0]["status"],
        "notice_required"
    );

    let mut manifest = notices::load(&fixture.snapshot().files).unwrap();
    notices::upsert(
        &mut manifest,
        &fixture.policy.evidence[0],
        "source.py",
        1,
        2,
        PUBLIC_SOURCE,
        "Pinned public source reuse",
    )
    .unwrap();
    for (path, bytes) in notices::proposed_files(&manifest).unwrap() {
        fixture.stage(&path, &bytes);
    }
    let (code, allowed) = cached_check(&fixture, cache.path());
    assert_eq!(code, 0);
    let source_finding = allowed["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "source.py")
        .unwrap();
    assert_eq!(source_finding["findings"][0]["status"], "allowed");

    fixture.stage("copy.py", PUBLIC_SOURCE);
    let (code, copy) = cached_check(&fixture, cache.path());
    assert_eq!(code, 1);
    let copy_finding = copy["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "copy.py")
        .unwrap();
    assert_eq!(copy_finding["findings"][0]["status"], "notice_required");

    notices::upsert(
        &mut manifest,
        &fixture.policy.evidence[0],
        "copy.py",
        1,
        2,
        PUBLIC_SOURCE,
        "Second use of pinned public source",
    )
    .unwrap();
    for (path, bytes) in notices::proposed_files(&manifest).unwrap() {
        fixture.stage(&path, &bytes);
    }
    fixture.commit();
    fixture.policy.allow.clear();
    fixture.policy.deny.push("MIT".into());
    fixture.policy_bytes = toml::to_string(&fixture.policy).unwrap().into_bytes();
    fixture.stage(policy::POLICY_PATH, &fixture.policy_bytes);
    fixture.commit();
    fixture.reference = fixture.git(&["rev-parse", "HEAD"]);
    fixture.stage("blocked.py", PUBLIC_SOURCE);
    let (code, denied) = cached_check(&fixture, cache.path());
    assert_eq!(code, 1);
    let blocked_finding = denied["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"] == "blocked.py")
        .unwrap();
    assert_eq!(blocked_finding["findings"][0]["status"], "blocked");
    assert_eq!(cache_bytes(cache.path()), seeded);
}

#[test]
fn denied_unknown_and_identity_conflicting_matches_remain_blocked() {
    let mut fixture = Fixture::new();
    fixture.stage("source.py", PUBLIC_SOURCE);
    let snapshot = fixture.snapshot();
    let candidate = fixture.candidate(1, 2);
    fixture.policy.allow.clear();
    fixture.policy.deny.push("MIT".into());
    let denied = fixture.assess(&snapshot, vec![candidate.clone()]);
    assert!(!denied.passed());
    assert_eq!(denied.files[0].findings[0].status, "blocked");
    assert!(check::ensure_resolvable(&denied).is_err());
    fixture.policy.deny.clear();
    let unknown = fixture.assess(&snapshot, vec![candidate.clone()]);
    assert!(!unknown.passed());
    assert_eq!(unknown.files[0].findings[0].status, "unresolved");
    fixture.policy.allow.push("MIT".into());
    let mut conflicting = candidate;
    conflicting.url = Some("https://example.invalid/unrelated".into());
    let conflict = fixture.assess(&snapshot, vec![conflicting]);
    assert!(!conflict.passed());
    assert!(conflict.files[0].findings[0].reason.contains("conflicts"));
}

#[test]
fn scanner_license_labels_without_admitted_evidence_never_clear_matches() {
    let fixture = Fixture::new();
    fixture.stage("source.py", PUBLIC_SOURCE);
    let mut candidate = fixture.candidate(1, 2);
    candidate.file_hash = Some("0".repeat(32));
    let report = fixture.assess(&fixture.snapshot(), vec![candidate]);
    assert!(!report.passed());
    assert_eq!(report.files[0].findings[0].status, "unresolved");
}

#[test]
fn forged_scanner_identity_cannot_clear_unrelated_local_content() {
    let fixture = Fixture::new();
    fixture.stage(
        "source.py",
        b"unrelated_local_content\nsecond_unrelated_line\n",
    );
    let report = fixture.assess(&fixture.snapshot(), vec![fixture.candidate(1, 2)]);
    assert!(!report.passed());
    assert_eq!(report.files[0].findings[0].status, "unresolved");
    assert!(
        report.files[0].findings[0]
            .reason
            .contains("correspondence")
    );
}

#[test]
fn actual_source_hash_mismatch_is_an_operational_error() {
    let mut fixture = Fixture::new();
    fixture.stage("source.py", PUBLIC_SOURCE);
    fixture.policy.evidence[0].source_sha256 = "0".repeat(64);
    let candidate = fixture.candidate(1, 2);
    let error = check::assess(
        &fixture.snapshot(),
        &fixture.policy,
        &fixture.reference,
        &fixture.policy_bytes,
        false,
        false,
        |_, _| {
            Ok(ScanResult {
                fingerprintable: true,
                candidates: vec![candidate.clone()],
            })
        },
        |_| Ok(PUBLIC_SOURCE.to_vec()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("source hashes differ"));
}

#[test]
fn metadata_deletion_blocks_even_without_added_source() {
    let fixture = Fixture::new();
    fixture.stage("source.py", PUBLIC_SOURCE);
    let snapshot = fixture.snapshot();
    let mut manifest = notices::load(&snapshot.files).unwrap();
    notices::upsert(
        &mut manifest,
        &fixture.policy.evidence[0],
        "source.py",
        1,
        2,
        PUBLIC_SOURCE,
        "Preserve this use",
    )
    .unwrap();
    for (path, bytes) in notices::proposed_files(&manifest).unwrap() {
        fixture.write(&path, &bytes);
    }
    fixture.commit();
    fixture.git(&["rm", "--", notices::MANIFEST_PATH]);
    let snapshot = fixture.snapshot();
    assert!(snapshot.added.is_empty());
    let report = check::assess(
        &snapshot,
        &fixture.policy,
        &fixture.reference,
        &fixture.policy_bytes,
        false,
        false,
        |_, _| panic!("unchanged source must not be scanned"),
        |_| Ok(PUBLIC_SOURCE.to_vec()),
    )
    .unwrap();
    assert!(!report.passed());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("manifest was removed"))
    );
}

#[test]
fn deleting_required_source_prefix_blocks_without_added_code() {
    let mut fixture = Fixture::new();
    let prefix = "# Required source attribution retained by admitted policy\n";
    fixture.policy.evidence[0].obligations = Obligations::SourcePrefix {
        text: prefix.into(),
    };
    fixture.policy_bytes = toml::to_string(&fixture.policy).unwrap().into_bytes();
    fixture.stage(policy::POLICY_PATH, &fixture.policy_bytes);
    let source = [prefix.as_bytes(), PUBLIC_SOURCE].concat();
    fixture.stage("source.py", &source);
    let mut manifest = notices::load(&fixture.snapshot().files).unwrap();
    notices::upsert(
        &mut manifest,
        &fixture.policy.evidence[0],
        "source.py",
        2,
        3,
        &source,
        "Preserve source-level attribution",
    )
    .unwrap();
    for (path, bytes) in notices::proposed_files(&manifest).unwrap() {
        fixture.write(&path, &bytes);
    }
    fixture.commit();
    fixture.reference = fixture.git(&["rev-parse", "HEAD"]);
    let before = fixture.snapshot();
    check::trusted_policy(&before, &fixture.reference, false).unwrap();
    assert!(fixture.assess(&before, Vec::new()).passed());

    fixture.stage("source.py", PUBLIC_SOURCE);
    let snapshot = fixture.snapshot();
    assert!(
        snapshot.added.is_empty(),
        "fixture must remove only the required prefix"
    );
    let report = fixture.assess(&snapshot, Vec::new());
    assert!(!report.passed());
    assert!(
        report.issues.iter().any(|issue| issue.contains("prefix")),
        "{:?}",
        report.issues
    );
}

#[test]
fn insufficient_coverage_and_empty_new_files_are_not_negative_matches() {
    let fixture = Fixture::new();
    fixture.stage("empty.rs", b"");
    fixture.stage("short.rs", b"short");
    fixture.stage("binary.rs", b"binary\0data");
    fixture.stage("invalid.rs", b"invalid\xff");
    let snapshot = fixture.snapshot();
    assert!(!snapshot.added.contains_key("empty.rs"));
    let mut scanned = Vec::new();
    let report = check::assess(
        &snapshot,
        &fixture.policy,
        &fixture.reference,
        &fixture.policy_bytes,
        false,
        false,
        |path, _| {
            scanned.push(path.to_owned());
            Ok(ScanResult {
                fingerprintable: false,
                candidates: Vec::new(),
            })
        },
        |_| Ok(PUBLIC_SOURCE.to_vec()),
    )
    .unwrap();
    assert_eq!(scanned, ["empty.rs", "short.rs"]);
    assert!(!report.passed());
    for path in ["empty.rs", "short.rs", "binary.rs", "invalid.rs"] {
        assert_eq!(source_status(&report, path), "unresolved");
    }
}

#[test]
fn exclusions_are_reported_explicitly_and_do_not_scan_excluded_bytes() {
    let mut fixture = Fixture::new();
    fixture.policy.exclude.push("vendor/".into());
    fixture.stage("vendor/blob.bin", b"private\0excluded");
    let report = check::assess(
        &fixture.snapshot(),
        &fixture.policy,
        &fixture.reference,
        &fixture.policy_bytes,
        false,
        false,
        |_, _| panic!("excluded bytes must not be scanned"),
        |_| Ok(PUBLIC_SOURCE.to_vec()),
    )
    .unwrap();
    assert!(report.passed());
    assert_eq!(source_status(&report, "vendor/blob.bin"), "excluded");
}

#[test]
fn unchanged_only_matches_are_distinct_from_a_negative_search() {
    let fixture = Fixture::new();
    fixture.stage("source.rs", b"unchanged\noriginal\n");
    fixture.commit();
    fixture.stage("source.rs", b"unchanged\noriginal\nnew line\n");
    let snapshot = fixture.snapshot();
    let report = fixture.assess(&snapshot, vec![fixture.candidate(1, 2)]);
    assert!(report.passed());
    assert_eq!(source_status(&report, "source.rs"), "unchanged_matches");
    assert!(report.files[0].findings.is_empty());
}

#[test]
fn explicit_negative_result_requires_complete_scanner_success() {
    let fixture = Fixture::new();
    fixture.stage("source.py", PUBLIC_SOURCE);
    let snapshot = fixture.snapshot();
    let report = fixture.assess(&snapshot, Vec::new());
    assert!(report.passed());
    assert_eq!(source_status(&report, "source.py"), "no_match");
    let error = check::assess(
        &snapshot,
        &fixture.policy,
        &fixture.reference,
        &fixture.policy_bytes,
        false,
        false,
        |_, _| anyhow::bail!("incomplete scanner response"),
        |_| Ok(PUBLIC_SOURCE.to_vec()),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("incomplete scanner response"));
}

#[test]
fn head_drift_during_scan_refuses_the_report() {
    let fixture = Fixture::new();
    fixture.stage("source.rs", b"candidate\n");
    let snapshot = fixture.snapshot();
    let error = check::assess(
        &snapshot,
        &fixture.policy,
        &fixture.reference,
        &fixture.policy_bytes,
        false,
        false,
        |_, _| {
            fixture.git(&["commit", "--allow-empty", "-m", "drift"]);
            Ok(ScanResult {
                fingerprintable: true,
                candidates: Vec::new(),
            })
        },
        |_| Ok(PUBLIC_SOURCE.to_vec()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("HEAD changed"));
}

#[test]
fn cli_init_is_inert_and_refuses_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let init = || {
        isolated(Command::new(BINARY))
            .arg("--repo")
            .arg(directory.path())
            .arg("init")
            .output()
            .unwrap()
    };
    exit(&init(), 0);
    let bytes = fs::read(directory.path().join(policy::POLICY_PATH)).unwrap();
    let policy = Policy::parse(&bytes).unwrap();
    assert!(!policy.scanner.enabled);
    assert!(policy.allow.is_empty());
    exit(&init(), 2);
    assert_eq!(
        fs::read(directory.path().join(policy::POLICY_PATH)).unwrap(),
        bytes
    );
}

#[test]
fn candidate_policy_cannot_admit_its_own_permissions() {
    let fixture = Fixture::new();
    let mut changed = fixture.policy.clone();
    changed.allow.push("Apache-2.0".into());
    fixture.stage(
        policy::POLICY_PATH,
        toml::to_string(&changed).unwrap().as_bytes(),
    );
    let snapshot = fixture.snapshot();
    let error = check::trusted_policy(&snapshot, &fixture.reference, false).unwrap_err();
    assert!(error.to_string().contains("candidate policy differs"));
    assert!(check::trusted_policy(&snapshot, &fixture.reference, true).is_ok());
}

#[test]
fn cli_requires_admission_and_evaluation_never_passes_or_admits() {
    let fixture = Fixture::new();
    let missing = fixture.cli(&["check", "--staged", "--format", "json"]);
    exit(&missing, 2);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("no admitted policy"));
    let evaluated = fixture.cli(&[
        "evaluate",
        "--all",
        "--initial-enrollment",
        "--head",
        &fixture.reference,
        "--policy-ref",
        &fixture.reference,
        "--format",
        "json",
    ]);
    exit(&evaluated, 1);
    let json: serde_json::Value = serde_json::from_slice(&evaluated.stdout).unwrap();
    assert_eq!(json["evaluation_only"], true);
    exit(&fixture.cli(&["check", "--staged"]), 2);
    exit(
        &fixture.cli(&["evaluate", "--policy-ref", &fixture.reference]),
        2,
    );
}

#[cfg(unix)]
#[test]
#[ignore = "Explicit public-fixture network verification against the hosted SCANOSS service"]
fn live_public_source_resolve_stage_and_real_precommit_gate() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.git(&[
        "config",
        "--local",
        "oss-provenance.policy-ref",
        &fixture.reference,
    ]);
    fixture.stage("source.py", PUBLIC_SOURCE);
    let sentinel = b"UNSTAGED SENTINEL: never scan or replace this worktree source\n";
    fixture.write("source.py", sentinel);
    let first = fixture.cli(&["check", "--staged", "--format", "json"]);
    exit(&first, 1);
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(
        report["files"][0]["findings"][0]["status"],
        "notice_required"
    );
    let proposal_parent = tempfile::tempdir().unwrap();
    let proposal = proposal_parent.path().join("proposal");
    exit(
        &fixture.cli(&[
            "resolve",
            "--staged",
            "--output",
            proposal.to_str().unwrap(),
            "--description",
            "Use the public MIT SCANOSS reference for provenance verification",
        ]),
        1,
    );
    assert_eq!(
        fs::read(fixture.path().join("source.py")).unwrap(),
        sentinel
    );
    assert!(!fixture.path().join(notices::MANIFEST_PATH).exists());
    let patch = proposal.join("notices.patch");
    fixture.git(&["apply", "--check", "-p2", patch.to_str().unwrap()]);
    fixture.git(&["apply", "-p2", patch.to_str().unwrap()]);
    assert!(fixture.path().join(notices::MANIFEST_PATH).exists());
    exit(&fixture.cli(&["check", "--staged"]), 1);
    fixture.git(&["add", "--", "LICENSE-NOTICES"]);
    exit(&fixture.cli(&["check", "--staged"]), 0);

    let hooks = fixture.path().join(".git/hooks");
    fixture.git(&[
        "config",
        "--local",
        "core.hooksPath",
        hooks.to_str().unwrap(),
    ]);
    let hook = hooks.join("pre-commit");
    let quoted_binary = BINARY.replace('\'', "'\\''");
    fs::write(
        &hook,
        format!("#!/bin/sh\nexec '{quoted_binary}' check --staged\n"),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let commit = |message: &str| {
        isolated(Command::new("git"))
            .arg("-C")
            .arg(fixture.path())
            .args(["-c", "commit.gpgsign=false", "commit", "-m", message])
            .output()
            .unwrap()
    };
    exit(&commit("public source with required notices"), 0);
    let head = fixture.git(&["rev-parse", "HEAD"]);
    fixture.git(&["rm", "--", notices::MANIFEST_PATH]);
    let blocked = commit("remove required attribution");
    assert!(
        !blocked.status.success(),
        "pre-commit allowed removed notice manifest"
    );
    assert_eq!(fixture.git(&["rev-parse", "HEAD"]), head);
    assert_eq!(
        fs::read(fixture.path().join("source.py")).unwrap(),
        sentinel
    );
}
