use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use oss_provenance::{
    check, evidence,
    git::{Blob, Scope, Snapshot},
    notices,
    policy::{self, Policy},
    scanner::Candidate,
};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Check staged source matches and enforce explicit reuse policy"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    repo: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Check(CheckArgs),
    Evaluate(CheckArgs),
    Resolve {
        #[command(flatten)]
        check: CheckArgs,
        #[arg(long, default_value = "Reuse of the matched source in this file")]
        description: String,
        #[arg(long, value_enum)]
        agent: Option<Agent>,
        #[arg(long)]
        brief: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Init,
    CollectEvidence {
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value_t = 0)]
        finding: usize,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        scancode_report: Option<PathBuf>,
        #[arg(long, requires = "scancode_report")]
        scancode_version: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Agent {
    Claude,
    Codex,
}

#[derive(Args)]
struct CheckArgs {
    #[arg(long, conflicts_with = "head")]
    staged: bool,
    #[arg(long)]
    all: bool,
    #[arg(long, requires = "all")]
    initial_enrollment: bool,
    #[arg(long, requires = "head")]
    base: Option<String>,
    #[arg(long)]
    head: Option<String>,
    #[arg(long)]
    policy_ref: Option<String>,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

impl CheckArgs {
    fn scope(&self) -> Result<Scope> {
        match (&self.base, &self.head) {
            (Some(base), Some(head)) => Ok(Scope::Range {
                base: base.clone(),
                head: head.clone(),
            }),
            (None, Some(head)) if self.all => Ok(Scope::Full { head: head.clone() }),
            (None, None) => Ok(Scope::Staged { all: self.all }),
            _ => bail!("use --staged, --all --head COMMIT, or --base BASE --head COMMIT"),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("oss-provenance: {error:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Init => {
            let root = fs::canonicalize(&cli.repo)?;
            let path = root.join(policy::POLICY_PATH);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .context("refusing to overwrite existing policy")?;
            file.write_all(policy::EXAMPLE.as_bytes())?;
            println!(
                "Created inert {}. Set your actual project license, use context, exclusions, rules and transmission consent before evaluation. No policy was admitted.",
                path.display()
            );
            Ok(0)
        }
        Commands::Check(args) => run_check_command(&cli.repo, args, false),
        Commands::Evaluate(args) => run_check_command(&cli.repo, args, true),
        Commands::Resolve {
            check: args,
            description,
            agent,
            brief,
            output,
        } => {
            ensure!(
                args.head.is_none() && args.base.is_none(),
                "resolve operates on the staged index only"
            );
            let reference = check::admitted_ref(&cli.repo, args.policy_ref.as_deref())?;
            let (snapshot, policy, report) =
                check::check(&cli.repo, args.scope()?, &reference, args.all, false)?;
            display(&report, args.format)?;
            if let Some(agent) = agent {
                let brief = brief.context(
                    "isolated rewrite requires --brief with independent behavioral requirements",
                )?;
                let output = output
                    .context("isolated rewrite requires --output for a new handoff directory")?;
                oss_provenance::repair::prepare_handoff(
                    &snapshot,
                    &report,
                    &brief,
                    &output,
                    match agent {
                        Agent::Claude => "claude",
                        Agent::Codex => "codex",
                    },
                )?;
                eprintln!(
                    "Prepared isolated rewrite handoff. Automatic agent execution and sandboxed candidate tests are not enabled on this platform; findings remain blocked."
                );
                return Ok(1);
            }
            check::ensure_resolvable(&report)?;
            ensure!(
                !report
                    .files
                    .iter()
                    .any(|f| f.status == "unresolved" && f.findings.is_empty()),
                "unsupported coverage must be resolved before writing notices"
            );
            let proposal =
                resolve_notices(&snapshot, &policy, &report, &description, output.as_deref())?;
            println!(
                "Notice proposal: {}. Review notices.patch, apply it with git apply --check -p2 then git apply -p2, stage the exact changed paths, and rerun check. The repository was not modified.",
                proposal.display()
            );
            Ok(1)
        }
        Commands::CollectEvidence {
            report,
            finding,
            output,
            scancode_report,
            scancode_version,
        } => {
            ensure!(!output.exists(), "evidence output directory already exists");
            let value: serde_json::Value = serde_json::from_slice(&fs::read(report)?)?;
            let raw = value
                .get("files")
                .and_then(|v| v.as_array())
                .context("report has no files")?
                .iter()
                .flat_map(|f| {
                    f.get("findings")
                        .and_then(|v| v.as_array())
                        .into_iter()
                        .flatten()
                })
                .nth(finding)
                .and_then(|f| f.get("candidate"))
                .context("finding not present in report")?;
            let candidate: Candidate = serde_json::from_value(raw.clone())?;
            let proposal = if let Some(path) = scancode_report {
                let version = scancode_version
                    .context("--scancode-version required with --scancode-report")?;
                evidence::collect_with_scancode_report(&candidate, 30, &fs::read(path)?, &version)?
            } else {
                evidence::collect(&candidate, 30)?
            };
            fs::create_dir(&output)?;
            fs::write(
                output.join("proposal.json"),
                serde_json::to_vec_pretty(&proposal)?,
            )?;
            for (path, contents) in &proposal.artifacts {
                policy::safe_path(path)?;
                let destination = output.join(path);
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(destination, contents)?;
            }
            println!(
                "Saved public upstream evidence to {}. This proposal is not admitted and does not clear the check.",
                output.display()
            );
            Ok(1)
        }
    }
}

fn run_check_command(root: &Path, args: CheckArgs, evaluation: bool) -> Result<i32> {
    ensure!(
        !evaluation || args.all,
        "maintenance evaluation requires --all"
    );
    ensure!(
        evaluation || args.head.is_none() || !args.all || args.base.is_some(),
        "enrolled full commit checks require --base for prior ledger history; use evaluate for initial enrollment"
    );
    ensure!(
        evaluation || !args.initial_enrollment,
        "--initial-enrollment is only for maintenance evaluation"
    );
    if evaluation && args.head.is_some() && args.base.is_none() {
        ensure!(
            args.initial_enrollment,
            "full evaluation requires --base, or explicit --initial-enrollment for a new project"
        );
        let existing = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["config", "--local", "--get", "oss-provenance.policy-ref"])
            .output()?;
        ensure!(
            existing.status.code() == Some(1),
            "an enrolled project requires a prior ledger --base"
        );
    }
    let reference = if evaluation {
        args.policy_ref
            .clone()
            .context("evaluation requires explicit --policy-ref")?
    } else {
        check::admitted_ref(root, args.policy_ref.as_deref())?
    };
    let (_, _, report) = check::check(root, args.scope()?, &reference, args.all, evaluation)?;
    display(&report, args.format)?;
    Ok(if report.passed() { 0 } else { 1 })
}

fn display(report: &check::Report, format: Format) -> Result<()> {
    if matches!(format, Format::Json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "Policy {}{}",
        report.policy_ref,
        if report.evaluation_only {
            " (evaluation only, not admitted)"
        } else {
            ""
        }
    );
    for file in &report.files {
        println!("{}: {}", file.path, file.status);
        for finding in &file.findings {
            println!("  {}: {}", finding.status, finding.reason);
        }
    }
    for issue in &report.issues {
        println!("unresolved: {issue}");
    }
    println!(
        "{}; no reported match is not proof of original authorship.",
        if report.passed() {
            "Check passed within reported coverage"
        } else {
            "Check blocked"
        }
    );
    Ok(())
}

fn resolve_notices(
    snapshot: &Snapshot,
    policy: &Policy,
    report: &check::Report,
    description: &str,
    output: Option<&Path>,
) -> Result<PathBuf> {
    ensure!(
        !description.trim().is_empty(),
        "notice description cannot be empty"
    );
    let conflicts = notices::validate_existing_readmes(&snapshot.files)?;
    ensure!(
        conflicts.is_empty(),
        "preserve existing README edits before resolution: {}",
        conflicts.join("; ")
    );
    let mut manifest = notices::load(&snapshot.files)?;
    notices::reconcile_retirements(&mut manifest, policy);
    for file in &report.files {
        for finding in &file.findings {
            if finding.status != "notice_required" {
                continue;
            }
            let evidence = policy
                .evidence_for(
                    finding
                        .candidate
                        .file_hash
                        .as_deref()
                        .context("missing source identity")?,
                )
                .context("missing admitted evidence")?;
            let bytes = &snapshot.files[&file.path].bytes;
            for (start, end) in &finding.candidate.local_ranges {
                notices::upsert(
                    &mut manifest,
                    evidence,
                    &file.path,
                    *start,
                    *end,
                    bytes,
                    description,
                )?;
            }
        }
    }
    let mut proposed = notices::proposed_files(&manifest)?;
    for entry in &manifest.entries {
        for artifact in &entry.evidence.artifacts {
            let bytes = snapshot
                .read_at(&report.policy_ref, &artifact.path)?
                .context("admitted artifact unavailable")?;
            policy::verify_artifact(artifact, &bytes)?;
            if let Some(existing) = proposed.insert(artifact.path.clone(), bytes.clone()) {
                ensure!(existing == bytes, "artifact collision");
            }
        }
    }
    let mut candidate = Snapshot::capture(&snapshot.root, Scope::Staged { all: false })?;
    for (path, bytes) in &proposed {
        candidate.files.insert(
            path.clone(),
            Blob {
                mode: "100644".into(),
                oid: policy::sha256(bytes),
                bytes: bytes.clone(),
            },
        );
    }
    let issues = notices::validate(&candidate, policy)?;
    ensure!(
        issues.is_empty(),
        "notice resolution cannot clear: {}",
        issues.join("; ")
    );
    write_proposal(snapshot, &proposed, output)
}

fn write_proposal(
    snapshot: &Snapshot,
    proposed: &BTreeMap<String, Vec<u8>>,
    output: Option<&Path>,
) -> Result<PathBuf> {
    snapshot.verify_unchanged()?;
    let output = if let Some(path) = output {
        fs::create_dir(path).context("proposal directory must be new")?;
        fs::canonicalize(path)?
    } else {
        tempfile::Builder::new()
            .prefix("oss-provenance-notices-")
            .tempdir()?
            .keep()
    };
    fs::create_dir(output.join("before"))?;
    fs::create_dir(output.join("after"))?;
    for (path, bytes) in proposed {
        policy::safe_path(path)?;
        let destination = output.join("after").join(path);
        let parent = destination.parent().context("invalid notice destination")?;
        fs::create_dir_all(parent)?;
        fs::write(destination, bytes)?;
        if let Some(old) = snapshot.files.get(path) {
            let previous = output.join("before").join(path);
            fs::create_dir_all(previous.parent().unwrap())?;
            fs::write(previous, &old.bytes)?;
        }
    }
    let diff = std::process::Command::new("git")
        .current_dir(&output)
        .args([
            "-c",
            "core.attributesFile=/dev/null",
            "diff",
            "--no-index",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--",
            "before",
            "after",
        ])
        .output()?;
    ensure!(
        matches!(diff.status.code(), Some(0 | 1)),
        "failed to generate notice patch: {}",
        String::from_utf8_lossy(&diff.stderr)
    );
    fs::write(output.join("notices.patch"), diff.stdout)?;
    fs::write(
        output.join("review.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"status":"proposal_only","policy":"rerun check after application and exact-path staging","paths":proposed.keys().collect::<Vec<_>>()}),
        )?,
    )?;
    snapshot.verify_unchanged()?;
    Ok(output)
}
