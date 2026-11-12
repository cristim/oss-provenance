use crate::process::{self, Limits};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    path::Path,
    process::Command,
    time::Duration,
};

const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_CANDIDATE: usize = 128 * 1024;
const CREDENTIAL_WRAPPER: &str = "IFS= read -r credential || exit 125; export \"$1=$credential\"; unset credential; shift; exec \"$@\"";

fn provider_input(credential: &std::ffi::OsStr, prompt: &str) -> Result<Vec<u8>> {
    let credential = credential
        .to_str()
        .context("provider credential must be valid UTF-8")?;
    ensure!(
        credential.len() <= 16 * 1024 && !credential.contains(['\r', '\n', '\0']),
        "provider credential must be at most 16 KiB and contain no NUL or line breaks"
    );
    Ok([credential.as_bytes(), b"\n", prompt.as_bytes()].concat())
}

#[derive(Debug)]
pub enum ProviderFailure {
    InvalidCandidate {
        session_id: String,
        cleanup_error: Option<String>,
    },
    IsolationViolation,
}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCandidate { .. } => "provider returned an invalid candidate",
            Self::IsolationViolation => "provider isolation metadata or events are invalid",
        })
    }
}

impl std::error::Error for ProviderFailure {}

pub struct Generated {
    pub session_id: String,
    pub files: BTreeMap<String, Vec<u8>>,
    pub cleanup_error: Option<String>,
}

pub struct TestOutcome {
    pub passed: bool,
    pub cleanup_error: Option<String>,
}

struct Execution {
    output: Result<std::process::Output>,
    started: bool,
    cleanup_error: Option<String>,
}

pub fn validate_image(image: &str) -> Result<()> {
    ensure!(
        image.starts_with("sha256:")
            && image.len() == 71
            && image[7..]
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "Docker images must use a full lowercase sha256 image ID"
    );
    Ok(())
}

fn docker() -> Command {
    let mut command = Command::new("docker");
    command
        .env_clear()
        .env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    command
}

fn container(name: &str, network: bool, cidfile: &Path) -> Command {
    let mut command = docker();
    command.args([
        "run",
        "--pull=never",
        "--name",
        name,
        "--read-only",
        "--user=65534:65534",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=512m",
        "--cpus=1",
        "--tmpfs=/tmp:rw,exec,nosuid,size=128m,mode=1777",
        "--env=HOME=/tmp",
        "--env=CLAUDE_CONFIG_DIR=/tmp/claude",
        "--workdir=/tmp",
        "--entrypoint=/usr/bin/timeout",
        "-i",
    ]);
    command.arg("--cidfile").arg(cidfile);
    if !network {
        command.arg("--network=none");
    }
    command
}

fn execute(
    command: &mut Command,
    cidfile: &Path,
    input: &[u8],
    timeout: Duration,
) -> Result<Execution> {
    let output = process::run(
        command,
        input,
        Limits {
            timeout,
            max_output_bytes: MAX_OUTPUT,
        },
    );
    let id = created_container(cidfile)?;
    let started = id.as_deref().is_some_and(test_started);
    let cleanup_error = id
        .as_deref()
        .and_then(|id| cleanup(id).err())
        .map(|error| format!("{error:#}"));
    Ok(Execution {
        output,
        started,
        cleanup_error,
    })
}

fn cleanup(id: &str) -> Result<()> {
    let output = process::run(
        docker().args(["rm", "--force", id]),
        b"",
        Limits {
            timeout: Duration::from_secs(10),
            max_output_bytes: 4096,
        },
    )
    .context("removing the created sandbox container")?;
    ensure!(
        output.status.success(),
        "created sandbox container cleanup failed"
    );
    Ok(())
}

fn created_container(path: &Path) -> Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 65,
        "invalid sandbox ownership record"
    );
    let mut value = String::new();
    fs::File::open(path)?.take(66).read_to_string(&mut value)?;
    let id = value.trim();
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid sandbox container ID"
    );
    Ok(Some(id.to_owned()))
}

fn test_started(name: &str) -> bool {
    let Ok(output) = process::run(
        docker().args(["inspect", "--format", "{{json .State}}", name]),
        b"",
        Limits {
            timeout: Duration::from_secs(3),
            max_output_bytes: 4096,
        },
    ) else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let Ok(state) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    state.get("Running").and_then(Value::as_bool).is_some()
        && state
            .get("StartedAt")
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() >= 20 && !value.starts_with("0001-"))
}

pub fn generate(
    image: &str,
    prompt: &str,
    targets: &[String],
    previous_sessions: &BTreeSet<String>,
) -> Result<Generated> {
    validate_image(image)?;
    let credentials: Vec<_> = ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]
        .into_iter()
        .filter_map(|key| {
            std::env::var_os(key)
                .filter(|value| !value.is_empty())
                .map(|value| (key, value))
        })
        .collect();
    ensure!(
        credentials.len() == 1,
        "set exactly one of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN for isolated generation"
    );
    let (key, value) = &credentials[0];
    let input = provider_input(value, prompt)?;
    let unique = tempfile::Builder::new()
        .prefix("ai-cleanroom-provider-")
        .tempdir()?;
    let name = unique
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .context("invalid container name")?;
    let cidfile = unique.path().join("cid");
    let mut command = container(name, true, &cidfile);
    command.args([
        "--log-driver=none",
        "--env=CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
        "--env=CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1",
        "--env=CLAUDE_CODE_DISABLE_POLICY_SKILLS=1",
        image,
        "--signal=KILL",
        "180",
        "/bin/sh",
        "-c",
        CREDENTIAL_WRAPPER,
        "ai-cleanroom-provider",
        key,
        "claude",
    ]);
    command.args(["--safe-mode", "--restricted", "--tools", "", "--strict-mcp-config", "--mcp-config", "{\"mcpServers\":{}}", "--setting-sources", "", "--settings", "{\"enabledPlugins\":{\"cc-plugin-agents-md@builtin\":false}}", "--no-session-persistence", "--disable-slash-commands", "--no-chrome", "--permission-mode", "dontAsk", "--permission-prompts", "none", "--system-prompt", "You are a fresh text-only implementation worker. Use only the independent requirements in this request. Return only a JSON object with files, an array of objects containing exactly path and content. Do not use tools, external sources, or Markdown fences.", "--verbose", "--output-format", "stream-json", "-p"]);
    let execution = execute(&mut command, &cidfile, &input, Duration::from_secs(190))?;
    ensure!(
        execution.started,
        "provider container startup could not be confirmed"
    );
    let output = execution.output?;
    ensure!(
        output.status.success(),
        "isolated provider did not complete successfully (exit {:?}); generation is paused",
        output.status.code()
    );
    match parse_generation(&output.stdout, targets, previous_sessions) {
        Ok(mut generated) => {
            generated.cleanup_error = execution.cleanup_error;
            Ok(generated)
        }
        Err(error) => {
            if let Some(ProviderFailure::InvalidCandidate { session_id, .. }) =
                error.downcast_ref::<ProviderFailure>()
            {
                return Err(ProviderFailure::InvalidCandidate {
                    session_id: session_id.clone(),
                    cleanup_error: execution.cleanup_error,
                }
                .into());
            }
            Err(error)
        }
    }
}

pub fn test(image: &str, candidate: &Path, trusted: &Path, argv: &[String]) -> Result<TestOutcome> {
    validate_image(image)?;
    ensure!(
        !argv.is_empty() && argv[0].starts_with('/'),
        "test command must start with an absolute container executable"
    );
    verify_test_environment(image, candidate, trusted, &argv[0])?;
    let unique = tempfile::Builder::new()
        .prefix("ai-cleanroom-test-")
        .tempdir()?;
    let name = unique
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .context("invalid container name")?;
    let cidfile = unique.path().join("cid");
    let mut command = container(name, false, &cidfile);
    mount_inputs(&mut command, candidate, trusted)?;
    command.arg(image).args(["--signal=KILL", "60"]).args(argv);
    classify_test(execute(
        &mut command,
        &cidfile,
        b"",
        Duration::from_secs(70),
    )?)
}

fn classify_test(execution: Execution) -> Result<TestOutcome> {
    ensure!(
        execution.started,
        "test container startup could not be confirmed"
    );
    let passed = match execution.output {
        Ok(output) => output.status.success(),
        Err(error) if error.is::<process::ProcessFailure>() => false,
        Err(error) => return Err(error),
    };
    Ok(TestOutcome {
        passed,
        cleanup_error: execution.cleanup_error,
    })
}

fn verify_test_environment(
    image: &str,
    candidate: &Path,
    trusted: &Path,
    executable: &str,
) -> Result<()> {
    let unique = tempfile::Builder::new()
        .prefix("ai-cleanroom-preflight-")
        .tempdir()?;
    let name = unique
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .context("invalid container name")?;
    let cidfile = unique.path().join("cid");
    let mut command = container(name, false, &cidfile);
    mount_inputs(&mut command, candidate, trusted)?;
    command.args([
        image,
        "--signal=KILL",
        "5",
        "/bin/sh",
        "-c",
        "test -f \"$1\" && test -x \"$1\" && /usr/bin/timeout --version",
        "ai-cleanroom-preflight",
        executable,
    ]);
    let execution = execute(&mut command, &cidfile, b"", Duration::from_secs(10))?;
    let output = execution.output?;
    ensure!(
        execution.started
            && output.status.success()
            && output.stdout.starts_with(b"timeout (GNU coreutils) "),
        "test image requires GNU timeout and an existing executable test command"
    );
    ensure!(
        execution.cleanup_error.is_none(),
        "test image preflight cleanup failed: {}",
        execution.cleanup_error.unwrap_or_default()
    );
    Ok(())
}

fn mount_inputs(command: &mut Command, candidate: &Path, trusted: &Path) -> Result<()> {
    for (source, destination) in [(candidate, "/candidate"), (trusted, "/trusted")] {
        let source = source.to_str().context("non-UTF-8 sandbox input path")?;
        ensure!(
            !source.contains([',', '\n', '\r']),
            "sandbox input path cannot contain Docker mount separators"
        );
        command.args([
            "--mount",
            &format!("type=bind,src={source},dst={destination},readonly"),
        ]);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    files: Vec<CandidateFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateFile {
    path: String,
    content: String,
}

pub fn parse_generation(
    output: &[u8],
    targets: &[String],
    previous_sessions: &BTreeSet<String>,
) -> Result<Generated> {
    let mut init = None;
    let mut result = None;
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let event: Value =
            serde_json::from_slice(line).map_err(|_| ProviderFailure::IsolationViolation)?;
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .context(ProviderFailure::IsolationViolation)?;
        match kind {
            "system" if event.get("subtype").and_then(Value::as_str) == Some("init") => {
                ensure!(
                    init.is_none() && result.is_none(),
                    ProviderFailure::IsolationViolation
                );
                for field in [
                    "tools",
                    "skills",
                    "mcp_servers",
                    "slash_commands",
                    "plugins",
                ] {
                    ensure!(
                        event
                            .get(field)
                            .and_then(Value::as_array)
                            .is_some_and(Vec::is_empty),
                        ProviderFailure::IsolationViolation
                    );
                }
                for field in ["plugin_errors", "mcp_server_errors"] {
                    ensure!(
                        event
                            .get(field)
                            .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
                        ProviderFailure::IsolationViolation
                    );
                }
                let session = event
                    .get("session_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .context(ProviderFailure::IsolationViolation)?;
                ensure!(
                    !previous_sessions.contains(session),
                    ProviderFailure::IsolationViolation
                );
                init = Some(session.to_owned());
            }
            "assistant" => {
                ensure!(
                    init.is_some() && result.is_none(),
                    ProviderFailure::IsolationViolation
                );
                ensure!(
                    event.get("session_id").and_then(Value::as_str) == init.as_deref(),
                    ProviderFailure::IsolationViolation
                );
                let content = event
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .context(ProviderFailure::IsolationViolation)?;
                ensure!(
                    content.iter().all(|block| matches!(
                        block.get("type").and_then(Value::as_str),
                        Some("text" | "thinking")
                    )),
                    ProviderFailure::IsolationViolation
                );
            }
            "result" => {
                ensure!(
                    init.is_some() && result.is_none(),
                    ProviderFailure::IsolationViolation
                );
                ensure!(
                    event.get("session_id").and_then(Value::as_str) == init.as_deref(),
                    ProviderFailure::IsolationViolation
                );
                ensure!(
                    event.get("subtype").and_then(Value::as_str) == Some("success")
                        && event.get("is_error").and_then(Value::as_bool) == Some(false),
                    "provider result was not successful"
                );
                result = Some(
                    event
                        .get("result")
                        .and_then(Value::as_str)
                        .context(ProviderFailure::InvalidCandidate {
                            session_id: init.clone().expect("validated init"),
                            cleanup_error: None,
                        })?
                        .to_owned(),
                );
            }
            _ => bail!(ProviderFailure::IsolationViolation),
        }
    }
    let session_id = init.context(ProviderFailure::IsolationViolation)?;
    let result = result.context(ProviderFailure::IsolationViolation)?;
    let files =
        parse_candidate(&result, targets).map_err(|_| ProviderFailure::InvalidCandidate {
            session_id: session_id.clone(),
            cleanup_error: None,
        })?;
    Ok(Generated {
        session_id,
        files,
        cleanup_error: None,
    })
}

fn parse_candidate(result: &str, targets: &[String]) -> Result<BTreeMap<String, Vec<u8>>> {
    let candidate: Candidate = serde_json::from_str(result)?;
    let mut files = BTreeMap::new();
    let mut size = 0usize;
    for file in candidate.files {
        size = size
            .checked_add(file.content.len())
            .context("candidate size overflow")?;
        ensure!(
            !file.content.trim().is_empty()
                && !file.content.contains('\0')
                && size <= MAX_CANDIDATE
                && targets.contains(&file.path),
            "invalid candidate contents or path"
        );
        ensure!(
            files.insert(file.path, file.content.into_bytes()).is_none(),
            "duplicate candidate path"
        );
    }
    ensure!(files.len() == targets.len(), "candidate target mismatch");
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_frame_preserves_prompt_and_rejects_line_injection() {
        let credential = "  local-$value;`tick`'\"\\backslash=checked  ";
        let prompt = "\n\nrequirements\\with\\backslashes\n";
        assert_eq!(
            provider_input(credential.as_ref(), prompt).unwrap(),
            format!("{credential}\n{prompt}").as_bytes()
        );
        for credential in ["dummy\rsecret", "dummy\nsecret", "dummy\0secret"] {
            let error = provider_input(credential.as_ref(), prompt).unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
        assert!(provider_input("x".repeat(16 * 1024 + 1).as_ref(), prompt).is_err());
        use std::os::unix::ffi::OsStrExt;
        assert!(provider_input(std::ffi::OsStr::from_bytes(&[255]), prompt).is_err());
    }

    #[test]
    #[ignore = "requires local Docker fixture image"]
    fn credential_wrapper_preserves_special_characters_and_remaining_stdin() {
        let image = std::env::var("AI_CLEANROOM_TEST_PROVIDER_IMAGE").unwrap();
        let token = "  local-$value;`tick`'\"\\backslash=checked  ";
        let prompt = "\n\nrequirements\\with\\backslashes\n";
        for key in ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"] {
            let unique = tempfile::Builder::new()
                .prefix("ai-cleanroom-framing-")
                .tempdir()
                .unwrap();
            let name = unique.path().file_name().unwrap().to_str().unwrap();
            let cidfile = unique.path().join("cid");
            let mut command = container(name, false, &cidfile);
            command.args([&image, "--signal=KILL", "5", "/bin/sh", "-c", CREDENTIAL_WRAPPER, "ai-cleanroom-provider", key, "/usr/local/bin/node", "-e", "const keys=['ANTHROPIC_API_KEY','CLAUDE_CODE_OAUTH_TOKEN'].filter(k=>process.env[k]);if(keys.length!==1||keys[0]!==process.argv[1]||require('node:crypto').createHash('sha256').update(process.env[keys[0]]).digest('hex')!==process.argv[2])process.exit(2);process.stdin.pipe(process.stdout)", key, &crate::policy::sha256(token.as_bytes())]);
            let execution = execute(
                &mut command,
                &cidfile,
                &provider_input(token.as_ref(), prompt).unwrap(),
                Duration::from_secs(10),
            )
            .unwrap();
            assert!(execution.started);
            assert!(execution.cleanup_error.is_none());
            let output = execution.output.unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, prompt.as_bytes());
        }
    }

    #[test]
    #[ignore = "requires local Docker fixture image"]
    fn pid_one_timeout_stops_children_after_client_is_killed() {
        let image = std::env::var("AI_CLEANROOM_TEST_PROVIDER_IMAGE").unwrap();
        let unique = tempfile::Builder::new()
            .prefix("ai-cleanroom-lifetime-")
            .tempdir()
            .unwrap();
        let name = unique.path().file_name().unwrap().to_str().unwrap();
        let cidfile = unique.path().join("cid");
        let mut client = container(name, false, &cidfile)
            .args([&image, "--signal=KILL", "2", "/usr/local/bin/node", "-e", "if(require('node:fs').readFileSync('/proc/1/comm','utf8').trim()!=='timeout')process.exit(2);require('node:child_process').spawn('/bin/sleep',['120'],{stdio:'ignore'});console.log('pid-one-verified');setInterval(()=>{},1000)"])
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let probe = |args: &[&str]| {
            process::run(
                docker().args(args),
                b"",
                Limits {
                    timeout: Duration::from_secs(3),
                    max_output_bytes: 4096,
                },
            )
            .unwrap()
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let id = loop {
            if let Ok(Some(id)) = created_container(&cidfile) {
                let logs = probe(&["logs", &id]);
                if logs.status.success() && logs.stdout == b"pid-one-verified\n" {
                    break id;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "container did not verify PID1"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        client.kill().unwrap();
        assert!(!client.wait().unwrap().success());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let state = probe(&["inspect", "--format", "{{.State.Running}}", &id]);
            assert!(state.status.success());
            if state.stdout == b"false\n" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "abandoned container kept running"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(probe(&["rm", "--force", &id]).status.success());
    }

    #[test]
    #[ignore = "requires local Docker fixture image"]
    fn running_output_limit_fails_tests_but_missing_image_is_operational() {
        let image = std::env::var("AI_CLEANROOM_TEST_PROVIDER_IMAGE").unwrap();
        let inputs = tempfile::tempdir().unwrap();
        let candidate = inputs.path().join("candidate");
        let trusted = inputs.path().join("trusted");
        std::fs::create_dir(&candidate).unwrap();
        std::fs::create_dir(&trusted).unwrap();
        assert!(
            !test(&image, &candidate, &trusted, &["/usr/bin/yes".into()])
                .unwrap()
                .passed
        );
        assert!(
            !test(
                &image,
                &candidate,
                &trusted,
                &[
                    "/usr/local/bin/node".into(),
                    "-e".into(),
                    "process.stdout.write('x'.repeat(9 * 1024 * 1024))".into()
                ]
            )
            .unwrap()
            .passed
        );
        let missing = format!("sha256:{}", "0".repeat(64));
        assert!(test(&missing, &candidate, &trusted, &["/usr/bin/yes".into()]).is_err());
        assert!(
            test(
                &image,
                &candidate,
                &trusted,
                &["/missing-executable".into()]
            )
            .is_err()
        );
        for code in [125, 126, 127] {
            let outcome = test(
                &image,
                &candidate,
                &trusted,
                &[
                    "/usr/local/bin/node".into(),
                    "-e".into(),
                    format!("process.exit({code})"),
                ],
            )
            .unwrap();
            assert!(!outcome.passed);
            assert!(outcome.cleanup_error.is_none());
        }
    }

    #[test]
    fn cleanup_failure_preserves_confirmed_test_outcome() {
        use std::os::unix::process::ExitStatusExt;
        for code in [0, 1, 125, 126, 127] {
            let outcome = classify_test(Execution {
                output: Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(code << 8),
                    stdout: vec![],
                    stderr: vec![],
                }),
                started: true,
                cleanup_error: Some("daemon became unavailable".into()),
            })
            .unwrap();
            assert_eq!(outcome.passed, code == 0);
            assert_eq!(
                outcome.cleanup_error.as_deref(),
                Some("daemon became unavailable")
            );
        }
        let outcome = classify_test(Execution {
            output: Err(process::ProcessFailure::OutputLimit.into()),
            started: true,
            cleanup_error: Some("cleanup timed out".into()),
        })
        .unwrap();
        assert!(!outcome.passed);
        assert_eq!(outcome.cleanup_error.as_deref(), Some("cleanup timed out"));
    }

    fn events() -> Vec<Value> {
        vec![
            serde_json::json!({"type":"system","subtype":"init","session_id":"new-session","tools":[],"skills":[],"mcp_servers":[],"slash_commands":[],"plugins":[]}),
            serde_json::json!({"type":"result","subtype":"success","is_error":false,"session_id":"new-session","result":"{\"files\":[{\"path\":\"source.py\",\"content\":\"def answer(): return 42\\n\"}]}"}),
        ]
    }

    fn parse(events: &[Value], seen: &BTreeSet<String>) -> Result<Generated> {
        let text = events
            .iter()
            .map(|event| serde_json::to_string(event).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        parse_generation(text.as_bytes(), &["source.py".into()], seen)
    }

    #[test]
    fn requires_a_fresh_empty_tool_session_and_exact_candidate() {
        let valid = events();
        assert_eq!(
            parse(&valid, &BTreeSet::new()).unwrap().files["source.py"],
            b"def answer(): return 42\n"
        );
        assert!(parse(&valid, &BTreeSet::from(["new-session".into()])).is_err());
        for field in [
            "tools",
            "skills",
            "mcp_servers",
            "slash_commands",
            "plugins",
        ] {
            let mut changed = valid.clone();
            changed[0][field] = serde_json::json!(["unexpected"]);
            assert!(parse(&changed, &BTreeSet::new()).is_err());
            changed[0].as_object_mut().unwrap().remove(field);
            assert!(parse(&changed, &BTreeSet::new()).is_err());
        }
        let mut changed = valid.clone();
        changed[1]["session_id"] = "other".into();
        assert!(parse(&changed, &BTreeSet::new()).is_err());
        let mut changed = valid;
        changed[1]["result"] = "{\"files\":[{\"path\":\"../escape\",\"content\":\"bad\"}]}".into();
        assert!(parse(&changed, &BTreeSet::new()).is_err());
    }

    #[test]
    fn rejects_tool_calls_and_nonexact_json() {
        let mut messages = events();
        messages.insert(1, serde_json::json!({"type":"assistant","session_id":"new-session","message":{"content":[{"type":"tool_use","name":"Read"}]}}));
        assert!(parse(&messages, &BTreeSet::new()).is_err());
        for content in [
            "not JSON",
            "{\"files\":[],\"extra\":true}",
            "{\"files\":[{\"path\":\"source.py\",\"content\":\"\"}]}",
        ] {
            let mut messages = events();
            messages[1]["result"] = content.into();
            assert!(parse(&messages, &BTreeSet::new()).is_err());
        }
    }
}
