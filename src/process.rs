use anyhow::{Context, Result, bail};
use std::{
    fmt,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub struct Limits {
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, PartialEq)]
pub enum ProcessFailure {
    Timeout,
    OutputLimit,
}

impl fmt::Display for ProcessFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Timeout => "process deadline exceeded",
            Self::OutputLimit => "process output limit exceeded",
        })
    }
}

impl std::error::Error for ProcessFailure {}

struct Running {
    child: Child,
    reaped: bool,
}

impl Running {
    fn exited(&self) -> Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error()).context("observing bounded process");
        }
        Ok(info.si_signo != 0)
    }

    fn finish(&mut self) -> io::Result<std::process::ExitStatus> {
        // Retaining the unreaped group leader prevents PID/PGID reuse before signaling.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.finish();
        }
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error()).context("setting process pipe nonblocking");
    }
    Ok(())
}

fn read_pipe(pipe: &mut impl Read, output: &mut Vec<u8>, remaining: usize) -> Result<bool> {
    let mut buffer = [0; 8192];
    match pipe.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(count) => {
            if count > remaining {
                bail!(ProcessFailure::OutputLimit);
            }
            output.extend_from_slice(&buffer[..count]);
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error).context("reading process output"),
    }
}

pub fn run(command: &mut Command, input: &[u8], limits: Limits) -> Result<Output> {
    let deadline = Instant::now()
        .checked_add(limits.timeout)
        .context("process timeout is too large")?;
    let mut child = Running {
        child: command
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting bounded process")?,
        reaped: false,
    };
    let mut stdin = child.child.stdin.take();
    let mut stdout_pipe = child
        .child
        .stdout
        .take()
        .context("missing process stdout")?;
    let mut stderr_pipe = child
        .child
        .stderr
        .take()
        .context("missing process stderr")?;
    nonblocking(stdin.as_ref().context("missing process stdin")?)?;
    nonblocking(&stdout_pipe)?;
    nonblocking(&stderr_pipe)?;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let (mut stdout_done, mut stderr_done) = (false, false);
    let mut written = 0;
    loop {
        if Instant::now() >= deadline {
            bail!(ProcessFailure::Timeout);
        }
        if written == input.len() {
            stdin = None;
        }
        if let Some(pipe) = &mut stdin {
            let end = input.len().min(written.saturating_add(8192));
            match pipe.write(&input[written..end]) {
                Ok(0) => bail!("process stdin closed before input was written"),
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => stdin = None,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error).context("writing process input"),
            }
        }
        if !stdout_done {
            let remaining = limits.max_output_bytes - stdout.len() - stderr.len();
            stdout_done = read_pipe(&mut stdout_pipe, &mut stdout, remaining)?;
        }
        if !stderr_done {
            let remaining = limits.max_output_bytes - stdout.len() - stderr.len();
            stderr_done = read_pipe(&mut stderr_pipe, &mut stderr, remaining)?;
        }
        if child.exited()? && stdout_done && stderr_done {
            let status = child.finish().context("reaping bounded process")?;
            anyhow::ensure!(
                !status.success() || written == input.len(),
                "process succeeded without accepting its complete input"
            );
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(bytes: usize) -> Limits {
        Limits {
            timeout: Duration::from_secs(2),
            max_output_bytes: bytes,
        }
    }

    #[test]
    fn exchanges_input_and_captures_exit_status() {
        let result = run(Command::new("/bin/cat").arg("-"), b"hello\n", limits(6)).unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"hello\n");
        assert!(result.stderr.is_empty());
        let result = run(&mut Command::new("/usr/bin/false"), b"", limits(1)).unwrap();
        assert!(!result.status.success());
    }

    #[test]
    fn combines_stdout_and_stderr_budget() {
        let error = run(
            Command::new("/bin/sh").args(["-c", "printf 123; printf 456 >&2"]),
            b"",
            limits(5),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<ProcessFailure>(),
            Some(&ProcessFailure::OutputLimit)
        );
    }

    #[test]
    fn successful_exit_cannot_discard_input() {
        let error = run(
            &mut Command::new("/usr/bin/true"),
            &vec![b'x'; 1024 * 1024],
            limits(64),
        )
        .unwrap_err();
        assert!(error.to_string().contains("complete input"));
        let result = run(
            &mut Command::new("/usr/bin/false"),
            &vec![b'x'; 1024 * 1024],
            limits(64),
        )
        .unwrap();
        assert!(!result.status.success());
    }

    #[test]
    fn observes_without_reaping_until_group_cleanup() {
        let mut running = Running {
            child: Command::new("/usr/bin/true")
                .process_group(0)
                .spawn()
                .unwrap(),
            reaped: false,
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !running.exited().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(running.exited().unwrap());
        assert_eq!(unsafe { libc::kill(running.child.id() as i32, 0) }, 0);
        assert!(running.finish().unwrap().success());
        assert!(running.reaped);
        assert!(running.exited().is_err());
    }

    #[test]
    fn kills_descendants_even_after_parent_exits() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("survived");
        let error = run(
            Command::new("/bin/sh")
                .args(["-c", "(sleep 1; touch \"$1\") &", "probe"])
                .arg(&marker),
            b"",
            Limits {
                timeout: Duration::from_millis(80),
                max_output_bytes: 1024,
            },
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<ProcessFailure>(),
            Some(&ProcessFailure::Timeout)
        );
        std::thread::sleep(Duration::from_millis(1100));
        assert!(!marker.exists());
    }
}
