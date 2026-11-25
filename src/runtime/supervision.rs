//! Transaction subprocess ownership, deadlines and signal cleanup.
//! @ref LLP 0001#ownership
use crate::Result;
use std::{
    io::Read,
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const MARKER: &str = "--porter-owned-command";
const CONTROL: &str = "GIT_PORTER_CHILD_CONTROL";
const GIT_CLEANUP: &str = "GIT_PORTER_GIT_CLEANUP";

/// Preserve normal Command environment/stdio behavior through an exec-only entry.
/// Session::spawn enables the separate key-free guardian for long-lived children.
pub fn command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let executable = std::env::current_exe()
        .expect("running executable path")
        .canonicalize()
        .expect("installed running executable");
    // Cargo's unit/integration harnesses live in deps; the internal library has
    // no separate installed API and uses the freshly built admin executable.
    let harness = executable
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.rsplit_once('-'))
        .is_some_and(|(_, suffix)| {
            suffix.len() == 16 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
        });
    let executable = if harness
        && executable
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|p| p == "deps")
    {
        executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("git-porter")
    } else {
        executable
    };
    let mut command = Command::new(executable);
    command
        .arg(MARKER)
        .arg(program)
        .env_remove(CONTROL)
        .env_remove(GIT_CLEANUP);
    command
}

/// One fixed session lifetime, shared with owned children and deadline-aware I/O.
#[derive(Clone)]
pub(crate) struct Cancellation {
    stopping: Arc<AtomicBool>,
    deadline: Instant,
    parent: libc::pid_t,
}
impl Cancellation {
    pub(crate) fn is_cancelled(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
            || Instant::now() >= self.deadline
            || unsafe { libc::getppid() } != self.parent
    }
}

pub struct OwnedChild {
    child: Child,
    control: std::os::unix::net::UnixStream,
    group: i32,
    cancellation: Cancellation,
}
impl std::ops::Deref for OwnedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}
impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}
impl OwnedChild {
    pub fn check(&self) -> Result<()> {
        if self.cancellation.is_cancelled() {
            return Err("transaction interrupted or timed out".into());
        }
        Ok(())
    }
    pub fn wait(&mut self) -> Result<ExitStatus> {
        loop {
            self.check()?;
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn kill(&mut self) -> std::io::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        unsafe {
            libc::kill(-self.group, libc::SIGKILL);
        }
        self.child.kill()
    }
}
impl OwnedChild {
    /// Graceful guardian EOF first, then bounded forced cleanup. Independent of cancellation.
    pub(crate) fn stop(&mut self) -> std::io::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        if let Err(error) = self.control.shutdown(std::net::Shutdown::Both)
            && error.kind() != std::io::ErrorKind::NotConnected
        {
            return Err(error);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.kill()?;
                self.child.wait()?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            crate::cli::terminal::warning(format_args!("owned subprocess cleanup: {error}"));
            let _ = self.kill();
            let _ = self.child.wait();
        }
    }
}

/// Dispatch before argv[0]-based hook/client parsing. No private material
/// crosses re-exec: the guardian receives only argv/environment and a liveness FD.
pub fn dispatch() -> Option<Result<()>> {
    // Git supplies transport argv, so internal argv[0] roles must validate it
    // themselves; their first argument can never select this local runner.
    let invoked = std::env::args_os().next().unwrap_or_default();
    if std::path::Path::new(&invoked)
        .file_name()
        .is_some_and(|name| {
            matches!(
                name.to_str(),
                Some("pre-receive" | "ssh" | "client-ssh" | "hydration-ssh")
            )
        })
    {
        return None;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_none_or(|a| a != MARKER) {
        return None;
    }
    Some(guardian(&args[1..]))
}
fn monotonic_nanos() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    u64::try_from(value.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| "monotonic clock exceeds startup format".into())
}
fn guardian(args: &[std::ffi::OsString]) -> Result<()> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::ExitStatusExt;
    let program = args.first().ok_or("missing owned executable")?;
    let mut command = Command::new(program);
    let git_cleanup = std::env::var_os(GIT_CLEANUP).is_some_and(|value| value == "1");
    command
        .args(&args[1..])
        .env_remove(CONTROL)
        .env_remove(GIT_CLEANUP);
    if std::env::var_os(CONTROL).is_none() {
        return Err(command.exec().into());
    }
    if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err("missing child control socket".into());
    }
    let control = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    control.peer_addr()?;
    let session = Session::new()?;
    // Announce readiness without starting native code, then require owner consent.
    let mut startup = crate::runtime::protocol::DeadlineIo::new(control, Duration::from_secs(2));
    startup.write_all(b"R")?;
    let mut permit = [0; 9];
    startup.read_exact(&mut permit)?;
    if permit[0] != b'G' {
        return Err("missing owner startup permit".into());
    }
    let mut control = startup.into_inner();
    control.set_nonblocking(true)?;
    // Refuse a permit whose owner closed the connection before we could act.
    let mut byte = [0];
    match control.read(&mut byte) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
        _ => return Err("owning process ended before native launch".into()),
    }
    if monotonic_nanos()? >= u64::from_be_bytes(permit[1..].try_into()?) {
        return Err("owner startup permit expired".into());
    }
    session.check()?;
    command.process_group(0);
    let mut child = command.spawn()?;
    let group = child.id() as i32;
    let result = (|| -> Result<ExitStatus> {
        control.write_all(&(group as u32).to_be_bytes())?;
        loop {
            session.check()?;
            let mut byte = [0];
            match control.read(&mut byte) {
                Ok(_) => return Err("owning process ended".into()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                Err(e) => return Err(e.into()),
            }
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            let mut poll = libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut poll, 1, 5);
            }
        }
    })();
    if result.is_err() && git_cleanup {
        unsafe {
            libc::kill(-group, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                _ => break,
            }
        }
    }
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    match result {
        Ok(status) => std::process::exit(
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
        ),
        // Cancellation is expected; never write control diagnostics onto Git stdout.
        Err(_) => std::process::exit(1),
    }
}

pub struct Session {
    cancellation: Cancellation,
    handlers: Vec<signal_hook::SigId>,
    cancel_on_drop: bool,
}
impl Session {
    pub fn new() -> Result<Self> {
        Self::with_timeout(Duration::from_secs(1200))
    }
    pub(crate) fn with_timeout(timeout: Duration) -> Result<Self> {
        let stopping = Arc::new(AtomicBool::new(false));
        let mut handlers = Vec::new();
        for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
            handlers.push(signal_hook::flag::register(signal, Arc::clone(&stopping))?);
        }
        disable_core_dumps()?;
        Ok(Self {
            cancellation: Cancellation {
                stopping,
                deadline: Instant::now() + timeout,
                parent: unsafe { libc::getppid() },
            },
            handlers,
            cancel_on_drop: true,
        })
    }
    /// A child operation cannot extend or cancel its owning session.
    pub(crate) fn bounded(&self, timeout: Duration) -> Result<Self> {
        self.check()?;
        let mut cancellation = self.cancellation();
        cancellation.deadline = cancellation.deadline.min(Instant::now() + timeout);
        Ok(Self {
            cancellation,
            handlers: Vec::new(),
            cancel_on_drop: false,
        })
    }
    #[cfg(test)]
    pub(crate) fn cancel(&self) {
        self.cancellation.stopping.store(true, Ordering::Relaxed);
    }
    pub fn check(&self) -> Result<()> {
        if self.cancellation.is_cancelled() {
            return Err("transaction interrupted, parent ended or timed out".into());
        }
        Ok(())
    }
    pub(crate) fn remaining(&self) -> Duration {
        self.cancellation
            .deadline
            .saturating_duration_since(Instant::now())
    }
    pub(crate) fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
    pub fn spawn(&self, mut command: Command) -> Result<OwnedChild> {
        use std::os::fd::AsRawFd;
        self.check()?;
        if command.get_args().next().is_none_or(|a| a != MARKER) {
            return Err("owned commands require supervision::command".into());
        }
        let (control, inherited) = std::os::unix::net::UnixStream::pair()?;
        let descriptor = inherited.as_raw_fd();
        command.env(CONTROL, "v1").process_group(0);
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(descriptor, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        drop(inherited);
        let allowance = Duration::from_secs(2).min(self.remaining());
        let startup_deadline = Instant::now() + allowance;
        let mut startup = crate::runtime::protocol::DeadlineIo::new(control, allowance);
        startup.cancel_on(self);
        let mut permitted = false;
        let handshake = (|| -> Result<i32> {
            let mut ready = [0];
            startup.read_exact(&mut ready)?;
            if ready != *b"R" {
                return Err("invalid guardian readiness".into());
            }
            self.check()?;
            use std::io::Write;
            let remaining = startup_deadline.saturating_duration_since(Instant::now());
            let deadline = monotonic_nanos()?
                .checked_add(u64::try_from(remaining.as_nanos())?)
                .ok_or("startup permit deadline overflow")?;
            let mut permit = vec![b'G'];
            permit.extend_from_slice(&deadline.to_be_bytes());
            startup.write_all(&permit)?;
            permitted = true;
            let mut pid = [0; 4];
            startup.read_exact(&mut pid)?;
            self.check()?;
            let group = u32::from_be_bytes(pid);
            if group < 2 || group > i32::MAX as u32 {
                return Err("invalid child group acknowledgement".into());
            }
            Ok(group as i32)
        })();
        let control = startup.into_inner();
        let group = match handshake {
            Ok(group) => group,
            Err(error) => {
                let _ = control.shutdown(std::net::Shutdown::Both);
                if !permitted {
                    // No native process can exist yet; kill the delayed guardian group.
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                    let _ = child.wait();
                } else {
                    // A permitted launch may own a separate native group. Let its guardian
                    // observe EOF and reap it before escalating the guardian itself.
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while child.try_wait()?.is_none() {
                        if Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                return Err(error);
            }
        };
        Ok(OwnedChild {
            child,
            control,
            group,
            cancellation: self.cancellation(),
        })
    }
    pub fn run(&self, mut command: Command, capture: bool) -> Result<(ExitStatus, Vec<u8>)> {
        self.check()?;
        command.stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
        let mut process = self.spawn(command)?;
        std::thread::scope(move |scope| {
            let reader = process.child.stdout.take().map(|stdout| {
                scope.spawn(move || {
                    let mut bytes = Vec::new();
                    stdout
                        .take(1024 * 1024 + 1)
                        .read_to_end(&mut bytes)
                        .map(|_| bytes)
                })
            });
            let status = process.wait();
            // Close the guardian before joining: descendants must not retain
            // stdout on cancellation, a wait error, or worker unwind.
            drop(process);
            let bytes = if let Some(reader) = reader {
                reader.join().map_err(|_| "subprocess reader failed")??
            } else {
                Vec::new()
            };
            let status = status?;
            if bytes.len() > 1024 * 1024 {
                return Err("subprocess output exceeds limit".into());
            }
            Ok((status, bytes))
        })
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.cancellation.stopping.store(true, Ordering::Relaxed);
        }
        for handler in self.handlers.drain(..) {
            signal_hook::low_level::unregister(handler);
        }
    }
}

pub fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err("cannot disable core dumps".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guardian_requires_a_live_unexpired_owner_permit_before_native_git() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        for expired in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let repo = directory.path().join("repo");
            git2::Repository::init_bare(&repo).unwrap();
            let (mut owner, inherited) = std::os::unix::net::UnixStream::pair().unwrap();
            owner
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let descriptor = inherited.as_raw_fd();
            let mut command = command(crate::server::config::executable("git").unwrap());
            command
                .arg("-C")
                .arg(&repo)
                .args(["config", "fixture.launched", "true"])
                .env(CONTROL, "v1")
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(descriptor, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut guardian = command.spawn().unwrap();
            drop(inherited);
            let mut ready = [0];
            owner.read_exact(&mut ready).unwrap();
            assert_eq!(ready, *b"R");
            if expired {
                let mut permit = vec![b'G'];
                permit.extend_from_slice(&0u64.to_be_bytes());
                owner.write_all(&permit).unwrap();
            } else {
                owner.shutdown(std::net::Shutdown::Both).unwrap();
            }
            let start = Instant::now();
            while guardian.try_wait().unwrap().is_none() {
                if start.elapsed() > Duration::from_secs(3) {
                    guardian.kill().unwrap();
                    guardian.wait().unwrap();
                    panic!("guardian did not refuse missing/expired permit");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(!guardian.wait().unwrap().success());
            assert!(
                git2::Config::open(&repo.join("config"))
                    .unwrap()
                    .get_string("fixture.launched")
                    .is_err()
            );
        }
    }
    #[test]
    fn bounded_sessions_share_cancellation_without_canceling_the_parent_on_drop() {
        let parent = Session::new().unwrap();
        {
            let child = parent.bounded(Duration::from_millis(30)).unwrap();
            std::thread::sleep(Duration::from_millis(40));
            assert!(child.check().is_err());
        }
        assert!(parent.check().is_ok());
        let child = parent.bounded(Duration::from_secs(60)).unwrap();
        parent.cancel();
        assert!(child.check().is_err());
        assert!(parent.bounded(Duration::from_secs(120)).is_err());
        let parent = Session::with_timeout(Duration::from_millis(20)).unwrap();
        let child = parent.bounded(Duration::from_secs(120)).unwrap();
        assert_eq!(child.cancellation.deadline, parent.cancellation.deadline);
        let orphan = {
            let owner = Session::new().unwrap();
            owner.bounded(Duration::from_secs(60)).unwrap()
        };
        assert!(orphan.check().is_err());
    }
    #[test]
    fn fixed_deadline_stops_and_reaps_a_child() {
        let session = Session::new().unwrap();
        let mut command = command("/bin/sh");
        let directory = tempfile::tempdir().unwrap();
        let pid = directory.path().join("child-pid");
        command
            .args(["-c", "printf '%s' $$ > \"$1\"; exec sleep 30", "fixture"])
            .arg(&pid);
        let mut child = session.spawn(command).unwrap();
        let startup = Instant::now();
        while !pid.exists() {
            assert!(startup.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(5));
        }
        // Measure cancellation after readiness, independently of cold exec
        // latency (including CPU-emulated qualification).
        child.cancellation.deadline = Instant::now() + Duration::from_millis(100);
        let start = Instant::now();
        assert!(child.wait().is_err());
        drop(child);
        assert!(start.elapsed() < Duration::from_secs(2));
        let pid: i32 = std::fs::read_to_string(pid).unwrap().parse().unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }
}
