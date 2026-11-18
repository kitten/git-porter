//! Bounded local socket connection shared by provisioning and source-agent access.
//! @ref LLP 0001#signing
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    time::{Duration, Instant},
};

pub(crate) fn connect(path: &Path, timeout: Duration) -> std::io::Result<UnixStream> {
    connect_with(path, timeout, None)
}
pub(crate) fn connect_in(
    path: &Path,
    timeout: Duration,
    session: &super::supervision::Session,
) -> std::io::Result<UnixStream> {
    connect_with(
        path,
        timeout.min(session.remaining()),
        Some(session.cancellation()),
    )
}
fn connect_with(
    path: &Path,
    timeout: Duration,
    cancel: Option<super::supervision::Cancellation>,
) -> std::io::Result<UnixStream> {
    let check = || -> std::io::Result<()> {
        if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "session canceled",
            ))
        } else {
            Ok(())
        }
    };
    check()?;
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    let address = SockAddr::unix(path)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    'connect: loop {
        check()?;
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Unix socket connection deadline exceeded",
            ));
        }
        match socket.connect(&address) {
            Ok(()) => break,
            Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => loop {
                check()?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                let milliseconds = remaining.as_millis().max(1).min(if cancel.is_some() {
                    20
                } else {
                    i32::MAX as u128
                }) as i32;
                let mut fd = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut fd, 1, milliseconds) };
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                if result == 0 {
                    continue;
                }
                if let Some(error) = socket.take_error()? {
                    return Err(error);
                }
                break 'connect;
            },
            // A full Unix-listener backlog can return EAGAIN, not EINPROGRESS.
            // It must be retried against the same deadline, not treated as connected.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
    socket.set_nonblocking(false)?;
    let descriptor: std::os::fd::OwnedFd = socket.into();
    Ok(UnixStream::from(descriptor))
}
