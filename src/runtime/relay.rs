//! Bounded, cancelable raw Git relay with no thread left reading inherited stdin.
//! @ref LLP 0001#ownership
use crate::{Result, runtime::supervision::Session};
use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
};
struct Direction {
    input: OwnedFd,
    output: Option<OwnedFd>,
    bytes: Box<[u8; 65536]>,
    start: usize,
    end: usize,
    eof: bool,
}
impl Direction {
    fn new(input: OwnedFd, output: OwnedFd) -> io::Result<Self> {
        for fd in [&input, &output] {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            input,
            output: Some(output),
            bytes: Box::new([0; 65536]),
            start: 0,
            end: 0,
            eof: false,
        })
    }
    fn read(&mut self) -> io::Result<()> {
        if self.eof || self.start != self.end {
            return Ok(());
        }
        let count = unsafe {
            libc::read(
                self.input.as_raw_fd(),
                self.bytes.as_mut_ptr().cast(),
                self.bytes.len(),
            )
        };
        if count == 0 {
            self.eof = true;
            self.output.take();
        } else if count > 0 {
            self.start = 0;
            self.end = count as usize;
        } else {
            return transient();
        }
        Ok(())
    }
    fn write(&mut self) -> io::Result<()> {
        if self.start == self.end {
            return Ok(());
        }
        let output = self
            .output
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let count = unsafe {
            libc::write(
                output.as_raw_fd(),
                self.bytes[self.start..self.end].as_ptr().cast(),
                self.end - self.start,
            )
        };
        if count > 0 {
            self.start += count as usize;
        } else if count < 0 {
            return transient();
        }
        Ok(())
    }
    fn poll(&self) -> [libc::pollfd; 2] {
        [
            libc::pollfd {
                fd: if !self.eof && self.start == self.end {
                    self.input.as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if self.start != self.end {
                    self.output.as_ref().map_or(-1, AsRawFd::as_raw_fd)
                } else {
                    -1
                },
                events: libc::POLLOUT,
                revents: 0,
            },
        ]
    }
}
fn transient() -> io::Result<()> {
    let error = io::Error::last_os_error();
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        Ok(())
    } else {
        Err(error)
    }
}
pub(crate) fn run(
    session: &Session,
    input: std::process::ChildStdout,
    output: std::process::ChildStdin,
) -> Result<()> {
    let stdin = unsafe { BorrowedFd::borrow_raw(0) }.try_clone_to_owned()?;
    let stdout = unsafe { BorrowedFd::borrow_raw(1) }.try_clone_to_owned()?;
    let mut upload = Direction::new(stdin, output.into())?;
    let mut download = Direction::new(input.into(), stdout)?;
    loop {
        session.check()?;
        if download.eof && download.start == download.end {
            return Ok(());
        }
        let [a, b] = upload.poll();
        let [c, d] = download.poll();
        let mut poll = [a, b, c, d];
        if unsafe { libc::poll(poll.as_mut_ptr(), 4, 10) } < 0 {
            transient()?;
            continue;
        }
        if poll[0].revents != 0 {
            upload.read()?;
        }
        if poll[1].revents != 0 {
            upload.write()?;
        }
        if poll[2].revents != 0 {
            download.read()?;
        }
        if poll[3].revents != 0 {
            download.write()?;
        }
    }
}

/// Receiver data and the terminal result are demultiplexed before native Git.
pub(crate) fn framed(
    session: &Session,
    input: std::process::ChildStdout,
    output: std::process::ChildStdin,
) -> Result<crate::runtime::push_result::Report> {
    use crate::runtime::{
        protocol::DeadlineIo,
        push_result::{self, Frame},
    };
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    let stopped = AtomicBool::new(false);
    std::thread::scope(|scope| -> Result<_> {
        struct Stop<'a>(&'a AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let _stop = Stop(&stopped);
        let upload = scope.spawn(|| -> std::result::Result<(), String> {
            let run = || -> Result<()> {
                let stdin = unsafe { BorrowedFd::borrow_raw(0) }.try_clone_to_owned()?;
                let mut direction = Direction::new(stdin, output.into())?;
                while !stopped.load(Ordering::Relaxed) && !direction.eof {
                    session.check()?;
                    let mut poll = direction.poll();
                    if unsafe { libc::poll(poll.as_mut_ptr(), 2, 10) } < 0 {
                        transient()?;
                        continue;
                    }
                    if poll[0].revents != 0 {
                        direction.read()?;
                    }
                    if poll[1].revents != 0 && direction.write().is_err() {
                        break;
                    }
                }
                Ok(())
            };
            run().map_err(|e| e.to_string())
        });
        let result = (|| -> Result<_> {
            let mut input = DeadlineIo::new(input, std::time::Duration::from_secs(1200));
            input.cancel_on(session);
            let fd = unsafe { BorrowedFd::borrow_raw(1) }.try_clone_to_owned()?;
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut output = DeadlineIo::new(
                std::fs::File::from(fd),
                std::time::Duration::from_secs(1200),
            );
            output.cancel_on(session);
            let mut closed = false;
            loop {
                match push_result::read_frame(&mut input)? {
                    Frame::Data(bytes) => {
                        if !closed && let Err(e) = output.write_all(&bytes) {
                            if e.kind() == io::ErrorKind::BrokenPipe {
                                closed = true;
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                    Frame::Final(report) => {
                        let mut extra = [0];
                        if input.read(&mut extra)? != 0 {
                            return Err("trailing bytes after final push result".into());
                        }
                        return Ok(report);
                    }
                }
            }
        })();
        stopped.store(true, Ordering::Relaxed);
        let _ = upload.join().map_err(|_| "upload relay panicked")?;
        result
    })
}

pub(crate) fn receive_framed(
    session: &Session,
    mut command: std::process::Command,
    output: &mut impl std::io::Write,
) -> Result<std::process::ExitStatus> {
    use std::io::Read;
    command.stdout(std::process::Stdio::piped());
    let mut child = session.spawn(command)?;
    let mut input = crate::runtime::protocol::DeadlineIo::new(
        child.stdout.take().ok_or("missing Git output")?,
        std::time::Duration::from_secs(1200),
    );
    input.cancel_on(session);
    let mut bytes = [0; 65536];
    loop {
        let count = input.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        crate::runtime::push_result::write_data(output, &bytes[..count])?;
    }
    child.wait()
}
