//! Bounded pre-Git control framing. Never buffer beyond one frame.
//! @ref LLP 0001#framing
use crate::Result;
use std::io::{Read, Write};

pub const MAX_FRAME: usize = 16 * 1024;
pub const MAX_SESSION: usize = 64 * 1024;
pub const MAX_MESSAGES: usize = 8;
const VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Intent = 2,
    Resolved = 3,
    DeriveEd25519V2 = 4,
    Signature = 5,
    Ready = 6,
    Complete = 7,
    Error = 8,
    Signing = 9,
    SigningDone = 10,
    Result = 11,
}
impl TryFrom<u8> for Kind {
    type Error = &'static str;
    fn try_from(value: u8) -> std::result::Result<Self, &'static str> {
        Ok(match value {
            1 => Self::Hello,
            2 => Self::Intent,
            3 => Self::Resolved,
            4 => Self::DeriveEd25519V2,
            5 => Self::Signature,
            6 => Self::Ready,
            7 => Self::Complete,
            8 => Self::Error,
            9 => Self::Signing,
            10 => Self::SigningDone,
            11 => Self::Result,
            _ => return Err("unknown control message"),
        })
    }
}

#[derive(Default)]
pub struct Budget {
    bytes: usize,
    messages: usize,
    closed: bool,
}
impl Budget {
    fn charge(&mut self, length: usize) -> Result<()> {
        if self.closed || !(2..=MAX_FRAME).contains(&length) {
            self.closed = true;
            return Err("invalid frame length or closed control channel".into());
        }
        self.messages += 1;
        self.bytes += length + 4;
        if self.messages > MAX_MESSAGES || self.bytes > MAX_SESSION {
            self.closed = true;
            return Err("control session budget exceeded".into());
        }
        Ok(())
    }
    pub fn read(&mut self, input: &mut impl Read) -> Result<(Kind, Vec<u8>)> {
        if self.closed {
            return Err("closed control channel".into());
        }
        let result = (|| {
            let mut header = [0; 4];
            input.read_exact(&mut header)?;
            let length = u32::from_be_bytes(header) as usize;
            self.charge(length)?;
            let mut body = zeroize::Zeroizing::new(vec![0; length]);
            input.read_exact(&mut body)?;
            if body[0] != VERSION {
                return Err("unsupported control version".into());
            }
            let kind = Kind::try_from(body[1])?;
            Ok((kind, body[2..].to_vec()))
        })();
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    /// Read exactly the message required at this point in the conversation.
    pub fn expect(&mut self, input: &mut impl Read, expected: Kind) -> Result<Vec<u8>> {
        let frame = self.read(input)?;
        self.require(frame, expected)
    }
    pub(crate) fn require(&mut self, frame: (Kind, Vec<u8>), expected: Kind) -> Result<Vec<u8>> {
        if self.closed || frame.0 != expected {
            self.close();
            return Err(format!("expected {expected:?} control message").into());
        }
        Ok(frame.1)
    }
    pub fn expect_empty(&mut self, input: &mut impl Read, expected: Kind) -> Result<()> {
        if !self.expect(input, expected)?.is_empty() {
            self.close();
            return Err(format!("expected empty {expected:?} control message").into());
        }
        Ok(())
    }
    pub fn write(&mut self, output: &mut impl Write, kind: Kind, payload: &[u8]) -> Result<()> {
        let result = (|| {
            let length = payload.len().checked_add(2).ok_or("frame overflow")?;
            self.charge(length)?;
            output.write_all(&(length as u32).to_be_bytes())?;
            output.write_all(&[VERSION, kind as u8])?;
            output.write_all(payload)?;
            output.flush()?;
            Ok(())
        })();
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    pub fn close(&mut self) {
        self.closed = true;
    }
}

/// One shared operation state must own this across transport helper invocations.
/// Mark the signing allowance consumed before calling the agent, even on refusal.
/// @ref LLP 0001#signing
#[derive(Default)]
pub struct SigningBudget(bool);
impl SigningBudget {
    pub fn consume(&mut self) -> Result<()> {
        if std::mem::replace(&mut self.0, true) {
            return Err("derivation already attempted for this operation".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn leaves_native_git_bytes_unread() {
        let mut bytes = Vec::new();
        Budget::default()
            .write(&mut bytes, Kind::Ready, b"")
            .unwrap();
        bytes.extend_from_slice(b"0010native bytes");
        let mut input = Cursor::new(bytes);
        let mut budget = Budget::default();
        assert_eq!(budget.read(&mut input).unwrap(), (Kind::Ready, vec![]));
        budget.close();
        assert!(budget.read(&mut input).is_err());
        assert_eq!(input.position(), 6);
    }
    #[test]
    fn rejects_lengths_before_allocation_and_poisoned_retries() {
        for length in [0u32, 1, MAX_FRAME as u32 + 1, u32::MAX] {
            let mut budget = Budget::default();
            assert!(budget.read(&mut &length.to_be_bytes()[..]).is_err());
            assert!(budget.write(&mut Vec::new(), Kind::Hello, b"").is_err());
        }
    }
    #[test]
    fn rejects_truncation_unknown_types_and_versions() {
        for bytes in [
            vec![0, 0],
            vec![0, 0, 0, 2, 1],
            vec![0, 0, 0, 2, VERSION + 1, 1],
            vec![0, 0, 0, 2, 1, 99],
        ] {
            assert!(Budget::default().read(&mut &bytes[..]).is_err());
        }
    }
    #[test]
    fn signing_is_consumed_before_refusal() {
        let mut budget = SigningBudget::default();
        assert!(budget.consume().is_ok());
        assert!(budget.consume().is_err());
    }
    #[test]
    fn bounds_message_count() {
        let mut budget = Budget::default();
        for _ in 0..MAX_MESSAGES {
            budget.write(&mut Vec::new(), Kind::Hello, b"").unwrap();
        }
        assert!(budget.write(&mut Vec::new(), Kind::Hello, b"").is_err());
    }
}

#[cfg(test)]
mod order_tests {
    use super::*;
    #[test]
    fn unexpected_or_duplicate_messages_poison_the_channel() {
        for (actual, expected) in [
            (Kind::DeriveEd25519V2, Kind::Ready),
            (Kind::DeriveEd25519V2, Kind::Signature),
            (Kind::Ready, Kind::Complete),
            (Kind::Signature, Kind::Intent),
        ] {
            let mut bytes = vec![];
            Budget::default().write(&mut bytes, actual, b"").unwrap();
            let mut reader = std::io::Cursor::new(bytes);
            let mut budget = Budget::default();
            assert!(budget.expect(&mut reader, expected).is_err());
            let position = reader.position();
            assert!(budget.read(&mut reader).is_err());
            assert_eq!(reader.position(), position);
        }
    }
    #[test]
    fn prompt_markers_must_be_empty() {
        for kind in [Kind::Signing, Kind::SigningDone] {
            let mut bytes = vec![];
            Budget::default().write(&mut bytes, kind, b"extra").unwrap();
            let mut budget = Budget::default();
            assert!(budget.expect_empty(&mut &bytes[..], kind).is_err());
            assert!(budget.write(&mut vec![], Kind::Hello, b"").is_err());
        }
    }
}

/// Poll every individual I/O operation against one fixed setup deadline.
pub struct DeadlineIo<T> {
    inner: T,
    deadline: std::time::Instant,
    paused: Option<std::time::Instant>,
    cancellation: Option<crate::runtime::supervision::Cancellation>,
}
impl<T: std::os::fd::AsRawFd> DeadlineIo<T> {
    pub fn into_inner(self) -> T {
        self.inner
    }
    pub fn new(inner: T, timeout: std::time::Duration) -> Self {
        Self {
            inner,
            deadline: std::time::Instant::now() + timeout,
            paused: None,
            cancellation: None,
        }
    }
    pub fn pause(&mut self) -> Result<()> {
        if self.paused.is_some() || std::time::Instant::now() >= self.deadline {
            return Err("invalid signing pause or expired network deadline".into());
        }
        self.paused = Some(std::time::Instant::now());
        Ok(())
    }
    pub fn resume(&mut self) {
        if let Some(start) = self.paused.take() {
            self.deadline += start.elapsed();
        }
    }
    pub(crate) fn reset(&mut self, timeout: std::time::Duration) {
        self.deadline = std::time::Instant::now() + timeout;
    }
    pub(crate) fn cancel_on(&mut self, session: &crate::runtime::supervision::Session) {
        self.cancellation = Some(session.cancellation());
    }
    fn wait(&self, events: i16) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};
        loop {
            if self
                .cancellation
                .as_ref()
                .is_some_and(crate::runtime::supervision::Cancellation::is_cancelled)
            {
                return Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "session canceled or parent ended",
                ));
            }
            let deadline = self
                .paused
                .map(|start| start + std::time::Duration::from_secs(1200))
                .unwrap_or(self.deadline);
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| {
                    Error::new(ErrorKind::TimedOut, "session setup deadline exceeded")
                })?;
            let mut fd = libc::pollfd {
                fd: self.inner.as_raw_fd(),
                events,
                revents: 0,
            };
            let interval = if self.cancellation.is_some() {
                20
            } else {
                i32::MAX as u128
            };
            let timeout = remaining.as_millis().clamp(1, interval) as i32;
            let result = unsafe { libc::poll(&mut fd, 1, timeout) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 && self.cancellation.is_some() {
                continue;
            }
            if result == 0 {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "session setup deadline exceeded",
                ));
            }
            let error = Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}
impl<T: std::io::Read + std::os::fd::AsRawFd> std::io::Read for DeadlineIo<T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.wait(libc::POLLIN)?;
        self.inner.read(bytes)
    }
}
impl<T: std::io::Write + std::os::fd::AsRawFd> std::io::Write for DeadlineIo<T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.wait(libc::POLLOUT)?;
        // Frames never exceed 16 KiB. Preserve partial-write behavior.
        self.inner.write(&bytes[..bytes.len().min(512)])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    #[test]
    fn silent_peer_times_out_without_an_unbounded_header_read() {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut reader = DeadlineIo::new(stream, std::time::Duration::from_millis(20));
        assert!(Budget::default().read(&mut reader).is_err());
    }
}

/// Signing-prompt subprotocol: only empty BEGIN/END frames can pause the network
/// clock. Signature bytes still have the original remaining network allowance.
pub fn signature<T: Read + std::os::fd::AsRawFd, U: std::os::fd::AsRawFd>(
    budget: &mut Budget,
    input: &mut DeadlineIo<T>,
    output: &mut DeadlineIo<U>,
) -> Result<Vec<u8>> {
    budget.expect_empty(input, Kind::Signing)?;
    finish_approval(budget, input, output)?;
    budget.expect(input, Kind::Signature)
}
/// Called only after a validated empty SIGNING marker.
pub(crate) fn finish_approval<T: Read + std::os::fd::AsRawFd, U: std::os::fd::AsRawFd>(
    budget: &mut Budget,
    input: &mut DeadlineIo<T>,
    output: &mut DeadlineIo<U>,
) -> Result<()> {
    input.pause()?;
    if let Err(error) = output.pause() {
        input.resume();
        return Err(error);
    }
    let end = budget.expect_empty(input, Kind::SigningDone);
    input.resume();
    output.resume();
    end
}

#[cfg(test)]
mod prompt_tests {
    use super::*;
    #[test]
    fn prompt_pause_still_obeys_the_overall_session_ceiling() {
        let (receiver, mut sender) = std::os::unix::net::UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            let mut out = Budget::default();
            out.write(&mut sender, Kind::Signing, b"").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        let session = crate::runtime::supervision::Session::with_timeout(
            std::time::Duration::from_millis(40),
        )
        .unwrap();
        let mut reader = DeadlineIo::new(receiver, std::time::Duration::from_secs(1));
        reader.cancel_on(&session);
        let mut writer = DeadlineIo::new(
            reader.inner.try_clone().unwrap(),
            std::time::Duration::from_secs(1),
        );
        let error = signature(&mut Budget::default(), &mut reader, &mut writer)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("canceled") || error.contains("parent"),
            "{error}"
        );
        thread.join().unwrap();
    }

    #[test]
    fn approval_wait_is_not_network_time_but_signature_still_is_bounded() {
        let (receiver, mut sender) = std::os::unix::net::UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            let mut out = Budget::default();
            out.write(&mut sender, Kind::Signing, b"").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            out.write(&mut sender, Kind::SigningDone, b"").unwrap();
            out.write(&mut sender, Kind::Signature, &[7; 64]).unwrap();
            Budget::default()
                .expect_empty(&mut sender, Kind::Ready)
                .unwrap();
        });
        let mut reader = DeadlineIo::new(receiver, std::time::Duration::from_millis(50));
        let mut writer = DeadlineIo::new(
            reader.inner.try_clone().unwrap(),
            std::time::Duration::from_millis(50),
        );
        assert_eq!(
            signature(&mut Budget::default(), &mut reader, &mut writer).unwrap(),
            vec![7; 64]
        );
        Budget::default()
            .write(&mut writer, Kind::Ready, b"")
            .unwrap();
        thread.join().unwrap();
    }
}

#[cfg(test)]
mod mutation_tests {
    //! Reproducible mutation corpus: framing boundaries, short reads and typed input.
    use crate::{
        credentials::derivation::Request,
        credentials::wrapping::Metadata,
        runtime::protocol::{Budget, Kind, MAX_FRAME},
    };
    use std::io::{Cursor, Read};

    struct Fragments {
        bytes: Cursor<Vec<u8>>,
        maximum: usize,
    }
    impl Read for Fragments {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = output.len().min(self.maximum);
            self.bytes.read(&mut output[..length])
        }
    }

    #[test]
    fn mutated_setup_frames_are_bounded_and_failed_channels_never_resume() {
        let key = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let request = Request::new(
            key.public_key().clone(),
            Metadata::generate(key.public_key()).unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        let mut original = Vec::new();
        Budget::default()
            .write(&mut original, Kind::DeriveEd25519V2, &request)
            .unwrap();
        let mut state = 0x718c_a54d_1023_ef89u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as usize
        };
        for iteration in 0..16_384 {
            let mut bytes = original.clone();
            match iteration % 4 {
                0 => bytes.truncate(next() % (bytes.len() + 1)),
                1 => bytes[..4].copy_from_slice(&(next() as u32).to_be_bytes()),
                2 => {
                    for _ in 0..1 + next() % 8 {
                        let offset = next() % bytes.len();
                        bytes[offset] ^= (1 + next() % 255) as u8;
                    }
                }
                _ => bytes.extend((0..next() % 32).map(|_| next() as u8)),
            }
            let mut input = Fragments {
                bytes: Cursor::new(bytes),
                maximum: 1 + next() % 17,
            };
            let mut budget = Budget::default();
            match budget.read(&mut input) {
                Ok((kind, payload)) => {
                    assert!(payload.len() <= MAX_FRAME - 2);
                    // One frame consumes exactly its own bytes, even with coalesced
                    // trailing data or a reader delivering only one byte at a time.
                    assert_eq!(input.bytes.position() as usize, payload.len() + 6);
                    if kind == Kind::DeriveEd25519V2 {
                        let _ = Request::parse(&payload);
                    }
                }
                Err(_) => {
                    let position = input.bytes.position();
                    assert!(budget.read(&mut input).is_err());
                    assert_eq!(input.bytes.position(), position);
                }
            }
        }
    }
}

// @ref LLP 0002#search-policy
pub(crate) fn relative_hint(value: &str) -> crate::Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value.contains('\\')
        || value
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err("invalid relative repository hint".into());
    }
    Ok(())
}

#[cfg(test)]
mod hint_tests {
    #[test]
    fn relative_paths_are_bounded_and_cannot_traverse() {
        for path in [
            "",
            "/repo",
            "../repo",
            "org/../repo",
            "./repo",
            "org//repo",
            "org\nrepo",
            "org\\repo",
        ] {
            assert!(super::relative_hint(path).is_err(), "{path:?}");
        }
        assert!(super::relative_hint(&"x".repeat(4097)).is_err());
        assert!(super::relative_hint("kitten/git-porter").is_ok());
    }
}
