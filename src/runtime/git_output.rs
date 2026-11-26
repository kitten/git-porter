//! Streaming Git listings without retaining unrelated rows.
//! @ref LLP 0002#local-only-transport
use crate::{Result, runtime::supervision::Session};
use std::{
    io::{BufRead, BufReader, Read},
    process::{Command, ExitStatus, Stdio},
};

pub(crate) fn lines<T: Send>(
    mut command: Command,
    session: &Session,
    initial: T,
    mut consume: impl FnMut(&mut T, &[u8]) -> std::io::Result<()> + Send,
) -> Result<(ExitStatus, T)> {
    command.stdout(Stdio::piped());
    let mut child = session.spawn(command)?;
    let stdout = child.stdout.take().ok_or("missing Git listing output")?;
    std::thread::scope(|scope| {
        let reader = scope.spawn(move || -> std::io::Result<T> {
            let mut reader = BufReader::new(stdout);
            let mut state = initial;
            let mut row = Vec::new();
            loop {
                row.clear();
                // Bound one row, not the listing. Git object names are disabled
                // for graph walks; ref advertisements still need path space.
                if reader
                    .by_ref()
                    .take(16 * 1024 + 1)
                    .read_until(b'\n', &mut row)?
                    == 0
                {
                    break;
                }
                if row.len() > 16 * 1024 {
                    return Err(std::io::Error::other("Git listing row exceeds limit"));
                }
                if row.last() == Some(&b'\n') {
                    row.pop();
                }
                consume(&mut state, &row)?;
            }
            Ok(state)
        });
        let status = child.wait();
        drop(child); // Reap/close producers before joining, including cancellation.
        let state = reader.join().map_err(|_| "Git listing reader failed")??;
        Ok((status?, state))
    })
}
