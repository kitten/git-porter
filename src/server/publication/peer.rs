//! Kernel peer credentials and bounded, revalidated process ancestry.
use crate::Result;
use std::{
    os::fd::AsRawFd,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Process {
    pub pid: i32,
    pub parent: i32,
    pub birth: (u64, u64),
    pub executable: PathBuf,
}
#[cfg(target_os = "macos")]
pub(super) fn process(pid: i32) -> Result<Process> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    if unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    } != size
        || info.pbi_uid != unsafe { libc::geteuid() }
    {
        return Err("cannot authenticate process ownership".into());
    }
    let mut path = vec![0u8; 4096];
    let count = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if count <= 0 {
        return Err("cannot inspect process executable".into());
    }
    path.truncate(path.iter().position(|b| *b == 0).unwrap_or(count as usize));
    use std::os::unix::ffi::OsStringExt;
    Ok(Process {
        pid,
        parent: info.pbi_ppid as i32,
        birth: (info.pbi_start_tvsec, info.pbi_start_tvusec),
        executable: PathBuf::from(std::ffi::OsString::from_vec(path)),
    })
}
#[cfg(target_os = "linux")]
pub(super) fn process(pid: i32) -> Result<Process> {
    use std::os::unix::fs::MetadataExt;
    let dir = PathBuf::from(format!("/proc/{pid}"));
    if std::fs::metadata(&dir)?.uid() != unsafe { libc::geteuid() } {
        return Err("wrong process owner".into());
    }
    let text = std::fs::read_to_string(dir.join("stat"))?;
    let fields: Vec<_> = text
        .rsplit_once(')')
        .ok_or("invalid proc stat")?
        .1
        .split_whitespace()
        .collect();
    Ok(Process {
        pid,
        parent: fields.get(1).ok_or("missing parent")?.parse()?,
        birth: (fields.get(19).ok_or("missing birth")?.parse()?, 0),
        executable: std::fs::read_link(dir.join("exe"))?,
    })
}
pub(super) fn peer(stream: &UnixStream) -> Result<Process> {
    let fd = stream.as_raw_fd();
    #[cfg(target_os = "macos")]
    let pid = {
        let mut pid = 0i32;
        let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                0,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut i32).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        pid
    };
    #[cfg(target_os = "linux")]
    let pid = {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
            || cred.uid != unsafe { libc::geteuid() }
        {
            return Err("cannot authenticate socket peer".into());
        }
        cred.pid
    };
    process(pid)
}
pub(super) fn allowed(peer: &Process, owner: &Process, git: &Path, ssh: &Path) -> Result<()> {
    if peer.executable != ssh {
        return Err("agent peer is not the pinned ssh executable".into());
    }
    let mut chain = vec![peer.clone()];
    let mut git_seen = false;
    for _ in 0..64 {
        let current = chain.last().unwrap();
        if current.pid == owner.pid {
            if current != owner || !git_seen {
                break;
            }
            for item in &chain {
                if process(item.pid)? != *item {
                    return Err("process ancestry changed".into());
                }
            }
            return Ok(());
        }
        git_seen |= current.executable == git;
        let parent = process(current.parent)?;
        if chain.iter().any(|p| p.pid == parent.pid) {
            break;
        }
        chain.push(parent);
    }
    Err("ssh peer is not descended from this publication's Git command".into())
}
