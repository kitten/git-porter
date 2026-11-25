//! Sender object hydration outside the receiver-pinned transport.
//! @ref LLP 0002#client-git-configuration
use super::repository::Repository;
use crate::{Result, runtime::supervision::Session};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    os::fd::AsRawFd,
    path::Path,
    process::{Command, Stdio},
};

pub(super) fn prepare(
    repository: &Repository,
    sha: &str,
    mut observe: Command,
    user_ssh: &str,
    admin: &Path,
    directory: &Path,
    session: &Session,
) -> Result<()> {
    let primary = repository.config_value("extensions.partialClone");
    let remotes = repository.output(&["remote"])?;
    let mut sources: Vec<_> = remotes.lines().collect();
    let promisors: Vec<_> = remotes
        .lines()
        .filter(|name| {
            primary.as_deref() == Some(*name)
                || repository
                    .output(&[
                        "config",
                        "--type=bool",
                        "--get",
                        &format!("remote.{name}.promisor"),
                    ])
                    .is_ok_and(|v| v == "true")
                || repository
                    .config_value(&format!("remote.{name}.partialclonefilter"))
                    .is_some()
        })
        .collect();
    let mut partial = !promisors.is_empty();
    if !partial {
        let packs = repository.output(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects/pack",
        ])?;
        match fs::read_dir(packs) {
            Ok(entries) => {
                for entry in entries {
                    partial |= entry?
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "promisor");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    let shallow_path = repository.output(&[
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "shallow",
    ])?;
    let shallow = || -> Result<HashSet<String>> {
        match fs::read_to_string(&shallow_path) {
            Ok(value) => Ok(value.lines().map(str::to_owned).collect()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(HashSet::new()),
            Err(error) => Err(error.into()),
        }
    };
    if shallow()?.is_empty() && !partial {
        return Ok(());
    }
    let helper = directory.join("hydration-ssh");
    std::os::unix::fs::symlink(admin, &helper)?;
    let roots = directory.join("hydration-roots");
    let objects = directory.join("hydration-objects");
    let common = repository.output(&["rev-parse", "--path-format=absolute", "--git-common-dir"])?;
    let lock = File::open(common)?;
    while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Err(error.into());
        }
        session.check()?;
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let advertised = directory.join("advertised");
    observe.stdout(File::create(&advertised)?);
    if !session.spawn(observe)?.wait()?.success() {
        return Err("cannot inspect receiver history; push not attempted".into());
    }
    let mut revisions = File::create(&roots)?;
    writeln!(revisions, "{sha}")?;
    for line in BufReader::new(File::open(&advertised)?).split(b'\n') {
        let line = line?;
        let tab = line
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or("invalid receiver advertisement")?;
        let oid = &line[..tab];
        if !matches!(oid.len(), 40 | 64) || !oid.iter().all(u8::is_ascii_hexdigit) {
            return Err("invalid receiver object ID".into());
        }
        writeln!(revisions, "^{}", std::str::from_utf8(oid)?)?;
    }
    drop(revisions);
    let fetch = |remote: &str, batch: &[String], deepen: Option<u32>| -> Result<bool> {
        let requests = directory.join("hydration-requests");
        let mut file = File::create(&requests)?;
        for oid in batch {
            writeln!(file, "{oid}")?;
        }
        drop(file);
        let mut command = repository.command();
        command
            .env("GIT_PORTER_USER_SSH", user_ssh)
            .env("GIT_SSH_COMMAND", crate::cli::ssh::quoted_path(&helper))
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_PORTER_GIT_CLEANUP", "1");
        if partial {
            command
                .arg("-c")
                .arg(format!("remote.{remote}.partialclonefilter=blob:none"));
        }
        command.args([
            "-c",
            "fetch.negotiationAlgorithm=noop",
            "-c",
            "fetch.bundleURI=",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "fetch",
            remote,
            "--no-tags",
            "--no-prune",
            "--no-prune-tags",
            "--no-write-fetch-head",
            "--recurse-submodules=no",
            "--refmap=",
            "--stdin",
        ]);
        if let Some(depth) = deepen {
            command.arg(format!("--deepen={depth}"));
        }
        command.stdin(File::open(&requests)?).stdout(Stdio::null());
        Ok(session.spawn(command)?.wait()?.success())
    };
    let mut previous = Vec::new();
    let mut depth = 256u32;
    loop {
        session.check()?;
        let boundaries = shallow()?;
        if boundaries.is_empty() && !partial {
            return Ok(());
        }
        let mut scan = repository.command();
        scan.env("GIT_NO_LAZY_FETCH", "1")
            .args([
                "rev-list",
                "--missing=print",
                "--ignore-missing",
                "--boundary",
                "--stdin",
            ])
            .stdin(File::open(&roots)?)
            .stdout(File::create(&objects)?);
        if !session.spawn(scan)?.wait()?.success() {
            return Err("cannot enumerate sender objects; push not attempted".into());
        }
        let edges = directory.join("hydration-edges");
        let mut edge_roots = File::create(&edges)?;
        let mut frontier = Vec::new();
        for line in BufReader::new(File::open(&objects)?).lines() {
            let line = line?;
            if let Some(oid) = line.strip_prefix('-') {
                writeln!(edge_roots, "{oid}")?;
            }
            if boundaries.contains(&line) {
                frontier.push(line);
            }
        }
        drop(edge_roots);
        if !frontier.is_empty() {
            let mut progressed = false;
            for batch in std::iter::once(frontier.as_slice()).chain(
                frontier
                    .iter()
                    .map(std::slice::from_ref)
                    .filter(|_| frontier.len() > 1),
            ) {
                for index in 0..sources.len() {
                    let _ = fetch(sources[index], batch, Some(depth))?;
                    let updated = shallow()?;
                    if frontier.iter().any(|root| !updated.contains(root)) {
                        sources.swap(0, index);
                        progressed = true;
                        break;
                    }
                }
                if progressed {
                    break;
                }
            }
            if !progressed {
                return Err("cannot deepen required sender history from its configured remotes; push not attempted".into());
            }
            depth = depth.saturating_mul(2).min(i32::MAX as u32);
            continue;
        }
        if !partial {
            return Ok(());
        }
        let catalog = |input: &Path, options: &[&str]| -> Result<Vec<String>> {
            let mut command = repository.command();
            command
                .env("GIT_NO_LAZY_FETCH", "1")
                .args([
                    "rev-list",
                    "--objects",
                    "--missing=print",
                    "--no-object-names",
                ])
                .args(options)
                .arg("--stdin")
                .stdin(File::open(input)?)
                .stdout(File::create(&objects)?);
            if !session.spawn(command)?.wait()?.success() {
                return Err("cannot enumerate required sender objects; push not attempted".into());
            }
            let mut missing = Vec::new();
            for line in BufReader::new(File::open(&objects)?).lines() {
                if let Some(oid) = line?.strip_prefix('?') {
                    missing.push(oid.to_owned());
                }
            }
            Ok(missing)
        };
        let mut missing = catalog(&edges, &["--no-walk", "--filter=blob:none"])?;
        if missing.is_empty() {
            missing = catalog(&roots, &["--ignore-missing"])?;
        }
        missing.sort_unstable();
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }
        if promisors.is_empty() {
            return Err(
                "required sender objects have no configured promisor remote; push not attempted"
                    .into(),
            );
        }
        if missing == previous {
            return Err("required sender objects are unavailable from its promisor remotes; push not attempted".into());
        }
        previous = missing.clone();
        let mut pending = vec![missing.as_slice()];
        while let Some(batch) = pending.pop() {
            let mut fetched = false;
            for remote in &promisors {
                if fetch(remote, batch, None)? {
                    fetched = true;
                    break;
                }
            }
            if !fetched {
                if batch.len() == 1 {
                    return Err("required sender objects are unavailable from its promisor remotes; push not attempted".into());
                }
                let (left, right) = batch.split_at(batch.len() / 2);
                pending.extend([right, left]);
            }
        }
    }
}
