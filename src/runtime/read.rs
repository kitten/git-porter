//! Explicit origin refresh and hydration in the operator repository.
//! @ref LLP 0002#local-only-transport
use crate::{Result, runtime::supervision::Session};
use std::{
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

/// Shared origin lookup; route-specific callers still confine/authorize the URL.
pub(crate) fn origin(make: impl Fn() -> Command, session: &Session) -> Result<Option<String>> {
    let mut probe = make();
    probe
        .args(["config", "--get-all", "remote.origin.url"])
        .stdout(Stdio::null());
    match session.spawn(probe)?.wait()?.code() {
        Some(1) => return Ok(None),
        Some(0) => (),
        _ => return Err("cannot read receiver origin configuration".into()),
    }
    let mut command = make();
    command.args(["remote", "get-url", "--all", "origin"]);
    let (status, bytes) = session.run(command, true)?;
    if !status.success() {
        return Err("cannot resolve receiver origin".into());
    }
    let text = std::str::from_utf8(&bytes)?;
    let urls: Vec<_> = text.lines().collect();
    let [url] = urls.as_slice() else {
        return Err("origin requires exactly one fetch URL".into());
    };
    if url.is_empty() {
        return Err("origin fetch URL is empty".into());
    }
    Ok(Some((*url).to_owned()))
}

pub(crate) fn validate_reference(
    mut git: Command,
    reference: &str,
    session: &Session,
) -> Result<()> {
    if !crate::runtime::push_result::read_reference(reference) {
        return Err("expected branch reference".into());
    }
    git.args(["check-ref-format", reference]);
    if !session.run(git, false)?.0.success() {
        return Err("invalid receive branch".into());
    }
    Ok(())
}

fn metadata(
    make: &impl Fn() -> Command,
    arguments: &[&str],
    session: &Session,
) -> Result<Option<String>> {
    let mut command = make();
    command
        .env("GIT_NO_LAZY_FETCH", "1")
        .arg("rev-parse")
        .args(arguments)
        .stderr(Stdio::null());
    let (status, bytes) = session.run(command, true)?;
    if !status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(bytes)?;
    Ok(Some(text.strip_suffix('\n').unwrap_or(&text).to_owned()))
}

/// Temporary ref/config metadata; all objects live in the operator repository.
pub(crate) struct PreparedRead {
    directory: PathBuf,
    objects: PathBuf,
}
impl PreparedRead {
    fn git(&self, mut command: Command) -> Command {
        command
            .env("GIT_DIR", &self.directory)
            .env("GIT_OBJECT_DIRECTORY", &self.objects)
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env("GIT_NO_LAZY_FETCH", "1")
            .args(["-c", "core.alternateRefsCommand=false"]);
        command
    }
    pub(crate) fn upload(self, command: Command, session: &Session) -> Result<()> {
        let mut command = self.git(command);
        command
            .env_remove("SSH_AUTH_SOCK")
            .arg("upload-pack")
            .arg(&self.directory);
        if !session.run(command, false)?.0.success() {
            return Err("receive transfer failed".into());
        }
        Ok(())
    }
}

pub(crate) fn prepare(
    directory: &Path,
    repository: impl Fn() -> Command,
    transport: impl Fn() -> Command,
    reference: &str,
    origin: Option<&str>,
    session: &Session,
) -> Result<PreparedRead> {
    let format = metadata(&repository, &["--show-object-format"], session)?
        .ok_or("not a usable Git repository")?;
    let objects = metadata(
        &repository,
        &["--path-format=absolute", "--git-path", "objects"],
        session,
    )?
    .ok_or("cannot locate repository objects")?;
    let prepared = PreparedRead {
        directory: directory.to_owned(),
        objects: objects.into(),
    };
    let mut init = transport();
    init.env("GIT_DIR", directory)
        .env("GIT_OBJECT_DIRECTORY", &prepared.objects)
        .args(["init", "--bare", "--quiet"])
        .arg(format!("--object-format={format}"))
        .arg(directory);
    if !session.run(init, false)?.0.success() {
        return Err("cannot initialize receive metadata".into());
    }
    let make = || prepared.git(transport());
    let mut head = make();
    head.args(["symbolic-ref", "HEAD", reference]);
    if !session.run(head, false)?.0.success() {
        return Err("cannot select receive metadata branch".into());
    }
    let local = metadata(
        &repository,
        &["--verify", &format!("{reference}^{{commit}}")],
        session,
    )?;
    let branch = reference
        .strip_prefix("refs/heads/")
        .ok_or("expected branch reference")?;
    let tracking = format!("refs/remotes/origin/{branch}");
    let upstream_present = if let Some(url) = origin {
        let authentication = session.bounded(std::time::Duration::from_secs(120))?;
        advertised_tip(make(), url, reference, &authentication)?.is_some()
    } else {
        false
    };
    let mut verified = Vec::new();
    // An ordinary fetch may negotiate from commits whose historical blobs are
    // still promised. Only explicitly verified roots may be sent as haves.
    for tip in [
        local.clone(),
        metadata(
            &repository,
            &["--verify", &format!("{tracking}^{{commit}}")],
            session,
        )?,
        metadata(&repository, &["--verify", "HEAD^{commit}"], session)?,
    ]
    .into_iter()
    .flatten()
    {
        if !verified.contains(&tip)
            && complete(make(), std::slice::from_ref(&tip), &verified, session)?
        {
            verified.push(tip);
        }
    }
    if upstream_present && verified.is_empty() {
        // A previously received sibling may be complete even when HEAD and the
        // requested tracking branch still contain promised objects.
        let tips = directory.join("negotiation-tips");
        let mut list = repository();
        list.env("GIT_NO_LAZY_FETCH", "1")
            .args([
                "for-each-ref",
                "--format=%(objectname)",
                "refs/remotes/origin/",
            ])
            .stdout(std::fs::File::create(&tips)?);
        if !session.spawn(list)?.wait()?.success() {
            return Err("cannot inspect receiver origin tracking tips".into());
        }
        for tip in BufReader::new(std::fs::File::open(tips)?).lines() {
            let tip = tip?;
            if !crate::runtime::push_result::oid(&tip) {
                return Err("invalid origin tracking tip".into());
            }
            if complete(make(), std::slice::from_ref(&tip), &[], session)? {
                verified.push(tip);
                break;
            }
        }
    }
    let refetched = verified.is_empty();
    let upstream_tip = if upstream_present {
        let mut fetch = fetch_command(make(), &verified);
        fetch.args([
            "--",
            origin.ok_or("missing origin")?,
            &format!("+{reference}:{reference}"),
        ]);
        if !session.run(fetch, false)?.0.success() {
            return Err("receiver origin fetch failed".into());
        }
        metadata(&make, &["--verify", reference], session)?
    } else {
        None
    };
    if let Some(local) = local {
        let mut ancestor = make();
        ancestor
            .args(["merge-base", "--is-ancestor", reference, &local])
            .stderr(Stdio::null());
        let ahead = upstream_present && session.run(ancestor, false)?.0.success();
        let local_complete =
            ahead && complete(make(), std::slice::from_ref(&local), &verified, session)?;
        if ahead && !local_complete {
            crate::cli::terminal::warning(format_args!(
                "operator branch is incomplete; receiving the complete origin branch"
            ));
        }
        let prefer_local = !upstream_present || local_complete;
        if prefer_local {
            let mut select = make();
            select.args(["update-ref", reference, &local]);
            if !session.run(select, false)?.0.success() {
                return Err("cannot select receiver branch".into());
            }
        }
    } else if !upstream_present {
        return Err("requested branch does not exist on receiver or origin".into());
    }
    hydrate(
        directory,
        &make,
        reference,
        origin,
        upstream_present,
        &verified,
        refetched,
        session,
    )?;
    if let Some(tip) = upstream_tip {
        let mut update = repository();
        update.env("GIT_NO_LAZY_FETCH", "1").args([
            "-c",
            "core.hooksPath=/dev/null",
            "update-ref",
            "--no-deref",
            &tracking,
            &tip,
        ]);
        if !session.run(update, false)?.0.success() {
            return Err("cannot update receiver origin tracking ref".into());
        }
    }
    Ok(prepared)
}

#[allow(clippy::too_many_arguments)]
fn hydrate(
    directory: &Path,
    make: &impl Fn() -> Command,
    reference: &str,
    origin: Option<&str>,
    upstream_present: bool,
    verified: &[String],
    mut refetched: bool,
    session: &Session,
) -> Result<()> {
    for _ in 0..8 {
        let requests = directory.join("missing-objects");
        let (status, missing) = missing_file(make(), reference, verified, &requests, session)?;
        if !status.success() {
            return Err("cannot inspect receive object closure".into());
        }
        if missing == 0 {
            return Ok(());
        }
        let url = origin.ok_or("receiver branch is unavailable or incomplete and has no origin; configure an authenticated origin before receiving")?;
        let mut fetch = if !refetched && upstream_present {
            refetched = true;
            let mut fetch = fetch_command(make(), &[]);
            fetch.args(["--", url, reference]);
            fetch
        } else {
            let mut fetch = fetch_command(make(), verified);
            fetch
                .args(["--quiet", "--stdin", "--", url])
                .stdin(std::fs::File::open(requests)?);
            fetch
        };
        fetch.stdout(Stdio::null());
        if !session.run(fetch, false)?.0.success() {
            return Err("receiver origin object hydration failed".into());
        }
    }
    Err("receiver hydration exceeded eight object-walk rounds".into())
}

fn complete(
    mut command: Command,
    roots: &[String],
    exclude: &[String],
    session: &Session,
) -> Result<bool> {
    command
        .args(["rev-list", "--objects", "--quiet", "--missing=error"])
        .args(roots)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !exclude.is_empty() {
        command.arg("--not").args(exclude);
    }
    let status = session.spawn(command)?.wait()?;
    Ok(status.success())
}
fn missing_file(
    command: Command,
    reference: &str,
    exclude: &[String],
    path: &Path,
    session: &Session,
) -> Result<(ExitStatus, usize)> {
    let mut command = command;
    command.args([
        "rev-list",
        "--objects",
        "--no-object-names",
        "--missing=print",
        reference,
    ]);
    if !exclude.is_empty() {
        command.arg("--not").args(exclude);
    }
    let file = BufWriter::new(std::fs::File::create(path)?);
    let (status, (count, mut file)) =
        crate::runtime::git_output::lines(command, session, (0, file), |(count, file), row| {
            if let Some(id) = row.strip_prefix(b"?") {
                let id = std::str::from_utf8(id).map_err(std::io::Error::other)?;
                if !crate::runtime::push_result::oid(id) {
                    return Err(std::io::Error::other("invalid missing object ID"));
                }
                writeln!(file, "{id}")?;
                *count += 1;
            }
            Ok(())
        })?;
    file.flush()?;
    Ok((status, count))
}

fn fetch_command(mut command: Command, verified: &[String]) -> Command {
    command.args([
        "fetch",
        "--no-tags",
        "--no-recurse-submodules",
        "--no-write-fetch-head",
        "--no-filter",
    ]);
    if verified.is_empty() {
        command.arg("--refetch");
    } else {
        for tip in verified {
            command.arg(format!("--negotiation-tip={tip}"));
        }
    }
    command
}

fn advertised_tip(
    mut command: Command,
    url: &str,
    reference: &str,
    session: &Session,
) -> Result<Option<String>> {
    command.args(["ls-remote", "--refs", "--", url, reference]);
    let (status, tip) = crate::runtime::git_output::lines(command, session, None, |tip, row| {
        let text = std::str::from_utf8(row).map_err(std::io::Error::other)?;
        let (oid, name) = text
            .split_once('\t')
            .ok_or_else(|| std::io::Error::other("invalid upstream advertisement"))?;
        if !crate::runtime::push_result::oid(oid) {
            return Err(std::io::Error::other("invalid upstream object ID"));
        }
        if name == reference && tip.replace(oid.to_owned()).is_some() {
            return Err(std::io::Error::other(
                "duplicate upstream branch advertisement",
            ));
        }
        Ok(())
    })?;
    if !status.success() {
        return Err("upstream authentication or branch discovery failed".into());
    }
    Ok(tip)
}
