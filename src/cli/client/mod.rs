//! Sender command dispatch and branch transfer orchestration.
//! @ref LLP 0002#installation-boundary
use crate::Result;
use std::process::Command;
mod hydration;
pub(crate) mod provision;
pub(crate) mod read;
mod repository;
mod signing;
pub(crate) mod transport;
use repository::Repository;
fn git_status(session: &crate::runtime::supervision::Session, command: Command) -> Result<()> {
    if !session.run(command, false)?.0.success() {
        return Err("Git transfer failed; inspect its diagnostics above".into());
    }
    Ok(())
}
pub fn run(receive: bool) -> Result<()> {
    if let Some(result) = crate::runtime::supervision::dispatch() {
        return result;
    }
    let supplied: Vec<_> = std::env::args().skip(1).collect();
    run_arguments(receive, supplied)
}

pub fn run_arguments(receive: bool, supplied: Vec<String>) -> Result<()> {
    let mut arguments = supplied.into_iter();
    let mut branch = None;
    let mut force = false;
    let mut unconditional = false;
    let mut destination = None;
    let mut publish = true;
    let mut local_only = false;
    let mut quiet = false;
    let mut switch = false;
    while let Some(arg) = arguments.next() {
        match arg.as_str() {
            "--local-only" => {
                publish = false;
                local_only = true;
            }
            "--switch" if receive => switch = true,
            "--quiet" if !receive => quiet = true,
            "--force-with-lease" if !receive => force = true,
            "--force" if !receive => unconditional = true,
            "--branch" => {
                branch = Some(
                    arguments
                        .next()
                        .filter(|s| !s.is_empty())
                        .ok_or("--branch requires a branch name")?,
                )
            }
            "--help" | "-h" => {
                println!(
                    "Usage: git {} {}[--branch name] [user@host]",
                    if receive { "receive" } else { "send" },
                    if receive {
                        "[--local-only] [--switch] "
                    } else {
                        "[--quiet] [--local-only] [--force-with-lease|--force] "
                    }
                );
                if receive {
                    println!(
                        "\nFetch a receiver branch and fast-forward your local branch.\n\n  --branch <name>  Pull this remote branch into the current branch.\n  --switch         Receive into the named local branch and switch to it.\n  --local-only     Skip upstream fetching."
                    );
                } else {
                    println!(
                        "\nSend a branch over SSH. Restricted receivers also forward it to their configured origin.\n\n  --branch <name>      Send this branch instead of the current branch.\n  --local-only         Update only the receiver; skip forwarding to origin.\n  --force-with-lease   Allow rewriting only if the observed remote tips match.\n  --force              Allow rewriting without a lease.\n  --quiet              Hide successful status blocks; keep failures and uncertainty."
                    );
                }
                println!(
                    "\nSupply user@host or host, or set porter.destination in Git configuration.\nUse host:path to select an explicit receiver repository."
                );
                return Ok(());
            }
            _ if arg.starts_with('-') || destination.is_some() => {
                return Err(format!(
                    "unknown option or extra destination; run git {} --help for usage",
                    if receive { "receive" } else { "send" }
                )
                .into());
            }
            _ => destination = Some(arg),
        }
    }
    if force && unconditional {
        return Err("--force and --force-with-lease are mutually exclusive".into());
    }
    let repository = Repository::discover()?;
    let destination = destination
        .or_else(|| repository.config_value("porter.destination"))
        .ok_or("no receiver destination was supplied or configured; pass user@host to git send or git receive")?;
    let (host, explicit) = destination.split_once(':').unwrap_or((&destination, ""));
    destination_host(host)?;
    if !explicit.is_empty() {
        crate::cli::client::transport::validate_path(explicit)?;
    }
    let current = repository.output(&["symbolic-ref", "--quiet", "HEAD"]).ok();
    let branch = branch
        .or_else(|| {
            current
                .as_deref()
                .and_then(|s| s.strip_prefix("refs/heads/"))
                .map(str::to_owned)
        })
        .ok_or("Detached HEAD; select a branch with --branch <name>")?;
    let reference = format!("refs/heads/{branch}");
    if !receive
        && !reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._/-".contains(&b))
    {
        return Err("unsupported branch name; select a valid branch with --branch <name>, or rename it with git branch -m <name>. Branch names must use ASCII letters, digits or @._/- and pass git check-ref-format".into());
    }
    repository.output(&["check-ref-format", &reference])?;
    let target = if receive && !switch {
        current
            .clone()
            .ok_or("Detached HEAD; use --switch --branch <name> to receive a branch")?
    } else {
        reference.clone()
    };
    if repository
        .command()
        .args(["symbolic-ref", "--quiet", &target])
        .output()?
        .status
        .code()
        != Some(1)
    {
        return Err("select a direct branch, not a symbolic ref".into());
    }
    // Ordinary SSH needs no remotes. Defer discovery errors until the receiver
    // explicitly identifies itself as the restricted Porter route.
    let (origin, lookup_error) = if explicit.is_empty() {
        match repository.lookup_identity() {
            Ok(identity) => (identity, String::new()),
            Err(error) => (String::new(), error.to_string()),
        }
    } else {
        (String::new(), String::new())
    };
    let native_path = if explicit.is_empty() {
        repository.receiver_path()?.unwrap_or_default()
    } else {
        explicit.to_owned()
    };
    let user_ssh = crate::cli::ssh::selected()?;
    let session = crate::runtime::supervision::Session::new()?;
    let temporary = tempfile::Builder::new()
        .prefix("git-porter-client-")
        .tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
    let result_file = temporary.path().join("result.json");
    let route_file = temporary.path().join("route");
    let helper = temporary.path().join("client-ssh");
    let executable = std::env::current_exe()?;
    let admin = executable
        .parent()
        .ok_or("missing executable directory")?
        .join("git-porter");
    if !admin.is_file() {
        return Err("git-porter must be installed beside git-send/git-receive".into());
    }
    std::os::unix::fs::symlink(&admin, &helper)?;
    // A private name prevents repository remote.<name>.vcs/pushurl settings
    // from selecting a helper or another endpoint for our internal transfer.
    let remote = temporary.path().file_name().unwrap().to_str().unwrap();
    let remote_setting = format!("remote.{remote}.url={host}:porter");
    let push_setting = format!("remote.{remote}.pushurl={host}:porter");
    let hint = if explicit.is_empty() {
        repository.search_hint()?.unwrap_or_default()
    } else {
        String::new()
    };
    let mut resolve = repository.command();
    resolve.args(["-c", &remote_setting, "ls-remote", "--get-url"]);
    let resolved = resolve.arg(remote).output()?;
    if !resolved.status.success() {
        return Err("cannot resolve the internal receiver transport".into());
    }
    let url = std::str::from_utf8(&resolved.stdout)?.trim_end_matches('\n');
    let ssh = if url.contains("://") {
        url.starts_with("ssh://")
    } else {
        url.split_once(':').is_some_and(|(host, path)| {
            !host.is_empty() && !host.contains('/') && !path.starts_with(':')
        })
    };
    if !ssh {
        return Err("rewritten receiver transport is not allowed; SSH is required".into());
    }
    let make = || -> Command {
        let mut cmd = repository.command();
        // Git shell-parses GIT_SSH_COMMAND: quote the literal helper path even
        // when TMPDIR contains spaces, quotes or shell metacharacters.
        // This must override repository/global core.sshCommand, otherwise Git
        // bypasses the controlled negotiation.
        // URL rewrites may change the protocol before Git consults the helper.
        // Whitelist SSH for every receiver operation; the helper ignores
        // rewritten host/path arguments and uses the pinned intent.
        cmd.args(["-c", &remote_setting, "-c", &push_setting])
            .env("GIT_PORTER_USER_SSH", &user_ssh)
            // Lazy fetch children would inherit this receiver-pinned helper and
            // fetch from the receiver instead of their configured promisor.
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_ALLOW_PROTOCOL", "ssh")
            .env("GIT_SSH_COMMAND", crate::cli::ssh::quoted_path(&helper))
            .env("GIT_SSH", &helper)
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_PORTER_RESULT_FILE", &result_file)
            .env("GIT_PORTER_CLIENT_DESTINATION", host)
            .env("GIT_PORTER_CLIENT_PATH", explicit)
            .env("GIT_PORTER_NATIVE_PATH", &native_path)
            .env("GIT_PORTER_ROUTE_FILE", &route_file)
            .env("GIT_PORTER_LOOKUP_ERROR", &lookup_error)
            .env("GIT_PORTER_CLIENT_READ", "false")
            .env("GIT_PORTER_CLIENT_MODE", "ff")
            .env("GIT_PORTER_CLIENT_LEASE", "")
            .env("GIT_PORTER_CLIENT_HINT", &hint)
            .env("GIT_PORTER_CLIENT_ORIGIN", &origin)
            .env(
                "GIT_PORTER_CLIENT_PUBLISH",
                if publish && !receive { "true" } else { "false" },
            )
            .env(
                "GIT_PORTER_SIGN_BUDGET",
                temporary.path().join("derivation-used"),
            );
        cmd
    };
    if !receive {
        let sha =
            repository.output(&["rev-parse", "--verify", &format!("{reference}^{{commit}}")])?;
        let mut observe = make();
        observe.env("GIT_PORTER_CLIENT_PUBLISH", "false").args([
            "ls-remote",
            "--upload-pack=git-receive-pack",
            "--refs",
            remote,
        ]);
        hydration::prepare(
            &repository,
            &sha,
            observe,
            &user_ssh,
            &admin,
            temporary.path(),
            &session,
        )?;
        let mut push = make();
        push.env("GIT_PORTER_CLIENT_REF", &reference)
            .env("GIT_PORTER_CLIENT_SHA", &sha)
            .env(
                "GIT_PORTER_CLIENT_MODE",
                if unconditional {
                    "force"
                } else if force {
                    "lease"
                } else {
                    "ff"
                },
            );
        push.args([
            "-c",
            "push.pushOption=",
            "-c",
            "push.negotiate=false",
            "-c",
            "pack.useSparse=false",
            "push",
            "--porcelain",
            "--signed=false",
            "--no-follow-tags",
            "--no-thin",
            "--recurse-submodules=no",
        ]);
        if quiet {
            push.arg("--quiet");
        }
        if force {
            let mut observe = make();
            observe
                .env("GIT_PORTER_CLIENT_PUBLISH", "false")
                .env("GIT_PORTER_CLIENT_MODE", "lease")
                .args(["ls-remote", "--refs", remote, &reference]);
            let (status, observed) = session.run(observe, true)?;
            if !status.success() {
                return Err("cannot observe receiver lease; push not attempted".into());
            }
            let tip =
                crate::runtime::push_result::ref_tip(&observed, &reference)?.unwrap_or_default();
            push.env("GIT_PORTER_CLIENT_LEASE", tip);
            push.arg(format!("--force-with-lease={reference}:{tip}"));
        }
        if unconditional {
            push.arg("--force");
        }
        push.arg(remote).arg(format!("{sha}:{reference}"));
        let (status, bytes) = session.run(push, true)?;
        let (native, diagnostics) =
            crate::runtime::push_result::receiver_porcelain(&bytes, &reference)?;
        use std::io::Write;
        std::io::stderr().write_all(&diagnostics)?;
        let result = match std::fs::read(&result_file) {
            Ok(bytes) => {
                let record = crate::runtime::push_result::Report::parse(&bytes)?;
                record.pin(&reference, &sha)?;
                Some(record)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let native_route = crate::cli::client::transport::is_native_route(&route_file)?;
        let receiver = result
            .as_ref()
            .and_then(|r| r.repository.as_ref())
            .map(|p| format!("{host}:{p}"))
            .unwrap_or_else(|| {
                if native_route {
                    format!("{host}:{native_path}")
                } else {
                    destination.clone()
                }
            });
        eprint!(
            "{}",
            crate::cli::status::render_terminal(
                &receiver,
                &reference,
                &native,
                result.as_ref(),
                quiet
            )
        );
        if publish && result.is_none() && !native_route {
            return Err("publication result channel missing; upgrade receiver or inspect origin before retrying; no onward outcome is known".into());
        }
        if !status.success() || result.as_ref().is_some_and(|r| !r.successful()) {
            return Err(crate::runtime::push_result::Reported.into());
        }
        return Ok(());
    }
    let source = if local_only {
        let mut observe = make();
        observe.args(["ls-remote", "--refs", remote, &branch]);
        local_read_source(observe, &reference, &session)?
    } else {
        reference.clone()
    };
    let mut fetch = make();
    if !local_only {
        fetch
            .env("GIT_PORTER_CLIENT_READ", "true")
            .env("GIT_PORTER_CLIENT_MODE", "read")
            .env("GIT_PORTER_CLIENT_REF", &reference)
            .env("GIT_PORTER_CLIENT_SHA", "");
    }
    fetch.args([
        "-c",
        "fetch.prune=false",
        "-c",
        "fetch.pruneTags=false",
        "fetch",
        "--no-tags",
        "--no-recurse-submodules",
        "--refmap=",
    ]);
    let result = if current.as_deref() == Some(&target) {
        if !repository
            .output(&[
                "status",
                "--porcelain",
                "--untracked-files=normal",
                "--ignore-submodules=none",
            ])?
            .is_empty()
        {
            return Err(
                "commit or stash local changes before receiving into the current branch".into(),
            );
        }
        let temporary_ref = format!("refs/git-receive/{:032x}", rand::random::<u128>());
        let cleanup = RefCleanup {
            repository: &repository,
            reference: temporary_ref.clone(),
        };
        fetch.arg(remote).arg(format!("+{source}:{temporary_ref}"));
        git_status(&session, fetch)?;
        let fetched = repository.output(&[
            "rev-parse",
            "--verify",
            &format!("{temporary_ref}^{{commit}}"),
        ])?;
        if repository
            .output(&["symbolic-ref", "--quiet", "HEAD"])
            .ok()
            .as_deref()
            != Some(&target)
        {
            return Err(
                "Current branch changed during fetch; fetched history remains in FETCH_HEAD. Switch back before retrying".into(),
            );
        }
        let mut merge = repository.command();
        merge.args([
            "merge",
            "--ff-only",
            "--no-autostash",
            "--no-overwrite-ignore",
            &fetched,
        ]);
        let result = git_status(&session, merge).map_err(|e| -> Box<dyn std::error::Error> {
            format!("{e}. Could not fast-forward {target} from {host}. Fetched history remains in FETCH_HEAD; inspect it with: git log --left-right --graph {target}...FETCH_HEAD").into()
        });
        drop(cleanup);
        result
    } else {
        fetch.arg(remote).arg(format!("{source}:{target}"));
        git_status(&session, fetch).map_err(|e|format!("{e}. Could not receive {target} from {host}. Resolve the fetch error above; if histories diverged, inspect FETCH_HEAD before merging or rebasing.").into())
    };
    result?;
    if switch && current.as_deref() != Some(&target) {
        let mut checkout = repository.command();
        checkout.args([
            "switch",
            "--no-guess",
            "--no-overwrite-ignore",
            "--",
            &branch,
        ]);
        git_status(&session, checkout).map_err(|e| -> Box<dyn std::error::Error> {
            format!("{e}. Received {target}, but could not switch; inspect your worktree before retrying git switch").into()
        })?;
    }
    Ok(())
}

struct RefCleanup<'a> {
    repository: &'a Repository,
    reference: String,
}
impl Drop for RefCleanup<'_> {
    fn drop(&mut self) {
        let _ = self
            .repository
            .command()
            .args(["update-ref", "-d", &self.reference])
            .status();
    }
}

fn destination_host(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.matches('@').count() > 1
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
    {
        return Err("expected hostname or user@hostname".into());
    }
    Ok(())
}

fn local_read_source(
    command: Command,
    reference: &str,
    session: &crate::runtime::supervision::Session,
) -> Result<String> {
    let branch = reference
        .strip_prefix("refs/heads/")
        .ok_or("expected branch")?;
    let (status, (head, candidate, ambiguous)) = crate::runtime::git_output::lines(
        command,
        session,
        (false, None::<String>, false),
        |(head, candidate, ambiguous), row| {
            let text = std::str::from_utf8(row).map_err(std::io::Error::other)?;
            let (oid, name) = text
                .split_once('\t')
                .ok_or_else(|| std::io::Error::other("invalid ref advertisement"))?;
            if !crate::runtime::push_result::oid(oid) {
                return Err(std::io::Error::other("invalid object ID"));
            }
            if name == reference {
                *head = true;
            }
            if name
                .strip_prefix("refs/remotes/")
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(_, name)| name == branch)
            {
                if candidate.is_some() {
                    *ambiguous = true;
                } else {
                    *candidate = Some(name.to_owned());
                }
            }
            Ok(())
        },
    )?;
    if !status.success() {
        return Err("cannot observe receiver branches".into());
    }
    if head {
        return Ok(reference.into());
    }
    if ambiguous {
        return Err("multiple cached receiver branches match; retry without --local-only".into());
    }
    candidate.ok_or_else(|| {
        "branch is unavailable locally on receiver; retry without --local-only".into()
    })
}
