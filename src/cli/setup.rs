//! Receiver SSH glue; policy is supplied independently.
//! @ref LLP 0004#setup
use super::terminal;
use crate::{
    Result,
    server::{authorized, config::ServerConfig},
};
use std::{fs, io};
pub fn run(arguments: &[std::ffi::OsString]) -> Result<()> {
    if arguments == ["--help"] || arguments == ["-h"] {
        println!(
            "Usage: git porter setup [--yes]\n\nCheck the receiver settings and install restricted SSH access and Git hooks.\nInteractive setup also offers to create a missing forwarder key: paste a public\nwrapping token from the sender, or wait for the sender to approve over SSH.\nExisting keys and receiver settings are preserved.\n\n  --yes  Install SSH access and hooks without prompts or key creation."
        );
        return Ok(());
    }
    if arguments.iter().any(|a| a != "--yes") {
        return Err("Usage: git porter setup [--yes]".into());
    }
    let executable = std::env::current_exe()?.canonicalize()?;
    let config = ServerConfig::for_setup();
    if let Err(ref error) = config {
        terminal::warning(format_args!(
            "Receiver settings need attention: {error}. Configure them before accepting SSH transfers."
        ));
    }
    if let Ok(ref c) = config {
        terminal::title("Receiver setup");
        crate::cli::diagnostics::setup_checks(c);
        eprintln!("Git settings: receiver account's global configuration");
        eprintln!("Repository access stays within {}", c.home.display());
        if c.discovery.strict {
            for root in &c.discovery.roots {
                eprintln!("Allowed directory: {}", root.display());
            }
        }
        let policy = &c.publication;
        if policy.skip_wrapped_key {
            terminal::warning(
                "porter.skipWrappedKey=true: any process on this receiver account can push using its SSH agent, without sender approval. Set it to false to require the wrapped forwarder key.",
            );
        } else {
            match policy.ready() {
                Ok(_) => terminal::success("Forwarder key files are present"),
                Err(e)
                    if e.downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
                {
                    terminal::warning(
                        "Forwarder key files are missing. Create a key in interactive setup, or run git porter key:create.",
                    )
                }
                Err(e) => terminal::warning(format_args!(
                    "Forwarder key needs attention: {e}. To create one, follow the steps below or run git porter key:create."
                )),
            }
        }
        eprintln!(
            "SSH host trust: built-in forge keys and {}. Trust other hosts through normal Git/SSH use.",
            policy.known_hosts.display()
        );
        for key in &c.keys {
            eprintln!(
                "{}: {}",
                c.home.join(".ssh/authorized_keys").display(),
                authorized::render(&executable, key)?
            );
        }
        eprintln!(
            "You can also install these entries through another SSH authorization file or manager. Configure SSH to read that source; setup only attempts ~/.ssh/authorized_keys."
        );
        eprintln!("Install restricted SSH access and Git hooks using the settings shown above.");
    }
    if !arguments.iter().any(|a| a == "--yes")
        && !terminal::confirm("Install SSH access and hooks? [y/N]")?
    {
        return Err("setup canceled; no files were changed".into());
    }
    let c = config?;
    crate::credentials::keys::owner_directory(&c.data)?;
    let c = ServerConfig::read()?;
    for entry in ["hooks/pre-receive", "transport/ssh"] {
        let link = c.data.join(entry);
        fs::create_dir_all(link.parent().unwrap())?;
        match fs::symlink_metadata(&link) {
            Ok(metadata) => {
                if !metadata.file_type().is_symlink() {
                    return Err("an existing hook or transport entry is not a managed git-porter link; review it before replacing it".into());
                }
                if link.canonicalize().ok().as_ref() == Some(&executable) {
                    continue;
                }
                let old = fs::read_link(&link)?;
                if old.file_name() != executable.file_name() {
                    return Err("an existing hook or transport entry is not a managed git-porter link; review it before replacing it".into());
                }
                // Keep an older porter link intact until its replacement exists.
                let parent = link.parent().unwrap();
                let temporary = tempfile::Builder::new()
                    .prefix(".porter-link-")
                    .tempdir_in(parent)?;
                let replacement = temporary.path().join("entry");
                std::os::unix::fs::symlink(&executable, &replacement)?;
                fs::rename(&replacement, &link)?;
                fs::File::open(parent)?.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::os::unix::fs::symlink(&executable, &link)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    authorized::apply_or_explain(&c.home, &executable, &c.keys)?;
    if !c.publication.skip_wrapped_key
        && fs::symlink_metadata(&c.publication.wrapped)
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
    {
        if !arguments.iter().any(|a| a == "--yes") {
            terminal::title("Create a forwarder key");
            terminal::info("Option 1: paste a public wrapping token");
            terminal::info("  On the sender, run: git porter key:create --sign");
            terminal::info(
                "  Paste the resulting public token here. To select a particular sender key,",
            );
            terminal::info("  run: git porter key:create /path/to/sender.pub --sign");
            terminal::info("Option 2: approve over SSH");
            terminal::info(
                "  Enter wait below, then run on the sender:\n    git porter key:create --sign user@receiver",
            );
            terminal::info(
                "  The restricted SSH entry must be installed before the sender connects.",
            );
            terminal::info("Both options keep each private key on its own machine.");
            let answer = terminal::prompt(
                "Paste a public wrapping token, type 'wait', or press Enter to skip:",
                4096,
            )?
            .unwrap_or_default();
            match answer.trim() {
                "" => (),
                choice if choice.eq_ignore_ascii_case("wait") => {
                    let mut args = vec![std::ffi::OsString::from("key:create")];
                    if !c.publication.source.exists() && c.keys.len() == 1 {
                        eprintln!(
                            "Using sender key {} to unlock the forwarder key.",
                            c.keys[0].fingerprint(ssh_key::HashAlg::Sha256)
                        );
                        args.push(c.keys[0].to_openssh().map_err(|e| e.to_string())?.into());
                    }
                    crate::cli::keys::create_only(&args)?;
                }
                token => {
                    crate::runtime::supervision::disable_core_dumps()?;
                    let token = crate::credentials::wrapping::PublicWrapping::parse(token)?;
                    eprintln!(
                        "Creating a forwarder key for sender {}.",
                        token.request.source.fingerprint(ssh_key::HashAlg::Sha256)
                    );
                    let public = crate::credentials::keys::create_from_token(
                        &c.data,
                        &token,
                        crate::credentials::keys::Choice::Create,
                        false,
                    )?;
                    terminal::success(
                        "Forwarder key saved. Register the public key below with your forge.",
                    );
                    println!("{}", public.to_openssh().map_err(|e| e.to_string())?);
                }
            }
        } else {
            eprintln!(
                "SSH hooks are installed. To create a forwarder key, rerun git porter setup interactively or pass a public wrapping token to git porter key:create."
            );
        }
    }
    Ok(())
}
