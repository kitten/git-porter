//! Key command parsing, enrollment prompts and sender participation.
//! @ref LLP 0004#setup
use crate::{
    Result,
    credentials::{
        derivation::Request,
        keys::{Choice, Lock, create_from_token, data_directory, fulfill, public, read_import},
        wrapping,
    },
};
use ssh_key::PublicKey;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(crate) fn run(arguments: &[std::ffi::OsString]) -> Result<()> {
    run_enrollment(arguments, true)
}
pub(crate) fn create_only(arguments: &[std::ffi::OsString]) -> Result<()> {
    run_enrollment(arguments, false)
}
fn run_enrollment(arguments: &[std::ffi::OsString], replace: bool) -> Result<()> {
    crate::runtime::supervision::disable_core_dumps()?;
    let action = arguments
        .first()
        .and_then(|s| s.to_str())
        .ok_or("expected key:create or key:public")?;
    let mut import = None;
    let mut sign = None;
    let mut source_argument = None;
    let mut args = arguments[1..].iter().peekable();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--key-import") if action == "key:create" => {
                import = Some(PathBuf::from(
                    args.next()
                        .ok_or("--key-import needs a private-key path, or - to read stdin")?,
                ))
            }
            Some("--sign") if action == "key:create" => {
                let host = if args
                    .peek()
                    .is_some_and(|value| !value.to_string_lossy().starts_with('-'))
                {
                    Some(
                        args.next()
                            .unwrap()
                            .to_str()
                            .ok_or("SSH destination must be valid UTF-8; use user@host")?
                            .to_owned(),
                    )
                } else {
                    None
                };
                sign = Some(host);
            }
            Some("--help" | "-h") => {
                println!(
                    r#"Usage: git porter key:create [<sender-key-or-public-wrapping-token>] [--key-import <path|->]
       git porter key:create [<sender-public-key-or-path>] --sign
       git porter key:create --sign user@host
       git porter key:public

The forwarder key lets the receiver push to your forge.
The sender key unlocks the forwarder key for each push.

On the receiver:
  key:create  Create or replace the forwarder key. Supply a public wrapping
              token, a sender public-key path, or one quoted Ed25519 public key.
              Without an argument, reuse the recorded sender key or ask for one.
  --key-import <path|->
              Import an existing forwarder private key instead of creating one.
              Use - to read it from stdin.
  key:public  Print the public key to register with your forge.

On the sender:
  key:create --sign
              Print a public wrapping token to paste into receiver setup or
              pass to git porter key:create on the receiver. To select a key,
              supply its public-key path or a quoted Ed25519 public key.
              Without an argument, use the sole Ed25519 key in SSH_AUTH_SOCK.
  key:create --sign user@host
              Complete key creation already approved and waiting on the receiver.

Private keys stay on their own machine. Use a new wrapping token for each
forwarder key. Run git porter setup --help for the receiver setup steps."#
                );
                return Ok(());
            }
            Some(value) if action == "key:create" && !value.starts_with('-') => {
                if source_argument.replace(value.to_owned()).is_some() {
                    return Err(
                        "supply one sender public-key path, quoted public-key line, or public wrapping token".into(),
                    );
                }
            }
            _ => {
                return Err(
                    "unknown key option; run git porter key:create --help for usage".into(),
                );
            }
        }
    }
    if let Some(destination) = sign {
        if import.is_some() || destination.is_some() && source_argument.is_some() {
            return Err(
                "--sign cannot be combined with --key-import. With --sign user@host, also omit the sender public key; the receiver selects it"
                    .into(),
            );
        }
        return match destination {
            Some(host) => crate::cli::client::provision::sign_pending(&host),
            None => crate::cli::client::provision::public_wrapping(source_argument.as_deref()),
        };
    }
    let data = &data_directory()?;
    let config = crate::server::config::ServerConfig::for_setup()?;
    if config.publication.skip_wrapped_key {
        if action == "key:public" {
            let socket = crate::server::publication::account_socket()?;
            for key in crate::credentials::agent::Client::connect(&socket)?.list_all_identities()? {
                println!("{}", key.to_openssh().map_err(|e| e.to_string())?);
            }
        } else {
            eprintln!(
                "porter.skipWrappedKey is enabled, so forwarding uses this receiver account's SSH agent. No wrapped key is needed. Load the forge key into that agent with your usual SSH tools."
            );
        }
        return Ok(());
    }
    if action == "key:public" {
        println!("{}", public(data)?.to_openssh().map_err(|e| e.to_string())?);
        return Ok(());
    }
    if action != "key:create" {
        return Err("unknown key command".into());
    }
    let source_text = source_argument
        .map(|value| -> Result<String> {
            if Path::new(&value).is_file() {
                Ok(fs::read_to_string(value)?)
            } else {
                Ok(value)
            }
        })
        .transpose()?;
    if let Some(text) = &source_text
        && wrapping::PublicWrapping::is_token(text)
    {
        let token = wrapping::PublicWrapping::parse(text)?;
        let choice = import
            .map(|path| read_import(&path))
            .transpose()?
            .unwrap_or(Choice::Create);
        let public = create_from_token(data, &token, choice, replace)?;
        crate::cli::terminal::success(
            "Forwarder key saved. Register the public key below with your forge.",
        );
        println!("{}", public.to_openssh().map_err(|e| e.to_string())?);
        return Ok(());
    }
    // Resolve the source before `--key-import -` consumes stdin to EOF.
    let source_path = data.join("publication.source.pub");
    let source = if let Some(text) = source_text {
        if text.trim().contains(['\n', '\r']) {
            return Err("expected one sender public-key line, not a list of keys".into());
        }
        PublicKey::from_openssh(text.trim()).map_err(|e| {
            format!(
                "expected a sender public-key file path or one quoted OpenSSH public-key line: {e}"
            )
        })?
    } else if source_path.exists() {
        wrapping::read_public(&source_path)?
    } else {
        crate::cli::terminal::info(
            "Choose the sender key that will unlock the forwarder key. Paste its Ed25519 public key below, or pass a public-key path to git porter key:create.",
        );
        if import.as_deref() == Some(Path::new("-"))
            && !std::io::IsTerminal::is_terminal(&std::io::stdin())
        {
            return Err("stdin is reserved for --key-import -; supply the sender public key as a positional argument".into());
        }
        let value = crate::cli::terminal::prompt("Sender Ed25519 public key:", 4096)?
            .filter(|v| !v.trim().is_empty()).ok_or("no sender public key was supplied; pass its file path or a quoted public key to git porter key:create")?;
        PublicKey::from_openssh(value.trim()).map_err(|e| e.to_string())?
    };
    let choice = match import {
        Some(path) => read_import(&path)?,
        None => Choice::Create,
    };
    let lock = Lock::acquire(data)?;
    if !replace {
        crate::credentials::keys::ensure_create_only(&lock, data)?;
    }
    let request = Request::generate(source)?;
    let public = crate::credentials::jobs::participate(data, &request, |identity| {
        fulfill(&lock, data, choice, &request, identity, replace)
    })?;
    crate::cli::terminal::success(
        "Forwarder key saved. Register the public key below with your forge.",
    );
    println!("{}", public.to_openssh().map_err(|e| e.to_string())?);
    Ok(())
}
