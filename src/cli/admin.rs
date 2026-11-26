use crate::{Result, server::access, server::config::ServerConfig};
use std::path::Path;

const USAGE: &str = "Usage: git porter <setup|key:create|key:public> [options]";

pub fn run() -> Result<()> {
    if let Some(result) = crate::runtime::supervision::dispatch() {
        return result;
    }
    let arguments: Vec<_> = std::env::args_os().collect();
    if crate::cli::client::transport::is_role(Path::new(&arguments[0])) {
        return crate::cli::client::transport::run();
    }
    if Path::new(&arguments[0])
        .file_name()
        .is_some_and(|name| name == "hydration-ssh")
    {
        use std::os::unix::process::CommandExt;
        return Err(crate::cli::ssh::guarded_command()?
            .args(&arguments[1..])
            .exec()
            .into());
    }
    let invoked = Path::new(&arguments[0])
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if matches!(invoked, "pre-receive" | "ssh") {
        let context = crate::server::config::HookContext::read()?;
        let config = &context.config;
        return match invoked {
            "pre-receive" => access::check(&context),
            _ => crate::server::publication::transport(config, &arguments[1..]),
        };
    }
    let args = &arguments[1..];
    match args.first().and_then(|s| s.to_str()) {
        None | Some("--help" | "-h" | "help") => {
            println!(
                "{USAGE}\n\n  setup       Check receiver policy and install restricted SSH access and hooks\n  key:create  Create a forwarder key or approve its creation from the sender\n  key:public  Print the public key to register with your forge\n\nUse git send and git receive to transfer branches.\nRun git porter <command> --help for options and setup instructions."
            );
            Ok(())
        }
        Some("--version") => {
            println!("git-porter {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("key:create" | "key:public") => crate::cli::keys::run(args),
        Some("setup") => crate::cli::setup::run(&args[1..]),
        Some("internal:read") if args.len() == 3 => crate::cli::client::read::native(
            Path::new(&args[1]),
            args[2].to_str().ok_or("branch must be UTF-8")?,
        ),
        Some("internal:serve") if args.len() == 1 => access::serve(&ServerConfig::read()?),
        Some("internal:serve") => Err("internal:serve takes no arguments".into()),
        _ => Err(USAGE.into()),
    }
}
