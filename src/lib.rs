//! Restricted Git access, controlled publication and installed client commands.
pub mod cli;
pub mod credentials;
pub mod runtime;
pub mod server;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
