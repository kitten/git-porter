pub mod admin;
pub mod client;
pub(crate) mod diagnostics;
pub(crate) mod keys;
pub mod setup;
pub(crate) mod ssh;

pub mod status;

pub(crate) mod terminal;
pub fn report_error(program: &str, error: impl std::fmt::Display) {
    terminal::error(program, error);
}
