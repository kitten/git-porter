//! Human diagnostics and bounded prompts; stdout payloads remain unstyled.
//! @ref LLP 0004#terminal-output
use crate::Result;
use std::{
    fmt::Display,
    io::{self, BufRead, IsTerminal, Write},
    sync::OnceLock,
};

fn color(tty: bool, env: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    let equals = |name: &str, value: &str| {
        env(name).is_some_and(|v| v.to_str().is_some_and(|v| v.eq_ignore_ascii_case(value)))
    };
    tty && !env("NO_COLOR").is_some_and(|v| !v.is_empty())
        && !["dumb", "unknown"].iter().any(|v| equals("TERM", v))
        && !["1", "true"].iter().any(|v| equals("CI", v))
        && !["CLICOLOR", "COLOR", "FORCE_COLOR"]
            .iter()
            .any(|key| equals(key, "0"))
}
#[derive(Clone, Copy, Default)]
pub(crate) struct Style(bool);
impl Style {
    fn paint(self, label: &str, code: u8) -> String {
        if self.0 {
            format!("\x1b[{code}m{label}\x1b[0m")
        } else {
            label.to_owned()
        }
    }
    pub(crate) fn heading(self, label: &str) -> String {
        self.paint(label, 1)
    }
    pub(crate) fn status(self, flag: char, label: &str) -> String {
        self.paint(
            label,
            match flag {
                '!' => 31,
                '+' | '-' => 33,
                _ => 32,
            },
        )
    }
}
pub(crate) fn current() -> Style {
    static COLOR: OnceLock<bool> = OnceLock::new();
    Style(*COLOR.get_or_init(|| color(io::stderr().is_terminal(), |key| std::env::var_os(key))))
}
fn styled(label: &str, code: u8) -> String {
    current().paint(label, code)
}
pub(crate) fn info(message: impl Display) {
    eprintln!("{message}");
}
pub(crate) fn heading(message: &str) -> String {
    styled(message, 1)
}
pub(crate) fn title(message: &str) {
    eprintln!("{}", heading(message));
}
pub(crate) fn warning(message: impl Display) {
    eprintln!("{} {message}", styled("Warning:", 33));
}
pub(crate) fn success(message: impl Display) {
    eprintln!("{} {message}", styled("OK:", 32));
}
pub(super) fn error(program: &str, error: impl Display) {
    eprintln!("{} {error}", styled(&format!("{program}:"), 31));
}

// Input echo may go to a different stream, or be disabled. Always finish stderr's
// prompt line, including EOF and read/flush errors, before the caller logs anything.
struct PromptLine;
impl Drop for PromptLine {
    fn drop(&mut self) {
        let mut out = io::stderr().lock();
        let _ = writeln!(out);
        let _ = out.flush();
    }
}
pub(crate) fn prompt(question: &str, limit: usize) -> Result<Option<String>> {
    let _line = PromptLine;
    eprint!("{} ", styled(question, 1));
    io::stderr().flush()?;
    read_line(io::stdin().lock(), limit)
}
fn read_line(input: impl BufRead, limit: usize) -> Result<Option<String>> {
    let mut value = String::new();
    let read = input.take((limit + 1) as u64).read_line(&mut value)?;
    if read == 0 {
        return Ok(None);
    }
    if value.len() > limit {
        return Err(format!("input exceeds {limit} bytes").into());
    }
    Ok(Some(value.trim_end_matches(['\r', '\n']).to_owned()))
}
fn answer(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Some(true),
        "" | "n" | "no" => Some(false),
        _ => None,
    }
}
pub(crate) fn confirm(question: &str) -> Result<bool> {
    loop {
        let Some(value) = prompt(question, 64)? else {
            return Ok(false);
        };
        if let Some(yes) = answer(&value) {
            return Ok(yes);
        }
        warning("Enter yes or no; press Enter to decline.");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn color_obeys_linn_disable_policy_and_never_forces_a_pipe() {
        for (name, value) in [
            ("NO_COLOR", "0"),
            ("NO_COLOR", "1"),
            ("TERM", "DUMB"),
            ("TERM", "unknown"),
            ("CI", "TRUE"),
            ("CI", "1"),
            ("CLICOLOR", "0"),
            ("COLOR", "0"),
            ("FORCE_COLOR", "0"),
        ] {
            assert!(!color(true, |key| match key {
                "CLICOLOR_FORCE" => Some("1".into()),
                key if key == name => Some(value.into()),
                _ => None,
            }));
        }
        assert!(color(true, |key| match key {
            "NO_COLOR" => Some("".into()),
            "CI" => Some("false".into()),
            _ => None,
        }));
        assert!(!color(false, |_| Some("1".into())));
        assert_eq!(Style(true).heading("Heading"), "\x1b[1mHeading\x1b[0m");
        assert_eq!(
            Style(true).status('!', "[unknown]"),
            "\x1b[31m[unknown]\x1b[0m"
        );
        assert_eq!(Style(false).status('!', "[unknown]"), "[unknown]");
    }
    #[test]
    fn prompts_bound_input_distinguish_eof_and_accept_normal_consent_words() {
        assert!(read_line(io::Cursor::new(b"oversized"), 4).is_err());
        assert!(read_line(io::Cursor::new([0xff]), 4).is_err());
        assert_eq!(read_line(io::Cursor::new(b""), 4).unwrap(), None);
        assert_eq!(
            read_line(io::Cursor::new(b"\n"), 4).unwrap(),
            Some("".into())
        );
        assert_eq!(
            read_line(io::Cursor::new(b"yes\r\n"), 8).unwrap(),
            Some("yes".into())
        );
        for yes in ["Y", "yes", " YES "] {
            assert_eq!(answer(yes), Some(true));
        }
        for no in ["", "n", " NO "] {
            assert_eq!(answer(no), Some(false));
        }
        assert_eq!(answer("maybe"), None);
    }
}
