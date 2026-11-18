//! Versioned bounded publication results and the private Git-data envelope.
//! @ref LLP 0001#publication-results
use crate::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
pub const MAX_RESULT: usize = 16382;
pub const MAX_DATA: usize = 65536;
#[derive(Debug)]
pub struct Reported;
impl std::fmt::Display for Reported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("push result already reported")
    }
}
impl std::error::Error for Reported {}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    PolicyRefused,
    DestinationRefused,
    CredentialsUnavailable,
    SenderRefused,
    DefaultBranchProtected,
    DefaultBranchUnknown,
    ReceiverRejected,
    ReceiverMoved,
    OriginMoved,
    OriginUnavailable,
    HookUnavailable,
    Interrupted,
}
impl Reason {
    pub fn text(&self) -> &'static str {
        match self {
            Self::PolicyRefused => "publication policy refused",
            Self::DestinationRefused => "origin destination is not permitted",
            Self::CredentialsUnavailable => "forwarder credentials unavailable",
            Self::SenderRefused => "sender key signing failed",
            Self::DefaultBranchProtected => "default branch protected",
            Self::DefaultBranchUnknown => "origin default branch unknown",
            Self::ReceiverRejected => "receiver did not accept ref",
            Self::ReceiverMoved => "receiver lease changed",
            Self::OriginMoved => "origin lease changed",
            Self::OriginUnavailable => "origin pre-authentication failed",
            Self::HookUnavailable => "receiver hook unavailable",
            Self::Interrupted => "operation interrupted",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Complete,
    Published,
    NotPublished,
    Moved { actual: Option<String> },
    Unknown,
    NotAttempted { reason: Reason },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub flag: char,
    pub summary: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forwarded {
    pub url: Option<String>,
    pub rows: Vec<Row>,
    pub outcome: Outcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: u8,
    pub repository: Option<String>,
    pub reference: Option<String>,
    pub intended: Option<String>,
    pub receiver_ok: bool,
    pub receiver_reason: Option<String>,
    pub reason: Reason,
    pub forwarded: Option<Forwarded>,
}
impl Default for Report {
    fn default() -> Self {
        Self {
            version: 1,
            repository: None,
            reference: None,
            intended: None,
            receiver_ok: false,
            receiver_reason: None,
            reason: Reason::PolicyRefused,
            forwarded: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolved {
    pub version: u8,
    pub repository: String,
    pub publication: bool,
    pub signing: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookReport {
    pub version: u8,
    pub reference: String,
    pub intended: String,
    pub attempted: bool,
    pub accepted: bool,
    pub rows: Vec<Row>,
    pub reason: Reason,
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
pub fn oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
/// Both preflight leases and failure rechecks require one exact, canonical ref advertisement.
pub(crate) fn ref_tip<'a>(bytes: &'a [u8], reference: &str) -> Result<Option<&'a str>> {
    let text = std::str::from_utf8(bytes)?;
    if text.is_empty() {
        return Ok(None);
    }
    let (tip, name) = text
        .trim_end_matches('\n')
        .split_once('\t')
        .ok_or("invalid ref advertisement")?;
    if name != reference || !oid(tip) {
        return Err("invalid ref advertisement".into());
    }
    Ok(Some(tip))
}

/// Direct branch grammar shared by access policy and typed result validation.
pub(crate) fn direct_branch(value: &str) -> bool {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    !branch.is_empty()
        && !branch.contains("..")
        && !branch.ends_with('/')
        && !branch.ends_with('.')
        && branch
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
        && branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._/-".contains(&b))
}
pub fn reference(value: &str) -> bool {
    text(value, 1024) && direct_branch(value)
}
pub fn rows_valid(rows: &[Row]) -> bool {
    rows.len() <= 1
        && rows
            .iter()
            .all(|r| " +*-=!".contains(r.flag) && text(&r.summary, 512))
}
impl Report {
    pub fn successful(&self) -> bool {
        self.receiver_ok
            && self
                .forwarded
                .as_ref()
                .is_none_or(|f| matches!(f.outcome, Outcome::Complete))
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self
                .repository
                .as_ref()
                .is_some_and(|p| !p.starts_with('/') || !text(p, 4096))
            || self.reference.as_ref().is_some_and(|r| !reference(r))
            || self.intended.as_ref().is_some_and(|s| !oid(s))
            || self.reference.is_some() != self.intended.is_some()
            || self.receiver_reason.as_ref().is_some_and(|s| !text(s, 128))
        {
            return Err("invalid push-result record".into());
        }
        if let Some(f) = &self.forwarded {
            if !rows_valid(&f.rows) || self.reference.is_none() {
                return Err("invalid forwarded rows".into());
            }
            if let Some(url) = &f.url {
                validate_url(url)?;
            }
            if let Outcome::Moved { actual: Some(sha) } = &f.outcome
                && !oid(sha)
            {
                return Err("invalid origin outcome tip".into());
            }
            if matches!(f.outcome, Outcome::Complete)
                && (!self.receiver_ok
                    || f.url.is_none()
                    || f.rows.len() != 1
                    || f.rows[0].flag == '!')
            {
                return Err("invalid successful onward result".into());
            }
            if matches!(f.outcome, Outcome::NotAttempted { .. }) && !f.rows.is_empty() {
                return Err("unattempted publication has native rows".into());
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_RESULT {
            return Err("push result exceeds limit".into());
        }
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RESULT {
            return Err("push result exceeds limit".into());
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn pin(&self, r: &str, sha: &str) -> Result<()> {
        self.validate()?;
        if self.reference.as_deref() != Some(r) || self.intended.as_deref() != Some(sha) {
            return Err("push result does not match requested ref/commit".into());
        }
        Ok(())
    }
}
pub fn validate_url(url: &str) -> Result<()> {
    if !text(url, 4096) {
        return Err("invalid result URL".into());
    }
    crate::server::discovery::Identity::parse(url)?;
    if !url.starts_with("ssh://") && !url.contains('@') {
        return Err("result URL must use SSH".into());
    }
    Ok(())
}
pub fn parse_porcelain(bytes: &[u8], reference: &str) -> Result<Vec<Row>> {
    if bytes.len() > 8192 {
        return Err("push porcelain exceeds limit".into());
    }
    let mut rows = Vec::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        if line.is_empty() || line == "Done" || line.starts_with("To ") {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 3 || fields[0].chars().count() != 1 {
            return Err("malformed push porcelain".into());
        }
        let (_, destination) = fields[1]
            .split_once(':')
            .ok_or("malformed porcelain refspec")?;
        if destination != reference {
            return Err("porcelain describes another ref".into());
        }
        rows.push(Row {
            flag: fields[0].chars().next().unwrap(),
            summary: fields[2].into(),
        });
    }
    if !rows_valid(&rows) {
        return Err("invalid native push rows".into());
    }
    Ok(rows)
}
/// Local user hooks inherit Git's stdout. Preserve their diagnostics separately
/// from documented porcelain rows; remote diagnostics never enter this parser.
pub fn receiver_porcelain(bytes: &[u8], reference: &str) -> Result<(Vec<Row>, Vec<u8>)> {
    let mut porcelain = Vec::new();
    let mut diagnostics = Vec::new();
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if line.get(1) == Some(&b'\t') {
            porcelain.extend_from_slice(line);
        } else if !line.starts_with(b"To ") && line != b"Done\n" && line != b"Done" {
            diagnostics.extend_from_slice(line);
        }
    }
    Ok((parse_porcelain(&porcelain, reference)?, diagnostics))
}
/// Data and final-result frames are outside the native Git stream. Only the
/// negotiated transport helper sees this envelope; Git receives data payloads.
pub enum Frame {
    Data(Vec<u8>),
    Final(Report),
}
pub fn write_data(output: &mut impl Write, bytes: &[u8]) -> Result<()> {
    write_frame(output, 0, bytes, MAX_DATA)
}
pub fn write_final(output: &mut impl Write, report: &Report) -> Result<()> {
    write_frame(output, 1, &report.encode()?, MAX_RESULT)
}
fn write_frame(output: &mut impl Write, kind: u8, bytes: &[u8], limit: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err("invalid private stream frame length".into());
    }
    output.write_all(&((bytes.len() + 2) as u32).to_be_bytes())?;
    output.write_all(&[1, kind])?;
    output.write_all(bytes)?;
    output.flush()?;
    Ok(())
}
pub fn read_frame(input: &mut impl Read) -> Result<Frame> {
    let mut header = [0; 6];
    input.read_exact(&mut header).map_err(|_|"publication result channel missing or truncated; upgrade receiver or inspect origin before retrying")?;
    let length = u32::from_be_bytes(header[..4].try_into()?) as usize;
    if header[4] != 1
        || !matches!(header[5], 0 | 1)
        || !(3..=MAX_DATA + 2).contains(&length)
        || (header[5] == 1 && length > MAX_RESULT + 2)
    {
        return Err("invalid private stream frame".into());
    }
    let mut bytes = vec![0; length - 2];
    input.read_exact(&mut bytes)?;
    if header[5] == 0 {
        Ok(Frame::Data(bytes))
    } else {
        Ok(Frame::Final(Report::parse(&bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::push_result::{
        self as result, Forwarded, Frame, Outcome, Reason, Report, Row,
    };
    const REF: &str = "refs/heads/contributors/topic";
    fn report(outcome: Outcome) -> Report {
        Report {
            version: 1,
            repository: Some("/srv/repo".into()),
            reference: Some(REF.into()),
            intended: Some("a".repeat(40)),
            receiver_ok: false,
            receiver_reason: Some("onward push failed".into()),
            reason: Reason::ReceiverRejected,
            forwarded: Some(Forwarded {
                url: Some("git@forge.example:org/repo.git".into()),
                rows: vec![],
                outcome,
            }),
        }
    }
    #[test]
    fn framed_git_bytes_are_exact_and_result_records_are_strictly_bounded() {
        let record = report(Outcome::Unknown);
        let mut wire = vec![];
        result::write_data(&mut wire, b"0000PACK\0\x01\xffnative bytes").unwrap();
        result::write_final(&mut wire, &record).unwrap();
        let mut input = &wire[..];
        match result::read_frame(&mut input).unwrap() {
            Frame::Data(bytes) => assert_eq!(bytes, b"0000PACK\0\x01\xffnative bytes"),
            _ => panic!("expected native data"),
        };
        match result::read_frame(&mut input).unwrap() {
            Frame::Final(value) => value.pin(REF, &"a".repeat(40)).unwrap(),
            _ => panic!("expected terminal result"),
        };
        assert!(input.is_empty());
        for wire in [
            vec![0, 0, 0, 2, 1, 0],
            vec![0, 0, 0, 3, 2, 0, 0],
            vec![0, 0, 0, 3, 1, 2, 0],
            ((result::MAX_DATA + 3) as u32)
                .to_be_bytes()
                .into_iter()
                .chain([1, 0])
                .collect(),
            ((result::MAX_RESULT + 3) as u32)
                .to_be_bytes()
                .into_iter()
                .chain([1, 1])
                .collect(),
        ] {
            assert!(result::read_frame(&mut &wire[..]).is_err());
        }
        assert!(Report::parse(&vec![b' '; result::MAX_RESULT + 1]).is_err());
        let bytes = record.encode().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for invalid in [
            text.replace("\"version\":1", "\"version\":2"),
            text.replacen("{", "{\"extra\":1,", 1),
            text.replace("\"version\":1", "\"version\":1,\"version\":1"),
        ] {
            assert!(Report::parse(invalid.as_bytes()).is_err());
        }
        let mut bad = record.clone();
        bad.forwarded.as_mut().unwrap().rows = vec![Row {
            flag: '!',
            summary: "\x1b[31mwrong".into(),
        }];
        assert!(bad.encode().is_err());
        assert!(record.pin(REF, &"b".repeat(40)).is_err());
    }
    #[test]
    fn porcelain_parser_is_bounded_and_ref_pinned() {
        for flag in [' ', '+', '*', '-', '=', '!'] {
            let bytes = format!(
                "To forge\n{flag}\t{}:{REF}\t[native status]\nDone\n",
                "a".repeat(40)
            );
            assert_eq!(
                result::parse_porcelain(bytes.as_bytes(), REF).unwrap()[0].flag,
                flag
            );
        }
        for input in [
            b"remote: invented status\n".as_slice(),
            b"!\tbad:refs/heads/other\t[rejected]\n",
            &vec![b'x'; 8193],
        ] {
            assert!(result::parse_porcelain(input, REF).is_err());
        }
    }
    #[test]
    fn local_hook_stdout_remains_diagnostic_without_weakening_native_rows() {
        let bytes = format!("hook diagnostic\nTo receiver\n*\tHEAD:{REF}\t[new branch]\nDone\n");
        let (rows, diagnostics) = result::receiver_porcelain(bytes.as_bytes(), REF).unwrap();
        assert_eq!(rows[0].flag, '*');
        assert_eq!(diagnostics, b"hook diagnostic\n");
        assert!(result::receiver_porcelain(b"?\tHEAD:refs/heads/other\tbad\n", REF).is_err());
    }

    #[test]
    fn results_reject_non_branch_and_invalid_direct_ref_names() {
        for name in [
            "refs/tags/topic",
            "refs/heads/",
            "refs/heads/.hidden",
            "refs/heads/topic.lock",
            "refs/heads/topic.lock/sub",
            "refs/heads/topic.",
            "refs/heads/topic/",
            "refs/heads/topic//sub",
            "refs/heads/a..b",
        ] {
            let mut record = report(Outcome::Unknown);
            record.reference = Some(name.into());
            assert!(record.encode().is_err(), "accepted invalid ref {name}");
        }
        assert!(result::reference("refs/heads/topic./sub@name"));
    }
}
