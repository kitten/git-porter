//! Exact intent shapes and their transfer mode; origin text never grants force.
//! @ref LLP 0001#framing
use crate::Result;

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Ff,
    Force,
    Lease,
}
impl Mode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "ff" => Ok(Self::Ff),
            "force" => Ok(Self::Force),
            "lease" => Ok(Self::Lease),
            _ => Err("invalid transfer mode".into()),
        }
    }
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Ff => "ff",
            Self::Force => "force",
            Self::Lease => "lease",
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Update<'a> {
    pub(super) reference: &'a str,
    pub(super) sha: &'a str,
    pub(super) observed: &'a str,
}

pub(super) struct Intent<'a> {
    pub(super) operation: &'a [u8],
    pub(super) path: &'a [u8],
    pub(super) origin: &'a [u8],
    pub(super) request: Option<Update<'a>>,
    pub(super) hint: Option<&'a str>,
    pub(super) mode: Mode,
}
impl<'a> Intent<'a> {
    pub(super) fn parse(payload: &'a [u8], publication: bool) -> Result<Self> {
        let mut fields: Vec<_> = payload.split(|b| *b == 0).collect();
        let mut hint = None;
        if fields.len() >= 2 && fields[fields.len() - 2] == b"path-hint-v1" {
            let value = std::str::from_utf8(fields.last().unwrap())?;
            crate::runtime::protocol::relative_hint(value)?;
            hint = Some(value);
            fields.truncate(fields.len() - 2);
        }
        let (operation, path, origin, mode, request) = match fields.as_slice() {
            [op, path, origin] if !publication => (*op, *path, *origin, Mode::Ff, None),
            [op, path, origin, b"force-v1"] if !publication && *op == b"receive" => {
                (*op, *path, *origin, Mode::Force, None)
            }
            [
                b"intent-v2",
                op,
                path,
                origin,
                mode,
                reference,
                sha,
                observed,
            ] if publication || *op == b"receive" && *mode == b"lease" => {
                let mode = Mode::parse(std::str::from_utf8(mode)?)?;
                (
                    *op,
                    *path,
                    *origin,
                    mode,
                    Some(Update {
                        reference: std::str::from_utf8(reference)?,
                        sha: std::str::from_utf8(sha)?,
                        observed: std::str::from_utf8(observed)?,
                    }),
                )
            }
            _ => return Err("invalid transfer intent".into()),
        };
        if !origin.is_empty() {
            crate::server::discovery::RemoteIdentities::parse(std::str::from_utf8(origin)?)?;
        }
        Ok(Self {
            operation,
            path,
            origin,
            mode,
            request,
            hint,
        })
    }
}
#[cfg(test)]
mod intent_tests {
    use super::*;
    #[test]
    fn force_is_only_granted_by_its_matched_shape() {
        assert!(Intent::parse(b"receive\0repo\0force-v1", false).is_err());
        assert!(Intent::parse(b"receive\0repo\0\0force-v1\0extra", false).is_err());
        assert_eq!(
            Intent::parse(b"receive\0repo\0", false)
                .unwrap()
                .mode
                .as_str(),
            "ff"
        );
        assert_eq!(
            Intent::parse(b"receive\0repo\0\0force-v1", false)
                .unwrap()
                .mode
                .as_str(),
            "force"
        );
    }
}
