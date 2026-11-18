//! Length-prefixed SSH-agent fields within already bounded messages.
use crate::Result;

pub(crate) fn string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

pub(crate) fn take<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    if input.len() < 4 {
        return Err("truncated agent field".into());
    }
    let size = u32::from_be_bytes(input[..4].try_into()?) as usize;
    *input = &input[4..];
    if size > input.len() {
        return Err("truncated agent field".into());
    }
    let (value, rest) = input.split_at(size);
    *input = rest;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fields_borrow_exactly_their_payload_and_reject_truncation() {
        let mut wire = Vec::new();
        string(&mut wire, b"key");
        string(&mut wire, b"");
        wire.push(42);
        let mut input = wire.as_slice();
        assert_eq!(take(&mut input).unwrap(), b"key");
        assert_eq!(take(&mut input).unwrap(), b"");
        assert_eq!(input, [42]);
        for length in 0..7 {
            assert!(take(&mut &wire[..length]).is_err());
        }
        assert!(take(&mut u32::MAX.to_be_bytes().as_slice()).is_err());
    }
}
