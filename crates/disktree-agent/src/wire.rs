//! The bytes under the protocol: frames, and the numbers and strings inside
//! them.
//!
//! Hand-rolled rather than serde: the tree is the only payload that matters,
//! it needs a layout of its own anyway (pre-order, derived fields left out,
//! split at node boundaries), and the core types would otherwise all need
//! derives for a format that is a few dozen lines here.
//!
//! A frame is a tag byte, a varint payload length, then the payload.
//! Numbers are LEB128 varints, signed ones zigzagged first; strings and
//! paths are a varint length and their bytes.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// The largest payload a frame may claim. A tree chunk is a few MiB at
/// most; anything near this is a stream out of step, not a message, and
/// must not become an allocation.
pub const MAX_FRAME: usize = 64 << 20;

/// A payload under construction.
#[derive(Debug, Default)]
pub struct Encoder {
    pub buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn bool(&mut self, value: bool) {
        self.buf.push(u8::from(value));
    }

    pub fn uint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.buf.push((value as u8) | 0x80);
            value >>= 7;
        }
        self.buf.push(value as u8);
    }

    pub fn usize(&mut self, value: usize) {
        self.uint(value as u64);
    }

    pub fn int(&mut self, value: i64) {
        self.uint(((value << 1) ^ (value >> 63)).cast_unsigned());
    }

    /// The exact bits, so a fraction comes back unchanged.
    pub fn f64(&mut self, value: f64) {
        self.buf.extend_from_slice(&value.to_bits().to_le_bytes());
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.usize(value.len());
        self.buf.extend_from_slice(value);
    }

    pub fn str(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    /// A path as the bytes the OS gave, so a name that is not UTF-8
    /// still names the same file on the far side.
    pub fn path(&mut self, value: &Path) {
        self.bytes(os_bytes(value.as_os_str()).as_ref());
    }

    pub fn option<T>(
        &mut self,
        value: Option<T>,
        put: impl FnOnce(&mut Self, T),
    ) {
        self.bool(value.is_some());
        if let Some(value) = value {
            put(self, value);
        }
    }
}

/// Reads one payload.
#[derive(Debug)]
pub struct Decoder<'a> {
    buf: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// What has not been read yet.
    pub const fn rest(&self) -> &'a [u8] {
        self.buf
    }

    pub fn u8(&mut self) -> io::Result<u8> {
        let (&first, rest) = self.buf.split_first().ok_or_else(truncated)?;
        self.buf = rest;
        Ok(first)
    }

    pub fn bool(&mut self) -> io::Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(invalid(format!("{other} is not a boolean"))),
        }
    }

    pub fn uint(&mut self) -> io::Result<u64> {
        let mut value = 0_u64;
        // Ten groups of seven bits hold 64; an eleventh is a broken stream.
        for shift in (0..64).step_by(7) {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(invalid("a varint longer than 64 bits"))
    }

    pub fn usize(&mut self) -> io::Result<usize> {
        usize::try_from(self.uint()?)
            .map_err(|_| invalid("a count larger than this machine's memory"))
    }

    pub fn u32(&mut self) -> io::Result<u32> {
        u32::try_from(self.uint()?).map_err(|_| invalid("a u32 out of range"))
    }

    pub fn int(&mut self) -> io::Result<i64> {
        let raw = self.uint()?;
        Ok((raw >> 1).cast_signed() ^ -(raw & 1).cast_signed())
    }

    pub fn f64(&mut self) -> io::Result<f64> {
        let (bits, rest) =
            self.buf.split_at_checked(8).ok_or_else(truncated)?;
        self.buf = rest;
        let bits: [u8; 8] = bits.try_into().map_err(|_| truncated())?;
        Ok(f64::from_bits(u64::from_le_bytes(bits)))
    }

    pub fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let len = self.usize()?;
        let (value, rest) =
            self.buf.split_at_checked(len).ok_or_else(truncated)?;
        self.buf = rest;
        Ok(value)
    }

    pub fn str(&mut self) -> io::Result<&'a str> {
        std::str::from_utf8(self.bytes()?)
            .map_err(|_| invalid("a string that is not UTF-8"))
    }

    pub fn string(&mut self) -> io::Result<String> {
        self.str().map(str::to_owned)
    }

    pub fn path(&mut self) -> io::Result<PathBuf> {
        Ok(path_from_bytes(self.bytes()?))
    }

    pub fn option<T>(
        &mut self,
        take: impl FnOnce(&mut Self) -> io::Result<T>,
    ) -> io::Result<Option<T>> {
        if self.bool()? {
            take(self).map(Some)
        } else {
            Ok(None)
        }
    }

    /// A count of items that each take at least one byte: a larger count
    /// than the bytes left is a broken stream, and believing it would
    /// reserve memory for it.
    pub fn count(&mut self) -> io::Result<usize> {
        let count = self.usize()?;
        if count > self.buf.len() {
            return Err(invalid("a count longer than its payload"));
        }
        Ok(count)
    }
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> std::borrow::Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt;
    std::borrow::Cow::Borrowed(value.as_bytes())
}

/// Elsewhere a path crosses as UTF-8: the agent runs on Unix, and a
/// Windows client only ever shows its paths.
#[cfg(not(unix))]
fn os_bytes(value: &OsStr) -> std::borrow::Cow<'_, [u8]> {
    match value.to_string_lossy() {
        std::borrow::Cow::Borrowed(text) => {
            std::borrow::Cow::Borrowed(text.as_bytes())
        }
        std::borrow::Cow::Owned(text) => {
            std::borrow::Cow::Owned(text.into_bytes())
        }
    }
}

#[cfg(unix)]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn truncated() -> io::Error {
    invalid("a message ended early")
}

/// Write one frame. Not flushed: the caller decides when a batch is done.
pub fn write_frame(
    out: &mut impl Write,
    tag: u8,
    payload: &[u8],
) -> io::Result<()> {
    let mut header = Encoder::new();
    header.u8(tag);
    header.usize(payload.len());
    out.write_all(&header.buf)?;
    out.write_all(payload)
}

/// Read one frame, or `None` at a clean end of stream between frames.
pub fn read_frame(input: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut tag = [0_u8];
    if input.read(&mut tag)? == 0 {
        return Ok(None);
    }
    let mut len = 0_usize;
    let mut ended = false;
    for shift in (0..64).step_by(7) {
        let mut byte = [0_u8];
        input.read_exact(&mut byte)?;
        len |= usize::from(byte[0] & 0x7F) << shift;
        if byte[0] & 0x80 == 0 {
            ended = true;
            break;
        }
    }
    // Ten bytes that all go on would leave a length cut short, and the
    // stream read out of step from there.
    if !ended {
        return Err(invalid("a frame length longer than 64 bits"));
    }
    if len > MAX_FRAME {
        return Err(invalid(format!(
            "a frame of {len} bytes: the stream is out of step"
        )));
    }
    let mut payload = vec![0; len];
    input.read_exact(&mut payload)?;
    Ok(Some((tag[0], payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_round_trip_at_their_edges() {
        let unsigned = [0, 1, 127, 128, 16_383, 16_384, u64::MAX];
        let signed = [0, 1, -1, 63, -64, 64, i64::MAX, i64::MIN];
        let floats = [0.0, 0.8, -1.5, f64::MAX, f64::MIN_POSITIVE];
        let mut out = Encoder::new();
        for value in unsigned {
            out.uint(value);
        }
        for value in signed {
            out.int(value);
        }
        for value in floats {
            out.f64(value);
        }
        let mut input = Decoder::new(&out.buf);
        for value in unsigned {
            assert_eq!(input.uint().unwrap(), value);
        }
        for value in signed {
            assert_eq!(input.int().unwrap(), value);
        }
        for value in floats {
            assert_eq!(input.f64().unwrap().to_bits(), value.to_bits());
        }
        assert!(input.is_empty());
    }

    #[test]
    fn a_short_or_overlong_payload_is_an_error_not_a_panic() {
        assert!(Decoder::new(&[0x80]).uint().is_err());
        assert!(Decoder::new(&[0xFF; 11]).uint().is_err());
        assert!(Decoder::new(&[5, b'a']).bytes().is_err());
        assert!(Decoder::new(&[9, 1]).count().is_err());
        assert!(Decoder::new(&[2]).bool().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_keeps_its_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(OsStr::from_bytes(b"/tmp/caf\xe9\nnew"));
        let mut out = Encoder::new();
        out.path(path);
        assert_eq!(Decoder::new(&out.buf).path().unwrap(), path);
    }

    #[test]
    fn frames_round_trip_and_end_cleanly() {
        let mut stream = Vec::new();
        write_frame(&mut stream, 7, b"hello").unwrap();
        write_frame(&mut stream, 8, &[]).unwrap();
        let mut input = stream.as_slice();
        assert_eq!(read_frame(&mut input).unwrap(), Some((7, b"hello".into())));
        assert_eq!(read_frame(&mut input).unwrap(), Some((8, Vec::new())));
        assert_eq!(read_frame(&mut input).unwrap(), None);
    }

    #[test]
    fn an_overlong_frame_length_is_refused_not_read_out_of_step() {
        // Ten continuation bytes would read as a length of zero, and the
        // frame after as the next one.
        let mut stream = vec![1];
        stream.extend_from_slice(&[0x80; 10]);
        write_frame(&mut stream, 7, b"hello").unwrap();
        let error = read_frame(&mut stream.as_slice()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("longer than 64 bits"), "{error}");
    }

    #[test]
    fn a_frame_claiming_too_much_is_refused_before_allocating() {
        let mut stream = vec![1];
        let mut header = Encoder::new();
        header.usize(MAX_FRAME + 1);
        stream.extend_from_slice(&header.buf);
        assert!(read_frame(&mut stream.as_slice()).is_err());
    }
}
