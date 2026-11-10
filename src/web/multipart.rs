//! A guard in front of the multipart parser.
//!
//! multer buffers a part's headers until it finds `\r\n\r\n`, with no cap, and rescans the whole
//! buffer on every read. Without this guard, one unterminated header could hold the entire
//! upload limit in memory. The guard follows the body as multer will parse it, and fails the
//! stream when the preamble, or the header block of any part, runs past [`MAX_PART_HEAD`].

use std::error::Error as StdError;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body_util::LengthLimitError;

type BoxError = Box<dyn StdError + Send + Sync>;

/// The longest preamble, and the longest delimiter line plus header block of one part.
pub const MAX_PART_HEAD: usize = 16 << 10;

#[derive(Debug)]
pub struct PartHeadTooLarge;

impl fmt::Display for PartHeadTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a multipart header block is too long")
    }
}

impl StdError for PartHeadTooLarge {}

/// Incremental (KMP) search for one pattern; matches may span chunks.
struct Matcher {
    pat: Vec<u8>,
    fail: Vec<usize>,
    matched: usize,
}

impl Matcher {
    fn new(pat: Vec<u8>) -> Self {
        let mut fail = vec![0; pat.len()];
        let mut k = 0;
        for i in 1..pat.len() {
            while k > 0 && pat.get(i) != pat.get(k) {
                k = fail.get(k - 1).copied().unwrap_or(0);
            }
            if pat.get(i) == pat.get(k) {
                k += 1;
            }
            if let Some(f) = fail.get_mut(i) {
                *f = k;
            }
        }
        Self { pat, fail, matched: 0 }
    }

    /// Feeds one byte; true when it completes the pattern (the matcher then starts over).
    fn step(&mut self, b: u8) -> bool {
        while self.matched > 0 && self.pat.get(self.matched) != Some(&b) {
            self.matched = self.fail.get(self.matched - 1).copied().unwrap_or(0);
        }
        if self.pat.get(self.matched) == Some(&b) {
            self.matched += 1;
        }
        if self.matched == self.pat.len() {
            self.matched = 0;
            return true;
        }
        false
    }

    fn first(&self) -> u8 {
        self.pat.first().copied().unwrap_or(0)
    }
}

enum Stage {
    /// Before `--boundary`, which multer accepts anywhere in the preamble.
    Preamble { seen: usize },
    /// In part data, looking for `\r\n--boundary`.
    Data,
    /// After a delimiter: `--` closes the form; otherwise the delimiter line ends with `\r\n`,
    /// and the header block runs to the next `\r\n\r\n`.
    Head { seen: usize, first: [u8; 2], line_done: bool },
    /// After the closing delimiter multer reads no more.
    Done,
}

struct Scanner {
    first: Matcher,
    delim: Matcher,
    crlf: Matcher,
    end_of_head: Matcher,
    stage: Stage,
}

impl Scanner {
    fn new(boundary: &str) -> Self {
        Self {
            first: Matcher::new(format!("--{boundary}").into_bytes()),
            delim: Matcher::new(format!("\r\n--{boundary}").into_bytes()),
            crlf: Matcher::new(b"\r\n".to_vec()),
            end_of_head: Matcher::new(b"\r\n\r\n".to_vec()),
            stage: Stage::Preamble { seen: 0 },
        }
    }

    fn head() -> Stage {
        Stage::Head { seen: 0, first: [0; 2], line_done: false }
    }

    fn feed(&mut self, chunk: &[u8]) -> Result<(), PartHeadTooLarge> {
        let mut i = 0;
        while i < chunk.len() {
            let rest = chunk.get(i..).unwrap_or_default();
            match &mut self.stage {
                Stage::Done => return Ok(()),
                Stage::Data => {
                    // Skip straight to the next byte that could start a delimiter.
                    if self.delim.matched == 0 {
                        match memchr::memchr(self.delim.first(), rest) {
                            Some(off) => i += off,
                            None => return Ok(()),
                        }
                    }
                    let b = chunk.get(i).copied().unwrap_or_default();
                    i += 1;
                    if self.delim.step(b) {
                        self.stage = Self::head();
                    }
                }
                Stage::Preamble { seen } => {
                    let skip = if self.first.matched == 0 {
                        memchr::memchr(self.first.first(), rest).unwrap_or(rest.len())
                    } else {
                        0
                    };
                    *seen += skip;
                    i += skip;
                    if *seen > MAX_PART_HEAD {
                        return Err(PartHeadTooLarge);
                    }
                    let Some(&b) = chunk.get(i) else { return Ok(()) };
                    i += 1;
                    *seen += 1;
                    if self.first.step(b) {
                        self.stage = Self::head();
                    } else if *seen > MAX_PART_HEAD {
                        return Err(PartHeadTooLarge);
                    }
                }
                Stage::Head { seen, first, line_done } => {
                    let b = chunk.get(i).copied().unwrap_or_default();
                    i += 1;
                    *seen += 1;
                    if *seen > MAX_PART_HEAD {
                        return Err(PartHeadTooLarge);
                    }
                    if *seen <= 2 {
                        if let Some(slot) = first.get_mut(*seen - 1) {
                            *slot = b;
                        }
                        if *seen == 2 && *first == *b"--" {
                            self.stage = Stage::Done;
                            continue;
                        }
                    }
                    if !*line_done {
                        if self.crlf.step(b) {
                            *line_done = true;
                        }
                    } else if self.end_of_head.step(b) {
                        self.stage = Stage::Data;
                    }
                }
            }
        }
        Ok(())
    }
}

/// The request body, failing with [`PartHeadTooLarge`] once a header block runs too long.
pub struct Guarded<S> {
    inner: S,
    scan: Scanner,
    failed: bool,
}

impl<S> Guarded<S> {
    pub fn new(inner: S, boundary: &str) -> Self {
        Self { inner, scan: Scanner::new(boundary), failed: false }
    }
}

impl<S, E> Stream for Guarded<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<BoxError>,
{
    type Item = Result<Bytes, BoxError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.failed {
            return Poll::Ready(None);
        }
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(chunk))) => match self.scan.feed(&chunk) {
                Ok(()) => Poll::Ready(Some(Ok(chunk))),
                Err(e) => {
                    self.failed = true;
                    Poll::Ready(Some(Err(Box::new(e))))
                }
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Whether a parser error comes from the body limit or from this guard.
pub fn too_large(e: &multer::Error) -> bool {
    let multer::Error::StreamReadFailed(source) = e else { return false };
    let mut cur: Option<&(dyn StdError + 'static)> = Some(&**source);
    while let Some(err) = cur {
        if err.is::<PartHeadTooLarge>() || err.is::<LengthLimitError>() {
            return true;
        }
        cur = err.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(boundary: &str, chunks: &[&[u8]]) -> Result<(), PartHeadTooLarge> {
        let mut s = Scanner::new(boundary);
        chunks.iter().try_for_each(|c| s.feed(c))
    }

    #[test]
    fn a_well_formed_body_passes_in_any_chunking() {
        let mut body = b"--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n".to_vec();
        body.extend(vec![b'-'; 100_000]);
        body.extend(b"\r\n--xy\r\n--xyz\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nv\r\n--xyz--\r\n");
        for size in [1, 2, 3, 7, 4096, body.len()] {
            let chunks: Vec<&[u8]> = body.chunks(size).collect();
            assert!(scan("xyz", &chunks).is_ok(), "chunk size {size}");
        }
    }

    #[test]
    fn long_headers_and_preambles_are_refused() {
        let junk = vec![b'a'; MAX_PART_HEAD + 1];
        let head = [b"--xyz\r\nX: ".as_slice(), &junk].concat();
        assert!(scan("xyz", &[&head]).is_err());
        let bare = [b"--xyz\r\n\r\n".as_slice(), &junk].concat();
        assert!(scan("xyz", &[&bare]).is_err());
        assert!(scan("xyz", &[&junk]).is_err());
        let second = [b"--xyz\r\n\r\n\r\nv\r\n--xyz\r\nX: ".as_slice(), &junk].concat();
        assert!(scan("xyz", &[&second]).is_err());
        assert!(scan("xyz", &[b"--xyz--", &junk]).is_ok());
    }
}
