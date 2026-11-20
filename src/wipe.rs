//! Blocks holding a peer's bytes are wiped before they go back to the allocator.
//!
//! A header block carries credentials (an `authorization` value, a cookie, a token in `:path`),
//! and so can a DATA payload. The read buffer the frames are cut from, each frame, the header
//! block's literal strings, the HPACK dynamic table's entries and the DATA payloads all live in
//! blocks of memory that are freed when the last view of them is dropped. Freed as they are, the
//! credential stays readable in freed memory for as long as the allocator leaves it there.
//!
//! So every byte read from the peer is wiped before its block is released:
//!
//! - a buffer holding a peer's bytes (the read buffer, a frame, a header block, the Huffman
//!   scratch) is a [`WipingBuf`]: its bytes are wiped when it is dropped, when it skips or cuts
//!   bytes, and when it grows into a new block (the old block is wiped before it is freed);
//! - what outlives the frame (a header value, a DATA payload) is copied once by [`hold`] into a
//!   block that wipes itself when the last `Bytes` sharing it is dropped, and the bytes it was
//!   copied from are wiped at once.
//!
//! The same bytes are read and decoded in the same order; only the release changes.

use std::fmt;
use std::ops::{Deref, DerefMut};

use bytes::{Buf, Bytes, BytesMut};
use zeroize::Zeroize;

/// A block holding a copy of a peer's bytes; wiped before it is freed.
struct Wiped(Box<[u8]>);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0[..].zeroize();
    }
}

/// Copies `src` into a block that wipes itself when the last `Bytes` sharing it is dropped, and
/// wipes `src` where it stands.
pub(crate) fn hold(src: &mut [u8]) -> Bytes {
    if src.is_empty() {
        return Bytes::new();
    }
    let held = Bytes::from_owner(Wiped(Box::from(&src[..])));
    src.zeroize();
    held
}

/// A `BytesMut` holding a peer's bytes: wiped before any of its bytes leave its view unwiped.
pub(crate) struct WipingBuf(BytesMut);

impl WipingBuf {
    pub(crate) fn with_capacity(capacity: usize) -> WipingBuf {
        WipingBuf(BytesMut::with_capacity(capacity))
    }

    /// Hands the view over unwiped: the caller takes on wiping it (see `frame::Headers::load`).
    pub(crate) fn into_inner(mut self) -> BytesMut {
        std::mem::take(&mut self.0)
    }

    /// Makes room for at least `additional` more bytes. When that takes a new block, the bytes
    /// are copied into it and the old view is wiped before it is released (`BytesMut::reserve`
    /// would free or reuse the old block with the bytes still in it).
    pub(crate) fn reserve(&mut self, additional: usize) {
        if self.0.capacity() - self.0.len() >= additional {
            return;
        }
        let mut grown = BytesMut::with_capacity(self.0.len() + additional);
        grown.extend_from_slice(&self.0);
        self.0[..].zeroize();
        self.0 = grown;
    }

    /// Appends `src`, growing through the wiping [`reserve`](Self::reserve).
    pub(crate) fn extend_from_slice(&mut self, src: &[u8]) {
        self.reserve(src.len());
        self.0.extend_from_slice(src);
    }

    /// Skips the first `cnt` bytes, wiping them.
    pub(crate) fn advance(&mut self, cnt: usize) {
        self.0[..cnt].zeroize();
        self.0.advance(cnt);
    }

    /// Cuts the view to `len` bytes, wiping what is cut.
    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.0.len() {
            self.0[len..].zeroize();
            self.0.truncate(len);
        }
    }

    /// Splits off the first `at` bytes as a view that wipes itself.
    pub(crate) fn split_to(&mut self, at: usize) -> WipingBuf {
        WipingBuf(self.0.split_to(at))
    }

    /// Splits off the bytes from `at` on as a view that wipes itself.
    pub(crate) fn split_off(&mut self, at: usize) -> WipingBuf {
        WipingBuf(self.0.split_off(at))
    }
}

impl From<BytesMut> for WipingBuf {
    fn from(src: BytesMut) -> WipingBuf {
        WipingBuf(src)
    }
}

impl Deref for WipingBuf {
    type Target = BytesMut;

    fn deref(&self) -> &BytesMut {
        &self.0
    }
}

impl DerefMut for WipingBuf {
    fn deref_mut(&mut self) -> &mut BytesMut {
        &mut self.0
    }
}

impl fmt::Debug for WipingBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl Drop for WipingBuf {
    fn drop(&mut self) {
        self.0[..].zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"authorization: Bearer sk-wipe-test-0123456789";

    #[test]
    fn hold_keeps_the_bytes_and_wipes_where_they_stood() {
        let mut src = SECRET.to_vec();
        let held = hold(&mut src);
        assert_eq!(&held[..], SECRET);
        assert!(src.iter().all(|b| *b == 0));
        assert!(hold(&mut []).is_empty());
    }

    #[test]
    fn advance_and_truncate_keep_the_view_they_are_asked_for() {
        let mut buf = WipingBuf::from(BytesMut::from(SECRET));
        buf.advance(15);
        buf.truncate(6);
        assert_eq!(&buf[..], b"Bearer");
        buf.truncate(10);
        assert_eq!(&buf[..], b"Bearer");
    }

    #[test]
    fn reserve_and_extend_keep_the_bytes_when_they_move() {
        let mut buf = WipingBuf::with_capacity(8);
        buf.extend_from_slice(&SECRET[..8]);
        buf.extend_from_slice(&SECRET[8..]);
        assert_eq!(&buf[..], SECRET);
        let before = buf.as_ptr();
        buf.reserve(0);
        assert_eq!(buf.as_ptr(), before);
    }

    #[test]
    fn splits_are_wiping_views_of_the_same_bytes() {
        let mut buf = WipingBuf::from(BytesMut::from(SECRET));
        let mut head = buf.split_to(13);
        let tail = head.split_off(5);
        assert_eq!(&head[..], b"autho");
        assert_eq!(&tail[..], b"rization");
        assert_eq!(&buf[..], &SECRET[13..]);
        assert_eq!(&buf.into_inner()[..], &SECRET[13..]);
    }
}
