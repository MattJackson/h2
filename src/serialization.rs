//! Optional labels for outgoing bytes, on both roles.
//!
//! A connection built with a [`Labels`] sink reports, in the order it encodes, which wire stream each
//! run of encoded bytes belongs to, whether the run is DATA payload or control, where a sealed header
//! value goes, and when a stream's last frame is encoded. The labels describe encoded bytes, never
//! socket progress. Every call is infallible and synchronous: nothing is batched, held or bound.

use std::fmt;

/// A connection's label sink. `wire` is the stream identifier of the frame; 0 is the connection.
pub trait Labels: Send + Sync + fmt::Debug {
    /// `len` bytes (never 0) were encoded for `wire`. `payload`: DATA frame payload, one for one.
    /// Everything else is control: frame heads, header blocks, padding, RST_STREAM. Frames that are
    /// about a stream but not part of its message (WINDOW_UPDATE, PRIORITY) are reported on 0.
    fn span(&self, wire: u32, payload: bool, len: usize);
    /// Bytes `offset..offset + len` of sealed value `slot` of `wire` belong here. Nothing was encoded
    /// for them; the frame's length counts them.
    fn sealed(&self, wire: u32, slot: u32, offset: u32, len: u32);
    /// The last frame of `wire` is encoded: END_STREAM (`None`) or RST_STREAM (its reason).
    fn end(&self, wire: u32, failed: Option<u32>);
}

/// Request extension (client): the places in `:path` where a sealed value goes, as `(offset, len)` into
/// the path as supplied, ascending and not overlapping. The path holds a filler of `len` bytes at each;
/// no byte of a filler is encoded. The spans are slots 0, 1, 2, ... in order.
///
/// On a connection with a sink, a header value marked sensitive is a sealed value as well: a
/// never-indexed literal, not Huffman-coded, whose length is stated and whose bytes are not encoded.
/// Header slots are numbered in encoding order after the path's.
#[derive(Clone, Debug, Default)]
pub struct SealedPath(pub Vec<(u32, u32)>);

/// One sealed place in an encoded header block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mark {
    /// Index into the block's encoded bytes (the sealed bytes themselves are not there).
    pub(crate) at: usize,
    pub(crate) slot: u32,
    /// The first byte of the slot not yet placed in a frame.
    pub(crate) offset: u32,
    /// Bytes of the slot still to place.
    pub(crate) len: u32,
}

/// What the header encoder seals in the block it is encoding.
#[derive(Debug, Default)]
pub(crate) struct Seal {
    /// The connection has a sink: sensitive values are sealed.
    pub(crate) on: bool,
    /// The spans of `:path` for the block being encoded.
    pub(crate) path: Vec<(u32, u32)>,
    /// The marks of the block being encoded, ascending.
    pub(crate) marks: Vec<Mark>,
    next_slot: u32,
    /// Where the block being encoded starts in the encoder's buffer.
    pub(crate) base: usize,
}

impl Seal {
    /// Starts a block.
    pub(crate) fn begin(&mut self, path: Vec<(u32, u32)>) {
        self.path = path;
        self.marks.clear();
        self.next_slot = 0;
    }
    /// A sealed value of `len` bytes belongs at `at` of the block.
    pub(crate) fn mark(&mut self, at: usize, len: usize) {
        if len == 0 {
            return;
        }
        self.marks.push(Mark {
            at,
            slot: self.next_slot,
            offset: 0,
            len: len as u32,
        });
        self.next_slot += 1;
    }
    /// The block's marks, leaving none (and no memory when there were none).
    pub(crate) fn take(&mut self) -> Vec<Mark> {
        self.path = Vec::new();
        std::mem::take(&mut self.marks)
    }
}

/// One run of a header frame's payload as it was placed in the frame, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Segment {
    /// Encoded bytes (the frame head included in the first).
    Bytes(usize),
    /// Sealed bytes: counted by the frame's length, absent from the buffer.
    Sealed { slot: u32, offset: u32, len: u32 },
}
