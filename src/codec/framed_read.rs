use crate::frame::{self, Frame, Kind, Reason};
use crate::frame::{
    DEFAULT_MAX_FRAME_SIZE, DEFAULT_SETTINGS_HEADER_TABLE_SIZE, MAX_MAX_FRAME_SIZE,
};
use crate::proto::Error;

use crate::hpack;
use crate::wipe::{self, WipingBuf};

use futures_core::Stream;

use bytes::BytesMut;

use std::io;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tokio_util::io::poll_read_buf;

// 16 MB "sane default" taken from golang http2
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: usize = 16 << 20;

/// What the read buffer starts with: tokio-util `FramedRead`'s `INITIAL_CAPACITY`, the reader this
/// one replaces (its buffer freed the peer's bytes unwiped).
const INITIAL_CAPACITY: usize = 8 * 1024;

/// The frame head starts with the payload length, 24 bits (RFC 9113 section 4.1).
const LENGTH_LEN: usize = 3;

/// Reads frames off `T` and decodes them.
///
/// The frames are cut the way tokio-util's `FramedRead` over a `LengthDelimitedCodec` (3-byte
/// big-endian length, adjusted by the 9-byte head, nothing skipped) cut them: the same reads, the
/// same states, the same refusals. The read buffer is a [`WipingBuf`], and so is every frame cut
/// from it, so no block holding the peer's bytes is freed unwiped.
#[derive(Debug)]
pub struct FramedRead<T> {
    io: T,

    /// What the peer sent and is not yet cut into frames.
    buf: WipingBuf,

    /// The largest frame payload accepted.
    max_frame_size: usize,

    /// The whole length (head included) of the frame being read, once its length is in.
    frame_len: Option<usize>,

    /// The last read returned 0 bytes.
    eof: bool,

    /// The buffer may hold a frame.
    is_readable: bool,

    /// The last poll returned an error: the next one returns `None`.
    has_errored: bool,

    decoder: FrameDecoder,
}

#[derive(Debug)]
struct FrameDecoder {
    // hpack decoder state
    hpack: hpack::Decoder,

    max_header_list_size: usize,

    max_continuation_frames: usize,

    partial: Option<Partial>,
}

/// Partially loaded headers frame
#[derive(Debug)]
struct Partial {
    /// Empty frame
    frame: Continuable,

    /// Partial header payload
    buf: WipingBuf,

    continuation_frames_count: usize,
}

#[derive(Debug)]
enum Continuable {
    Headers(frame::Headers),
    PushPromise(frame::PushPromise),
}

impl<T> FramedRead<T> {
    /// A reader accepting frames up to the default max frame size (the caller sets its own with
    /// [`set_max_frame_size`](Self::set_max_frame_size)).
    pub fn new(io: T) -> FramedRead<T> {
        let max_frame_size = DEFAULT_MAX_FRAME_SIZE as usize;
        FramedRead {
            io,
            buf: WipingBuf::with_capacity(INITIAL_CAPACITY),
            max_frame_size,
            frame_len: None,
            eof: false,
            is_readable: false,
            has_errored: false,
            decoder: FrameDecoder::new(max_frame_size),
        }
    }

    pub fn get_ref(&self) -> &T {
        &self.io
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.io
    }

    /// Returns the current max frame size setting
    #[inline]
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Updates the max frame size setting.
    ///
    /// Must be within 16,384 and 16,777,215.
    #[inline]
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(DEFAULT_MAX_FRAME_SIZE as usize <= val && val <= MAX_MAX_FRAME_SIZE as usize);
        self.max_frame_size = val;
        // Update max CONTINUATION frames too, since its based on this
        self.decoder.set_max_frame_size(val);
    }

    /// Update the max header list size setting.
    #[inline]
    pub fn set_max_header_list_size(&mut self, val: usize) {
        self.decoder
            .set_max_header_list_size(val, self.max_frame_size());
    }

    /// Update the header table size setting.
    #[inline]
    pub fn set_header_table_size(&mut self, val: usize) {
        self.decoder.set_header_table_size(val);
    }
}

fn calc_max_continuation_frames(header_max: usize, frame_max: usize) -> usize {
    // At least this many frames needed to use max header list size
    let min_frames_for_list = (header_max / frame_max).max(1);
    // Some padding for imperfectly packed frames
    // 25% without floats
    let padding = min_frames_for_list >> 2;
    min_frames_for_list.saturating_add(padding).max(5)
}

impl FrameDecoder {
    fn new(max_frame_size: usize) -> Self {
        let max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
        FrameDecoder {
            hpack: hpack::Decoder::new(DEFAULT_SETTINGS_HEADER_TABLE_SIZE),
            max_header_list_size,
            max_continuation_frames: calc_max_continuation_frames(
                max_header_list_size,
                max_frame_size,
            ),
            partial: None,
        }
    }

    fn set_max_frame_size(&mut self, val: usize) {
        self.max_continuation_frames = calc_max_continuation_frames(self.max_header_list_size, val);
    }

    fn set_max_header_list_size(&mut self, val: usize, max_frame_size: usize) {
        self.max_header_list_size = val;
        // Update max CONTINUATION frames too, since its based on this
        self.max_continuation_frames = calc_max_continuation_frames(val, max_frame_size);
    }

    fn set_header_table_size(&mut self, val: usize) {
        self.hpack.queue_size_update(val);
    }

    fn decode(&mut self, bytes: WipingBuf) -> Result<Option<Frame>, Error> {
        decode_frame(self, bytes)
    }
}

/// Decodes a frame.
///
/// This function is intentionally de-generified and outlined because it is very large.
fn decode_frame(decoder: &mut FrameDecoder, mut bytes: WipingBuf) -> Result<Option<Frame>, Error> {
    let span = tracing::trace_span!("FramedRead::decode_frame", offset = bytes.len());
    let _e = span.enter();

    tracing::trace!("decoding frame from {}B", bytes.len());

    // Parse the head
    let head = frame::Head::parse(&bytes);

    if decoder.partial.is_some() && head.kind() != Kind::Continuation {
        proto_err!(conn: "expected CONTINUATION, got {:?}", head.kind());
        return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
    }

    let kind = head.kind();

    tracing::trace!(frame.kind = ?kind);

    macro_rules! header_block {
        ($frame:ident, $head:ident, $bytes:ident) => ({
            // Drop the frame header (wiped)
            $bytes.advance(frame::HEADER_LEN);

            // Parse the header frame w/o parsing the payload (`load` wipes what it skips, and
            // all of it when it refuses the frame)
            let (mut frame, payload) = match frame::$frame::load($head, $bytes.into_inner()) {
                Ok(res) => res,
                Err(frame::Error::InvalidDependencyId) => {
                    proto_err!(stream: "invalid HEADERS dependency ID");
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    return Err(Error::library_reset($head.stream_id(), Reason::PROTOCOL_ERROR));
                },
                Err(e) => {
                    proto_err!(conn: "failed to load frame; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };
            // The header block: what HPACK takes from it is wiped as it is taken, the rest when
            // it is dropped (or, partial, when the CONTINUATION frames are done with it).
            let mut payload = WipingBuf::from(payload);

            let is_end_headers = frame.is_end_headers();

            // Load the HPACK encoded headers
            match frame.load_hpack(&mut payload, decoder.max_header_list_size, &mut decoder.hpack) {
                Ok(_) => {},
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {},
                Err(frame::Error::MalformedMessage) => {
                    let id = $head.stream_id();
                    proto_err!(stream: "malformed header block; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                },
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                },
                Err(e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                frame.into()
            } else {
                tracing::trace!("loaded partial header block");
                // Defer returning the frame
                decoder.partial = Some(Partial {
                    frame: Continuable::$frame(frame),
                    buf: payload,
                    continuation_frames_count: 0,
                });

                return Ok(None);
            }
        });
    }

    let frame = match kind {
        Kind::Settings => {
            let res = frame::Settings::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load SETTINGS frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Ping => {
            let res = frame::Ping::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load PING frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::WindowUpdate => {
            let res = frame::WindowUpdate::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load WINDOW_UPDATE frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Data => {
            bytes.advance(frame::HEADER_LEN);
            // The payload outlives the frame: held in a wiping block, wiped in the frame.
            let res = frame::Data::load(head, wipe::hold(&mut bytes));

            // TODO: Should this always be connection level? Probably not...
            res.map_err(|e| {
                proto_err!(conn: "failed to load DATA frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Headers => header_block!(Headers, head, bytes),
        Kind::Reset => {
            let res = frame::Reset::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|e| {
                proto_err!(conn: "failed to load RESET frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::GoAway => {
            let res = frame::GoAway::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|e| {
                proto_err!(conn: "failed to load GO_AWAY frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::PushPromise => header_block!(PushPromise, head, bytes),
        Kind::Priority => {
            if head.stream_id() == 0 {
                // Invalid stream identifier
                proto_err!(conn: "invalid stream ID 0");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            match frame::Priority::load(head, &bytes[frame::HEADER_LEN..]) {
                Ok(frame) => frame.into(),
                Err(frame::Error::InvalidDependencyId) => {
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    let id = head.stream_id();
                    proto_err!(stream: "PRIORITY invalid dependency ID; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(e) => {
                    proto_err!(conn: "failed to load PRIORITY frame; err={:?};", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }
        }
        Kind::Continuation => {
            let is_end_headers = (head.flag() & 0x4) == 0x4;

            let mut partial = match decoder.partial.take() {
                Some(partial) => partial,
                None => {
                    proto_err!(conn: "received unexpected CONTINUATION frame");
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            // The stream identifiers must match
            if partial.frame.stream_id() != head.stream_id() {
                proto_err!(conn: "CONTINUATION frame stream ID does not match previous frame stream ID");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            // Check for CONTINUATION flood
            if is_end_headers {
                partial.continuation_frames_count = 0;
            } else {
                let cnt = partial.continuation_frames_count + 1;
                if cnt > decoder.max_continuation_frames {
                    tracing::debug!(
                        "too_many_continuations, max = {}",
                        decoder.max_continuation_frames
                    );
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "too_many_continuations",
                    ));
                } else {
                    partial.continuation_frames_count = cnt;
                }
            }

            // Extend the buf
            if partial.buf.is_empty() {
                partial.buf = bytes.split_off(frame::HEADER_LEN);
            } else {
                if partial.frame.is_over_size() {
                    // If there was left over bytes previously, they may be
                    // needed to continue decoding, even though we will
                    // be ignoring this frame. This is done to keep the HPACK
                    // decoder state up-to-date.
                    //
                    // Still, we need to be careful, because if a malicious
                    // attacker were to try to send a gigantic string, such
                    // that it fits over multiple header blocks, we could
                    // grow memory uncontrollably again, and that'd be a shame.
                    //
                    // Instead, we use a simple heuristic to determine if
                    // we should continue to ignore decoding, or to tell
                    // the attacker to go away.
                    if partial.buf.len() + bytes.len() > decoder.max_header_list_size {
                        proto_err!(conn: "CONTINUATION frame header block size over ignorable limit");
                        return Err(Error::library_go_away(Reason::COMPRESSION_ERROR));
                    }
                }
                partial.buf.extend_from_slice(&bytes[frame::HEADER_LEN..]);
            }

            match partial.frame.load_hpack(
                &mut partial.buf,
                decoder.max_header_list_size,
                &mut decoder.hpack,
            ) {
                Ok(_) => {}
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {}
                Err(frame::Error::MalformedMessage) => {
                    let id = head.stream_id();
                    proto_err!(stream: "malformed CONTINUATION frame; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded CONTINUATION header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                }
                Err(e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                partial.frame.into()
            } else {
                decoder.partial = Some(partial);
                return Ok(None);
            }
        }
        Kind::Unknown => {
            // Unknown frames are ignored
            return Ok(None);
        }
    };

    Ok(Some(frame))
}

impl<T> Stream for FramedRead<T>
where
    T: AsyncRead + Unpin,
{
    type Item = Result<Frame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let span = tracing::trace_span!("FramedRead::poll_next");
        let _e = span.enter();
        loop {
            tracing::trace!("poll");
            let bytes = match ready!(self.poll_frame(cx)) {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => return Poll::Ready(None),
            };

            tracing::trace!(read.bytes = bytes.len());
            if let Some(frame) = self.decoder.decode(bytes)? {
                tracing::debug!(?frame, "received");
                return Poll::Ready(Some(Ok(frame)));
            }
        }
    }
}

impl<T> FramedRead<T>
where
    T: AsyncRead + Unpin,
{
    /// The next whole frame (head and payload), as tokio-util's `FramedRead` polled its codec:
    /// cut what the buffer holds; else read more; at end of stream, bytes left over that make no
    /// frame are an error; after an error, `None` once.
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<WipingBuf, Error>>> {
        loop {
            if self.has_errored {
                self.is_readable = false;
                self.has_errored = false;
                return Poll::Ready(None);
            }

            if self.is_readable {
                let cut = self.cut();
                if let Err(e) = cut {
                    self.has_errored = true;
                    return Poll::Ready(Some(Err(e)));
                }
                if let Ok(Some(frame)) = cut {
                    return Poll::Ready(Some(Ok(frame)));
                }
                if self.eof {
                    if self.buf.is_empty() {
                        self.is_readable = false;
                        return Poll::Ready(None);
                    }
                    self.has_errored = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "bytes remaining on stream",
                    )
                    .into())));
                }
                self.is_readable = false;
            }

            // Room for at least one byte, so a read of 0 means end of stream. The buffer grows
            // only through its wiping reserve: `poll_read_buf` then reads into the spare room.
            self.buf.reserve(1);
            let n = match poll_read_buf(Pin::new(&mut self.io), cx, &mut *self.buf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => {
                    self.has_errored = true;
                    return Poll::Ready(Some(Err(e.into())));
                }
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                if self.eof {
                    return Poll::Ready(None);
                }
                self.eof = true;
            } else {
                self.eof = false;
            }
            self.is_readable = true;
        }
    }

    /// Cuts the next whole frame off the buffer, if it holds one. A length over the max frame
    /// size is a connection error of type FRAME_SIZE_ERROR (RFC 9113 section 4.2).
    fn cut(&mut self) -> Result<Option<WipingBuf>, Error> {
        let n = match self.frame_len {
            Some(n) => n,
            None => {
                if self.buf.len() < LENGTH_LEN {
                    return Ok(None);
                }
                let len = (usize::from(self.buf[0]) << 16)
                    | (usize::from(self.buf[1]) << 8)
                    | usize::from(self.buf[2]);
                if len > self.max_frame_size {
                    return Err(Error::library_go_away(Reason::FRAME_SIZE_ERROR));
                }
                let n = len + frame::HEADER_LEN;
                // Room for the whole frame.
                self.buf.reserve(n.saturating_sub(self.buf.len()));
                self.frame_len = Some(n);
                n
            }
        };
        if self.buf.len() < n {
            return Ok(None);
        }
        self.frame_len = None;
        let frame = self.buf.split_to(n);
        // Room for the next frame's length.
        self.buf.reserve(LENGTH_LEN.saturating_sub(self.buf.len()));
        Ok(Some(frame))
    }
}

// ===== impl Continuable =====

impl Continuable {
    fn stream_id(&self) -> frame::StreamId {
        match *self {
            Continuable::Headers(ref h) => h.stream_id(),
            Continuable::PushPromise(ref p) => p.stream_id(),
        }
    }

    fn is_over_size(&self) -> bool {
        match *self {
            Continuable::Headers(ref h) => h.is_over_size(),
            Continuable::PushPromise(ref p) => p.is_over_size(),
        }
    }

    fn load_hpack(
        &mut self,
        src: &mut BytesMut,
        max_header_list_size: usize,
        decoder: &mut hpack::Decoder,
    ) -> Result<(), frame::Error> {
        match *self {
            Continuable::Headers(ref mut h) => h.load_hpack(src, max_header_list_size, decoder),
            Continuable::PushPromise(ref mut p) => p.load_hpack(src, max_header_list_size, decoder),
        }
    }
}

impl<T> From<Continuable> for Frame<T> {
    fn from(cont: Continuable) -> Self {
        match cont {
            Continuable::Headers(mut headers) => {
                headers.set_end_headers();
                headers.into()
            }
            Continuable::PushPromise(mut push) => {
                push.set_end_headers();
                push.into()
            }
        }
    }
}
