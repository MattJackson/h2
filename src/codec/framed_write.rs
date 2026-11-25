use crate::codec::UserError;
use crate::codec::UserError::*;
use crate::frame::{self, Frame, FrameSize};
use crate::hpack;

use bytes::{Buf, BufMut, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_write_buf;

use std::io::{self, Cursor};

// A macro to get around a method needing to borrow &mut self
macro_rules! limited_write_buf {
    ($self:expr) => {{
        let limit = $self.max_frame_size() + frame::HEADER_LEN;
        $self.buf.get_mut().limit(limit)
    }};
}

#[derive(Debug)]
pub struct FramedWrite<T, B> {
    /// Upstream `AsyncWrite`
    inner: T,
    final_flush_done: bool,

    encoder: Encoder<B>,
}

#[derive(Debug)]
struct Encoder<B> {
    /// The label sink, when the connection labels its output.
    labels: Option<std::sync::Arc<dyn crate::serialization::Labels>>,
    /// The header block being continued ends its stream.
    continuation_end: bool,
    /// How a header frame's payload was placed when it holds sealed values (else empty, no memory).
    segments: Vec<crate::serialization::Segment>,
    /// HPACK encoder
    hpack: hpack::Encoder,

    /// Write buffer
    ///
    /// TODO: Should this be a ring buffer?
    buf: Cursor<BytesMut>,

    /// Next frame to encode
    next: Option<Next<B>>,

    /// Last data frame
    last_data_frame: Option<frame::Data<B>>,

    /// Max frame size, this is specified by the peer
    max_frame_size: FrameSize,

    /// Chain payloads bigger than this.
    chain_threshold: usize,

    /// Min buffer required to attempt to write a frame
    min_buffer_capacity: usize,
}

#[derive(Debug)]
enum Next<B> {
    Data(frame::Data<B>),
    Continuation(frame::Continuation),
}

/// Initialize the connection with this amount of write buffer.
///
/// The minimum MAX_FRAME_SIZE is 16kb, so always be able to send a HEADERS
/// frame that big.
const DEFAULT_BUFFER_CAPACITY: usize = 16 * 1_024;

/// Chain payloads bigger than this when vectored I/O is enabled. The remote
/// will never advertise a max frame size less than this (well, the spec says
/// the max frame size can't be less than 16kb, so not even close).
const CHAIN_THRESHOLD: usize = 256;

/// Chain payloads bigger than this when vectored I/O is **not** enabled.
/// A larger value in this scenario will reduce the number of small and
/// fragmented data being sent, and hereby improve the throughput.
const CHAIN_THRESHOLD_WITHOUT_VECTORED_IO: usize = 1024;

// TODO: Make generic
impl<T, B> FramedWrite<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    pub fn new(inner: T) -> FramedWrite<T, B> {
        let chain_threshold = if inner.is_write_vectored() {
            CHAIN_THRESHOLD
        } else {
            CHAIN_THRESHOLD_WITHOUT_VECTORED_IO
        };
        FramedWrite {
            inner,
            final_flush_done: false,
            encoder: Encoder {
                labels: None,
                continuation_end: false,
                segments: Vec::new(),
                hpack: hpack::Encoder::default(),
                buf: Cursor::new(BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY)),
                next: None,
                last_data_frame: None,
                max_frame_size: frame::DEFAULT_MAX_FRAME_SIZE,
                chain_threshold,
                min_buffer_capacity: chain_threshold + frame::HEADER_LEN,
            },
        }
    }

    /// Returns `Ready` when `send` is able to accept a frame
    ///
    /// Calling this function may result in the current contents of the buffer
    /// to be flushed to `T`.
    pub fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.encoder.has_capacity() {
            // Try flushing
            ready!(self.flush(cx))?;

            if !self.encoder.has_capacity() {
                return Poll::Pending;
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Returns whether a frame can be buffered without first flushing the
    /// underlying I/O object.
    pub(crate) fn has_capacity(&self) -> bool {
        self.encoder.has_capacity()
    }

    /// Buffer a frame.
    ///
    /// `poll_ready` must be called first to ensure that a frame may be
    /// accepted.
    pub fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        self.encoder.buffer(item)
    }

    /// Flush buffered data to the wire
    pub fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        let span = tracing::trace_span!("FramedWrite::flush");
        let _e = span.enter();

        loop {
            while !self.encoder.is_empty() {
                let n = match self.encoder.next {
                    Some(Next::Data(ref mut frame)) => {
                        tracing::trace!(queued_data_frame = true);
                        let mut buf = (&mut self.encoder.buf).chain(frame.payload_mut());
                        ready!(poll_write_buf(Pin::new(&mut self.inner), cx, &mut buf))?
                    }
                    _ => {
                        tracing::trace!(queued_data_frame = false);
                        ready!(poll_write_buf(
                            Pin::new(&mut self.inner),
                            cx,
                            &mut self.encoder.buf
                        ))?
                    }
                };
                if n == 0 {
                    // No progress is possible; retrying would busy-loop.
                    tracing::trace!("write returned zero, but non-zero bytes remaining");
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
            }

            match self.encoder.unset_frame() {
                ControlFlow::Continue => (),
                ControlFlow::Break => break,
            }
        }

        tracing::trace!("flushing buffer");
        // Flush the upstream
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    /// Close the codec
    pub fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.final_flush_done {
            ready!(self.flush(cx))?;
            self.final_flush_done = true;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[must_use]
enum ControlFlow {
    Continue,
    Break,
}

impl<B> Encoder<B>
where
    B: Buf,
{
    /// States the labels of one header frame just encoded for `wire`: the buffer grew from `before`.
    /// With sealed values the frame's payload is runs of encoded bytes around the sealed places.
    fn label_header_frame(&mut self, wire: u32, before: usize) {
        let labels = match &self.labels {
            Some(labels) => labels,
            None => {
                self.segments.clear();
                return;
            }
        };
        if self.segments.is_empty() {
            labels.span(wire, false, self.buf.get_ref().len() - before);
            return;
        }
        for segment in self.segments.drain(..) {
            match segment {
                crate::serialization::Segment::Bytes(len) => labels.span(wire, false, len),
                crate::serialization::Segment::Sealed { slot, offset, len } => {
                    labels.sealed(wire, slot, offset, len)
                }
            }
        }
    }

    fn unset_frame(&mut self) -> ControlFlow {
        // Clear internal buffer
        self.buf.set_position(0);
        self.buf.get_mut().clear();

        // The data frame has been written, so unset it
        match self.next.take() {
            Some(Next::Data(frame)) => {
                self.last_data_frame = Some(frame);
                debug_assert!(self.is_empty());
                ControlFlow::Break
            }
            Some(Next::Continuation(frame)) => {
                let wire: u32 = frame.stream_id().into();

                // Buffer the continuation frame, then try to write again
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = frame.encode(&mut buf, &mut self.segments) {
                    self.next = Some(Next::Continuation(continuation));
                }
                // The buffer was cleared above: the frame is all of it.
                self.label_header_frame(wire, 0);
                if self.next.is_none() {
                    if self.continuation_end {
                        if let Some(labels) = &self.labels {
                            labels.end(wire, None);
                        }
                    }
                    self.continuation_end = false;
                }
                ControlFlow::Continue
            }
            None => ControlFlow::Break,
        }
    }

    fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        // Ensure that we have enough capacity to accept the write.
        assert!(self.has_capacity());
        let span = tracing::trace_span!("FramedWrite::buffer", frame = ?item);
        let _e = span.enter();

        tracing::debug!(frame = ?item, "send");

        // The label of this frame: its wire stream for the frames that are part of a message (HEADERS,
        // DATA, RST_STREAM, PUSH_PROMISE), the connection for every other.
        let before = self.buf.get_ref().len();
        let mut wire = 0u32;
        let mut ending = false;
        let mut payload = None;
        let mut reset = None;
        match &item {
            Frame::Data(frame) => {
                wire = frame.stream_id().into();
                ending = frame.is_end_stream();
                payload = Some(frame.payload().remaining());
            }
            Frame::Headers(frame) => {
                wire = frame.stream_id().into();
                ending = frame.is_end_stream();
            }
            Frame::PushPromise(frame) => wire = frame.stream_id().into(),
            Frame::Reset(frame) => {
                wire = frame.stream_id().into();
                reset = Some(u32::from(frame.reason()));
            }
            _ => {}
        }
        match item {
            Frame::Data(mut v) => {
                // Ensure that the payload is not greater than the max frame.
                let len = v.payload().remaining();

                if len > self.max_frame_size() {
                    return Err(PayloadTooBig);
                }

                if len >= self.chain_threshold {
                    let head = v.head();

                    // Encode the frame head to the buffer
                    head.encode(len, self.buf.get_mut());

                    if self.buf.get_ref().remaining() < self.chain_threshold {
                        let extra_bytes = self.chain_threshold - self.buf.remaining();
                        self.buf.get_mut().put(v.payload_mut().take(extra_bytes));
                    }

                    // Save the data frame
                    self.next = Some(Next::Data(v));
                } else {
                    v.encode_chunk(self.buf.get_mut());

                    // The chunk has been fully encoded, so there is no need to
                    // keep it around
                    assert_eq!(v.payload().remaining(), 0, "chunk not fully encoded");

                    // Save off the last frame...
                    self.last_data_frame = Some(v);
                }
            }
            Frame::Headers(v) => {
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf, &mut self.segments)
                {
                    self.next = Some(Next::Continuation(continuation));
                }
            }
            Frame::PushPromise(v) => {
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
            }
            Frame::Settings(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded settings");
            }
            Frame::GoAway(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded go_away");
            }
            Frame::Ping(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded ping");
            }
            Frame::WindowUpdate(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded window_update");
            }

            Frame::Priority(_) => {
                /*
                v.encode(self.buf.get_mut());
                tracing::trace!("encoded priority; rem={:?}", self.buf.remaining());
                */
                unimplemented!();
            }
            Frame::Reset(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded reset");
            }
        }
        // A DATA frame is whole here even when its payload is chained (written after the buffer); a
        // header block may continue in CONTINUATION frames, and ends its stream only with the last.
        let done = self.next.is_none() || payload.is_some();
        if let Some(len) = payload {
            if let Some(labels) = &self.labels {
                labels.span(wire, false, frame::HEADER_LEN);
                if len != 0 {
                    labels.span(wire, true, len);
                }
                if ending {
                    labels.end(wire, None);
                }
            }
        } else {
            self.label_header_frame(wire, before);
            if let Some(labels) = &self.labels {
                if let Some(reason) = reset {
                    labels.end(wire, Some(reason));
                } else if ending && done {
                    labels.end(wire, None);
                }
            }
        }
        self.continuation_end = ending && !done;
        Ok(())
    }

    fn has_capacity(&self) -> bool {
        self.next.is_none()
            && (self.buf.get_ref().capacity() - self.buf.get_ref().len()
                >= self.min_buffer_capacity)
    }

    fn is_empty(&self) -> bool {
        match self.next {
            Some(Next::Data(ref frame)) => !frame.payload().has_remaining(),
            _ => !self.buf.has_remaining(),
        }
    }
}

impl<B> Encoder<B> {
    fn max_frame_size(&self) -> usize {
        self.max_frame_size as usize
    }
}

impl<T, B> FramedWrite<T, B> {
    /// Labels every frame this connection encodes. `seal`: sensitive header values and marked path
    /// places are sealed (a client; a server writes every value it is given).
    pub(crate) fn set_labels(
        &mut self,
        labels: std::sync::Arc<dyn crate::serialization::Labels>,
        seal: bool,
    ) {
        self.encoder.labels = Some(labels);
        self.encoder.hpack.seal.on = seal;
    }

    /// Returns the max frame size that can be sent
    pub fn max_frame_size(&self) -> usize {
        self.encoder.max_frame_size()
    }

    /// Set the peer's max frame size.
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(val <= frame::MAX_MAX_FRAME_SIZE as usize);
        self.encoder.max_frame_size = val as FrameSize;
    }

    /// Set the peer's header table size.
    pub fn set_header_table_size(&mut self, val: usize) {
        self.encoder.hpack.update_max_size(val);
    }

    /// Retrieve the last data frame that has been sent
    pub fn take_last_data_frame(&mut self) -> Option<frame::Data<B>> {
        self.encoder.last_data_frame.take()
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: AsyncRead + Unpin, B> AsyncRead for FramedWrite<T, B> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// We never project the Pin to `B`.
impl<T: Unpin, B> Unpin for FramedWrite<T, B> {}

#[cfg(feature = "unstable")]
mod unstable {
    use super::*;

    impl<T, B> FramedWrite<T, B> {
        pub fn get_ref(&self) -> &T {
            &self.inner
        }
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use crate::serialization::Labels;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct Capture(Mutex<Vec<String>>);
    impl Labels for Capture {
        fn span(&self, wire: u32, payload: bool, len: usize) {
            self.0
                .lock()
                .unwrap()
                .push(format!("span {wire} {payload} {len}"));
        }
        fn sealed(&self, wire: u32, slot: u32, offset: u32, len: u32) {
            self.0
                .lock()
                .unwrap()
                .push(format!("sealed {wire} {slot} {offset} {len}"));
        }
        fn end(&self, wire: u32, failed: Option<u32>) {
            self.0
                .lock()
                .unwrap()
                .push(format!("end {wire} {failed:?}"));
        }
    }

    fn writer(seal: bool) -> (FramedWrite<tokio::io::Sink, bytes::Bytes>, Arc<Capture>) {
        let capture = Arc::new(Capture::default());
        let mut writer = FramedWrite::new(tokio::io::sink());
        writer.set_labels(capture.clone(), seal);
        (writer, capture)
    }

    #[test]
    fn a_data_frame_is_a_control_head_then_payload_and_its_end_stream_ends_the_stream() {
        let (mut writer, capture) = writer(false);
        let mut data = frame::Data::new(3.into(), bytes::Bytes::from_static(b"hello"));
        data.set_end_stream(true);
        writer.buffer(Frame::Data(data)).unwrap();
        assert_eq!(
            *capture.0.lock().unwrap(),
            ["span 3 false 9", "span 3 true 5", "end 3 None"]
        );
    }

    #[test]
    fn a_reset_ends_its_stream_failed_and_connection_frames_are_stream_zero() {
        let (mut writer, capture) = writer(false);
        writer
            .buffer(Frame::Reset(frame::Reset::new(
                5.into(),
                crate::Reason::CANCEL,
            )))
            .unwrap();
        writer
            .buffer(Frame::Ping(frame::Ping::new([0; 8])))
            .unwrap();
        assert_eq!(
            *capture.0.lock().unwrap(),
            ["span 5 false 13", "end 5 Some(8)", "span 0 false 17"]
        );
    }

    #[test]
    fn a_sensitive_value_on_a_sealing_connection_is_never_encoded_and_the_frame_length_counts_it() {
        let (mut writer, capture) = writer(true);
        let mut fields = http::HeaderMap::new();
        let mut secret = http::HeaderValue::from_static("xxxxxxxxxxxxxxxx");
        secret.set_sensitive(true);
        fields.insert("authorization", secret);
        let pseudo = frame::Pseudo::request(
            http::Method::GET,
            http::Uri::from_static("https://example.test/v1"),
            None,
        );
        let headers = frame::Headers::new(1.into(), pseudo, fields);
        writer.buffer(Frame::Headers(headers)).unwrap();
        let seen = capture.0.lock().unwrap().clone();
        // Control bytes, the 16 sealed bytes of slot 0, and nothing after them (the value is last).
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[0].starts_with("span 1 false "));
        assert_eq!(seen[1], "sealed 1 0 0 16");
        let encoded = writer.encoder.buf.get_ref();
        let stated = u32::from_be_bytes([0, encoded[0], encoded[1], encoded[2]]) as usize;
        assert_eq!(stated, encoded.len() - frame::HEADER_LEN + 16);
        assert!(!encoded.windows(4).any(|w| w == b"xxxx"));
    }
}
