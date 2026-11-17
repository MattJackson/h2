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
    observer: Option<std::sync::Arc<dyn crate::serialization::Observer>>,
    source: Option<crate::serialization::Source>,
    continuation_end: bool,
    poisoned: bool,
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
                observer: None,
                source: None,
                continuation_end: false,
                poisoned: false,
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
        match self.encoder.buffer(item) {
            // Internal callers know protocol frames are valid and historically
            // expect this method to succeed. Surface observer IO failure through
            // poll_ready/flush instead, before any poisoned bytes can escape.
            Err(UserError::Serialization) => Ok(()),
            result => result,
        }
    }

    /// Flush buffered data to the wire
    pub fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        let span = tracing::trace_span!("FramedWrite::flush");
        let _e = span.enter();

        loop {
            if self.encoder.poisoned {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "serialization observer failed",
                )));
            }
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
    fn record(&mut self, events: &[crate::serialization::Event]) -> Result<(), UserError> {
        if self.poisoned {
            return Err(Serialization);
        }
        if let Some(observer) = &self.observer {
            if observer.record(events).is_err() {
                self.poisoned = true;
                return Err(Serialization);
            }
        }
        Ok(())
    }

    fn unset_frame(&mut self) -> ControlFlow {
        // Clear internal buffer
        self.buf.set_position(0);
        self.buf.get_mut().clear();

        // The data frame has been written, so unset it
        match self.next.take() {
            Some(Next::Data(frame)) => {
                self.last_data_frame = Some(frame);
                self.source.take();
                debug_assert!(self.is_empty());
                ControlFlow::Break
            }
            Some(Next::Continuation(frame)) => {
                let host = self.source.as_ref().map_or(0, |source| source.identity());

                // Buffer the continuation frame, then try to write again
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = frame.encode(&mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
                let len = self.buf.get_ref().len() as u64;
                let event = crate::serialization::Event::Span {
                    stream: host,
                    payload: false,
                    len,
                };
                let done = self.next.is_none();
                let ending = done
                    && self.continuation_end
                    && self.source.as_ref().map_or(false, |s| !s.aborted());
                if ending {
                    let _ =
                        self.record(&[event, crate::serialization::Event::End { stream: host }]);
                } else {
                    let _ = self.record(&[event]);
                }
                if done {
                    self.source.take();
                    self.continuation_end = false;
                }
                ControlFlow::Continue
            }
            None => {
                self.source.take();
                ControlFlow::Break
            }
        }
    }

    fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        // Ensure that we have enough capacity to accept the write.
        assert!(self.has_capacity());
        let span = tracing::trace_span!("FramedWrite::buffer", frame = ?item);
        let _e = span.enter();

        tracing::debug!(frame = ?item, "send");

        use crate::serialization::Event;
        let before = self.buf.get_ref().len();
        let host = self.source.as_ref().map_or(0, |source| source.identity());
        let mut ending = false;
        let mut payload = None;
        match &item {
            Frame::Data(frame) => {
                ending = frame.is_end_stream();
                payload = Some(frame.payload().remaining());
            }
            Frame::Headers(frame) => {
                ending = frame.is_end_stream();
            }
            _ => {}
        }
        if self.observer.is_some()
            && matches!(&item, Frame::Data(_) | Frame::Headers(_))
            && host == 0
        {
            self.poisoned = true;
            return Err(Serialization);
        }
        // The scheduler must already have obtained terminal authorization.
        if ending {
            self.record(&[Event::ReleaseBarrier { stream: host }])?;
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
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf) {
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
        let done = self.next.is_none() || payload.is_some();
        let successful_end = ending && done && self.source.as_ref().map_or(false, |s| !s.aborted());
        if let Some(len) = payload {
            let header = Event::Span {
                stream: host,
                payload: false,
                len: frame::HEADER_LEN as u64,
            };
            let body = Event::Span {
                stream: host,
                payload: true,
                len: len as u64,
            };
            let end = Event::End { stream: host };
            match (len != 0, successful_end) {
                (true, true) => self.record(&[header, body, end])?,
                (true, false) => self.record(&[header, body])?,
                (false, true) => self.record(&[header, end])?,
                (false, false) => self.record(&[header])?,
            }
        } else {
            let span = Event::Span {
                stream: host,
                payload: false,
                len: (self.buf.get_ref().len() - before) as u64,
            };
            if successful_end {
                self.record(&[span, Event::End { stream: host }])?;
            } else {
                self.record(&[span])?;
            }
        }
        self.continuation_end = ending && !done;
        if self.next.is_none() {
            self.source.take();
        }
        Ok(())
    }

    fn has_capacity(&self) -> bool {
        !self.poisoned
            && self.next.is_none()
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
    pub(crate) fn set_observer(
        &mut self,
        observer: std::sync::Arc<dyn crate::serialization::Observer>,
    ) {
        self.encoder.observer = Some(observer);
    }
    pub(crate) fn observer(&self) -> Option<std::sync::Arc<dyn crate::serialization::Observer>> {
        self.encoder.observer.clone()
    }
    pub(crate) fn set_frame_source(&mut self, source: Option<crate::serialization::Source>) {
        debug_assert!(self.encoder.source.is_none());
        self.encoder.source = source;
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
    use crate::serialization::{Event, Observer, ResponseState};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct Capture(Mutex<Vec<Event>>);
    impl Observer for Capture {
        fn record(&self, events: &[Event]) -> io::Result<()> {
            self.0.lock().unwrap().extend_from_slice(events);
            Ok(())
        }
        fn bind(&self, _wire: u32, host: u64) -> io::Result<Arc<ResponseState>> {
            Ok(Arc::new(ResponseState::new(host)))
        }
        fn reset(&self, _wire: u32) -> io::Result<()> {
            Ok(())
        }
        fn connection_error(&self) -> io::Result<()> {
            Ok(())
        }
        fn poll_release(&self, _host: u64, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn chained_data_is_described_once_before_any_write() {
        let capture = Arc::new(Capture::default());
        let mut writer = FramedWrite::new(tokio::io::sink());
        writer.set_observer(capture.clone());
        let source =
            crate::serialization::Source::new(Arc::new(ResponseState::new(47)), capture.clone());
        writer.set_frame_source(Some(source));
        let mut frame = frame::Data::new(1.into(), bytes::Bytes::from(vec![3; 4096]));
        frame.set_end_stream(true);
        writer.buffer(frame.into()).unwrap();
        let events = capture.0.lock().unwrap().clone();
        assert_eq!(
            &events[..4],
            &[
                Event::ReleaseBarrier { stream: 47 },
                Event::Span {
                    stream: 47,
                    payload: false,
                    len: 9
                },
                Event::Span {
                    stream: 47,
                    payload: true,
                    len: 4096
                },
                Event::End { stream: 47 },
            ]
        );
        std::future::poll_fn(|cx| writer.flush(cx)).await.unwrap();
        assert_eq!(
            capture
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| matches!(e, Event::Span { payload: true, .. }))
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn terminal_headers_end_only_after_the_last_continuation_unless_aborted() {
        for aborted in [false, true] {
            let capture = Arc::new(Capture::default());
            let state = Arc::new(ResponseState::new(47));
            let mut writer: FramedWrite<_, bytes::Bytes> = FramedWrite::new(tokio::io::sink());
            writer.set_observer(capture.clone());
            writer.set_frame_source(Some(crate::serialization::Source::new(
                state.clone(),
                capture.clone(),
            )));
            let response = http::Response::builder()
                .header("large", "x".repeat(65536))
                .body(())
                .unwrap();
            let frame = crate::server::Peer::convert_send_message(1.into(), response, true);
            writer.buffer(frame.into()).unwrap();
            assert!(!capture
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, Event::End { .. })));
            if aborted {
                state.abort(capture.as_ref()).unwrap();
            }
            std::future::poll_fn(|cx| writer.flush(cx)).await.unwrap();
            let events = capture.0.lock().unwrap();
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e, Event::End { stream: 47 }))
                    .count(),
                usize::from(!aborted)
            );
            assert!(
                events
                    .iter()
                    .filter(|e| matches!(
                        e,
                        Event::Span {
                            stream: 47,
                            payload: false,
                            ..
                        }
                    ))
                    .count()
                    > 1
            );
            assert!(!events
                .iter()
                .any(|e| matches!(e, Event::Span { payload: true, .. })));
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e, Event::Quiescent { stream: 47 }))
                    .count(),
                1
            );
        }
    }
}
