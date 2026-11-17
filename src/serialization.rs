//! Exact server serialization facts, independent of delivery receipts.
use std::{
    fmt, io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

/// A serializer event in connection byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// An actual nonempty encoded span.
    Span {
        /// Admitted application response identity (zero only for connection control).
        stream: u64,
        /// True only for actual DATA application bytes.
        payload: bool,
        /// Exact nonzero encoded length.
        len: u64,
    },
    /// The terminal unit was authorized before scheduler admission.
    ReleaseBarrier {
        /// Admitted application response identity.
        stream: u64,
    },
    /// The last response frame has been fully encoded.
    End {
        /// Admitted application response identity.
        stream: u64,
    },
    /// Response serialization failed.
    Abort {
        /// Admitted application response identity.
        stream: u64,
    },
    /// No protocol producer or active codec frame retains this response.
    Quiescent {
        /// Admitted application response identity.
        stream: u64,
    },
}

/// Bounded connection observer. It must retain bindings until host settlement
/// and input retirement, independently of application stream handles.
pub trait Observer: Send + Sync + fmt::Debug {
    /// Atomically append a complete finite batch, or accept nothing.
    fn record(&self, events: &[Event]) -> io::Result<()>;
    /// Bind an actual responder wire ID to an admitted application identity.
    fn bind(&self, wire: u32, host: u64) -> io::Result<Arc<ResponseState>>;
    /// Observe a peer reset even if h2 no longer has an application stream.
    fn reset(&self, wire: u32) -> io::Result<()>;
    /// Abort all still-live bindings on a genuine connection error.
    fn connection_error(&self) -> io::Result<()>;
    /// Poll terminal authorization using one reserved waker per response.
    fn poll_release(&self, host: u64, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

/// Identity and abort latch shared only by actual serializer producers and the
/// bounded live association. Application SendStream clones do not count.
#[derive(Debug)]
pub struct ResponseState {
    host: u64,
    aborted: AtomicBool,
    sources: AtomicUsize,
}
impl ResponseState {
    /// Create a state for a nonzero, admitted application identity.
    pub fn new(host: u64) -> Self {
        assert_ne!(host, 0);
        Self {
            host,
            aborted: AtomicBool::new(false),
            sources: AtomicUsize::new(0),
        }
    }
    /// Application identity, never an integer cast of the wire ID.
    pub fn identity(&self) -> u64 {
        self.host
    }
    /// Latch and report failure once, preserving any prior byte facts.
    pub fn abort(&self, observer: &dyn Observer) -> io::Result<()> {
        if !self.aborted.swap(true, Ordering::AcqRel) {
            observer.record(&[Event::Abort { stream: self.host }])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Source {
    state: Arc<ResponseState>,
    observer: Arc<dyn Observer>,
}
impl Source {
    pub(crate) fn new(state: Arc<ResponseState>, observer: Arc<dyn Observer>) -> Self {
        let old = state.sources.fetch_add(1, Ordering::Relaxed);
        assert!(old < usize::MAX / 2);
        Self { state, observer }
    }
    pub(crate) fn identity(&self) -> u64 {
        self.state.host
    }
    pub(crate) fn aborted(&self) -> bool {
        self.state.aborted.load(Ordering::Acquire)
    }
    pub(crate) fn abort(&self) {
        // Lifecycle notification storage is reserved at bind. An observer must
        // latch its own connection fault if this notification cannot be stored.
        let _ = self.state.abort(self.observer.as_ref());
    }
    pub(crate) fn poll_release(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.aborted() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "response aborted",
            )));
        }
        self.observer.poll_release(self.state.host, cx)
    }
}
impl Clone for Source {
    fn clone(&self) -> Self {
        Self::new(self.state.clone(), self.observer.clone())
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        if self.state.sources.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _ = self.observer.record(&[Event::Quiescent {
                stream: self.state.host,
            }]);
        }
    }
}
