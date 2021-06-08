use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::ReadBuf;

use tor_proto::stream::DataStream;

/// Wrapper for a [`DataStream`] to implement tokio AsyncRead & AsyncWrite
///
/// [`DataStream`] is actually a reimplementation of a [`Stream`], so it can not be directly used
/// with tokio or futures.
///
/// [`DataStream`]: tor_proto::stream::DataStream
/// [`Stream`]: futures::stream::Stream
pub struct TorStream {
    wrapped: DataStream,
}

impl From<DataStream> for TorStream {
    fn from(wrapped: DataStream) -> Self {
        Self { wrapped }
    }
}

impl tokio::io::AsyncRead for TorStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use futures::{io::AsyncRead, ready};
        let slice = buf.initialize_unfilled();
        let read = ready!(Pin::new(&mut self.wrapped).poll_read(cx, slice))?;
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TorStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        use futures::{io::AsyncWrite, ready};
        let ret = Pin::new(&mut self.wrapped).poll_write(cx, buf);
        // FIXME dirty fix to force tls->tor communication
        ready!(self.poll_flush(cx)).unwrap();
        ret
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        use futures::io::AsyncWrite;
        Pin::new(&mut self.wrapped).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        use futures::io::AsyncWrite;
        Pin::new(&mut self.wrapped).poll_close(cx)
    }
}
