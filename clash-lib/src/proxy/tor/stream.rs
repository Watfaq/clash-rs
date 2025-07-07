use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use arti_client::DataStream;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

#[derive(Debug)]
pub(super) struct StreamWrapper(Arc<Mutex<DataStream>>);

impl StreamWrapper {
    pub(super) fn new(stream: DataStream) -> Self {
        Self(Arc::new(Mutex::new(stream)))
    }
}

impl AsyncRead for StreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.0.try_lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_read(cx, buf),
            Err(_) => Poll::Pending,
        }
    }
}

impl AsyncWrite for StreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.0.try_lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_write(cx, buf),
            Err(_) => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.0.try_lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_flush(cx),
            Err(_) => Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.0.try_lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_shutdown(cx),
            Err(_) => Poll::Pending,
        }
    }
}
