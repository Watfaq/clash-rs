use crate::{stack::IfaceEvent, tcp_listener::TcpStreamHandle};
use log::{error, trace};
use std::{net::SocketAddr, sync::Arc};

pub struct TcpStream {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,

    pub(crate) handle: Arc<TcpStreamHandle>,
    pub(crate) stack_notifier:
        tokio::sync::mpsc::UnboundedSender<IfaceEvent<'static>>,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        trace!(
            "TcpStream dropped: {} <-> {}",
            self.local_addr, self.remote_addr
        );

        self.handle
            .socket_dropped
            .store(true, std::sync::atomic::Ordering::Release);
        if let Err(e) = self.stack_notifier.send(IfaceEvent::TcpSocketClosed) {
            error!("Failed to notify TCP socket closed: {e}");
        }
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStream")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}

impl tokio::io::AsyncRead for TcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let read_buf = &self.handle.recv_buffer;
        if read_buf.is_empty() {
            return std::task::Poll::Pending;
        }
        read_buf.with_lock(|buf_lock| {
            let unfilled = buf.unfilled_mut();
            let n = buf_lock.dequeue_slice(&mut unfilled[..unfilled.len()]);
            // Safety: `dequeue_slice` writes valid data into the buffer, initializing it.
            unsafe { buf.assume_init(n) };
            buf.advance(n);
        });
        std::task::Poll::Ready(Ok(()))
    }
}
impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let send_buf = &self.handle.send_buffer;
        if send_buf.is_full() {
            return std::task::Poll::Pending;
        }
        let n = send_buf.with_lock(|buf_lock| buf_lock.enqueue_slice(buf));
        self.stack_notifier
            .send(IfaceEvent::TcpSocketReady)
            .expect("Failed to notify TCP socket ready");
        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // No-op for our TcpStream, as we don't have a real underlying stream
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        trace!("TcpStream::poll_shutdown called, client side closing");
        std::task::Poll::Ready(Ok(()))
    }
}
