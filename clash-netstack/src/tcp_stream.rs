use crate::{stack::IfaceEvent, tcp_listener::TcpStreamHandle};
use log::{error, trace};
use std::{net::SocketAddr, sync::Arc, task::ready};

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

    pub fn split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
        let (r, w) = tokio::io::split(self);
        (r, w)
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
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        trace!(
            "TcpStream::poll_read called: {} <-> {}",
            self.local_addr, self.remote_addr
        );
        let read_buf = &self.handle.recv_buffer;

        if read_buf.is_empty() {
            trace!("TcpStream::poll_read: recv buffer is empty, waiting for data");
            // Register the waker to be notified when data is available
            self.handle.recv_waker.register(cx.waker());

            return std::task::Poll::Pending;
        }

        buf.initialize_unfilled();
        let recv_buf = unsafe {
            std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(
                buf.unfilled_mut(),
            )
        };
        let n = read_buf.dequeue_slice(recv_buf);
        buf.advance(n);

        self.stack_notifier
            .send(IfaceEvent::TcpSocketReady)
            .expect("Failed to notify TCP socket ready");
        trace!("TcpStream::poll_read: (proxy)read {n} bytes from recv buffer");

        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let send_buf = &self.handle.send_buffer;

        if send_buf.is_full() {
            trace!("TcpStream::poll_write: send buffer is full, waiting for space");
            // Register the waker to be notified when space is available
            self.handle.send_waker.register(cx.waker());

            return std::task::Poll::Pending;
        }

        let n = send_buf.enqueue_slice(buf);

        self.stack_notifier
            .send(IfaceEvent::TcpSocketReady)
            .expect("Failed to notify TCP socket ready");
        trace!("TcpStream::poll_write: (proxy)write {n} bytes to send buffer");

        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.stack_notifier
            .send(IfaceEvent::TcpSocketReady)
            .expect("Failed to notify TCP socket ready");
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        ready!(self.poll_flush(cx))?;
        trace!("TcpStream::poll_shutdown called, client side closing");
        std::task::Poll::Ready(Ok(()))
    }
}
