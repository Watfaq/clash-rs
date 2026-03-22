use crate::{stack::IfaceEvent, tcp_listener::TcpStreamHandle};
use log::{error, trace};
use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::Ordering,
    },
    task::{Context, Poll, ready},
};

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

        self.handle.socket_dropped.store(true, Ordering::Release);
        self.handle.read_closed.store(true, Ordering::Release);
        self.handle.write_closed.store(true, Ordering::Release);
        self.handle.recv_waker.wake();
        self.handle.send_waker.wake();
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        trace!(
            "TcpStream::poll_read called: {} <-> {}",
            self.local_addr, self.remote_addr
        );
        let read_buf = &self.handle.recv_buffer;

        if read_buf.is_empty() {
            if self.handle.read_closed.load(Ordering::Acquire) {
                trace!("TcpStream::poll_read: returning EOF");
                return Poll::Ready(Ok(()));
            }

            trace!("TcpStream::poll_read: recv buffer is empty, waiting for data");
            self.handle.recv_waker.register(cx.waker());

            if self.handle.read_closed.load(Ordering::Acquire) {
                trace!("TcpStream::poll_read: peer closed while registering waker");
                return Poll::Ready(Ok(()));
            }

            // Re-check buffer after registering waker to avoid missed wakeups.
            if read_buf.is_empty() {
                return Poll::Pending;
            }
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

        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.handle.write_closed.load(Ordering::Acquire)
            || self.handle.write_shutdown.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "TCP stream write half closed",
            )));
        }

        let send_buf = &self.handle.send_buffer;

        if send_buf.is_full() {
            trace!("TcpStream::poll_write: send buffer is full, waiting for space");
            self.handle.send_waker.register(cx.waker());
            self.stack_notifier
                .send(IfaceEvent::TcpSocketReady)
                .expect("Failed to notify TCP socket ready");

            if self.handle.write_closed.load(Ordering::Acquire)
                || self.handle.write_shutdown.load(Ordering::Acquire)
            {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    "TCP stream write half closed",
                )));
            }

            // Re-check fullness after registering the waker to avoid missing a wake
            if send_buf.is_full() {
                return Poll::Pending;
            }
        }

        let n = send_buf.enqueue_slice(buf);

        self.stack_notifier
            .send(IfaceEvent::TcpSocketReady)
            .expect("Failed to notify TCP socket ready");
        trace!("TcpStream::poll_write: (proxy)write {n} bytes to send buffer");

        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.stack_notifier
            .send(IfaceEvent::TcpSocketReady)
            .expect("Failed to notify TCP socket ready");
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.poll_flush(cx))?;
        trace!("TcpStream::poll_shutdown called, client side closing");
        self.handle.write_shutdown.store(true, Ordering::Release);
        self.stack_notifier
            .send(IfaceEvent::TcpSocketReady)
            .expect("Failed to notify TCP socket ready");
        self.handle.send_waker.wake();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker_ref;
    use crate::tcp_listener::TcpStreamHandle;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::sync::mpsc;

    fn build_stream() -> (
        TcpStream,
        mpsc::UnboundedReceiver<IfaceEvent<'static>>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            TcpStream {
                local_addr: "127.0.0.1:12345".parse().unwrap(),
                remote_addr: "127.0.0.1:80".parse().unwrap(),
                handle: Arc::new(TcpStreamHandle::new()),
                stack_notifier: tx,
            },
            rx,
        )
    }

    fn noop_cx() -> Context<'static> {
        Context::from_waker(noop_waker_ref())
    }

    #[test]
    fn poll_read_returns_eof_after_peer_close() {
        let (mut stream, _rx) = build_stream();
        stream.handle.read_closed.store(true, Ordering::Release);
        let mut cx = noop_cx();
        let mut bytes = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);

        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);

        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(buf.filled().len(), 0);
    }

    #[test]
    fn poll_shutdown_marks_write_shutdown() {
        let (mut stream, mut rx) = build_stream();
        let mut cx = noop_cx();

        let result = Pin::new(&mut stream).poll_shutdown(&mut cx);

        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert!(stream.handle.write_shutdown.load(Ordering::Acquire));
        assert!(matches!(rx.try_recv(), Ok(IfaceEvent::TcpSocketReady)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn poll_write_fails_after_write_close() {
        let (mut stream, _rx) = build_stream();
        stream.handle.write_closed.store(true, Ordering::Release);
        let mut cx = noop_cx();

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");

        assert!(matches!(result, Poll::Ready(Err(err)) if err.kind() == ErrorKind::BrokenPipe));
    }
}
