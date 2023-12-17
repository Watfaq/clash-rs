use std::fmt::Debug;

use bytes::Bytes;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{Receiver, Sender},
};
use tracing::trace;

#[derive(Debug)]
pub struct SocketPair {
    pub read: Receiver<Bytes>,
    pub write: Sender<Bytes>,
}

impl AsyncRead for SocketPair {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.read.try_recv() {
            Ok(data) => {
                trace!("tcp socket received: {:?}", data);
                buf.put_slice(&data);
                std::task::Poll::Ready(Ok(()))
            }
            Err(_) => {
                trace!("no data ready");
                std::task::Poll::Pending
            }
        }
    }
}

impl AsyncWrite for SocketPair {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.write.try_send(buf.to_owned().into()) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
