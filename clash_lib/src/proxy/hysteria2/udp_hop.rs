use futures::ready;
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket,
};
use std::{fmt::Debug, io::IoSliceMut, sync::Arc, task::Poll};

pub(super) struct Hop {
    /// The inner udp socket
    inner: Arc<dyn AsyncUdpSocket>,
    // The port that quinn packet should be sent to
    server_port: u16,
    /// The port that quinn connection is connecting to
    connection_port: u16,
}

impl Hop {
    pub(super) fn new(
        udp_socket: Arc<dyn AsyncUdpSocket>,
        server_port: u16,
        connection_port: u16,
    ) -> Self {
        Self {
            inner: udp_socket,
            server_port,
            connection_port,
        }
    }
}

impl Debug for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria HopSocket").finish()
    }
}

impl quinn::AsyncUdpSocket for Hop {
    fn create_io_poller(
        self: Arc<Self>,
    ) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        unsafe {
            let transmit = transmit as *const Transmit as *mut Transmit;
            (*transmit).destination.set_port(self.server_port);
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let packet_nums = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for i in &mut meta[..packet_nums] {
            i.addr.set_port(self.connection_port);
        }
        Poll::Ready(Ok(packet_nums))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}
