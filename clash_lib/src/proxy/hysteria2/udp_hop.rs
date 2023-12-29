use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut, Sub},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::ready;
use quinn::{
    udp::{may_fragment, Transmit, UdpSocketState, UdpState},
    AsyncUdpSocket,
};

use tokio::{io::Interest, net::UdpSocket};

use crate::proxy::converters::hysteria2::PortGenrateor;

/// A udp socket hopper, it can hop to a new port when the time interval is greater than interval
///
/// https://v2.hysteria.network/docs/advanced/Port-Hopping/
pub struct UdpHop {
    /// (prev_conn, cur_conn, last, new_hop_port), here mybe we can use struct
    state: Mutex<(Option<Arc<UdpSocket>>, Arc<UdpSocket>, Instant, u16)>,
    /// a udpsocket reader and writer encapsulated by quinn_udp crate
    socket_rw: UdpSocketState,
    /// The default port is the initial port when this quic connect connects to the server.
    /// Every time we call poll_recv, we must rewrite the source of the data packet inside to this port,
    /// because quic will check the source of the data packet and discard the unknown source data.
    init_port: u16,
    /// generate new port used to hop
    port_range: PortGenrateor,
    /// interval to hop
    interval: Duration,
}

impl UdpHop {
    const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
    pub fn new(
        port: u16,
        port_range: PortGenrateor,
        interval: Option<Duration>,
    ) -> io::Result<Self> {
        let sock = std::net::UdpSocket::bind(SocketAddr::new([0, 0, 0, 0].into(), 0))?;
        // Everytime we create a new udpsocket, and then MUST configure the socket, otherwise the socket will be block
        UdpSocketState::configure((&sock).into())?;
        let socket = UdpSocket::from_std(sock)?;
        Ok(UdpHop {
            state: Mutex::new((None, Arc::new(socket), Instant::now(), port)),
            socket_rw: UdpSocketState::new(),
            init_port: port,
            port_range,
            interval: interval.unwrap_or(Self::DEFAULT_INTERVAL),
        })
    }

    fn hop(&self) -> u16 {
        let mut lock = self.state.lock().unwrap();
        let (prev_conn, cur_conn, last, port) = lock.deref_mut();
        let now = Instant::now();
        let to_hop = now.sub(*last) > self.interval;

        if to_hop && prev_conn.is_none() {
            *last = now;
            tracing::trace!("port hopping");

            std::net::UdpSocket::bind(SocketAddr::new([0, 0, 0, 0].into(), 0))
                .and_then(|udp| {
                    UdpSocketState::configure((&udp).into())?;
                    Ok(udp)
                })
                .and_then(|udp| UdpSocket::from_std(udp))
                .map(|new_conn| {
                    *port = self.port_range.get();
                    *prev_conn = Some(std::mem::replace(cur_conn, Arc::new(new_conn)));
                })
                .unwrap_or_else(|e| {
                    tracing::error!("port hopping err {}", e);
                });
        }
        *port
    }

    fn get_conn(&self) -> (Option<Arc<UdpSocket>>, Arc<UdpSocket>) {
        let lock = self.state.lock().unwrap();
        let (prev_conn, conn, _, _) = lock.deref();
        (prev_conn.clone(), conn.clone())
    }

    fn drop_prcv_conn(&self) {
        let mut lock = self.state.lock().unwrap();
        let (prev_conn, _, _, _) = lock.deref_mut();
        *prev_conn = None;
    }
}

impl Debug for UdpHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHop")
            .field("cur_conn", &self.state)
            .finish()
    }
}

impl AsyncUdpSocket for UdpHop {
    fn poll_send(
        &self,
        state: &UdpState,
        cx: &mut Context,
        transmits: &[Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        // try to hop when we send data
        let port = self.hop();

        let (_pre_conn, io) = self.get_conn();

        // here just need change send addr, it is not nessary to change send contents, so we can use unsafe
        unsafe {
            let prt = transmits.as_ptr() as *mut Transmit;
            let slice_mut: &mut [Transmit] = std::slice::from_raw_parts_mut(prt, transmits.len());
            slice_mut.iter_mut().for_each(|v| {
                v.destination.set_port(port);
            })
        }

        loop {
            ready!(io.poll_send_ready(cx))?;
            if let Ok(res) = io.try_io(Interest::WRITABLE, || {
                self.socket_rw.send((&io).into(), state, &transmits)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (prev_io, io) = self.get_conn();

        let mut should_drop_prev = false;
        loop {
            //read prev conn
            let len = match prev_io {
                Some(ref prev_io) => match prev_io.poll_recv_ready(cx) {
                    // can readable, it is represent that the prev conn is not closed, and we recv the data from prev conn
                    Poll::Ready(Ok(())) => {
                        match prev_io.try_io(Interest::READABLE, || {
                            self.socket_rw.recv(prev_io.into(), bufs, meta)
                        }) {
                            Ok(res) => {
                                tracing::trace!("read prev conn len {}", res);
                                res
                            }
                            Err(e) => {
                                tracing::trace!("read prev conn err {}", e);
                                match e.kind() {
                                    // it is represent that the prev conn is readable, but when we read it, it is return err
                                    io::ErrorKind::TimedOut => return Poll::Ready(Err(e)),
                                    _ => 0,
                                }
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        tracing::trace!("poll prev conn err {}", e);
                        match e.kind() {
                            // io::ErrorKind::WouldBlock => {}
                            io::ErrorKind::TimedOut => return Poll::Ready(Err(e)),
                            _ => 0,
                        }
                    }
                    Poll::Pending => {
                        tracing::trace!("poll prev conn pending");
                        should_drop_prev = true;
                        0
                    }
                },
                None => 0,
            };

            //todo: poll prev conn
            ready!(io.poll_recv_ready(cx))?;
            if let Ok(res) = io.try_io(Interest::READABLE, || {
                self.socket_rw.recv((&io).into(), bufs, &mut meta[len..])
            }) {
                // when we recv data from new conn, we must rewrite the source port to init port
                meta.iter_mut()
                    .take(res + len)
                    .for_each(|m| m.addr.set_port(self.init_port));

                //  cur_conn is readable but prev_conn is pending, we should drop prev conn
                if should_drop_prev {
                    self.drop_prcv_conn();
                }

                tracing::trace!("recv meta {:?}", &meta[..res + len]);
                return Poll::Ready(Ok(res + len));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        let (_, cur) = self.get_conn();
        cur.local_addr()
    }

    fn may_fragment(&self) -> bool {
        may_fragment()
    }
}
