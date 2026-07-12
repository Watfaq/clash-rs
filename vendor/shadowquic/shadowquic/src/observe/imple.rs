use std::{
    collections::HashMap,
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};
use tracing::info;

use crate::{
    AnyTcp, AnyUdpRecv, AnyUdpSend, ProxyRequest, TcpSession, TcpTrait, UdpRecv, UdpSend,
    UdpSession, UserContext, UserName,
    error::SError,
    msgs::{socks5::SocksAddr, squic::UserStats},
};

#[derive(Default, Clone)]
pub struct ProxyStatsAtm {
    tcp_sent: Arc<AtomicU64>,
    tcp_recv: Arc<AtomicU64>,
    udp_sent: Arc<AtomicU64>,
    udp_recv: Arc<AtomicU64>,
    tcp_conns: Arc<AtomicU64>,
    udp_conns: Arc<AtomicU64>,
}

impl ProxyStatsAtm {
    fn tcp_counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>) {
        (
            self.tcp_recv.clone(),
            self.tcp_sent.clone(),
            self.tcp_conns.clone(),
        )
    }

    fn udp_counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>) {
        (
            self.udp_recv.clone(),
            self.udp_sent.clone(),
            self.udp_conns.clone(),
        )
    }
}

#[derive(Clone, Default)]
pub struct Observer {
    pub user_stats: Arc<Mutex<HashMap<UserName, ProxyStatsAtm>>>,
    pub conns: Arc<Mutex<HashMap<u64, UserContext>>>,
}
impl Observer {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn on_new_request(&self, user_context: &UserContext) -> ProxyStatsAtm {
        let mut conns = self.conns.lock().await;
        conns.insert(user_context.conn_id, user_context.clone());
        conns.retain(|_, ctx| ctx.conn_handle.upgrade().is_some());
        drop(conns);
        self.user_stats
            .lock()
            .await
            .entry(user_context.username.clone())
            .or_default()
            .clone()
    }

    pub async fn remove_user(&self, username: &str) {
        {
            let mut user_stats = self.user_stats.lock().await;
            user_stats.remove(username);
        }
        self.close_conn(username).await;
        let mut conns = self.conns.lock().await;
        conns.retain(|_, ctx| ctx.username != username);
    }
    pub async fn close_conn(&self, username: &str) {
        let to_close: Vec<_> = {
            let conns = self.conns.lock().await;
            conns
                .iter()
                .filter(|(_, ctx)| ctx.username == username)
                .map(|(id, ctx)| (*id, ctx.conn_handle.clone()))
                .collect()
        };
        for (id, handle) in to_close {
            if let Some(handle) = handle.upgrade() {
                handle.stop();
                info!(%id, "connection closed by observer");
            }
        }
    }
    pub async fn get_conn_num(&self, username: &str) -> usize {
        let mut conns = self.conns.lock().await;
        conns.retain(|_, ctx| ctx.conn_handle.upgrade().is_some());
        conns
            .iter()
            .filter(|(_, ctx)| ctx.username == username)
            .count()
    }
    pub async fn get_user_stats(&self, username: &str) -> UserStats {
        let conn_num = self.get_conn_num(username).await;
        let user_stats = self.user_stats.lock().await;
        if let Some(stats) = user_stats.get(username) {
            let tcp_recv = stats.tcp_recv.load(Ordering::Relaxed);
            let tcp_sent = stats.tcp_sent.load(Ordering::Relaxed);
            let udp_recv = stats.udp_recv.load(Ordering::Relaxed);
            let udp_sent = stats.udp_sent.load(Ordering::Relaxed);
            UserStats {
                tcp_sent,
                tcp_recv,
                udp_sent,
                udp_recv,
                tcp_conns: stats.tcp_conns.load(Ordering::Relaxed),
                udp_conns: stats.udp_conns.load(Ordering::Relaxed),
                conn_num: conn_num as u32,
                username: username.to_owned(),
            }
        } else {
            UserStats {
                username: username.to_owned(),
                ..Default::default()
            }
        }
    }

    pub async fn get_all_stats(&self, usernames: &[String]) -> Vec<UserStats> {
        let mut conns = self.conns.lock().await;
        conns.retain(|_, ctx| ctx.conn_handle.upgrade().is_some());
        let conn_nums = usernames
            .iter()
            .map(|username| {
                let conn_num = conns
                    .iter()
                    .filter(|(_, ctx)| ctx.username == *username)
                    .count() as u32;
                (username.clone(), conn_num)
            })
            .collect::<HashMap<_, _>>();
        drop(conns);

        let user_stats = self.user_stats.lock().await;
        usernames
            .iter()
            .map(|username| {
                user_stats
                    .get(username)
                    .map(|stats| UserStats {
                        tcp_sent: stats.tcp_sent.load(Ordering::Relaxed),
                        tcp_recv: stats.tcp_recv.load(Ordering::Relaxed),
                        udp_sent: stats.udp_sent.load(Ordering::Relaxed),
                        udp_recv: stats.udp_recv.load(Ordering::Relaxed),
                        tcp_conns: stats.tcp_conns.load(Ordering::Relaxed),
                        udp_conns: stats.udp_conns.load(Ordering::Relaxed),
                        conn_num: *conn_nums.get(username).unwrap_or(&0),
                        username: username.clone(),
                    })
                    .unwrap_or_else(|| UserStats {
                        username: username.clone(),
                        ..Default::default()
                    })
            })
            .collect()
    }
}

struct TrackedTcp {
    inner: AnyTcp,
    bytes_recv: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    tcp_conns: Arc<AtomicU64>,
}

impl TrackedTcp {
    fn new(
        inner: AnyTcp,
        bytes_recv: Arc<AtomicU64>,
        bytes_sent: Arc<AtomicU64>,
        tcp_conns: Arc<AtomicU64>,
    ) -> Self {
        tcp_conns.fetch_add(1, Ordering::Relaxed);
        Self {
            inner,
            bytes_recv,
            bytes_sent,
            tcp_conns,
        }
    }
}

impl Drop for TrackedTcp {
    fn drop(&mut self) {
        self.tcp_conns.fetch_sub(1, Ordering::Relaxed);
    }
}

impl AsyncRead for TrackedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &poll {
            let n = buf.filled().len().saturating_sub(filled_before);
            self.bytes_recv.fetch_add(n as u64, Ordering::Relaxed);
        }

        poll
    }
}

impl AsyncWrite for TrackedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);

        if let Poll::Ready(Ok(n)) = &poll {
            self.bytes_sent.fetch_add(*n as u64, Ordering::Relaxed);
        }

        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);

        if let Poll::Ready(Ok(n)) = &poll {
            self.bytes_sent.fetch_add(*n as u64, Ordering::Relaxed);
        }

        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TcpTrait for TrackedTcp {}

struct TrackedUdpRecv {
    inner: AnyUdpRecv,
    bytes_recv: Arc<AtomicU64>,
    udp_conns: Arc<AtomicU64>,
}

impl Drop for TrackedUdpRecv {
    fn drop(&mut self) {
        self.udp_conns.fetch_sub(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl UdpRecv for TrackedUdpRecv {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError> {
        let (bytes, addr) = self.inner.recv_from().await?;
        self.bytes_recv
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok((bytes, addr))
    }
}

struct TrackedUdpSend {
    inner: AnyUdpSend,
    bytes_sent: Arc<AtomicU64>,
}

#[async_trait]
impl UdpSend for TrackedUdpSend {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError> {
        let len = self.inner.send_to(buf, addr).await?;
        self.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        Ok(len)
    }
}

impl Observer {
    pub(crate) async fn wrap_request(&self, req: ProxyRequest) -> ProxyRequest {
        match req {
            ProxyRequest::Tcp(tcp) => {
                let Some(user_context) = tcp.user_context else {
                    return ProxyRequest::Tcp(tcp);
                };
                let stats = self.on_new_request(&user_context).await;
                let (tcp_recv, tcp_sent, tcp_conns) = stats.tcp_counters();

                ProxyRequest::Tcp(TcpSession {
                    stream: Box::new(TrackedTcp::new(tcp.stream, tcp_recv, tcp_sent, tcp_conns))
                        as AnyTcp,
                    dst: tcp.dst,
                    user_context: Some(user_context),
                })
            }
            ProxyRequest::Udp(udp) => {
                let Some(user_context) = udp.user_context else {
                    return ProxyRequest::Udp(udp);
                };

                let stats = self.on_new_request(&user_context).await;
                let (udp_recv, udp_sent, udp_conns) = stats.udp_counters();
                udp_conns.fetch_add(1, Ordering::Relaxed);

                ProxyRequest::Udp(UdpSession {
                    recv: Box::new(TrackedUdpRecv {
                        inner: udp.recv,
                        bytes_recv: udp_recv,
                        udp_conns,
                    }) as AnyUdpRecv,
                    send: Arc::new(TrackedUdpSend {
                        inner: udp.send,
                        bytes_sent: udp_sent,
                    }) as AnyUdpSend,
                    stream: udp.stream,
                    bind_addr: udp.bind_addr,
                    user_context: Some(user_context),
                })
            }
        }
    }
}
