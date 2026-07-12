use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use bytes::BytesMut;
use tokio::{
    net::{TcpStream, lookup_host},
    sync::Mutex,
};
use tracing::{Instrument, error, info_span, trace};

use crate::{
    Outbound, UdpSession,
    config::{DirectOutCfg, DnsStrategy},
    error::SError,
    msgs::socks5::{AddrOrDomain, SocksAddr, VarVec},
    utils::dual_socket::DualSocket,
};
use async_trait::async_trait;

#[derive(Clone, Debug, Default)]
pub struct DirectOut {
    pub cfg: DirectOutCfg,
}

#[async_trait]
impl Outbound for DirectOut {
    async fn handle(
        &mut self,
        req: crate::ProxyRequest,
    ) -> anyhow::Result<(), crate::error::SError> {
        let dns_strategy = self.cfg.dns_strategy.clone();
        let self_clone = self.clone();

        let fut = async move {
            match req {
                crate::ProxyRequest::Tcp(mut tcp_session) => {
                    trace!("direct tcp to {}", tcp_session.dst);
                    let dst = tcp_session.dst.to_socket_addrs()?;
                    let dst = apply_dns_strategy(dst, &dns_strategy)
                        .ok_or(SError::DomainResolveFailed(tcp_session.dst.to_string()))?;
                    trace!("resolved to {}", dst);

                    let mut upstream = TcpStream::connect(dst).await?;
                    let _ = upstream.set_nodelay(true);
                    let (_, _) = tokio::io::copy_bidirectional_with_sizes(
                        &mut tcp_session.stream,
                        &mut upstream,
                        1024 * 16,
                        1024 * 16,
                    )
                    .await?;
                }

                crate::ProxyRequest::Udp(udp_session) => {
                    self_clone.handle_udp(udp_session).await?;
                }
            }

            Ok(()) as Result<(), SError>
        };
        let span = info_span!("direct");
        tokio::spawn(
            async {
                let _ = fut.await.map_err(|x| error!("{}", x));
            }
            .instrument(span),
        );

        Ok(())
    }
}

#[derive(Default, Clone)]
struct DnsResolve(Arc<Mutex<HashMap<Vec<u8>, SocketAddr>>>);
impl DnsResolve {
    async fn resolve(
        &self,
        socks: SocksAddr,
        strategy: &DnsStrategy,
    ) -> Result<SocketAddr, SError> {
        if let AddrOrDomain::Domain(x) = &socks.addr {
            if let Some(v) = self.0.lock().await.get(&x.contents) {
                Ok(*v)
            } else {
                let s = resolve(&socks, strategy).await?;
                self.0.lock().await.insert(x.contents.clone(), s);
                Ok(s)
            }
        } else {
            Ok(resolve(&socks, strategy).await?)
        }
    }
    async fn inv_resolve(&self, addr: &SocketAddr) -> SocksAddr {
        if let Some(add) = self.0.lock().await.iter().find(|x| x.1 == addr) {
            SocksAddr {
                addr: AddrOrDomain::Domain(VarVec {
                    len: add.0.len() as u8,
                    contents: add.0.clone(),
                }),
                port: addr.port(),
            }
        } else {
            (*addr).into()
        }
    }
}

async fn resolve(socks: &SocksAddr, strategy: &DnsStrategy) -> Result<SocketAddr, SError> {
    let mut s = match socks.addr.clone() {
        crate::msgs::socks5::AddrOrDomain::V4(x) => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(x)), 0)
        }
        crate::msgs::socks5::AddrOrDomain::V6(x) => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(x)), 0)
        }
        crate::msgs::socks5::AddrOrDomain::Domain(var_vec) => {
            let ip_list = lookup_host((
                String::from_utf8(var_vec.contents)
                    .map_err(|_| SError::DomainResolveFailed(socks.to_string()))?,
                socks.port,
            ))
            .await?;
            apply_dns_strategy(ip_list, strategy)
                .ok_or(SError::DomainResolveFailed(socks.to_string()))?
        }
    };
    s.set_port(socks.port);
    Ok(s)
}

impl DirectOut {
    pub fn new(cfg: DirectOutCfg) -> Self {
        Self { cfg }
    }

    async fn handle_udp(&self, udp_session: UdpSession) -> Result<(), SError> {
        trace!(bind_addr = %udp_session.bind_addr,"associating udp");
        let dst =
            udp_session
                .bind_addr
                .to_socket_addrs()?
                .next()
                .ok_or(SError::DomainResolveFailed(
                    udp_session.bind_addr.to_string(),
                ))?;
        let ipv4 = dst.is_ipv4();
        // For unspecified address, we try to bind a dual stack socket first.
        // If it fails, we fallback to single stack socket
        // https://github.com/spongebob888/shadowquic/issues/172
        let socket = if dst.ip().is_unspecified() {
            let socket = DualSocket::new_bind("[::]:0".parse().unwrap(), true)?;
            if socket.dual_stack || !ipv4 {
                trace!("bound to dual stack socket");
                socket
            } else {
                trace!("fallback to single stack socket");
                DualSocket::new_bind(dst, false)?
            }
        } else {
            DualSocket::new_bind(dst, false)?
        };
        let upstream = Arc::new(socket);
        let upstream_clone = upstream.clone();
        let mut downstream = udp_session.recv;

        let dns_cache = DnsResolve::default();
        let dns_cache_clone = dns_cache.clone();
        let dns_strategy = self.cfg.dns_strategy.clone();
        let fut1 = async move {
            loop {
                let mut buf_send = BytesMut::new();
                buf_send.resize(2000, 0);
                //trace!("recv upstream");
                let (len, dst) = upstream.recv_from(&mut buf_send).await?;
                //trace!("udp request reply from:{}", dst);
                let dst = dns_cache_clone.inv_resolve(&dst).await;
                //trace!("udp source inverse resolved to:{}", dst);
                let buf = buf_send.freeze();
                //trace!("udp recved:{} bytes", len);
                let _ = udp_session.send.send_to(buf.slice(..len), dst).await?;
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        let fut2 = async move {
            loop {
                let (buf, dst) = downstream.recv_from().await?;

                //trace!("udp request to:{}", dst);
                let dst = dns_cache.resolve(dst, &dns_strategy).await?;
                //trace!("udp resolve to:{}", dst);
                let _siz = upstream_clone.send_to(&buf, &dst).await?;
                //trace!("udp request sent:{}bytes", siz);
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        // We can use spawn, but it requirs communication to shutdown the other
        // Flatten spawn handle using try_join! doesn't work. Don't know why
        tokio::try_join!(fut1, fut2)?;
        Ok(())
    }
}
fn apply_dns_strategy<It>(mut ip_list: It, strategy: &DnsStrategy) -> Option<SocketAddr>
where
    It: Iterator<Item = SocketAddr>,
{
    match strategy {
        DnsStrategy::Ipv4Only => ip_list.find(|addr| addr.is_ipv4()),
        DnsStrategy::Ipv6Only => ip_list.find(|addr| addr.is_ipv6()),
        DnsStrategy::PreferIpv4 => {
            let mut first = None;
            for ip in ip_list {
                if ip.is_ipv4() {
                    return Some(ip);
                }
                if first.is_none() {
                    first = Some(ip);
                }
            }
            first
        }
        DnsStrategy::PreferIpv6 => {
            let mut first = None;
            for ip in ip_list {
                if ip.is_ipv6() {
                    return Some(ip);
                }
                if first.is_none() {
                    first = Some(ip);
                }
            }
            first
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_addrs() -> Vec<SocketAddr> {
        vec![
            // 127.0.0.1:8080 (IPv4)
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            // ::1:8080 (IPv6)
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
        ]
    }

    #[test]
    fn test_apply_dns_strategy_ipv4_only() {
        let addrs = make_addrs();
        let result = apply_dns_strategy(addrs.clone().into_iter(), &DnsStrategy::Ipv4Only);
        assert_eq!(result, Some(addrs[0]));
    }

    #[test]
    fn test_apply_dns_strategy_ipv6_only() {
        let addrs = make_addrs();
        let result = apply_dns_strategy(addrs.clone().into_iter(), &DnsStrategy::Ipv6Only);
        assert_eq!(result, Some(addrs[1]));
    }

    #[test]
    fn test_apply_dns_strategy_prefer_ipv4() {
        let addrs = make_addrs();
        let result = apply_dns_strategy(addrs.clone().into_iter(), &DnsStrategy::PreferIpv4);
        assert_eq!(result, Some(addrs[0]));
    }

    #[test]
    fn test_apply_dns_strategy_prefer_ipv6() {
        let addrs = make_addrs();
        let result = apply_dns_strategy(addrs.clone().into_iter(), &DnsStrategy::PreferIpv6);
        assert_eq!(result, Some(addrs[1]));
    }

    #[test]
    fn test_apply_dns_strategy_empty() {
        let addrs: Vec<SocketAddr> = vec![];
        let result = apply_dns_strategy(addrs.into_iter(), &DnsStrategy::PreferIpv4);
        assert_eq!(result, None);
    }
}
