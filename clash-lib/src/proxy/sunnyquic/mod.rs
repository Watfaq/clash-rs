use std::{
    collections::HashSet,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream};
use shadowquic::{
    Inbound, ProxyRequest,
    config::{AuthUser, CongestionControl, SunnyQuicServerCfg},
    msgs::socks5::{AddrOrDomain, SocksAddr as SunnySocksAddr},
};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::{debug, info, warn};

use crate::{
    Dispatcher,
    config::listener::InboundUser,
    proxy::{AnyInboundDatagram, datagram::UdpPacket, inbound::InboundHandlerTrait},
    session::{Network, Session, SocksAddr, Type},
};

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub users: Vec<InboundUser>,
    pub server_name: String,
    pub certificate: String,
    pub private_key: String,
    pub max_path_num: u32,
    pub alpn: Vec<String>,
    pub zero_rtt: bool,
    pub congestion_control: CongestionControl,
    pub initial_mtu: u16,
    pub min_mtu: u16,
    pub gso: bool,
    pub mtu_discovery: bool,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<u32>,
    pub users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

pub struct SunnyQuicInbound {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    config: SunnyQuicServerCfg,
    users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

impl SunnyQuicInbound {
    pub fn new(opts: InboundOptions) -> io::Result<Self> {
        validate_users(&opts.users)?;
        validate_options(&opts)?;
        let config = SunnyQuicServerCfg {
            bind_addr: opts.addr,
            users: to_auth_users(&opts.users),
            server_name: opts.server_name,
            cert_path: opts.certificate.into(),
            key_path: opts.private_key.into(),
            max_path_num: opts.max_path_num,
            alpn: opts.alpn,
            zero_rtt: opts.zero_rtt,
            congestion_control: normalize_congestion_control(
                opts.congestion_control,
            ),
            initial_mtu: opts.initial_mtu,
            min_mtu: opts.min_mtu,
            gso: opts.gso,
            mtu_discovery: opts.mtu_discovery,
            brutal: None,
        };
        Ok(Self {
            addr: opts.addr,
            dispatcher: opts.dispatcher,
            fw_mark: opts.fw_mark,
            config,
            users_rx: opts.users_rx,
        })
    }
}

#[async_trait::async_trait]
impl InboundHandlerTrait for SunnyQuicInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> io::Result<()> {
        let mut config = self.config.clone();
        let mut users_rx = self.users_rx.clone();
        let mut users_rx_open = true;
        let mut server =
            shadowquic::sunnyquic::inbound::SunnyQuicServer::new(config.clone())
                .await
                .map_err(io::Error::other)?;
        server.init().await.map_err(io::Error::other)?;
        info!("SunnyQUIC listening at: {}", self.addr);

        loop {
            enum Event {
                Request(Result<ProxyRequest, shadowquic::error::SError>),
                UsersChanged(Result<(), tokio::sync::watch::error::RecvError>),
            }

            let event = tokio::select! {
                request = server.accept() => Event::Request(request),
                changed = users_rx.changed(), if users_rx_open => {
                    Event::UsersChanged(changed)
                },
            };

            match event {
                Event::Request(Ok(request)) => {
                    dispatch_request(
                        request,
                        unspecified_source(self.addr),
                        self.dispatcher.clone(),
                        self.fw_mark,
                    );
                }
                Event::Request(Err(error)) => return Err(io::Error::other(error)),
                Event::UsersChanged(Ok(())) => {
                    let users = users_rx.borrow_and_update().clone();
                    if let Err(error) = validate_users(&users) {
                        warn!(
                            "sunnyquic inbound {}: ignoring invalid user update: {}",
                            self.addr, error
                        );
                        continue;
                    }
                    config.users = to_auth_users(&users);
                    server
                        .update_config(&config)
                        .await
                        .map_err(io::Error::other)?;
                    info!(
                        "sunnyquic inbound {}: user list updated ({} users)",
                        self.addr,
                        users.len()
                    );
                }
                Event::UsersChanged(Err(_)) => {
                    users_rx_open = false;
                    debug!(
                        "sunnyquic inbound {}: user update channel closed",
                        self.addr
                    );
                }
            }
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_users(users: &[InboundUser]) -> io::Result<()> {
    if users.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sunnyquic inbound requires at least one user",
        ));
    }
    let mut names = HashSet::with_capacity(users.len());
    for user in users {
        if user.name.is_empty() || user.password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sunnyquic inbound users require non-empty name and password",
            ));
        }
        if user.name.starts_with("admin") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "sunnyquic inbound user name must not start with \"admin\": {}",
                    user.name
                ),
            ));
        }
        if !names.insert(user.name.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate sunnyquic inbound user: {}", user.name),
            ));
        }
    }
    Ok(())
}

fn validate_options(opts: &InboundOptions) -> io::Result<()> {
    if opts.server_name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sunnyquic inbound requires a non-empty server-name",
        ));
    }
    if opts.certificate.is_empty() || opts.private_key.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sunnyquic inbound requires certificate and private-key paths",
        ));
    }
    if opts.alpn.is_empty() || opts.alpn.iter().any(String::is_empty) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sunnyquic inbound requires at least one non-empty ALPN",
        ));
    }
    if opts.min_mtu < 1200 || opts.initial_mtu < opts.min_mtu {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sunnyquic inbound requires initial-mtu >= min-mtu >= 1200",
        ));
    }
    validate_listener_access(opts.addr, opts.allow_lan)?;
    Ok(())
}

fn validate_listener_access(addr: SocketAddr, allow_lan: bool) -> io::Result<()> {
    if !allow_lan && !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sunnyquic inbound with allow-lan disabled must listen on a loopback \
             address",
        ));
    }
    Ok(())
}

fn to_auth_users(users: &[InboundUser]) -> Vec<AuthUser> {
    users
        .iter()
        .map(|user| AuthUser {
            username: user.name.clone(),
            password: user.password.clone(),
        })
        .collect()
}

fn normalize_congestion_control(
    congestion_control: CongestionControl,
) -> CongestionControl {
    match congestion_control {
        CongestionControl::Bbr => CongestionControl::Bbr3,
        other => other,
    }
}

fn unspecified_source(listen: SocketAddr) -> SocketAddr {
    if listen.is_ipv6() {
        "[::]:0".parse().expect("valid unspecified IPv6 address")
    } else {
        "0.0.0.0:0".parse().expect("valid unspecified IPv4 address")
    }
}

fn dispatch_request(
    request: ProxyRequest,
    source: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
) {
    match request {
        ProxyRequest::Tcp(session) => {
            let destination = match to_clash_socks_addr(session.dst) {
                Ok(destination) => destination,
                Err(error) => {
                    warn!(
                        "sunnyquic inbound TCP request has invalid target: {error}"
                    );
                    return;
                }
            };
            let stream = session.stream;
            tokio::spawn(async move {
                let sess = Session {
                    network: Network::Tcp,
                    typ: Type::SunnyQuic,
                    source,
                    destination,
                    so_mark: fw_mark,
                    inbound_user: None,
                    ..Default::default()
                };
                dispatcher.dispatch_stream(sess, Box::new(stream)).await;
            });
        }
        ProxyRequest::Udp(session) => {
            let datagram = SunnyQuicInboundDatagram::new(
                session.recv,
                session.send,
                source,
                None,
            );
            tokio::spawn(async move {
                let sess = Session {
                    network: Network::Udp,
                    typ: Type::SunnyQuic,
                    source,
                    so_mark: fw_mark,
                    inbound_user: None,
                    ..Default::default()
                };
                let _ = dispatcher
                    .dispatch_datagram(
                        sess,
                        Box::new(datagram) as AnyInboundDatagram,
                    )
                    .await;
            });
        }
    }
}

struct SunnyQuicInboundDatagram {
    sender: PollSender<(Bytes, SunnySocksAddr)>,
    receiver: mpsc::Receiver<(Bytes, SunnySocksAddr)>,
    source: SocketAddr,
    inbound_user: Option<String>,
}

impl SunnyQuicInboundDatagram {
    fn new(
        mut recv: shadowquic::AnyUdpRecv,
        send: shadowquic::AnyUdpSend,
        source: SocketAddr,
        inbound_user: Option<String>,
    ) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Ok(packet) = recv.recv_from().await {
                if incoming_tx.send(packet).await.is_err() {
                    break;
                }
            }
        });

        let (outgoing_tx, mut outgoing_rx) =
            mpsc::channel::<(Bytes, SunnySocksAddr)>(64);
        tokio::spawn(async move {
            while let Some((data, addr)) = outgoing_rx.recv().await {
                if send.send_to(data, addr).await.is_err() {
                    break;
                }
            }
        });

        Self {
            sender: PollSender::new(outgoing_tx),
            receiver: incoming_rx,
            source,
            inbound_user,
        }
    }
}

impl fmt::Debug for SunnyQuicInboundDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SunnyQuicInboundDatagram")
            .field("source", &self.source)
            .finish()
    }
}

impl Stream for SunnyQuicInboundDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match self.receiver.poll_recv(context) {
                Poll::Ready(Some((data, destination))) => {
                    let destination = match to_clash_socks_addr(destination) {
                        Ok(destination) => destination,
                        Err(error) => {
                            warn!(
                                "sunnyquic inbound UDP packet has invalid target: \
                                 {error}"
                            );
                            continue;
                        }
                    };
                    return Poll::Ready(Some(UdpPacket {
                        data: data.into(),
                        src_addr: SocksAddr::Ip(self.source),
                        dst_addr: destination,
                        inbound_user: self.inbound_user.clone(),
                    }));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<UdpPacket> for SunnyQuicInboundDatagram {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .sender
            .poll_ready_unpin(context)
            .map_err(io::Error::other)
    }

    fn start_send(
        self: Pin<&mut Self>,
        packet: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.get_mut()
            .sender
            .start_send_unpin((
                packet.data.into(),
                to_sunny_socks_addr(packet.src_addr),
            ))
            .map_err(io::Error::other)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .sender
            .poll_flush_unpin(context)
            .map_err(io::Error::other)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .sender
            .poll_close_unpin(context)
            .map_err(io::Error::other)
    }
}

fn to_clash_socks_addr(addr: SunnySocksAddr) -> io::Result<SocksAddr> {
    Ok(match addr.addr {
        AddrOrDomain::V4(ip) => SocksAddr::Ip(SocketAddr::new(ip.into(), addr.port)),
        AddrOrDomain::V6(ip) => SocksAddr::Ip(SocketAddr::new(ip.into(), addr.port)),
        AddrOrDomain::Domain(domain) => SocksAddr::Domain(
            String::from_utf8(domain.contents).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, error)
            })?,
            addr.port,
        ),
    })
}

fn to_sunny_socks_addr(addr: SocksAddr) -> SunnySocksAddr {
    match addr {
        SocksAddr::Ip(addr) => addr.into(),
        SocksAddr::Domain(domain, port) => SunnySocksAddr::from_domain(domain, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_users() {
        let error = validate_users(&[]).expect_err("empty users must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn converts_domain_addresses() {
        let addr = SunnySocksAddr::from_domain("example.com".to_owned(), 443);
        assert_eq!(
            to_clash_socks_addr(addr).unwrap(),
            SocksAddr::Domain("example.com".to_owned(), 443)
        );
    }

    #[test]
    fn rejects_duplicate_users() {
        let users = vec![
            InboundUser {
                name: "alice".to_owned(),
                password: "first".to_owned(),
            },
            InboundUser {
                name: "alice".to_owned(),
                password: "second".to_owned(),
            },
        ];
        assert_eq!(
            validate_users(&users).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn rejects_user_management_names() {
        let users = vec![InboundUser {
            name: "administrator".to_owned(),
            password: "password".to_owned(),
        }];
        assert_eq!(
            validate_users(&users).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn maps_bbr_to_bbr3() {
        assert!(matches!(
            normalize_congestion_control(CongestionControl::Bbr),
            CongestionControl::Bbr3
        ));
    }

    #[test]
    fn requires_loopback_when_lan_access_is_disabled() {
        assert!(
            validate_listener_access("127.0.0.1:1443".parse().unwrap(), false)
                .is_ok()
        );
        assert!(
            validate_listener_access("[::1]:1443".parse().unwrap(), false).is_ok()
        );
        assert_eq!(
            validate_listener_access("0.0.0.0:1443".parse().unwrap(), false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(
            validate_listener_access("0.0.0.0:1443".parse().unwrap(), true).is_ok()
        );
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use std::{fs, io::Write as _, path::Path};

    use crate::{
        proxy::utils::test_utils::{
            config_helper,
            consts::{IMAGE_SHADOWQUIC, LOCAL_ADDR},
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

    async fn get_sunnyquic_client(
        socks_port: u16,
        server_port: u16,
        certificate: &Path,
    ) -> anyhow::Result<DockerTestRunner> {
        let client_config = format!(
            r#"inbound:
    type: socks
    bind-addr: "127.0.0.1:{socks_port}"
outbound:
    type: sunnyquic
    addr: "127.0.0.1:{server_port}"
    username: "sunny-user"
    password: "sunny-password"
    server-name: "dns.example.com"
    cert-path: "/etc/shadowquic/server.crt"
    alpn: ["h3"]
    initial-mtu: 1300
    min-mtu: 1290
    congestion-control:
      brutal:
        bandwidth: "1G"
        min-window: 16384
        cwnd-gain: 1.10
        min-ack-rate: 0.8
        min-sample-count: 50
        ack-compensate: true
    zero-rtt: true
    gso: true
    over-stream: false
log-level: "error"
"#,
        );
        let mut config_file = tempfile::NamedTempFile::new()?;
        config_file.write_all(client_config.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOWQUIC)
            .no_port()
            .net_mode("host")
            .entrypoint(&["/bin/sh"])
            .cmd(&[
                "-c",
                "sleep 2; exec /usr/bin/shadowquic -c /etc/shadowquic/config.yaml",
            ])
            .mounts(&[
                (
                    config_file.path().to_str().unwrap(),
                    "/etc/shadowquic/config.yaml",
                ),
                (certificate.to_str().unwrap(), "/etc/shadowquic/server.crt"),
            ])
            .build()
            .await?;
        drop(config_file);
        Ok(runner)
    }

    fn generate_test_certificate(
        directory: &Path,
    ) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["dns.example.com".to_owned()])?;
        let certificate = directory.join("server.crt");
        let private_key = directory.join("server.key");
        fs::write(&certificate, cert.pem())?;
        fs::write(&private_key, signing_key.serialize_pem())?;
        Ok((certificate, private_key))
    }

    #[tokio::test]
    async fn e2e_throughput_sunnyquic_inbound_brutal() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let server_port = alloc_port();
        let echo_port = alloc_port();
        let certificate_directory = tempfile::tempdir()?;
        let (certificate, private_key) =
            generate_test_certificate(certificate_directory.path())?;
        let client =
            get_sunnyquic_client(socks_port, server_port, &certificate).await?;

        let config_dir = config_helper::test_config_base_dir();
        let mmdb = config_dir.join("Country.mmdb");
        let config = format!(
            r#"mmdb: "{mmdb}"
mode: direct
log-level: error
listeners:
  - name: sunnyquic-in
    type: sunnyquic
    listen: 0.0.0.0
    port: {server_port}
    allow-lan: true
    server-name: dns.example.com
    certificate: "{certificate}"
    private-key: "{private_key}"
    users:
      - name: sunny-user
        password: sunny-password
    alpn: [h3]
    congestion-control:
      brutal:
        bandwidth: "1G"
        min-window: 16384
        cwnd-gain: 1.10
        min-ack-rate: 0.8
        min-sample-count: 50
        ack-compensate: true
    zero-rtt: true
    initial-mtu: 1300
    min-mtu: 1290
    max-path-num: 12
    gso: true
    mtu-discovery: true
"#,
            mmdb = mmdb.display(),
            certificate = certificate.display(),
            private_key = private_key.display(),
        );
        let binary = find_clash_rs_binary();

        client
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "sunnyquic-inbound-brutal",
                    socks_port,
                    echo_port,
                    Some(LOCAL_ADDR.to_owned()),
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }
}
