//! System TCP/IP-stack TUN backend, ported from leaf's system stack.
//!
//! TCP packets are source-NATed in place to a kernel TCP listener bound on
//! the TUN gateway address. The kernel owns TCP state (congestion control,
//! window scaling) and the accepted stream is dispatched with the original
//! five-tuple recovered from the NAT table.
//!
//! UDP packets are forwarded through `watfaq_netstack::UdpSocket` — a pure
//! IP packet codec — so the existing datagram path, including DNS hijack,
//! is reused unchanged. ICMP echo requests to the gateway are answered in
//! place; other ICMP traffic is dropped.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, SockAddr, Socket, Type as SocketType};
use tokio::{net::TcpListener, sync::mpsc, time};
use tracing::{debug, error, trace, warn};

use crate::{
    Error,
    app::{
        dispatcher::Dispatcher, dns::ThreadSafeDNSResolver,
        net::DEFAULT_OUTBOUND_INTERFACE,
    },
    config::config::TunConfig,
    proxy::tun::datagram::handle_inbound_datagram,
    session::{Network, Session, Type},
};

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_MIN_HEADER: usize = 20;
const TCP_NAT_SHARDS: usize = 64;
const FIRST_NAT_PORT: u16 = 10_000;
const SYSTEM_WRITE_QUEUE: usize = 1024;
const UDP_DOWNLINK_QUEUE: usize = 4096;
/// How long a NAT entry may stay un-accepted before it is reclaimed. The
/// kernel retries SYNs well within this window; anything older is a dead
/// half-open connection.
const TCP_HALF_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const NAT_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
/// How long a mapping outlives its dispatched stream, so the kernel's
/// closing FIN and final ACK can still be translated.
const NAT_LINGER: Duration = Duration::from_secs(10);
/// Pause before retrying `accept` after a resource-exhaustion error, which
/// would otherwise recur immediately and spin the accept loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpKey {
    source: SocketAddr,
    destination: SocketAddr,
}

#[derive(Clone, Copy, Debug)]
struct TcpEntry {
    key: TcpKey,
    last_seen: Instant,
    accepted: bool,
}

/// Bidirectional map between an original TCP five-tuple and the NAT source
/// port that stands in for it.
///
/// Both directions are needed on the hot path: uplink packets look up by
/// five-tuple to find their NAT port, and downlink packets (plus `accept`)
/// look up by NAT port to recover the original tuple. Both maps are sharded
/// to keep concurrent flows off a single lock.
///
/// Lock order is **forward before reverse** — `lookup_or_insert` holds
/// forward while taking reverse, so anything that needs both must acquire
/// them in that order, or release one before taking the other.
struct TcpNat {
    forward: Box<[Mutex<HashMap<TcpKey, u16>>]>,
    reverse: Box<[Mutex<HashMap<u16, TcpEntry>>]>,
    next_port: AtomicU16,
}

/// Ignore mutex poisoning: every critical section below is a plain map
/// operation that cannot leave the map in an inconsistent state.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl TcpNat {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            forward: (0..TCP_NAT_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            reverse: (0..TCP_NAT_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            next_port: AtomicU16::new(FIRST_NAT_PORT),
        })
    }

    #[inline]
    fn forward_shard(key: &TcpKey) -> usize {
        fn address_hash(address: SocketAddr) -> usize {
            match address {
                SocketAddr::V4(address) => u32::from(*address.ip()) as usize,
                SocketAddr::V6(address) => {
                    address.ip().segments().iter().fold(0usize, |hash, seg| {
                        hash.rotate_left(5) ^ *seg as usize
                    })
                }
            }
        }
        (address_hash(key.source)
            ^ address_hash(key.destination)
            ^ key.source.port() as usize
            ^ key.destination.port() as usize)
            & (TCP_NAT_SHARDS - 1)
    }

    #[inline]
    fn reverse_shard(port: u16) -> usize {
        (port as usize) & (TCP_NAT_SHARDS - 1)
    }

    fn lookup_or_insert(&self, key: TcpKey) -> io::Result<u16> {
        let forward = &self.forward[Self::forward_shard(&key)];
        let mut forward = lock(forward);
        if let Some(port) = forward.get(&key).copied() {
            if let Some(entry) =
                lock(&self.reverse[Self::reverse_shard(port)]).get_mut(&port)
            {
                entry.last_seen = Instant::now();
                return Ok(port);
            }
            // Cleanup removes reverse state before the forward index. Do not
            // let a packet reuse that brief stale mapping after the NAT port
            // has become available again.
            forward.remove(&key);
        }

        for _ in FIRST_NAT_PORT..=u16::MAX {
            let mut port = self.next_port.fetch_add(1, Ordering::Relaxed);
            if port < FIRST_NAT_PORT {
                port = FIRST_NAT_PORT;
                self.next_port
                    .store(FIRST_NAT_PORT.wrapping_add(1), Ordering::Relaxed);
            }
            let mut reverse = lock(&self.reverse[Self::reverse_shard(port)]);
            if reverse.contains_key(&port) {
                continue;
            }
            reverse.insert(
                port,
                TcpEntry {
                    key,
                    last_seen: Instant::now(),
                    accepted: false,
                },
            );
            forward.insert(key, port);
            return Ok(port);
        }
        Err(io::Error::other("system TUN TCP NAT port space exhausted"))
    }

    fn lookup_back(&self, port: u16) -> Option<TcpEntry> {
        let mut reverse = lock(&self.reverse[Self::reverse_shard(port)]);
        let entry = reverse.get_mut(&port)?;
        entry.last_seen = Instant::now();
        Some(*entry)
    }

    fn remove(&self, port: u16) {
        let entry = lock(&self.reverse[Self::reverse_shard(port)]).remove(&port);
        if let Some(entry) = entry {
            lock(&self.forward[Self::forward_shard(&entry.key)]).remove(&entry.key);
        }
    }

    fn mark_accepted(&self, port: u16) {
        if let Some(entry) =
            lock(&self.reverse[Self::reverse_shard(port)]).get_mut(&port)
        {
            entry.accepted = true;
            entry.last_seen = Instant::now();
        }
    }

    /// Removes `port`, but only if it is *still* expired.
    ///
    /// `cleanup` collects candidates without holding the shard lock, and in
    /// that gap `lookup_or_insert` may have refreshed `last_seen` for a new
    /// packet of the same flow, or `mark_accepted` may have claimed the
    /// entry. Removing it regardless would blackhole a live connection: the
    /// downlink path would find no mapping and drop every kernel packet.
    fn remove_if_still_expired(&self, port: u16, timeout: Duration) {
        let key = {
            let mut reverse = lock(&self.reverse[Self::reverse_shard(port)]);
            match reverse.get(&port) {
                Some(entry)
                    if !entry.accepted && entry.last_seen.elapsed() >= timeout =>
                {
                    reverse.remove(&port).map(|entry| entry.key)
                }
                _ => None,
            }
        };
        // The reverse guard is dropped above before the forward lock is
        // taken: `lookup_or_insert` acquires forward first, so holding
        // reverse while waiting on forward could deadlock.
        if let Some(key) = key {
            lock(&self.forward[Self::forward_shard(&key)]).remove(&key);
        }
    }

    fn cleanup(&self, timeout: Duration) {
        let now = Instant::now();
        let mut expired = Vec::new();
        for reverse in self.reverse.iter() {
            let reverse = lock(reverse);
            expired.extend(reverse.iter().filter_map(|(&port, entry)| {
                (!entry.accepted && now.duration_since(entry.last_seen) >= timeout)
                    .then_some(port)
            }));
        }
        for port in expired {
            self.remove_if_still_expired(port, timeout);
        }
    }
}

#[derive(Clone, Copy)]
struct Ipv4View {
    header_len: usize,
    total_len: usize,
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

/// Validates an IPv4 packet and locates its transport header.
///
/// Rejects fragments: this backend rewrites transport ports, which are only
/// present in the first fragment, so reassembly would be required to handle
/// them correctly.
fn parse_ipv4(packet: &[u8]) -> io::Result<Ipv4View> {
    if packet.len() < IPV4_MIN_HEADER || packet[0] >> 4 != 4 {
        return Err(io::Error::other("invalid IPv4 packet"));
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < IPV4_MIN_HEADER || header_len > packet.len() {
        return Err(io::Error::other("invalid IPv4 header length"));
    }
    let total_len = read_u16(packet, 2) as usize;
    if total_len < header_len || total_len > packet.len() {
        return Err(io::Error::other("truncated IPv4 packet"));
    }
    if read_u16(packet, 6) & 0x3fff != 0 {
        return Err(io::Error::other(
            "fragmented IPv4 packets are unsupported by system stack",
        ));
    }
    Ok(Ipv4View {
        header_len,
        total_len,
        protocol: packet[9],
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    })
}

#[derive(Clone, Copy)]
struct Ipv6View {
    transport_offset: usize,
    total_len: usize,
    protocol: u8,
    source: Ipv6Addr,
    destination: Ipv6Addr,
}

/// Validates an IPv6 packet and walks its extension-header chain to find the
/// transport header.
///
/// Rejects fragment (44) and ESP (50) headers: the former needs reassembly
/// before ports are visible, the latter hides them entirely.
fn parse_ipv6(packet: &[u8]) -> io::Result<Ipv6View> {
    if packet.len() < IPV6_HEADER || packet[0] >> 4 != 6 {
        return Err(io::Error::other("invalid IPv6 packet"));
    }
    let payload_len = read_u16(packet, 4) as usize;
    let total_len = IPV6_HEADER
        .checked_add(payload_len)
        .ok_or_else(|| io::Error::other("IPv6 packet length overflow"))?;
    if total_len > packet.len() {
        return Err(io::Error::other("truncated IPv6 packet"));
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
    let mut protocol = packet[6];
    let mut transport_offset = IPV6_HEADER;
    loop {
        match protocol {
            // Hop-by-hop, routing, and destination options carry a
            // next-header byte followed by an 8-octet-unit length.
            0 | 43 | 60 => {
                if transport_offset + 2 > total_len {
                    return Err(io::Error::other("truncated IPv6 extension header"));
                }
                let header_len = (packet[transport_offset + 1] as usize + 1) * 8;
                if transport_offset + header_len > total_len {
                    return Err(io::Error::other("truncated IPv6 extension header"));
                }
                protocol = packet[transport_offset];
                transport_offset += header_len;
            }
            51 => {
                if transport_offset + 2 > total_len {
                    return Err(io::Error::other(
                        "truncated IPv6 authentication header",
                    ));
                }
                let header_len = (packet[transport_offset + 1] as usize + 2) * 4;
                if transport_offset + header_len > total_len {
                    return Err(io::Error::other(
                        "truncated IPv6 authentication header",
                    ));
                }
                protocol = packet[transport_offset];
                transport_offset += header_len;
            }
            44 => {
                return Err(io::Error::other(
                    "fragmented IPv6 packets are unsupported by system stack",
                ));
            }
            50 => {
                return Err(io::Error::other(
                    "encrypted IPv6 payload is unsupported by system stack",
                ));
            }
            _ => break,
        }
    }
    Ok(Ipv6View {
        transport_offset,
        total_len,
        protocol,
        source,
        destination,
    })
}

#[inline]
fn read_u16(packet: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

#[inline]
fn write_u16(packet: &mut [u8], offset: usize, value: u16) {
    packet[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[inline]
fn checksum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// RFC 1624 incremental checksum update for a single 16-bit word.
#[inline]
fn checksum_replace(checksum: u16, old: u16, new: u16) -> u16 {
    let sum = (!checksum as u32) + (!old as u32) + new as u32;
    !checksum_fold(sum)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    !checksum_fold(sum)
}

/// Rewrites an IPv4 TCP packet's four-tuple in place.
///
/// Both the IP header checksum and the TCP checksum are updated
/// incrementally (RFC 1624) rather than recomputed, so cost is independent
/// of payload size. A TCP checksum that lands on zero is written as 0xffff,
/// since zero means "no checksum" and would be rejected.
fn rewrite_ipv4_tcp(
    packet: &mut [u8],
    header_len: usize,
    source: SocketAddrV4,
    destination: SocketAddrV4,
) -> io::Result<()> {
    if packet.len() < header_len + TCP_MIN_HEADER {
        return Err(io::Error::other("truncated TCP packet"));
    }
    let tcp_checksum_offset = header_len + 16;
    let mut ip_checksum = read_u16(packet, 10);
    let mut tcp_checksum = read_u16(packet, tcp_checksum_offset);
    for (offset, new_word) in [
        (
            12,
            u16::from_be_bytes(source.ip().octets()[..2].try_into().unwrap()),
        ),
        (
            14,
            u16::from_be_bytes(source.ip().octets()[2..].try_into().unwrap()),
        ),
        (
            16,
            u16::from_be_bytes(destination.ip().octets()[..2].try_into().unwrap()),
        ),
        (
            18,
            u16::from_be_bytes(destination.ip().octets()[2..].try_into().unwrap()),
        ),
    ] {
        let old_word = read_u16(packet, offset);
        ip_checksum = checksum_replace(ip_checksum, old_word, new_word);
        tcp_checksum = checksum_replace(tcp_checksum, old_word, new_word);
        write_u16(packet, offset, new_word);
    }
    for (offset, new_word) in [
        (header_len, source.port()),
        (header_len + 2, destination.port()),
    ] {
        let old_word = read_u16(packet, offset);
        tcp_checksum = checksum_replace(tcp_checksum, old_word, new_word);
        write_u16(packet, offset, new_word);
    }
    write_u16(packet, 10, ip_checksum);
    write_u16(
        packet,
        tcp_checksum_offset,
        if tcp_checksum == 0 {
            0xffff
        } else {
            tcp_checksum
        },
    );
    Ok(())
}

/// Rewrites an IPv6 TCP packet's four-tuple in place.
///
/// Like the IPv4 path this updates the TCP checksum incrementally; IPv6 has
/// no header checksum to maintain. Addresses are folded in word by word
/// because they participate in the TCP pseudo-header.
fn rewrite_ipv6_tcp(
    packet: &mut [u8],
    transport_offset: usize,
    source: SocketAddrV6,
    destination: SocketAddrV6,
) -> io::Result<()> {
    if packet.len() < transport_offset + TCP_MIN_HEADER {
        return Err(io::Error::other("truncated TCP packet"));
    }
    let tcp_checksum_offset = transport_offset + 16;
    let mut tcp_checksum = read_u16(packet, tcp_checksum_offset);
    for (offset, address) in [(8, source.ip()), (24, destination.ip())] {
        for (word_offset, new_word) in address
            .octets()
            .chunks_exact(2)
            .enumerate()
            .map(|(index, octets)| {
                (index * 2, u16::from_be_bytes([octets[0], octets[1]]))
            })
        {
            let offset = offset + word_offset;
            let old_word = read_u16(packet, offset);
            tcp_checksum = checksum_replace(tcp_checksum, old_word, new_word);
            write_u16(packet, offset, new_word);
        }
    }
    for (offset, new_word) in [
        (transport_offset, source.port()),
        (transport_offset + 2, destination.port()),
    ] {
        let old_word = read_u16(packet, offset);
        tcp_checksum = checksum_replace(tcp_checksum, old_word, new_word);
        write_u16(packet, offset, new_word);
    }
    write_u16(
        packet,
        tcp_checksum_offset,
        if tcp_checksum == 0 {
            0xffff
        } else {
            tcp_checksum
        },
    );
    Ok(())
}

/// Computes an IPv6 transport checksum from scratch, over the RFC 2460
/// pseudo-header (source, destination, payload length, next header) followed
/// by the transport payload.
///
/// Used where no prior checksum exists to update incrementally: synthesized
/// UDP downlink packets and ICMPv6 echo replies.
fn checksum_ipv6_transport(
    packet: &[u8],
    transport_offset: usize,
    next_header: u8,
) -> u16 {
    let payload_len = packet.len() - transport_offset;
    let mut sum = 0u32;
    for chunk in packet[8..40].chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += ((payload_len >> 16) as u16) as u32;
    sum += (payload_len as u16) as u32;
    sum += next_header as u32;
    let mut chunks = packet[transport_offset..].chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    let checksum = !checksum_fold(sum);
    if checksum == 0 { 0xffff } else { checksum }
}

fn make_icmp_echo_reply(
    packet: &mut [u8],
    view: Ipv4View,
    tun_address: Ipv4Addr,
) -> bool {
    if view.destination != tun_address || view.total_len < view.header_len + 8 {
        return false;
    }
    let icmp = view.header_len;
    if packet[icmp] != 8 || packet[icmp + 1] != 0 {
        return false;
    }
    packet[12..16].copy_from_slice(&view.destination.octets());
    packet[16..20].copy_from_slice(&view.source.octets());
    write_u16(packet, 10, 0);
    write_u16(packet, 10, checksum(&packet[..view.header_len]));
    packet[icmp] = 0;
    write_u16(packet, icmp + 2, 0);
    write_u16(packet, icmp + 2, checksum(&packet[icmp..view.total_len]));
    true
}

fn make_icmpv6_echo_reply(
    packet: &mut [u8],
    view: Ipv6View,
    tun_address: Ipv6Addr,
) -> bool {
    if view.destination != tun_address || view.total_len < view.transport_offset + 8
    {
        return false;
    }
    let icmp = view.transport_offset;
    if packet[icmp] != 128 || packet[icmp + 1] != 0 {
        return false;
    }
    packet[8..24].copy_from_slice(&view.destination.octets());
    packet[24..40].copy_from_slice(&view.source.octets());
    packet[icmp] = 129;
    write_u16(packet, icmp + 2, 0);
    write_u16(
        packet,
        icmp + 2,
        checksum_ipv6_transport(&packet[..view.total_len], icmp, 58),
    );
    true
}

/// Derives the NAT source address as `gateway + 1`.
///
/// Uplink packets are rewritten to come *from* this address so the kernel
/// routes the listener's replies back out the TUN rather than to the real
/// client. It must therefore be inside the TUN prefix, and must not be the
/// network or broadcast address.
fn ipv4_nat_address(gateway: ipnet::Ipv4Net) -> Result<Ipv4Addr, Error> {
    let tun_address = gateway.addr();
    let netmask = gateway.netmask();
    let nat_address =
        Ipv4Addr::from(u32::from(tun_address).checked_add(1).ok_or_else(|| {
            Error::InvalidConfig(
                "system TUN requires an IPv4 gateway with one following address"
                    .to_string(),
            )
        })?);
    let mask = u32::from(netmask);
    if u32::from(tun_address) & mask != u32::from(nat_address) & mask {
        return Err(Error::InvalidConfig(
            "system TUN requires an IPv4 prefix with one adjacent NAT address"
                .to_string(),
        ));
    }
    let network = u32::from(tun_address) & mask;
    let broadcast = network | !mask;
    if u32::from(nat_address) == network || u32::from(nat_address) == broadcast {
        return Err(Error::InvalidConfig(
            "system TUN adjacent NAT address must not be the network or broadcast \
             address"
                .to_string(),
        ));
    }
    Ok(nat_address)
}

fn ipv6_adjacent_address(
    address: Ipv6Addr,
    prefix_len: u8,
) -> Result<Ipv6Addr, Error> {
    if prefix_len >= 128 {
        return Err(Error::InvalidConfig(
            "system TUN requires an IPv6 prefix shorter than /128 for its adjacent \
             NAT address"
                .to_string(),
        ));
    }
    let nat_address =
        Ipv6Addr::from(u128::from(address).checked_add(1).ok_or_else(|| {
            Error::InvalidConfig(
                "system TUN IPv6 gateway has no following NAT address".to_string(),
            )
        })?);
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    if u128::from(address) & mask != u128::from(nat_address) & mask {
        return Err(Error::InvalidConfig(
            "system TUN requires an IPv6 prefix with one adjacent NAT address"
                .to_string(),
        ));
    }
    Ok(nat_address)
}

/// Accepts redirected connections and dispatches them under their original
/// five-tuple.
///
/// Only peers coming from `nat_ip` are ours; the listener is reachable by
/// other local traffic, so anything else is dropped rather than proxied.
async fn tcp_accept_loop(
    listener: TcpListener,
    nat_ip: IpAddr,
    nat: Arc<TcpNat>,
    dispatcher: Arc<Dispatcher>,
    so_mark: Option<u32>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Accept errors are per-connection or transient. Returning
                // here would resolve this future and, because `run` selects
                // over it, tear down the whole TUN backend — so a single
                // aborted handshake or file-descriptor shortage would kill
                // all TUN traffic.
                warn!("system TUN TCP accept failed: {e}");
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EMFILE)
                        | Some(libc::ENFILE)
                        | Some(libc::ENOBUFS)
                        | Some(libc::ENOMEM)
                ) {
                    // Resource exhaustion repeats immediately; back off so
                    // the loop does not spin at 100% CPU while it lasts.
                    time::sleep(ACCEPT_BACKOFF).await;
                }
                continue;
            }
        };
        if peer.ip() != nat_ip {
            continue;
        }
        let Some(entry) = nat.lookup_back(peer.port()) else {
            continue;
        };
        nat.mark_accepted(peer.port());
        let nat = Arc::clone(&nat);
        let dispatcher = Arc::clone(&dispatcher);
        tokio::spawn(async move {
            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tun,
                source: entry.key.source,
                destination: entry.key.destination.into(),
                iface: DEFAULT_OUTBOUND_INTERFACE.read().await.clone().inspect(
                    |x| {
                        debug!(
                            "selecting outbound interface: {:?} for tun TCP \
                             connection",
                            x
                        );
                    },
                ),
                so_mark,
                ..Default::default()
            };
            debug!("new tun TCP session assigned: {}", sess);
            dispatcher.dispatch_stream(sess, Box::new(stream)).await;
            // The kernel closes the accepted socket only once it is dropped
            // here, and the FIN plus final ACK it then sends still have to
            // be translated back to the original five-tuple. Dropping the
            // mapping immediately would blackhole them, leaving the client
            // to wait out its own timeout while the kernel retransmits.
            time::sleep(NAT_LINGER).await;
            nat.remove(peer.port());
        });
    }
}

fn bind_v4_listener(address: Ipv4Addr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, SocketType::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(address, 0)))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Binds the IPv6 listener to the TUN address.
///
/// The address can still be tentative (duplicate address detection) at this
/// point, which makes `bind` fail with `EADDRNOTAVAIL`. On Linux
/// `IPV6_FREEBIND` lifts that restriction; elsewhere we fall back to the
/// unspecified address, which works but leaves the port reachable on every
/// IPv6 interface until `tcp_accept_loop`'s peer filter rejects the
/// connection.
fn bind_v6_listener(address: Ipv6Addr) -> io::Result<TcpListener> {
    fn new_socket() -> io::Result<Socket> {
        let socket =
            Socket::new(Domain::IPV6, SocketType::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(true)?;
        Ok(socket)
    }

    fn listen(socket: Socket) -> io::Result<TcpListener> {
        socket.listen(1024)?;
        socket.set_nonblocking(true)?;
        TcpListener::from_std(socket.into())
    }

    let socket = new_socket()?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    socket.set_freebind_v6(true)?;
    match socket.bind(&SockAddr::from(SocketAddr::V6(SocketAddrV6::new(
        address, 0, 0, 0,
    )))) {
        Ok(()) => listen(socket),
        Err(e) => {
            warn!(
                "system TUN could not bind the IPv6 listener to {address}: {e}; \
                 falling back to the unspecified address"
            );
            let socket = new_socket()?;
            socket.bind(&SockAddr::from(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                0,
                0,
            ))))?;
            listen(socket)
        }
    }
}

/// Runs the system stack until one of its tasks fails.
///
/// Drives seven concurrent futures: the TUN reader (which rewrites TCP and
/// hands UDP to the codec), the single TUN writer that owns the device sink,
/// the UDP downlink pump, the IPv4 and IPv6 accept loops, the datagram
/// dispatcher, and the periodic NAT cleanup. They are selected over, so the
/// first failure tears the backend down and surfaces the error.
pub(crate) async fn run(
    cfg: TunConfig,
    tun: tun_rs::AsyncDevice,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) -> Result<(), Error> {
    let tun_address = cfg.gateway.addr();
    let nat_address = ipv4_nat_address(cfg.gateway)?;

    let listener = bind_v4_listener(tun_address)?;
    let listener_port = listener.local_addr()?.port();

    let (ipv6_listener, ipv6_addresses) = match cfg.gateway_v6 {
        Some(gateway_v6) => {
            let tun_address = gateway_v6.addr();
            let nat_address =
                ipv6_adjacent_address(tun_address, gateway_v6.prefix_len())?;
            let listener = bind_v6_listener(tun_address)?;
            let port = listener.local_addr()?.port();
            (Some(listener), Some((tun_address, nat_address, port)))
        }
        None => (None, None),
    };

    let framed = tun_rs::async_framed::DeviceFramed::new(
        tun,
        tun_rs::async_framed::BytesCodec::new(),
    );
    let (mut tun_sink, mut tun_stream) = framed.split::<Bytes>();

    // Everything written back to the TUN device goes through this queue so
    // the device sink has a single owner.
    let (writer_tx, mut writer_rx) = mpsc::channel::<Bytes>(SYSTEM_WRITE_QUEUE);

    // UDP reuses the userspace packet codec and the existing datagram path.
    let (udp_inbound_tx, udp_inbound_rx) =
        mpsc::unbounded_channel::<watfaq_netstack::Packet>();
    let (udp_outbound_tx, mut udp_outbound_rx) =
        mpsc::channel::<watfaq_netstack::Packet>(UDP_DOWNLINK_QUEUE);
    let udp_socket =
        watfaq_netstack::UdpSocket::new(udp_inbound_rx, udp_outbound_tx);

    let tcp_nat = TcpNat::new();

    let fut_writer = async {
        while let Some(packet) = writer_rx.recv().await {
            if let Err(e) = tun_sink.send(packet).await {
                // TimedOut means the Wintun/TUN send ring buffer was full for
                // too long (driver backpressure). Drop the packet and keep
                // the runner alive — packet loss is normal at the IP layer.
                if e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock
                {
                    warn!("tun send buffer full, dropping packet: {}", e);
                    continue;
                }
                error!("failed to send pkt to tun: {}", e);
                break;
            }
        }
        Err(Error::Operation(
            "tun system stack writer stopped unexpectedly".to_string(),
        ))
    };

    let fut_udp_downlink = {
        let writer_tx = writer_tx.clone();
        async move {
            while let Some(packet) = udp_outbound_rx.recv().await {
                if writer_tx.send(packet.into_bytes()).await.is_err() {
                    break;
                }
            }
            Err(Error::Operation(
                "tun system stack UDP downlink stopped unexpectedly".to_string(),
            ))
        }
    };

    let fut_accept_v4 = {
        let nat = Arc::clone(&tcp_nat);
        let dispatcher = Arc::clone(&dispatcher);
        async move {
            tcp_accept_loop(
                listener,
                IpAddr::V4(nat_address),
                nat,
                dispatcher,
                cfg.so_mark,
            )
            .await;
            Err(Error::Operation(
                "tun system stack TCP listener stopped unexpectedly".to_string(),
            ))
        }
    };

    let fut_accept_v6 = {
        let nat = Arc::clone(&tcp_nat);
        let dispatcher = Arc::clone(&dispatcher);
        async move {
            match (ipv6_listener, ipv6_addresses) {
                (Some(listener), Some((_, nat_address, _))) => {
                    tcp_accept_loop(
                        listener,
                        IpAddr::V6(nat_address),
                        nat,
                        dispatcher,
                        cfg.so_mark,
                    )
                    .await;
                    Err(Error::Operation(
                        "tun system stack TCP IPv6 listener stopped unexpectedly"
                            .to_string(),
                    ))
                }
                _ => std::future::pending().await,
            }
        }
    };

    let fut_nat_cleanup = {
        let nat = Arc::clone(&tcp_nat);
        async move {
            let mut interval = time::interval(NAT_CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                nat.cleanup(TCP_HALF_OPEN_TIMEOUT);
            }
        }
    };

    let fut_udp_dispatch = async move {
        handle_inbound_datagram(
            udp_socket,
            dispatcher,
            resolver,
            cfg.so_mark,
            cfg.dns_hijack,
        )
        .await;
        Err(Error::Operation(
            "tun system stack UDP dispatcher stopped unexpectedly".to_string(),
        ))
    };

    let fut_read_loop = {
        let tcp_nat = Arc::clone(&tcp_nat);
        async move {
            while let Some(packet) = tun_stream.next().await {
                let mut packet: BytesMut = match packet {
                    Ok(packet) => packet,
                    Err(e) => {
                        error!("tun stream error: {}", e);
                        break;
                    }
                };
                if packet.is_empty() {
                    continue;
                }
                match packet[0] >> 4 {
                    4 => {
                        let view = match parse_ipv4(&packet) {
                            Ok(view) => view,
                            Err(e) => {
                                trace!("system TUN ignored IPv4 packet: {}", e);
                                continue;
                            }
                        };
                        match view.protocol {
                            6 => {
                                if process_tcp_v4(
                                    &mut packet,
                                    view,
                                    &tcp_nat,
                                    tun_address,
                                    nat_address,
                                    listener_port,
                                )
                                .is_none()
                                {
                                    continue;
                                }
                                if writer_tx.send(packet.freeze()).await.is_err() {
                                    break;
                                }
                            }
                            17 => {
                                // Forwarded as a whole IP packet; the codec
                                // re-parses and hands the payload to the
                                // datagram path.
                                udp_inbound_tx
                                    .send(watfaq_netstack::Packet::new(
                                        packet.freeze(),
                                    ))
                                    .ok();
                            }
                            1 => {
                                if !make_icmp_echo_reply(
                                    &mut packet,
                                    view,
                                    tun_address,
                                ) {
                                    continue;
                                }
                                if writer_tx.send(packet.freeze()).await.is_err() {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    6 => {
                        let view = match parse_ipv6(&packet) {
                            Ok(view) => view,
                            Err(e) => {
                                trace!("system TUN ignored IPv6 packet: {}", e);
                                continue;
                            }
                        };
                        match view.protocol {
                            6 => {
                                let Some((
                                    tun_v6_address,
                                    nat_v6_address,
                                    v6_listener_port,
                                )) = ipv6_addresses
                                else {
                                    continue;
                                };
                                if process_tcp_v6(
                                    &mut packet,
                                    view,
                                    &tcp_nat,
                                    tun_v6_address,
                                    nat_v6_address,
                                    v6_listener_port,
                                )
                                .is_none()
                                {
                                    continue;
                                }
                                if writer_tx.send(packet.freeze()).await.is_err() {
                                    break;
                                }
                            }
                            17 => {
                                // The UDP codec assumes a fixed 40-byte IPv6
                                // header; packets carrying extension headers
                                // would be parsed incorrectly, so drop them.
                                if view.transport_offset != IPV6_HEADER {
                                    trace!(
                                        "system TUN dropped IPv6 UDP packet with \
                                         extension headers"
                                    );
                                    continue;
                                }
                                udp_inbound_tx
                                    .send(watfaq_netstack::Packet::new(
                                        packet.freeze(),
                                    ))
                                    .ok();
                            }
                            58 => {
                                let Some((tun_v6_address, ..)) = ipv6_addresses
                                else {
                                    continue;
                                };
                                if !make_icmpv6_echo_reply(
                                    &mut packet,
                                    view,
                                    tun_v6_address,
                                ) {
                                    continue;
                                }
                                if writer_tx.send(packet.freeze()).await.is_err() {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        trace!("system TUN ignored packet with unknown IP version");
                    }
                }
            }
            Err(Error::Operation(
                "tun system stack read loop stopped unexpectedly".to_string(),
            ))
        }
    };

    debug!(
        "tun system stack ready: gateway {} nat {} listener port {}",
        tun_address, nat_address, listener_port
    );

    tokio::select! {
        res = fut_writer => res,
        res = fut_udp_downlink => res,
        res = fut_accept_v4 => res,
        res = fut_accept_v6 => res,
        _ = fut_nat_cleanup => Ok(()),
        res = fut_udp_dispatch => res,
        res = fut_read_loop => res,
    }
}

/// Rewrites an uplink or downlink IPv4 TCP packet in place. Returns `None`
/// when the packet should be dropped.
fn process_tcp_v4(
    packet: &mut BytesMut,
    view: Ipv4View,
    nat: &TcpNat,
    tun_address: Ipv4Addr,
    nat_address: Ipv4Addr,
    listener_port: u16,
) -> Option<()> {
    let tcp = view.header_len;
    if view.total_len < tcp + TCP_MIN_HEADER {
        return None;
    }
    let source_port = read_u16(packet, tcp);
    let destination_port = read_u16(packet, tcp + 2);
    let rewritten = if view.source == tun_address && source_port == listener_port {
        // Downlink: a reply from the kernel listener back to the NAT
        // address; restore the original five-tuple.
        let entry = nat.lookup_back(destination_port)?;
        match (entry.key.destination, entry.key.source) {
            (SocketAddr::V4(destination), SocketAddr::V4(source)) => {
                rewrite_ipv4_tcp(packet, view.header_len, destination, source)
            }
            _ => Err(io::Error::other("IPv4 TCP NAT address family mismatch")),
        }
    } else {
        // Uplink: redirect the flow to the kernel listener, sourced from
        // the NAT address so replies come back through the TUN.
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(view.source, source_port)),
            destination: SocketAddr::V4(SocketAddrV4::new(
                view.destination,
                destination_port,
            )),
        };
        match nat.lookup_or_insert(key) {
            Ok(port) => rewrite_ipv4_tcp(
                packet,
                view.header_len,
                SocketAddrV4::new(nat_address, port),
                SocketAddrV4::new(tun_address, listener_port),
            ),
            Err(e) => Err(e),
        }
    };
    match rewritten {
        Ok(()) => Some(()),
        Err(e) => {
            trace!("system TUN IPv4 TCP rewrite failed: {}", e);
            None
        }
    }
}

/// Rewrites an uplink or downlink IPv6 TCP packet in place. Returns `None`
/// when the packet should be dropped.
fn process_tcp_v6(
    packet: &mut BytesMut,
    view: Ipv6View,
    nat: &TcpNat,
    tun_address: Ipv6Addr,
    nat_address: Ipv6Addr,
    listener_port: u16,
) -> Option<()> {
    let tcp = view.transport_offset;
    if view.total_len < tcp + TCP_MIN_HEADER {
        return None;
    }
    let source_port = read_u16(packet, tcp);
    let destination_port = read_u16(packet, tcp + 2);
    let rewritten = if view.source == tun_address && source_port == listener_port {
        let entry = nat.lookup_back(destination_port)?;
        match (entry.key.destination, entry.key.source) {
            (SocketAddr::V6(destination), SocketAddr::V6(source)) => {
                rewrite_ipv6_tcp(packet, tcp, destination, source)
            }
            _ => Err(io::Error::other("IPv6 TCP NAT address family mismatch")),
        }
    } else {
        let key = TcpKey {
            source: SocketAddr::V6(SocketAddrV6::new(
                view.source,
                source_port,
                0,
                0,
            )),
            destination: SocketAddr::V6(SocketAddrV6::new(
                view.destination,
                destination_port,
                0,
                0,
            )),
        };
        match nat.lookup_or_insert(key) {
            Ok(port) => rewrite_ipv6_tcp(
                packet,
                tcp,
                SocketAddrV6::new(nat_address, port, 0, 0),
                SocketAddrV6::new(tun_address, listener_port, 0, 0),
            ),
            Err(e) => Err(e),
        }
    };
    match rewritten {
        Ok(()) => Some(()),
        Err(e) => {
            trace!("system TUN IPv6 TCP rewrite failed: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_rewrite_updates_the_four_tuple_in_place() {
        let mut packet = [0u8; 40];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        write_u16(&mut packet, 2, packet_len);
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 9]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        write_u16(&mut packet, 20, 12345);
        write_u16(&mut packet, 22, 443);
        packet[32] = 0x50;
        let header_checksum = checksum(&packet[..20]);
        write_u16(&mut packet, 10, header_checksum);
        rewrite_ipv4_tcp(
            &mut packet,
            20,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 233, 3), 10000),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 233, 2), 20000),
        )
        .unwrap();
        assert_eq!(&packet[12..16], &[192, 168, 233, 3]);
        assert_eq!(&packet[16..20], &[192, 168, 233, 2]);
        assert_eq!(read_u16(&packet, 20), 10000);
        assert_eq!(read_u16(&packet, 22), 20000);
        // the incrementally updated IP checksum must match a full
        // recomputation
        let updated = read_u16(&packet, 10);
        write_u16(&mut packet, 10, 0);
        assert_eq!(updated, checksum(&packet[..20]));
    }

    #[test]
    fn tcp_nat_keeps_a_stable_port_and_removes_it() {
        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                34567,
            )),
            destination: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )),
        };
        let port = nat.lookup_or_insert(key).unwrap();
        assert_eq!(nat.lookup_or_insert(key).unwrap(), port);
        assert_eq!(nat.lookup_back(port).unwrap().key, key);
        nat.remove(port);
        assert!(nat.lookup_back(port).is_none());
    }

    #[test]
    fn tcp_nat_cleanup_reclaims_unaccepted_entries() {
        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                34567,
            )),
            destination: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )),
        };
        let port = nat.lookup_or_insert(key).unwrap();
        let accepted_key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 3),
                34567,
            )),
            ..key
        };
        let accepted_port = nat.lookup_or_insert(accepted_key).unwrap();
        nat.mark_accepted(accepted_port);
        nat.cleanup(Duration::ZERO);
        assert!(nat.lookup_back(port).is_none());
        assert!(nat.lookup_back(accepted_port).is_some());
    }

    #[test]
    fn icmp_echo_for_tun_address_is_replied_in_place() {
        let mut packet = [0u8; 28];
        packet[0] = 0x45;
        write_u16(&mut packet, 2, 28);
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 9]);
        packet[16..20].copy_from_slice(&[192, 168, 233, 2]);
        packet[20] = 8;
        packet[24..28].copy_from_slice(b"ping");
        let icmp_checksum = checksum(&packet[20..]);
        write_u16(&mut packet, 22, icmp_checksum);
        let ip_checksum = checksum(&packet[..20]);
        write_u16(&mut packet, 10, ip_checksum);
        let view = parse_ipv4(&packet).unwrap();
        assert!(make_icmp_echo_reply(
            &mut packet,
            view,
            Ipv4Addr::new(192, 168, 233, 2),
        ));
        assert_eq!(packet[20], 0);
        assert_eq!(&packet[12..16], &[192, 168, 233, 2]);
        assert_eq!(&packet[16..20], &[10, 0, 0, 9]);
    }

    #[test]
    fn ipv6_tcp_rewrite_updates_the_four_tuple_in_place() {
        let mut packet = [0u8; 60];
        packet[0] = 0x60;
        write_u16(&mut packet, 4, 20);
        packet[6] = 6;
        packet[8..24]
            .copy_from_slice(&"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(
            &"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets(),
        );
        write_u16(&mut packet, 40, 12345);
        write_u16(&mut packet, 42, 443);
        packet[52] = 0x50;
        // Start from a correct checksum: an incremental update applied to a
        // zero checksum would look plausible while being wrong.
        let original = checksum_ipv6_transport(&packet, 40, 6);
        write_u16(&mut packet, 56, original);
        rewrite_ipv6_tcp(
            &mut packet,
            40,
            SocketAddrV6::new("2001:2::3".parse().unwrap(), 10000, 0, 0),
            SocketAddrV6::new("2001:2::2".parse().unwrap(), 20000, 0, 0),
        )
        .unwrap();
        assert_eq!(
            &packet[8..24],
            &"2001:2::3".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            &packet[24..40],
            &"2001:2::2".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(read_u16(&packet, 40), 10000);
        assert_eq!(read_u16(&packet, 42), 20000);
        // the incrementally updated checksum must match a full recomputation
        let updated = read_u16(&packet, 56);
        write_u16(&mut packet, 56, 0);
        assert_eq!(updated, checksum_ipv6_transport(&packet, 40, 6));
    }

    /// The downlink branch of `process_tcp_v4`: a reply from the kernel
    /// listener must be rewritten back to the original five-tuple.
    #[test]
    fn downlink_tcp_v4_is_restored_to_the_original_tuple() {
        let client = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 12345);
        let server = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443);
        let tun_address = Ipv4Addr::new(198, 18, 0, 1);
        let nat_address = Ipv4Addr::new(198, 18, 0, 2);
        let listener_port = 40000;

        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(client),
            destination: SocketAddr::V4(server),
        };
        let nat_port = nat.lookup_or_insert(key).unwrap();

        // a reply travelling tun_address:listener_port -> nat_address:nat_port
        let mut packet = BytesMut::zeroed(40);
        packet[0] = 0x45;
        write_u16(&mut packet, 2, 40);
        packet[9] = 6;
        packet[12..16].copy_from_slice(&tun_address.octets());
        packet[16..20].copy_from_slice(&nat_address.octets());
        write_u16(&mut packet, 20, listener_port);
        write_u16(&mut packet, 22, nat_port);
        packet[32] = 0x50;
        let ip_checksum = checksum(&packet[..20]);
        write_u16(&mut packet, 10, ip_checksum);

        let view = parse_ipv4(&packet).unwrap();
        assert!(
            process_tcp_v4(
                &mut packet,
                view,
                &nat,
                tun_address,
                nat_address,
                listener_port,
            )
            .is_some()
        );

        // the client must see the packet as coming straight from the server
        assert_eq!(&packet[12..16], &server.ip().octets());
        assert_eq!(&packet[16..20], &client.ip().octets());
        assert_eq!(read_u16(&packet, 20), server.port());
        assert_eq!(read_u16(&packet, 22), client.port());
        let updated = read_u16(&packet, 10);
        write_u16(&mut packet, 10, 0);
        assert_eq!(updated, checksum(&packet[..20]));
    }

    /// A downlink packet whose NAT port is unknown must be dropped rather
    /// than forwarded with a bogus tuple.
    #[test]
    fn downlink_tcp_v4_without_a_mapping_is_dropped() {
        let tun_address = Ipv4Addr::new(198, 18, 0, 1);
        let nat_address = Ipv4Addr::new(198, 18, 0, 2);
        let listener_port = 40000;
        let nat = TcpNat::new();

        let mut packet = BytesMut::zeroed(40);
        packet[0] = 0x45;
        write_u16(&mut packet, 2, 40);
        packet[9] = 6;
        packet[12..16].copy_from_slice(&tun_address.octets());
        packet[16..20].copy_from_slice(&nat_address.octets());
        write_u16(&mut packet, 20, listener_port);
        write_u16(&mut packet, 22, 55555); // never allocated
        packet[32] = 0x50;

        let view = parse_ipv4(&packet).unwrap();
        assert!(
            process_tcp_v4(
                &mut packet,
                view,
                &nat,
                tun_address,
                nat_address,
                listener_port,
            )
            .is_none()
        );
    }

    #[test]
    fn cleanup_keeps_an_entry_refreshed_after_the_scan() {
        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                34567,
            )),
            destination: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )),
        };
        let port = nat.lookup_or_insert(key).unwrap();
        // Simulates cleanup having already decided the port was expired,
        // with a packet for the same flow arriving before the removal.
        nat.lookup_or_insert(key).unwrap();
        nat.remove_if_still_expired(port, Duration::from_secs(30));
        assert!(
            nat.lookup_back(port).is_some(),
            "a refreshed mapping must survive cleanup"
        );
    }

    #[test]
    fn icmpv6_echo_for_tun_address_is_replied_in_place() {
        let source = "2001:db8::9".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:2::2".parse::<Ipv6Addr>().unwrap();
        let mut packet = [0u8; 48];
        packet[0] = 0x60;
        write_u16(&mut packet, 4, 8);
        packet[6] = 58;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40] = 128;
        let checksum = checksum_ipv6_transport(&packet, 40, 58);
        write_u16(&mut packet, 42, checksum);
        let view = parse_ipv6(&packet).unwrap();
        assert!(make_icmpv6_echo_reply(&mut packet, view, destination));
        assert_eq!(packet[40], 129);
        assert_eq!(&packet[8..24], &destination.octets());
        assert_eq!(&packet[24..40], &source.octets());
    }

    #[test]
    fn nat_address_derivation_validates_the_prefix() {
        assert_eq!(
            ipv4_nat_address("198.18.0.1/24".parse().unwrap()).unwrap(),
            Ipv4Addr::new(198, 18, 0, 2)
        );
        // /32 leaves no room for the adjacent NAT address
        assert!(ipv4_nat_address("198.18.0.1/32".parse().unwrap()).is_err());
        // gateway at the end of the prefix: NAT address would be broadcast
        assert!(ipv4_nat_address("198.18.0.254/24".parse().unwrap()).is_err());
        assert_eq!(
            ipv6_adjacent_address("2001:fac::1".parse().unwrap(), 64).unwrap(),
            "2001:fac::2".parse::<Ipv6Addr>().unwrap()
        );
        assert!(ipv6_adjacent_address("2001:fac::1".parse().unwrap(), 128).is_err());
    }
}
