use crate::session::SocksAddr;
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    /// Original inbound destination (fake-IP or real IP from the client).
    /// This field is **never overwritten** after inbound parsing; it always
    /// reflects what the client sent.
    pub dst_addr: SocksAddr,
    /// Domain resolved from `dst_addr` via reverse-lookup (fake-IP → domain,
    /// or cache hit). Always a `SocksAddr::Domain` when set. Set by the
    /// dispatcher; `None` when the destination is a plain IP with no
    /// associated domain. Used for rule matching and as the address written
    /// into proxy-protocol headers instead of the fake-IP.
    ///
    /// **Invariant**: if `dst_addr` is a fake-IP, this field **must** be
    /// `Some`; sending a fake-IP without a domain is a dispatcher bug.
    pub dst_domain: Option<SocksAddr>,
    /// Authenticated user name from SS2022 EIH, propagated to the dispatcher
    /// session for per-user traffic attribution. `None` for all other
    /// protocols.
    pub inbound_user: Option<String>,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
            dst_domain: None,
            inbound_user: None,
        }
    }
}

impl Debug for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish()
    }
}

impl Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP Packet from {} to {} with {} bytes",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
            dst_domain: None,
            inbound_user: None,
        }
    }

    /// Returns the logical destination for outbound use: the resolved domain
    /// if one was set (i.e. `dst_domain`), otherwise `dst_addr`.
    ///
    /// **All proxy outbound implementations must use this for protocol
    /// headers** (Trojan ATYP, Shadowsocks SOCKS address, VMess target,
    /// etc.) so that the remote proxy server sees the intended domain name
    /// rather than a fake-IP.
    ///
    /// **Response `src_addr` contract**: when a proxy outbound yields a
    /// response `UdpPacket` it **must** set `src_addr` to `logical_dst()` of
    /// the corresponding outgoing packet (i.e. `sess.destination`).  The
    /// dispatcher relies on this invariant to map responses back to the
    /// original fake-IP or client-visible address via its
    /// `logical_dst → dst_addr` table.
    ///
    /// Some proxy protocols (e.g. Trojan, VMess) echo the destination address
    /// from the request header back as the response source, satisfying this
    /// automatically.  Others (e.g. Shadowsocks) return the **real upstream
    /// IP** parsed from the response — which is not `logical_dst()`.  In that
    /// case the outbound implementation must maintain an
    /// `ip_to_logical: HashMap<SocketAddr, SocksAddr>` (keyed on the resolved
    /// real IP, valued with `logical_dst()` of the outgoing packet) and
    /// translate `src_addr` in `poll_next` before returning — exactly as
    /// `OutboundDatagramImpl` (direct outbound,
    /// `proxy/direct/datagram.rs`) does.
    pub fn logical_dst(&self) -> SocksAddr {
        self.dst_domain
            .clone()
            .unwrap_or_else(|| self.dst_addr.clone())
    }
}
