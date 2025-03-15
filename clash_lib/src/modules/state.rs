use arc_swap::ArcSwap;

use super::{
    socket::Protector,
    types::{Iface, StackPrefer},
};

#[derive(Debug)]
pub struct Context {
    /// Whether current system have IPv6 Cap
    /// Linux: `cat /proc/sys/net/ipv6/conf/all/disable_ipv6`
    /// Windows: `Get-NetAdapterBinding -ComponentID ms_tcpip6`
    /// MacOS/FreeBSD `sysctl net.inet6.ip6.disable_ipv6`
    /// Other: ping a local v6 address such as `::1`
    /// However we should respect user configuration
    /// This option affects the creation of local socket
    pub system_ipv6_cap: bool,
    /// Affects:
    ///    1. proxy server's dns name resultion
    ///    2. ? creation of local socket
    ///    3. [when fake-ip disabled] proxied application's dns name resultion
    pub stack_prefer: StackPrefer,
    pub default_iface: ArcSwap<Iface>,
    pub protector: Protector,
    // TODO pub virtual_ipv6: bool,
}
