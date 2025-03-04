use std::ops::Deref;

use arc_swap::ArcSwap;

use watfaq_socket::Protector;
use watfaq_types::{Iface, StackPrefer};

pub struct Context {
    /// Whether current system have
    /// Respect user configuration
    /// Linux: `cat /proc/sys/net/ipv6/conf/all/disable_ipv6`
    /// Windows: `Get-NetAdapterBinding -ComponentID ms_tcpip6`
    /// MacOS/FreeBSD `sysctl net.inet6.ip6.disable_ipv6`
    /// Other: ping a local v6 address such as `::1`
    /// This option affects the creation of local socket
    pub system_ipv6_cap: bool,
    /// Affects:
    ///    1. proxy server's dns name resultion
    ///    2. creation of local socket
    ///    3. proxied application's dns name resultion
    pub stack_prefer: StackPrefer,
    pub default_iface: ArcSwap<Iface>,
    pub protector: Protector,
}
