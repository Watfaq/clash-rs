use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    ops::Deref,
    sync::atomic::{AtomicBool, AtomicU64},
};

use arc_swap::ArcSwapOption;
use socket2::{SockAddr, SockRef};
use watfaq_error::Result;
use watfaq_types::{Iface, Network, Stack};

use crate::{AbstractProtector, platform};

#[allow(dead_code)]
#[derive(Debug)]
pub struct BindProtector {
    iface: ArcSwapOption<Iface>,
    enable_fwmark: AtomicBool,
    fwmark: AtomicU64,
}

impl BindProtector {
    pub fn new(iface: ArcSwapOption<Iface>, fwmark: Option<u64>) -> Self {
        Self {
            iface,
            enable_fwmark: AtomicBool::new(fwmark.is_some()),
            fwmark: AtomicU64::new(fwmark.unwrap_or_default()),
        }
    }
}

impl AbstractProtector for BindProtector {
    #[inline(always)]
    fn protect(&self, socket: SockRef, stack: Stack, _proto: Network) -> Result<()> {
        match self.iface.load().as_deref() {
            Some(iface) => {
                platform::bind_iface(socket.deref(), iface, stack)?;
            }
            // If interface is not specified, just bind to UNSPECIFIED.
            // Let system itself determine which interface to use.
            None => match stack {
                Stack::V4 => socket.bind(&SockAddr::from(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    0,
                )))?,
                Stack::V6 => socket.bind(&SockAddr::from(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    0,
                    0,
                    0,
                )))?,
            },
        }
        #[cfg(target_os = "linux")]
        if self.enable_fwmark.load(Ordering::Relaxed) {
            let mark = self.fwmark.load(Ordering::Relaxed);
            socket.set_mark(mark)?;
        }
        Ok(())
    }
}
