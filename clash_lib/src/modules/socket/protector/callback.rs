use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use socket2::{SockAddr, SockRef};

use crate::modules::{
    socket::AbstractProtector,
    types::{Network, Stack},
};

#[allow(dead_code)]
#[derive(Debug)]
// TODO it do nothing for now
pub struct CallbackProtector;

impl AbstractProtector for CallbackProtector {
    fn protect(
        &self,
        socket: SockRef,
        stack: Stack,
        _: Network,
    ) -> anyhow::Result<()> {
        match stack {
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
        }
        Ok(())
    }
}
