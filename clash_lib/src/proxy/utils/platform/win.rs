use ipnet::IpNet;
use network_interface::NetworkInterfaceConfig;
use std::{
    f32::INFINITY,
    io,
    net::SocketAddr,
    os::windows::{io::AsRawSocket, raw::HANDLE},
    ptr::null_mut,
};
use tracing::{error, info, trace, warn};
use windows::Win32::{
    Foundation::{GetLastError, ERROR_SUCCESS},
    NetworkManagement::Rras::{
        RtmAddNextHop, RtmAddRouteToDest, RtmRegisterEntity, RtmReleaseNextHops,
        RTM_ENTITY_INFO, RTM_NET_ADDRESS, RTM_NEXTHOP_INFO, RTM_REGN_PROFILE,
        RTM_ROUTE_CHANGE_NEW, RTM_ROUTE_INFO, RTM_VIEW_MASK_MCAST,
        RTM_VIEW_MASK_UCAST,
    },
    Networking::WinSock::{
        setsockopt, AF_INET, AF_INET6, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF,
        PROTO_IP_RIP, SOCKET,
    },
};

use crate::{
    common::errors::new_io_error,
    proxy::{utils::OutboundInterface, Interface},
};

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &Interface,
    family: socket2::Domain,
) -> io::Result<()> {
    match iface {
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(*ip, 0).into()),
        Interface::Name(name) => {
            // TODO: we should avoid calling `show` multiple times
            let idx = network_interface::NetworkInterface::show()
                .map_err(|x| new_io_error(x.to_string().as_str()))?
                .into_iter()
                .find_map(|iface| {
                    if &iface.name == name {
                        Some(iface.index)
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            if idx == 0 {
                warn!("failed to get interface index for {}", name);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to get interface index for {}", name),
                ));
            }

            trace!("interface {} index is {}", name, idx);

            let handle = SOCKET(socket.as_raw_socket().try_into().unwrap());

            match match family {
                socket2::Domain::IPV4 => unsafe {
                    Ok(setsockopt(
                        handle,
                        IPPROTO_IP.0,
                        IP_UNICAST_IF,
                        Some(idx.to_be_bytes().as_ref()),
                    ))
                },
                socket2::Domain::IPV6 => unsafe {
                    Ok(setsockopt(
                        handle,
                        IPPROTO_IPV6.0,
                        IP_UNICAST_IF,
                        Some(idx.to_be_bytes().as_ref()),
                    ))
                },
                _ => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unsupported socket family",
                )),
            } {
                Ok(errno) => {
                    if errno != 0 {
                        let err = unsafe { GetLastError().to_hresult().message() };
                        error!("bind socket to interface failed: {}", err);
                        return Err(new_io_error(err));
                    }
                    Ok(())
                }
                Err(e) => {
                    warn!("failed to bind socket to interface: {}", e);
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to bind socket to interface: {}", e),
                    ))
                }
            }
        }
    }
}
