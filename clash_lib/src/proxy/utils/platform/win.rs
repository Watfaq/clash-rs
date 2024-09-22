use network_interface::NetworkInterfaceConfig;
use std::{io, net::SocketAddr, os::windows::io::AsRawSocket};
use tracing::{debug, error, warn};
use windows::Win32::{
    Foundation::GetLastError,
    Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF, SOCKET,
    },
};

use crate::{common::errors::new_io_error, proxy::utils::Interface};

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &Interface,
    family: socket2::Domain,
) -> io::Result<()> {
    match iface {
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(*ip, 0).into()),
        Interface::Name(name) => {
            // TODO: we should avoid calling `show` multiple times
            let iface = network_interface::NetworkInterface::show()
                .map_err(|x| new_io_error(x.to_string().as_str()))?
                .into_iter()
                .find_map(|iface| {
                    if &iface.name == name {
                        Some(iface)
                    } else {
                        None
                    }
                });

            let idx = iface.as_ref().map(|iface| iface.index).unwrap_or_default();
            if idx == 0 {
                warn!("failed to get interface index for {}", name);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to get interface index for {}", name),
                ));
            }

            let ip = match iface {
                Some(iface) => iface.addr.iter().find_map(|addr| {
                    if family == socket2::Domain::IPV4 {
                        if addr.ip().is_ipv4() {
                            Some(addr.ip())
                        } else {
                            None
                        }
                    } else {
                        if addr.ip().is_ipv6() {
                            Some(addr.ip())
                        } else {
                            None
                        }
                    }
                }),
                None => None,
            };

            debug!(
                "binding socket to interface: {}, index {}, ip {:?}",
                name, idx, ip
            );

            if let Some(ip) = ip {
                socket.bind(&SocketAddr::new(ip, 0).into())?;
            } else {
                warn!("failed to get address for interface {}", name);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to get address for interface {}", name),
                ));
            }

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
