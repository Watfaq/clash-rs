use std::{io, os::windows::io::AsRawSocket};
use tracing::{debug, error, warn};
use windows::Win32::{
    Foundation::GetLastError,
    Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, setsockopt,
    },
};

use crate::{app::net::OutboundInterface, common::errors::new_io_error};

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    debug!("binding socket to interface: {iface:?}, family {family:?}",);

    let handle = SOCKET(socket.as_raw_socket().try_into().unwrap());

    let idx = iface.index;

    match match family {
        socket2::Domain::IPV4 => unsafe {
            Ok(setsockopt(
                handle,
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
                // a 4-byte IPv4 address in network byte order
                Some(idx.to_be_bytes().as_ref()),
            ))
        },
        socket2::Domain::IPV6 => unsafe {
            Ok(setsockopt(
                handle,
                IPPROTO_IPV6.0,
                IPV6_UNICAST_IF,
                // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
                // 4-byte interface index of the desired outgoing interface in host
                // byte order
                // OMG Windows!
                Some(idx.to_ne_bytes().as_ref()),
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
                error!("bind socket to interface failed: {}, errno: {}", err, errno);
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
