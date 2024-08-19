use std::{io, net::SocketAddr};

use crate::proxy::utils::Interface;

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &Interface,
    family: socket2::Domain,
) -> io::Result<()> {
    match iface {
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(*ip, 0).into()),
        Interface::Name(name) => match family {
            socket2::Domain::IPV4 => {
                socket.bind_device_by_index_v4(std::num::NonZeroU32::new(unsafe {
                    libc::if_nametoindex(name.as_str().as_ptr() as *const _)
                }))
            }
            socket2::Domain::IPV6 => {
                socket.bind_device_by_index_v6(std::num::NonZeroU32::new(unsafe {
                    libc::if_nametoindex(name.as_str().as_ptr() as *const _)
                }))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported socket family",
            )),
        },
    }
}
