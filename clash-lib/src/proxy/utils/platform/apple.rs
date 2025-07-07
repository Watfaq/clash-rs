use std::{io, net::SocketAddr};

use tracing::warn;

use crate::{app::net::Interface, common::errors::new_io_error};

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &Interface,
    family: socket2::Domain,
) -> io::Result<()> {
    match iface {
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(*ip, 0).into()),
        Interface::Name(name) => {
            let index =
                unsafe { libc::if_nametoindex(name.as_str().as_ptr() as *const _) };
            if index == 0 {
                warn!("failed to get interface index: {}", name);
                return Err(new_io_error(format!(
                    "failed to get interface index: {}",
                    name
                )));
            }
            match family {
                socket2::Domain::IPV4 => {
                    socket.bind_device_by_index_v4(std::num::NonZeroU32::new(index))
                }
                socket2::Domain::IPV6 => {
                    socket.bind_device_by_index_v6(std::num::NonZeroU32::new(index))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported socket family",
                )),
            }
        }
    }
}
