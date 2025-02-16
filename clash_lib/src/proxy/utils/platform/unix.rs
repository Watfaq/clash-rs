use std::{io, net::SocketAddr};

use crate::proxy::utils::Interface;

#[allow(dead_code)]
pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &Interface,
    _family: socket2::Domain,
) -> io::Result<()> {
    match iface {
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(*ip, 0).into()),
        Interface::Name(name) => {
            #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux",
            ))]
            {
                socket.bind_device(Some(name.as_bytes()))
            }
            #[cfg(not(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux",
            )))]
            {
                use crate::common::errors::new_io_error;
                Err(new_io_error(format!("unsupported platform: {}", name)))
            }
        }
    }
}
