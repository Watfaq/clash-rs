use std::io;

use crate::app::net::OutboundInterface;

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux",))]
    {
        if iface.index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OutboundInterface index is 0, cannot bind to interface",
            ));
        }
        match family {
            socket2::Domain::IPV4 => {
                socket.bind_device_by_index_v4(Some(iface.index))?
            }
            socket2::Domain::IPV6 => {
                socket.bind_device_by_index_v6(Some(iface.index))?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported address family",
                ));
            }
        }
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    )))]
    {
        use crate::common::errors::new_io_error;
        Err(new_io_error(format!(
            "unsupported platform: {}",
            iface.name
        )))
    }
}
