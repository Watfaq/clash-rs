use std::io;

use crate::app::net::OutboundInterface;

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux",))]
    {
        use std::num::NonZeroU32;

        let index = NonZeroU32::new(iface.index).ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index cannot be zero",
        ))?;
        match family {
            socket2::Domain::IPV4 => socket.bind_device_by_index_v4(Some(index)),
            socket2::Domain::IPV6 => socket.bind_device_by_index_v6(Some(index)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported address family",
            )),
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
