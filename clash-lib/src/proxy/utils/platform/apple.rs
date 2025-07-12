use std::io;

use tracing::warn;

use crate::app::net::OutboundInterface;

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    let index = iface.index;
    if index == 0 {
        warn!(
            "OutboundInterface index is 0, skipping binding to interface {}",
            iface.name
        );
        return Ok(());
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
