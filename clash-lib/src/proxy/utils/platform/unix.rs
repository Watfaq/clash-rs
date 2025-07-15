use std::io;

use crate::app::net::OutboundInterface;

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    #[allow(unused)] family: socket2::Domain,
) -> io::Result<()> {
    socket.bind_device(Some(iface.name.as_bytes()))
}
