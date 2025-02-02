use std::{io, net::SocketAddr};
use crate::proxy::utils::Interface;

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &Interface,
    _family: socket2::Domain,
) -> io::Result<()> {
    match iface {
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(*ip, 0).into()),
        Interface::Name(_name) => 
            Err(io::Error::new(io::ErrorKind::Other, "Binding to interface by name is not supported on FreeBSD")),
    }
}