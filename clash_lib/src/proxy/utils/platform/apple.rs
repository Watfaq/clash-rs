fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &Interface,
    family: socket2::Domain,
) -> io::Result<()> {
    match iface {
        // TODO: should this be ever used vs. calling .bind(2) from the caller
        // side?
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(*ip, 0).into()),
        Interface::Name(name) | Interface::NameAndIndex(name, _) => socket
            .bind_device_by_index_v4(std::num::NonZeroU32::new(unsafe {
                libc::if_nametoindex(name.as_str().as_ptr() as *const _)
            })),
    }
}
