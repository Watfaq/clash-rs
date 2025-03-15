#[cfg(windows)]
pub(crate) mod win;
#[cfg(windows)]
pub(crate) use win::bind_iface;

#[cfg(not(windows))]
pub fn bind_iface(
    socket: &socket2::Socket,
    iface: &Iface,
    stack: Stack,
) -> anyhow::Result<()> {
    todo!()
}
