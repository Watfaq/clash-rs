use socket2::Socket;
use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;

pub fn bind_device(socket: &Socket, device_name: &str) -> io::Result<()> {
    let c_device_name =
        CString::new(device_name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let index = unsafe { libc::if_nametoindex(c_device_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }

    let is_ipv6 = socket
        .local_addr()
        .map(|addr| addr.is_ipv6())
        .unwrap_or(false);
    let (level, optname) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };

    let res = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            &index as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };

    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
