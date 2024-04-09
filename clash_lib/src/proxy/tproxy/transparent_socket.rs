use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::{io, mem};

use tokio::net::{TcpListener, TcpSocket, UdpSocket};

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

/// Set IP_TRANSPARENT for use of tproxy.
/// User may need to get root privilege to use it.
fn set_ip_transparent(socket_fd: i32) -> io::Result<i32> {
    let enable: libc::c_int = 1;
    syscall!(setsockopt(
        socket_fd,
        libc::SOL_IP,
        libc::IP_TRANSPARENT,
        &enable as *const _ as *const _,
        mem::size_of_val(&enable) as libc::socklen_t,
    ))
}

fn set_recv_tos(socket_fd: i32) -> io::Result<i32> {
    let enable: libc::c_int = 1;
    syscall!(setsockopt(
        socket_fd,
        libc::IPPROTO_IP,
        libc::IP_RECVTOS,
        &enable as *const _ as *const _,
        mem::size_of_val(&enable) as libc::socklen_t,
    ))
}

fn set_mark(socket_fd: i32, mark: u32) -> io::Result<i32> {
    syscall!(setsockopt(
        socket_fd,
        libc::SOL_SOCKET,
        libc::SO_MARK,
        &mark as *const _ as *const _,
        mem::size_of_val(&mark) as libc::socklen_t,
    ))
}

fn set_recv_origin_dst(socket_fd: i32) -> io::Result<i32> {
    let enable: libc::c_int = 1;
    syscall!(setsockopt(
        socket_fd,
        libc::IPPROTO_IP,
        libc::IP_RECVORIGDSTADDR,
        &enable as *const _ as *const _,
        mem::size_of_val(&enable) as libc::socklen_t,
    ))
}

fn set_reuse(socket_fd: i32) -> io::Result<i32> {
    let enable: libc::c_int = 1;
    syscall!(setsockopt(
        socket_fd,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &enable as *const _ as *const _,
        mem::size_of_val(&enable) as libc::socklen_t,
    ))
}

// only support v4 now
pub fn new_tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    set_ip_transparent(socket.as_raw_fd())?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    Ok(socket.listen(1024)?)
}

// TODO: return a udp transparent listener
pub async fn new_udp_listener(addr: SocketAddr) -> io::Result<unix_udp_sock::UdpSocket> {
    let socket = unix_udp_sock::UdpSocket::bind(addr).await?;
    let fd = socket.as_raw_fd();
    set_ip_transparent(fd)?;
    set_reuse(fd)?;
    set_recv_origin_dst(fd)?;
    // TODO: support tos
    set_recv_tos(fd)?;
    set_mark(fd, 0xff)?;

    Ok(socket)
}
