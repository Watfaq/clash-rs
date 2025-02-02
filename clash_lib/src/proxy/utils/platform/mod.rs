#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(target_vendor = "apple")]
pub(crate) use apple::must_bind_socket_on_interface;
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(crate) mod linux;
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(crate) use linux::must_bind_socket_on_interface;
#[cfg(target_os = "freebsd")]
pub(crate) mod freebsd;
#[cfg(target_os = "freebsd")]
pub(crate) use freebsd::must_bind_socket_on_interface;
#[cfg(windows)]
pub(crate) mod win;
#[cfg(windows)]
pub(crate) use win::must_bind_socket_on_interface;
