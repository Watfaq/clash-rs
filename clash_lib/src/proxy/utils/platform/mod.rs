#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
mod unix;
#[cfg(windows)]
pub(crate) mod win;
#[cfg(windows)]
pub(crate) use win::must_bind_socket_on_interface;
