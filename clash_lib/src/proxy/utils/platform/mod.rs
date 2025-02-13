#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(target_vendor = "apple")]
pub(crate) use apple::must_bind_socket_on_interface;
#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "freebsd"
))]
pub(crate) mod unix;
#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "freebsd"
))]
pub(crate) use unix::must_bind_socket_on_interface;
#[cfg(windows)]
pub(crate) mod win;
#[cfg(windows)]
pub(crate) use win::must_bind_socket_on_interface;
