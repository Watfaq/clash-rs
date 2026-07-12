#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
mod linux;
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub use linux::bind_device;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::bind_device;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::bind_device;

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
)))]
mod fallback;
#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
)))]
pub use fallback::bind_device;

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};

    #[test]
    fn test_bind_device_nonexistent() {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let res = bind_device(&socket, "nonexistent_device_name_123");

        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
        ))]
        {
            assert!(res.is_err());
            let err = res.unwrap_err();
            assert!(
                err.kind() == std::io::ErrorKind::NotFound
                    || err.kind() == std::io::ErrorKind::InvalidInput
                    || err.kind() == std::io::ErrorKind::PermissionDenied
                    || err.raw_os_error().is_some()
            );
        }

        #[cfg(not(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
        )))]
        {
            assert!(res.is_ok());
        }
    }
}
