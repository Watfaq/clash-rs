/// from https://github.com/Qv2ray/v2ray-rust/tree/dev/src/proxy/tls

#[cfg(target_os = "macos")]
mod macos;
mod stream;
#[cfg(all(unix, not(target_os = "macos")))]
mod unix;
#[cfg(windows)]
mod windows;
// todo: provide Mozilla's root certs as optional

pub use stream::TlsStreamBuilder;
