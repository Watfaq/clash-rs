mod enhanced;

#[cfg(target_os = "linux")]
#[path = "system_linux.rs"]
mod system;
#[cfg(not(target_os = "linux"))]
#[path = "system_non_linux.rs"]
mod system;

pub use enhanced::Resolver;
pub use system::SystemResolver;
