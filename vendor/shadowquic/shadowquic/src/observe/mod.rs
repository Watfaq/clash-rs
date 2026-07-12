#[cfg(all(feature = "statistics", target_has_atomic = "64"))]
mod imple;
#[cfg(not(all(feature = "statistics", target_has_atomic = "64")))]
mod unimpl;

#[cfg(all(feature = "statistics", target_has_atomic = "64"))]
pub use self::imple::*;
#[cfg(not(all(feature = "statistics", target_has_atomic = "64")))]
pub use self::unimpl::*;
