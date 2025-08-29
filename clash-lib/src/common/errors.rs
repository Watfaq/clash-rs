use std::io;

pub fn new_io_error<T>(msg: T) -> io::Error
where
    T: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::other(msg.into())
}

pub fn map_io_error<T>(err: T) -> io::Error
where
    T: Into<anyhow::Error> + Send,
{
    io::Error::other(format!("{:?}", anyhow::anyhow!(err)))
}

#[macro_export]
macro_rules! print_and_exit {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        std::process::exit(1);
    }};
}

pub trait IntoIoResultExt<T> {
    fn into_io(self) -> std::io::Result<T>;
}
impl<T: Send + Sync> IntoIoResultExt<T> for anyhow::Result<T> {
    fn into_io(self) -> std::io::Result<T> {
        match self {
            Ok(v) => Ok(v),
            Err(v) => Err(std::io::Error::other(v)),
        }
    }
}
