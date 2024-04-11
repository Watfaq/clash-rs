use std::io;

pub fn new_io_error(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub fn map_io_error<T>(err: T) -> io::Error
where
    T: Into<anyhow::Error> + Send,
{
    io::Error::new(io::ErrorKind::Other, format!("{:?}", anyhow::anyhow!(err)))
}
