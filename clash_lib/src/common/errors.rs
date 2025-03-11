use std::io;
// TODO remove this module

pub fn new_io_error<T>(msg: T) -> io::Error
where
    T: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, msg.into())
}


pub fn map_io_error<T>(err: T) -> io::Error
where
    T: Into<watfaq_error::Error> + Send,
{
    io::Error::other(anyhow!(err))

}

