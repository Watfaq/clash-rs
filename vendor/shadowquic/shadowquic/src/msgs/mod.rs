use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::SError;

#[cfg(test)]
mod socks5_addr_test;

pub mod socks5;
pub mod squic;
/// SEncode is a asyc trait for encoding. It can be automatically derived for struct by the SEncode macro
/// as long as fields are SEncode.
/// For enum, the macro will encode discriminant as u8/u16... defined by `#[repr(*)]` before encoding the content. So the enum can be decoded by first reading a u8/u16...  
/// and then decoding the content based on the value of disriminant.
/// For enum, at most one field is supported.
/// named field is not supported for enum for SDecode macro.
/// `#[repr(*)]` is required for enum to specify the type of discriminant.
#[async_trait::async_trait]
pub trait SEncode {
    async fn encode<T: AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError>;
}

/// A async decoding trait. It can be automatically derived for struct by the SDecode macro as long as fields are SDecode.
/// For enum, the macro will first read a u8/u16... defined by `#[repr(*)]` as discriminant and then decode the content based on the value of disriminant.
/// At most one field is supported for enum. Named field is not supported for enum for SDecode macro.
/// `#[repr(*)]` is required for enum to specify the type of discriminant.
#[async_trait::async_trait]
pub trait SDecode
where
    Self: Sized,
{
    async fn decode<T: AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError>;
}

#[async_trait::async_trait]
impl<S: SEncode + Send + Sync> SEncode for Arc<S> {
    async fn encode<T: AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError> {
        self.as_ref().encode(s).await?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: SDecode> SDecode for Arc<S> {
    async fn decode<T: AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError> {
        let data = S::decode(s).await?;
        Ok(Arc::new(data))
    }
}
#[async_trait::async_trait]
impl<const N: usize> SEncode for [u8; N] {
    async fn encode<T: AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError> {
        s.write_all(self).await?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl<const N: usize> SDecode for [u8; N] {
    async fn decode<T: AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError> {
        let mut data = [0u8; N];
        s.read_exact(&mut data).await?;
        Ok(data)
    }
}

#[async_trait::async_trait]
impl<T: SEncode + Send + Sync, E: SEncode + Send + Sync> SEncode for Result<T, E> {
    async fn encode<W: AsyncWrite + Unpin + Send>(&self, s: &mut W) -> Result<(), SError> {
        match self {
            Ok(val) => {
                0u8.encode(s).await?;
                val.encode(s).await?;
            }
            Err(val) => {
                1u8.encode(s).await?;
                val.encode(s).await?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<T: SDecode, E: SDecode> SDecode for Result<T, E> {
    async fn decode<R: AsyncRead + Unpin + Send>(s: &mut R) -> Result<Self, SError> {
        let tag = u8::decode(s).await?;
        match tag {
            0 => {
                let val = T::decode(s).await?;
                Ok(Ok(val))
            }
            1 => {
                let val = E::decode(s).await?;
                Ok(Err(val))
            }
            _ => Err(SError::ProtocolViolation),
        }
    }
}

#[async_trait::async_trait]
impl SEncode for () {
    async fn encode<T: AsyncWrite + Unpin + Send>(&self, _s: &mut T) -> Result<(), SError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl SDecode for () {
    async fn decode<T: AsyncRead + Unpin + Send>(_s: &mut T) -> Result<Self, SError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl<E: SEncode + Send + Sync> SEncode for Vec<E> {
    async fn encode<T: AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError> {
        let len = self.len() as u32;
        len.encode(s).await?;
        for item in self {
            item.encode(s).await?;
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl<E: SDecode + Send + Sync> SDecode for Vec<E> {
    async fn decode<T: AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError> {
        let len = u32::decode(s).await?;
        let mut data = Vec::with_capacity(len as usize);
        for _ in 0..len {
            data.push(E::decode(s).await?);
        }
        Ok(data)
    }
}
#[async_trait::async_trait]
impl SEncode for String {
    async fn encode<T: AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError> {
        self.as_bytes().to_vec().encode(s).await
    }
}
#[async_trait::async_trait]
impl SDecode for String {
    async fn decode<T: AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError> {
        let data = Vec::<u8>::decode(s).await?;
        Ok(String::from_utf8(data).map_err(|_| SError::ProtocolViolation)?)
    }
}
