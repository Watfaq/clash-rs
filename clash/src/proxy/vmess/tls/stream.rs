use boring::ssl::{SslConnector, SslSignatureAlgorithm};
use boring::ssl::{SslMethod, SslVersion};
use foreign_types_shared::ForeignTypeRef;
use std::io;

use tokio_boring::connect;

use crate::common::errors::new_io_error;
use crate::proxy::AnyStream;

#[cfg(target_os = "macos")]
use super::macos as platform;
#[cfg(all(unix, not(target_os = "macos")))]
use super::unix as platform;
#[cfg(windows)]
use super::windows as platform;

#[derive(Clone)]
pub struct TlsStreamBuilder {
    connector: SslConnector,
    sni: String,
    verify_hostname: bool,
    verify_sni: bool,
}

impl TlsStreamBuilder {
    pub fn new_from_config(
        sni: String,
        cert_file: &Option<String>,
        verify_hostname: bool,
        verify_sni: bool,
    ) -> Self {
        let mut configuration = SslConnector::builder(SslMethod::tls()).unwrap();
        {
            let certs = platform::load_native_certs().unwrap();
            let mut count = 0;
            for cert in certs.into_iter() {
                let err = configuration.cert_store_mut().add_cert(cert);
                if err.is_ok() {
                    count += 1;
                }
            }
        }
        if let Some(cert_file) = cert_file {
            configuration.set_ca_file(cert_file).unwrap();
        }
        configuration
            .set_alpn_protos(b"\x02h2\x08http/1.1")
            .unwrap();
        configuration
            .set_cipher_list("ALL:!aPSK:!ECDSA+SHA1:!3DES")
            .unwrap();
        configuration
            .set_verify_algorithm_prefs(&[
                SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
                SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                SslSignatureAlgorithm::RSA_PKCS1_SHA256,
                SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
                SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                SslSignatureAlgorithm::RSA_PKCS1_SHA384,
                SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
                SslSignatureAlgorithm::RSA_PKCS1_SHA512,
            ])
            .unwrap();
        configuration
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        configuration.enable_signed_cert_timestamps();
        configuration.enable_ocsp_stapling();
        configuration.set_grease_enabled(true);
        unsafe {
            boring_sys::SSL_CTX_add_cert_compression_alg(
                configuration.as_ptr(),
                boring_sys::TLSEXT_cert_compression_brotli as u16,
                None,
                Some(decompress_ssl_cert),
            );
        }
        Self {
            connector: configuration.build(),
            sni,
            verify_hostname,
            verify_sni,
        }
    }

    pub async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let mut configuration = self.connector.configure().unwrap();
        configuration.set_use_server_name_indication(self.verify_sni);
        configuration.set_verify_hostname(self.verify_hostname);
        unsafe {
            boring_sys::SSL_add_application_settings(
                configuration.as_ptr(),
                b"h2".as_ptr(),
                2,
                b"\x00\x03".as_ptr(),
                2,
            );
        }
        let stream = connect(configuration, self.sni.as_str(), stream).await;
        match stream {
            Ok(stream) => Ok(Box::new(stream)),
            Err(e) => {
                let res = e.to_string();
                Err(new_io_error(&res))
            }
        }
    }
}

extern "C" fn decompress_ssl_cert(
    _ssl: *mut boring_sys::SSL,
    out: *mut *mut boring_sys::CRYPTO_BUFFER,
    mut uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> libc::c_int {
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let x: *mut *mut u8 = &mut buf;
        let allocated_buffer = boring_sys::CRYPTO_BUFFER_alloc(x, uncompressed_len);
        if buf.is_null() {
            return 0;
        }
        let uncompressed_len_ptr: *mut usize = &mut uncompressed_len;
        if brotli::ffi::decompressor::CBrotliDecoderDecompress(
            in_len,
            in_,
            uncompressed_len_ptr,
            buf,
        ) as i32
            == 1
        {
            *out = allocated_buffer;
            1
        } else {
            boring_sys::CRYPTO_BUFFER_free(allocated_buffer);
            0
        }
    }
}
