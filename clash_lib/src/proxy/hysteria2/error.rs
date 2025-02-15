use snafu::{Location, Snafu};
use stack_error_macro::stack_trace_debug;

#[derive(Snafu)]
#[snafu(visibility(pub))]
#[stack_trace_debug]
pub enum Error {
    #[snafu(display("Failed to call Dns"))]
    Dns {
        #[snafu(implicit)]
        location: Location,
        source: crate::error::DnsError,
    },
    #[snafu(display("empty dns"))]
    DsnEmpty {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to call Io"))]
    Io {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: std::io::Error,
    },
    #[snafu(display("Failed to call Quinn"))]
    QuinnConnect {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: quinn::ConnectError,
    },
    #[snafu(display("Failed to call Quinn"))]
    QuinnConnection {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: quinn::ConnectionError,
    },
    #[snafu(display("Failed to call H3"))]
    H3 {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: h3::Error,
    },
    #[snafu(display("Failed to call Auth, status code: {status}"))]
    Auth { status: u16 },
    #[snafu(display("Failed to call Auth, msg: {msg}"))]
    AuthOther { msg: String },
    #[snafu(display("Failed to call to_str"))]
    ToStr {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: http::header::ToStrError,
    },
    #[snafu(display("Failed to call ParseInt"))]
    ParseInt {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: std::num::ParseIntError,
    },
    #[snafu(display("Failed to call ParseInt"))]
    ParseBool {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: core::str::ParseBoolError,
    },
}
