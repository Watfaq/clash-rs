use snafu::{Location, Snafu};
use stack_error_macro::stack_trace_debug;

#[derive(Snafu)]
#[snafu(visibility(pub))]
#[stack_trace_debug]
pub enum DnsError {
    #[snafu(display("invalid domain: {domain}"))]
    InvaldDomain {
        domain: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("no record: {host}"))]
    NoRecord {
        host: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("invalid query: {queries:?}"))]
    InvalidQuery {
        queries: Vec<hickory_proto::op::Query>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("dns timeout"))]
    Timeout {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("hickory proto"))]
    Proto {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: hickory_proto::ProtoError,
    },
    #[snafu(display("hickory resolve"))]
    ResolveError {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: hickory_resolver::ResolveError,
    },
    #[snafu(display("unsupported operation"))]
    Unsupported {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("ipv6 disabled"))]
    IPV6Disabled {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("empty dns"))]
    EmptyDns {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("dns timeout"))]
    ClientTimeout {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: tokio::time::error::Elapsed,
    },
    #[snafu(display("io error"))]
    Io {
        #[snafu(implicit)]
        location: Location,
        #[snafu(source)]
        error: std::io::Error,
    },
}

pub type DnsResult<T> = std::result::Result<T, DnsError>;

#[cfg(test)]
mod tests {

    use snafu::{Location, ResultExt, Snafu};
    use stack_error_macro::stack_trace_debug;

    // layer 1
    #[derive(Snafu)]
    #[snafu(visibility(pub))]
    #[stack_trace_debug]
    pub enum RustError {
        #[snafu(display("Failed to call Java"))]
        Rust {
            #[snafu(implicit)]
            location: Location,
            #[snafu(source)]
            source: JavaError,
        },
    }

    // layer 2
    #[derive(Snafu)]
    #[snafu(visibility(pub))]
    #[stack_trace_debug]
    pub enum JavaError {
        #[snafu(display("Failed to call Python"))]
        Python {
            #[snafu(implicit)]
            location: Location,
            #[snafu(source)]
            source: PythonError,
        },
    }

    // layer 3
    #[derive(Snafu)]
    #[snafu(visibility(pub))]
    #[stack_trace_debug]
    pub enum PythonError {
        #[snafu(display("IO Error"))]
        IO {
            #[snafu(implicit)]
            location: Location,
            #[snafu(source)]
            source: std::io::Error,
        },
    }

    fn fn1() -> Result<(), RustError> {
        fn2().context(RustSnafu)
    }

    fn fn2() -> Result<(), JavaError> {
        fn3().context(PythonSnafu)
    }

    fn fn3() -> Result<(), PythonError> {
        let res = Err(std::io::Error::new(std::io::ErrorKind::Other, "error"));
        res.context(IOSnafu)
    }

    #[test]
    fn test_snafu_error() {
        let res = fn1();
        println!("{:?}", res);
    }
}
