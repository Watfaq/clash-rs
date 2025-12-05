use anyhow::{Context, Result, anyhow, bail};
use byteorder::{BigEndian, ReadBytesExt};
use ipnet::IpNet;
use std::{
    io::{BufReader, Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tracing::{debug, error, warn};

use crate::{
    app::remote_content_manager::providers::rule_provider::{
        RuleSetBehavior, cidr_trie::CidrTrie, provider::RuleContent,
    },
    common::succinct_set::DomainSet,
};

// MRS Magic bytes for version 1
const MRS_MAGIC_BYTES: [u8; 4] = [b'M', b'R', b'S', 1]; // MRSv1

// MRS Payload Versions
const DOMAIN_SET_VERSION: u8 = 0x01;
const IP_CIDR_SET_VERSION: u8 = 0x01;

// Behavior byte values from spec
const BEHAVIOR_DOMAIN: u8 = 0x00;
const BEHAVIOR_IPCIDR: u8 = 0x01;

// Maximum IP addresses constants
const IPV4_MAX: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);
const IPV6_MAX: Ipv6Addr = Ipv6Addr::new(
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
);

impl RuleSetBehavior {
    /// Convert behavior to byte representation used in MRS format
    pub fn to_mrs_byte(self) -> Option<u8> {
        match self {
            RuleSetBehavior::Domain => Some(BEHAVIOR_DOMAIN),
            RuleSetBehavior::Ipcidr => Some(BEHAVIOR_IPCIDR),
            RuleSetBehavior::Classical => None, // Classical is not supported by MRS
        }
    }

    /// Create behavior from MRS byte representation
    pub fn from_mrs_byte(b: u8) -> Result<Self> {
        match b {
            BEHAVIOR_DOMAIN => Ok(RuleSetBehavior::Domain),
            BEHAVIOR_IPCIDR => Ok(RuleSetBehavior::Ipcidr),
            _ => bail!("Invalid MRS behavior byte: {}", b),
        }
    }
}

/// Parses MRS format rule set according to the v1 specification.
pub fn rules_mrs_parse(
    buf: &[u8],
    expected_behavior: RuleSetBehavior,
) -> Result<RuleContent> {
    // 1. Decompress using Zstandard
    let cursor = Cursor::new(buf);
    let mut reader = BufReader::new(
        zstd::Decoder::new(cursor).context("Failed to create zstd decoder")?,
    );

    // --- Header Parsing ---
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .context("Failed to read MRS magic bytes")?;
    if magic != MRS_MAGIC_BYTES {
        bail!(
            "Invalid MRS magic bytes. Expected {:?} but got {:?}",
            MRS_MAGIC_BYTES,
            magic
        );
    }

    let behavior_byte = reader
        .read_u8()
        .context("Failed to read MRS behavior byte")?;
    let actual_behavior = RuleSetBehavior::from_mrs_byte(behavior_byte)?;

    if actual_behavior != expected_behavior {
        bail!(
            "MRS behavior mismatch: file contains {:?} but expected {:?}",
            actual_behavior,
            expected_behavior
        );
    }

    let count = reader
        .read_i64::<BigEndian>()
        .context("Failed to read MRS rule count")?;
    if count < 0 {
        bail!("Invalid MRS rule count: {}", count);
    }
    debug!("MRS rule count: {}", count);

    let extra_length = reader
        .read_i64::<BigEndian>()
        .context("Failed to read MRS extra length")?;
    if extra_length != 0 {
        bail!(
            "Invalid MRS extra length for v1: expected 0, got {}",
            extra_length
        );
    }

    // --- Payload Parsing ---
    match actual_behavior {
        RuleSetBehavior::Domain => parse_domain_payload(&mut reader),
        RuleSetBehavior::Ipcidr => parse_ipcidr_payload(&mut reader),
        RuleSetBehavior::Classical => {
            bail!("Classical behavior is not supported by MRS format")
        }
    }
}

// --- Domain Payload Parsing ---
fn parse_domain_payload<R: Read>(reader: &mut R) -> Result<RuleContent> {
    let version = reader
        .read_u8()
        .context("Failed to read DomainSet version")?;
    if version != DOMAIN_SET_VERSION {
        bail!(
            "Unsupported DomainSet version: expected {}, got {}",
            DOMAIN_SET_VERSION,
            version
        );
    }

    let leaves_len = read_u64_length(reader, "Leaves")?;
    let leaves = read_u64_vec(reader, leaves_len, "Leaves")?;

    let label_bitmap_len = read_u64_length(reader, "LabelBitmap")?;
    let label_bitmap = read_u64_vec(reader, label_bitmap_len, "LabelBitmap")?;

    let labels_len = read_u64_length(reader, "Labels")?;
    let labels = read_byte_vec(reader, labels_len, "Labels")?;

    let domain_set = DomainSet::from_mrs_parts(leaves, label_bitmap, labels);
    Ok(RuleContent::Domain(domain_set))
}

// --- IPCIDR Payload Parsing ---
fn parse_ipcidr_payload<R: Read>(reader: &mut R) -> Result<RuleContent> {
    let version = reader
        .read_u8()
        .context("Failed to read IpCidrSet version")?;
    if version != IP_CIDR_SET_VERSION {
        bail!(
            "Unsupported IpCidrSet version: expected {}, got {}",
            IP_CIDR_SET_VERSION,
            version
        );
    }

    let ranges_len = read_u64_length(reader, "Ranges")?;
    debug!("Expecting {} IP ranges", ranges_len);

    let mut cidr_trie = CidrTrie::new();

    for i in 0..ranges_len {
        let mut range_buf = [0u8; 32];
        reader
            .read_exact(&mut range_buf)
            .with_context(|| format!("Failed to read IP range #{i}"))?;

        let from_ip_bytes: [u8; 16] = range_buf[0..16].try_into().unwrap();
        let to_ip_bytes: [u8; 16] = range_buf[16..32].try_into().unwrap();
        let from_ip = IpAddr::from(from_ip_bytes);
        let to_ip = IpAddr::from(to_ip_bytes);

        // Convert the range to CIDRs
        match range_to_cidrs(from_ip, to_ip) {
            Ok(cidrs) => {
                for cidr in cidrs {
                    // CidrTrie::insert expects a &str
                    if !cidr_trie.insert(&cidr.to_string()) {
                        // Log potentially invalid CIDR strings if insert fails
                        warn!(
                            "Failed to insert CIDR {} derived from range {} - {} \
                             into CidrTrie",
                            cidr, from_ip, to_ip
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to convert range {} - {} to CIDRs for range #{}: {}",
                    from_ip, to_ip, i, e
                );
                // Decide whether to continue or bail out
                // continue; // Skip this range
                return Err(e).context(format!("Error processing IP range #{i}")); // Bail out
            }
        }
    }

    debug!(
        "Successfully parsed and inserted CIDRs from {} ranges.",
        ranges_len
    );
    Ok(RuleContent::Ipcidr(Box::new(cidr_trie)))
}

// --- Helper Functions for Reading Data ---
fn read_u64_length<R: Read>(reader: &mut R, field_name: &str) -> Result<usize> {
    let len = reader
        .read_i64::<BigEndian>()
        .with_context(|| format!("Failed to read MRS {field_name} length"))?;
    if len < 0 {
        bail!("Invalid negative length for {}: {}", field_name, len);
    }
    Ok(len as usize)
}

fn read_u64_vec<R: Read>(
    reader: &mut R,
    count: usize,
    field_name: &str,
) -> Result<Vec<u64>> {
    let mut vec = Vec::with_capacity(count);
    for i in 0..count {
        let val = reader.read_u64::<BigEndian>().with_context(|| {
            format!("Failed to read {field_name} data element #{i}")
        })?;
        vec.push(val);
    }
    Ok(vec)
}

fn read_byte_vec<R: Read>(
    reader: &mut R,
    len: usize,
    field_name: &str,
) -> Result<Vec<u8>> {
    const MAX_BYTE_VEC_LEN: usize = 512 * 1024 * 1024; // 512 MiB limit
    if len > MAX_BYTE_VEC_LEN {
        bail!(
            "{} data length ({}) exceeds maximum allowed size ({})",
            field_name,
            len,
            MAX_BYTE_VEC_LEN
        );
    }
    let mut vec = vec![0u8; len];
    reader.read_exact(&mut vec).with_context(|| {
        format!("Failed to read {field_name} data ({len} bytes)")
    })?;
    Ok(vec)
}

// --- Range to CIDR Conversion Logic ---

/// Returns the maximum prefix length for an IP address type.
fn max_prefix_len(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Calculates the next IP address. Returns None if the input is the maximum IP.
fn ip_addr_succ(ip: IpAddr) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(v4) => {
            let int_val = u32::from(v4);
            if int_val == u32::MAX {
                None
            } else {
                Some(IpAddr::V4(Ipv4Addr::from(int_val + 1)))
            }
        }
        IpAddr::V6(v6) => {
            let int_val = u128::from(v6);
            if int_val == u128::MAX {
                None
            } else {
                Some(IpAddr::V6(Ipv6Addr::from(int_val + 1)))
            }
        }
    }
}

/// Converts an inclusive IP address range [start, end] into a minimal list of
/// CIDR prefixes using an optimized algorithm.
fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Result<Vec<IpNet>> {
    if start > end {
        return Ok(Vec::new()); // Empty range
    }

    // Normalize IPv4-mapped IPv6 addresses
    let normalize = |ip: IpAddr| -> IpAddr {
        match ip {
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    IpAddr::V4(v4)
                } else {
                    IpAddr::V6(v6)
                }
            }
            v4 => v4,
        }
    };

    let start = normalize(start);
    let end = normalize(end);

    // Ensure start and end are the same address family
    if start.is_ipv4() != end.is_ipv4() {
        bail!("Start and end IP addresses must be of the same family");
    }

    match (start, end) {
        (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
            range_to_cidrs_v4(start_v4, end_v4)
        }
        (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
            range_to_cidrs_v6(start_v6, end_v6)
        }
        _ => unreachable!("Already checked address family"),
    }
}

fn range_to_cidrs_v4(start: Ipv4Addr, end: Ipv4Addr) -> Result<Vec<IpNet>> {
    let mut result = Vec::new();
    let mut current = u32::from(start);
    let end_u32 = u32::from(end);

    while current <= end_u32 {
        // Find the maximum prefix length for a CIDR starting at current
        // that fits within the range

        // 1. Find the number of trailing zeros in current (alignment)
        let max_size_by_alignment = if current == 0 {
            32
        } else {
            current.trailing_zeros()
        };

        // 2. Find the maximum block size that fits in the remaining range
        let remaining = end_u32 - current + 1;
        let max_size_by_range = 32 - remaining.leading_zeros();

        // 3. Take the minimum of the two
        let prefix_len = 32 - max_size_by_alignment.min(max_size_by_range - 1);

        let cidr =
            IpNet::new(IpAddr::V4(Ipv4Addr::from(current)), prefix_len as u8)?;
        result.push(cidr);

        // Move to next block
        let block_size = 1u32 << (32 - prefix_len);
        if current > u32::MAX - block_size {
            break; // Would overflow
        }
        current += block_size;
    }

    Ok(result)
}

fn range_to_cidrs_v6(start: Ipv6Addr, end: Ipv6Addr) -> Result<Vec<IpNet>> {
    let mut result = Vec::new();
    let mut current = u128::from(start);
    let end_u128 = u128::from(end);

    while current <= end_u128 {
        // Find the maximum prefix length for a CIDR starting at current
        // that fits within the range

        // 1. Find the number of trailing zeros in current (alignment)
        let max_size_by_alignment = if current == 0 {
            128
        } else {
            current.trailing_zeros()
        };

        // 2. Find the maximum block size that fits in the remaining range
        let remaining = end_u128 - current + 1;
        let max_size_by_range = 128 - remaining.leading_zeros();

        // 3. Take the minimum of the two
        let prefix_len = 128 - max_size_by_alignment.min(max_size_by_range - 1);

        let cidr =
            IpNet::new(IpAddr::V6(Ipv6Addr::from(current)), prefix_len as u8)?;
        result.push(cidr);

        // Move to next block
        let block_size = 1u128 << (128 - prefix_len);
        if current > u128::MAX - block_size {
            break; // Would overflow
        }
        current += block_size;
    }

    Ok(result)
}
