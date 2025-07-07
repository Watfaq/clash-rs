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
            .with_context(|| format!("Failed to read IP range #{}", i))?;

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
                return Err(e).context(format!("Error processing IP range #{}", i)); // Bail out
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
        .with_context(|| format!("Failed to read MRS {} length", field_name))?;
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
            format!("Failed to read {} data element #{}", field_name, i)
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
        format!("Failed to read {} data ({} bytes)", field_name, len)
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
/// CIDR prefixes.
fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Result<Vec<IpNet>> {
    if start > end {
        return Ok(Vec::new()); // Empty range
    }

    // Ensure start and end are the same address family
    if start.is_ipv4() != end.is_ipv4() {
        bail!("Start and end IP addresses must be of the same family");
    }

    let mut current = start;
    let mut result = Vec::new();

    while current <= end {
        let max_len = max_prefix_len(current);
        let mut best_cidr: Option<IpNet> = None;

        // Iterate prefix lengths downwards (largest block /0 to smallest block
        // /max_len)
        for prefix_len in (0..=max_len).rev() {
            // Iterate downwards for efficiency
            // Attempt to create a network block starting at `current`
            match IpNet::new(current, prefix_len) {
                Ok(candidate_cidr) => {
                    // Check 1: Is `current` the actual start of this block?
                    // Check 2: Does the block end within the desired range `end`?
                    if candidate_cidr.network() == current {
                        let broadcast = candidate_cidr.broadcast(); // No Option needed per ipnet docs
                        if broadcast <= end {
                            // This is the largest valid block starting at `current`
                            // that fits within the range.
                            best_cidr = Some(candidate_cidr);
                            break; // Found the best (largest) block for `current`
                        }
                        // else: This block extends beyond `end`. Continue to
                        // try smaller blocks (larger prefix_len).
                    } else {
                        // `current` is not the start of this network block for this
                        // prefix_len. Since we iterate
                        // downwards, smaller blocks starting at `current` might
                        // still fit. Continue to the next
                        // smaller block size.
                        continue;
                    }
                }
                Err(_) => {
                    // Error creating CIDR (e.g., invalid prefix for address type,
                    // though unlikely here) Continue to the next
                    // smaller block size.
                    continue;
                }
            }
        }

        match best_cidr {
            Some(cidr_to_add) => {
                result.push(cidr_to_add);
                let current_broadcast = cidr_to_add.broadcast();

                // Check if we've covered the end of the range or the max possible IP
                let is_max_ip = match current_broadcast {
                    IpAddr::V4(v4) => v4 == IPV4_MAX,
                    IpAddr::V6(v6) => v6 == IPV6_MAX,
                };

                if current_broadcast == end || is_max_ip {
                    break; // Finished
                }

                // Move to the next address after the current block's broadcast
                match ip_addr_succ(current_broadcast) {
                    // Use the new successor function
                    Some(next_ip) => {
                        // Ensure next_ip is still the same family (should be
                        // guaranteed by ip_addr_succ)
                        current = next_ip;
                    }
                    None => break, // Reached absolute maximum IP address
                }
            }
            None => {
                // Should be impossible if start <= end, as /32 or /128 always
                // exists.
                return Err(anyhow!(
                    "Failed to find any suitable CIDR block for IP {}",
                    current
                ));
            }
        }
    }

    Ok(result)
}
