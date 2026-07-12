use std::fmt;

use serde::{
    Deserializer,
    de::{self, Visitor},
};

pub fn parse_bps(input: &str) -> Result<u64, String> {
    let s = input.trim();

    if s.is_empty() {
        return Err("empty bandwidth string".to_string());
    }

    let (num_str, multiplier) = match s.as_bytes().last().copied() {
        Some(b'K') | Some(b'k') => (&s[..s.len() - 1], 1024f64),
        Some(b'M') | Some(b'm') => (&s[..s.len() - 1], 1024f64 * 1024f64),
        Some(b'G') | Some(b'g') => (&s[..s.len() - 1], 1024f64 * 1024f64 * 1024f64),
        Some(b'0'..=b'9') => (s, 1f64),
        _ => return Err(format!("invalid bandwidth suffix: {input}")),
    };

    let value: f64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid bandwidth number: {input}"))?;

    if !value.is_finite() {
        return Err(format!("invalid bandwidth number: {input}"));
    }

    if value < 0.0 {
        return Err(format!("bandwidth must be non-negative: {input}"));
    }

    let result = value * multiplier;

    if result > u64::MAX as f64 {
        return Err(format!("bandwidth value overflow: {input}"));
    }

    Ok(result.round() as u64)
}

pub fn deserialize_bps<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct BpsVisitor;

    impl<'de> Visitor<'de> for BpsVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an integer bps value or a string like \"30M\" or \"1.5G\"")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value as u64)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value < 0 {
                return Err(E::custom("bandwidth must be non-negative"));
            }
            Ok(value as u64)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_bps(value).map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_bps(&value).map_err(E::custom)
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if !value.is_finite() {
                return Err(E::custom("bandwidth must be finite"));
            }
            if value < 0.0 {
                return Err(E::custom("bandwidth must be non-negative"));
            }
            Ok(value.round() as u64)
        }
    }

    deserializer.deserialize_any(BpsVisitor)
}
