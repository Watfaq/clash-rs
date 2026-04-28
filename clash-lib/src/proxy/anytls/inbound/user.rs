//! User authentication map for AnyTLS inbound.

use crate::config::internal::listener::InboundUser;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};

/// Build an O(1) password lookup map from the user list.
///
/// Maps SHA256(password) → user name (`""` for single-user mode).
/// If `users` is empty, falls back to `fallback_password`.
pub fn build_user_map(
    users: &[InboundUser],
    fallback_password: &str,
) -> Arc<HashMap<[u8; 32], String>> {
    let mut map = HashMap::new();
    if users.is_empty() {
        let hash: [u8; 32] = Sha256::digest(fallback_password.as_bytes()).into();
        map.insert(hash, String::new());
    } else {
        for u in users {
            let hash: [u8; 32] = Sha256::digest(u.password.as_bytes()).into();
            match map.entry(hash) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(u.name.clone());
                }
                std::collections::hash_map::Entry::Occupied(e) => {
                    tracing::warn!(
                        "anytls inbound: duplicate password hash for users '{}' \
                         and '{}'; keeping first",
                        e.get(),
                        u.name
                    );
                }
            }
        }
    }
    Arc::new(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn make_users(pairs: &[(&str, &str)]) -> Vec<InboundUser> {
        pairs
            .iter()
            .map(|(name, pw)| InboundUser {
                name: name.to_string(),
                password: pw.to_string(),
            })
            .collect()
    }

    #[test]
    fn test_build_user_map_empty_uses_fallback() {
        let map = build_user_map(&[], "secret");
        let hash: [u8; 32] = Sha256::digest("secret".as_bytes()).into();
        assert!(map.contains_key(&hash), "fallback hash must be in the map");
        assert_eq!(
            map.get(&hash).unwrap(),
            "",
            "fallback user name must be empty"
        );
    }

    #[test]
    fn test_build_user_map_correct_password_found() {
        let users = make_users(&[("alice", "pass123")]);
        let map = build_user_map(&users, "ignored");
        let hash: [u8; 32] = Sha256::digest("pass123".as_bytes()).into();
        assert_eq!(map.get(&hash).map(String::as_str), Some("alice"));
    }

    #[test]
    fn test_build_user_map_wrong_password_not_found() {
        let users = make_users(&[("alice", "correct")]);
        let map = build_user_map(&users, "ignored");
        let bad_hash: [u8; 32] = Sha256::digest("wrong".as_bytes()).into();
        assert!(
            !map.contains_key(&bad_hash),
            "wrong password must not be in map"
        );
    }

    #[test]
    fn test_build_user_map_multi_user() {
        let users = make_users(&[("alice", "pw_a"), ("bob", "pw_b")]);
        let map = build_user_map(&users, "ignored");
        assert_eq!(map.len(), 2);

        let hash_a: [u8; 32] = Sha256::digest("pw_a".as_bytes()).into();
        let hash_b: [u8; 32] = Sha256::digest("pw_b".as_bytes()).into();
        assert_eq!(map.get(&hash_a).map(String::as_str), Some("alice"));
        assert_eq!(map.get(&hash_b).map(String::as_str), Some("bob"));
    }
}
