//! BIP39 mnemonic validation and seed generation.
//!
//! - `validate_mnemonic` — checks word count + checksum (no false positives).
//! - `mnemonic_to_seed` — derives the 64-byte BIP39 seed via PBKDF2-HMAC-SHA512.

use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::OnceLock;

/// The official 2048-word English BIP39 wordlist, embedded at compile time.
pub const BIP39_WORDLIST: &str = include_str!("wordlists/english.txt");

static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
static WORD_INDEX: OnceLock<HashMap<&'static str, u16>> = OnceLock::new();

/// Returns the ordered list of 2048 BIP39 words.
pub fn words() -> &'static [&'static str] {
    WORDS.get_or_init(|| {
        let v: Vec<&'static str> = BIP39_WORDLIST
            .lines()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(v.len(), 2048, "BIP39 wordlist must have exactly 2048 words");
        v
    })
}

/// Word → BIP39 index lookup (cached).
pub fn word_index() -> &'static HashMap<&'static str, u16> {
    WORD_INDEX.get_or_init(|| {
        let mut m = HashMap::with_capacity(2048);
        for (i, w) in words().iter().enumerate() {
            m.insert(*w, i as u16);
        }
        m
    })
}

/// Validate a 12/15/18/21/24-word mnemonic against BIP39: words must exist
/// and the checksum must match.
pub fn validate_mnemonic(words_in: &[&str]) -> bool {
    let n = words_in.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return false;
    }
    let map = word_index();
    let mut indices = Vec::with_capacity(n);
    for w in words_in {
        match map.get(*w) {
            Some(&i) => indices.push(i),
            None => return false,
        }
    }
    validate_checksum(&indices)
}

/// Validate just the checksum given pre-resolved BIP39 indices.
/// Hot path inside the recovery loop — keep allocation-free.
pub fn validate_checksum(indices: &[u16]) -> bool {
    let n = indices.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return false;
    }
    let total_bits = n * 11;
    let checksum_bits = total_bits / 33;
    let entropy_bytes = (total_bits - checksum_bits) / 8;

    let mut buf = [0u8; 33]; // max 24 words = 264 bits = 33 bytes
    let mut bit_pos = 0usize;
    for &idx in indices {
        for b in (0..11).rev() {
            if (idx >> b) & 1 == 1 {
                buf[bit_pos >> 3] |= 1 << (7 - (bit_pos & 7));
            }
            bit_pos += 1;
        }
    }

    let entropy = &buf[..entropy_bytes];
    let mut hasher = Sha256::new();
    hasher.update(entropy);
    let hash = hasher.finalize();

    // Compare the trailing checksum_bits of the buffer against the leading
    // checksum_bits of SHA-256(entropy).
    let mut expected = 0u8;
    for i in 0..checksum_bits {
        let pos = entropy_bytes * 8 + i;
        let bit = (buf[pos >> 3] >> (7 - (pos & 7))) & 1;
        expected = (expected << 1) | bit;
    }
    let mut actual = 0u8;
    for i in 0..checksum_bits {
        let bit = (hash[i >> 3] >> (7 - (i & 7))) & 1;
        actual = (actual << 1) | bit;
    }
    expected == actual
}

/// Derive the 64-byte BIP39 seed from a mnemonic + optional passphrase.
/// Uses PBKDF2-HMAC-SHA512 with 2048 iterations as per the BIP39 spec.
pub fn mnemonic_to_seed(words_in: &[&str], passphrase: &str) -> [u8; 64] {
    let mnemonic = words_in.join(" ");
    let salt_str = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(
        mnemonic.as_bytes(),
        salt_str.as_bytes(),
        2048,
        &mut seed,
    );
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_loads() {
        let w = words();
        assert_eq!(w.len(), 2048);
        assert_eq!(w[0], "abandon");
        assert_eq!(w[2047], "zoo");
    }

    #[test]
    fn validates_canonical_seed() {
        let m = ["abandon"; 11]
            .iter()
            .copied()
            .chain(std::iter::once("about"))
            .collect::<Vec<_>>();
        assert!(validate_mnemonic(&m));
    }

    #[test]
    fn rejects_corrupted_seed() {
        let m = ["abandon"; 12].to_vec();
        assert!(!validate_mnemonic(&m));
    }

    #[test]
    fn seed_matches_bip39_test_vector() {
        // From BIP39 spec: "abandon" × 11 + "about" with no passphrase
        let m: Vec<&str> = ["abandon"; 11]
            .iter()
            .copied()
            .chain(std::iter::once("about"))
            .collect();
        let seed = mnemonic_to_seed(&m, "");
        let expected = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();
        assert_eq!(seed.to_vec(), expected);
    }
}
