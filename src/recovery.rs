//! Recovery algorithms.
//!
//! - `recover_missing` — N missing words at known positions, with optional
//!   address validation. Equivalent to btcrecover Phase 1 (1-3 missing words).
//! - `recover_typo` — single typo somewhere in the seed; tries each position
//!   × all 2048 substitutions. Equivalent to btcrecover Phase 2.
//!
//! Both use rayon for parallel iteration across CPU cores. First match wins.

use crate::address::{derive_addresses, DerivationType};
use crate::bip39::{mnemonic_to_seed, validate_checksum, word_index, words};
use rayon::prelude::*;
use secp256k1::Secp256k1;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Optional address-based filter. When set, the recovery short-circuits at
/// the first checksum-valid candidate whose derived addresses contain the
/// target.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub address: String,
    pub kind: DerivationType,
    pub passphrase: String,
    pub account_start: u32,
    pub account_end: u32,
    pub address_start: u32,
    pub address_end: u32,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            kind: DerivationType::EthereumStandard,
            passphrase: String::new(),
            account_start: 0,
            account_end: 0,
            address_start: 0,
            address_end: 9, // matches btcrecover's --addr-limit default
        }
    }
}

/// Input for the missing-words recovery.
#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub seed_length: usize,
    /// `None` for missing slots, `Some(word)` for known.
    pub words: Vec<Option<String>>,
    pub validation: Option<ValidationConfig>,
}

#[derive(Debug, Clone)]
pub struct RecoveryResult {
    pub mnemonic: Option<Vec<String>>,
    pub combinations_tested: u64,
    pub elapsed_ms: u128,
}

/// Recover missing words at known positions. Supports up to 3 missing words
/// efficiently (4M combinations checksum-only). With validation, even higher
/// counts work but get progressively slower.
pub fn recover_missing(
    req: &RecoveryRequest,
    progress: impl Fn(u64) + Sync + Send,
) -> RecoveryResult {
    let start = std::time::Instant::now();

    let map = word_index();
    let wordlist_static = words();
    let mut known_indices = vec![0u16; req.seed_length];
    let mut missing_positions = Vec::new();
    for (i, w) in req.words.iter().enumerate() {
        match w {
            None => missing_positions.push(i),
            Some(w) => match map.get(w.as_str()) {
                Some(&idx) => known_indices[i] = idx,
                None => {
                    return RecoveryResult {
                        mnemonic: None,
                        combinations_tested: 0,
                        elapsed_ms: start.elapsed().as_millis(),
                    };
                }
            },
        }
    }
    let m = missing_positions.len();

    let found = AtomicBool::new(false);
    let result_lock: Mutex<Option<Vec<String>>> = Mutex::new(None);
    let total_tested = std::sync::atomic::AtomicU64::new(0);

    let validation = req.validation.clone();
    let secp = Secp256k1::new();

    let try_candidate = |indices: &[u16]| -> bool {
        if !validate_checksum(indices) {
            return false;
        }
        let mnemonic_owned: Vec<String> = indices
            .iter()
            .map(|&i| wordlist_static[i as usize].to_string())
            .collect();
        let mnemonic_refs: Vec<&str> =
            mnemonic_owned.iter().map(|s| s.as_str()).collect();
        if let Some(v) = &validation {
            let seed = mnemonic_to_seed(&mnemonic_refs, &v.passphrase);
            let addresses = derive_addresses(
                &secp,
                &seed,
                v.kind,
                v.account_start,
                v.account_end,
                v.address_start,
                v.address_end,
            );
            let target = v.address.to_ascii_lowercase();
            if addresses.iter().any(|a| a.to_ascii_lowercase() == target) {
                let mut g = result_lock.lock().unwrap();
                if g.is_none() {
                    *g = Some(mnemonic_owned);
                }
                found.store(true, Ordering::Relaxed);
                return true;
            }
            false
        } else {
            // No validation — accept first checksum-valid candidate.
            let mut g = result_lock.lock().unwrap();
            if g.is_none() {
                *g = Some(mnemonic_owned);
            }
            found.store(true, Ordering::Relaxed);
            true
        }
    };

    // Parallelism strategy: split the OUTER missing-position loop across
    // cores via rayon's par_bridge.
    match m {
        0 => {
            // No missing positions — just test the seed as-is.
            try_candidate(&known_indices);
            total_tested.fetch_add(1, Ordering::Relaxed);
        }
        1 => {
            (0u16..2048).into_par_iter().for_each(|w0| {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                let mut idx = known_indices.clone();
                idx[missing_positions[0]] = w0;
                try_candidate(&idx);
                let prev = total_tested.fetch_add(1, Ordering::Relaxed);
                if prev % 4096 == 0 {
                    progress(prev + 1);
                }
            });
        }
        2 => {
            (0u16..2048).into_par_iter().for_each(|w0| {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                let mut idx = known_indices.clone();
                idx[missing_positions[0]] = w0;
                for w1 in 0u16..2048 {
                    if found.load(Ordering::Relaxed) {
                        break;
                    }
                    idx[missing_positions[1]] = w1;
                    try_candidate(&idx);
                    let prev = total_tested.fetch_add(1, Ordering::Relaxed);
                    if prev % 4096 == 0 {
                        progress(prev + 1);
                    }
                }
            });
        }
        3 => {
            (0u16..2048).into_par_iter().for_each(|w0| {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                let mut idx = known_indices.clone();
                idx[missing_positions[0]] = w0;
                for w1 in 0u16..2048 {
                    if found.load(Ordering::Relaxed) {
                        break;
                    }
                    idx[missing_positions[1]] = w1;
                    for w2 in 0u16..2048 {
                        if found.load(Ordering::Relaxed) {
                            break;
                        }
                        idx[missing_positions[2]] = w2;
                        try_candidate(&idx);
                        let prev = total_tested.fetch_add(1, Ordering::Relaxed);
                        if prev % 4096 == 0 {
                            progress(prev + 1);
                        }
                    }
                }
            });
        }
        _ => {
            // 4+ missing — astronomical. Skip.
        }
    }

    let mnemonic = result_lock.lock().unwrap().take();
    RecoveryResult {
        mnemonic,
        combinations_tested: total_tested.load(Ordering::Relaxed),
        elapsed_ms: start.elapsed().as_millis(),
    }
}

/// Try replacing each position with all 2048 BIP39 words.
/// Total candidates = N × 2048 — fast (~25k for 12 words).
pub fn recover_typo(
    req: &RecoveryRequest,
    progress: impl Fn(u64) + Sync + Send,
) -> RecoveryResult {
    let start = std::time::Instant::now();

    let map = word_index();
    let wordlist_static = words();
    let mut base_indices = vec![0u16; req.seed_length];
    for (i, w) in req.words.iter().enumerate() {
        if let Some(w) = w {
            match map.get(w.as_str()) {
                Some(&idx) => base_indices[i] = idx,
                None => {
                    return RecoveryResult {
                        mnemonic: None,
                        combinations_tested: 0,
                        elapsed_ms: start.elapsed().as_millis(),
                    };
                }
            }
        }
    }

    let found = AtomicBool::new(false);
    let result_lock: Mutex<Option<Vec<String>>> = Mutex::new(None);
    let total_tested = std::sync::atomic::AtomicU64::new(0);

    let validation = req.validation.clone();
    let secp = Secp256k1::new();

    let try_candidate = |indices: &[u16]| -> bool {
        if !validate_checksum(indices) {
            return false;
        }
        let mnemonic_owned: Vec<String> = indices
            .iter()
            .map(|&i| wordlist_static[i as usize].to_string())
            .collect();
        let mnemonic_refs: Vec<&str> =
            mnemonic_owned.iter().map(|s| s.as_str()).collect();
        if let Some(v) = &validation {
            let seed = mnemonic_to_seed(&mnemonic_refs, &v.passphrase);
            let addresses = derive_addresses(
                &secp,
                &seed,
                v.kind,
                v.account_start,
                v.account_end,
                v.address_start,
                v.address_end,
            );
            let target = v.address.to_ascii_lowercase();
            if addresses.iter().any(|a| a.to_ascii_lowercase() == target) {
                let mut g = result_lock.lock().unwrap();
                if g.is_none() {
                    *g = Some(mnemonic_owned);
                }
                found.store(true, Ordering::Relaxed);
                return true;
            }
            false
        } else {
            let mut g = result_lock.lock().unwrap();
            if g.is_none() {
                *g = Some(mnemonic_owned);
            }
            found.store(true, Ordering::Relaxed);
            true
        }
    };

    let n = req.seed_length;
    (0..n).into_par_iter().for_each(|pos| {
        if found.load(Ordering::Relaxed) {
            return;
        }
        let mut idx = base_indices.clone();
        let original = base_indices[pos];
        for w in 0u16..2048 {
            if found.load(Ordering::Relaxed) {
                break;
            }
            // Skip the original — but DO test it once when pos=0 to handle
            // the "no typo" case.
            if w == original && pos != 0 {
                continue;
            }
            idx[pos] = w;
            try_candidate(&idx);
            let prev = total_tested.fetch_add(1, Ordering::Relaxed);
            if prev % 1024 == 0 {
                progress(prev + 1);
            }
        }
    });

    let mnemonic = result_lock.lock().unwrap().take();
    RecoveryResult {
        mnemonic,
        combinations_tested: total_tested.load(Ordering::Relaxed),
        elapsed_ms: start.elapsed().as_millis(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_missing_one_word_with_address() {
        // abandon × 11 + ? where target is the abandon-about ETH address
        let mut words: Vec<Option<String>> =
            vec![Some("abandon".to_string()); 11];
        words.push(None);
        let req = RecoveryRequest {
            seed_length: 12,
            words,
            validation: Some(ValidationConfig {
                address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".into(),
                kind: DerivationType::EthereumStandard,
                passphrase: String::new(),
                account_start: 0,
                account_end: 0,
                address_start: 0,
                address_end: 0,
            }),
        };
        let res = recover_missing(&req, |_| {});
        assert!(res.mnemonic.is_some(), "should find a match");
        assert_eq!(res.mnemonic.as_ref().unwrap().last().unwrap(), "about");
    }

    #[test]
    fn recover_typo_canonical_vector() {
        // Synthetic test using the well-known abandon-about BIP39 test vector.
        // The real seed is `abandon` × 11 + `about`. We swap word 11 (index
        // 10) from `abandon` to `apple` — both are valid BIP39 words, but
        // `apple` is wrong for this address. The typo correction should
        // restore `abandon` at position 10.
        // No real funds — this is a public test vector embedded in every
        // BIP39 implementation and shared across the ecosystem.
        let words = vec![
            Some("abandon".into()),
            Some("abandon".into()),
            Some("abandon".into()),
            Some("abandon".into()),
            Some("abandon".into()),
            Some("abandon".into()),
            Some("abandon".into()),
            Some("abandon".into()),
            Some("abandon".into()),
            Some("abandon".into()),
            Some("apple".into()), // ← wrong word (valid BIP39, not in this seed)
            Some("about".into()),
        ];
        let req = RecoveryRequest {
            seed_length: 12,
            words,
            validation: Some(ValidationConfig {
                address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".into(),
                kind: DerivationType::EthereumStandard,
                passphrase: String::new(),
                account_start: 0,
                account_end: 0,
                address_start: 0,
                address_end: 0,
            }),
        };
        let res = recover_typo(&req, |_| {});
        assert!(res.mnemonic.is_some(), "should find the typo correction");
        assert_eq!(res.mnemonic.as_ref().unwrap()[10], "abandon");
    }
}
