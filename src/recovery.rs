//! Recovery algorithms.
//!
//! Every mode below builds a `CandidateSpace` and hands it to the shared
//! `run_chunked_search` runner (`src/search.rs`), which is what makes
//! checkpoint/resume (`src/checkpoint.rs`) work identically across modes.

use crate::address::{derive_addresses, DerivationType};
use crate::bip39::{mnemonic_to_seed, validate_checksum, word_index, words};
use crate::candidate_space::{CandidateSpace, MissingSpace, TypoSpace};
use crate::search::run_chunked_search;
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
    /// `true` if the search was interrupted (Ctrl+C) before completion or
    /// a match. When `true`, `mnemonic` is `None` and the caller should
    /// have already been given a checkpoint to resume from.
    pub interrupted: bool,
}

/// Resolves `req.words` into (known_indices with 0 placeholders at missing
/// slots, missing_positions, known_positions). Returns `None` if any known
/// word isn't a valid BIP39 word.
fn resolve_words(req: &RecoveryRequest) -> Option<(Vec<u16>, Vec<usize>, Vec<usize>)> {
    let map = word_index();
    let mut known_indices = vec![0u16; req.seed_length];
    let mut missing_positions = Vec::new();
    let mut known_positions = Vec::new();
    for (i, w) in req.words.iter().enumerate() {
        match w {
            None => missing_positions.push(i),
            Some(w) => match map.get(w.as_str()) {
                Some(&idx) => {
                    known_indices[i] = idx;
                    known_positions.push(i);
                }
                None => return None,
            },
        }
    }
    Some((known_indices, missing_positions, known_positions))
}

/// Builds the shared per-candidate test closure: checksum-validate, then
/// (if a `ValidationConfig` is set) derive addresses and compare. On match,
/// records the mnemonic and flips `found`.
fn make_try_candidate<'a>(
    validation: &'a Option<ValidationConfig>,
    secp: &'a Secp256k1<secp256k1::All>,
    found: &'a AtomicBool,
    result_lock: &'a Mutex<Option<Vec<String>>>,
) -> impl Fn(&[u16]) -> bool + Sync + 'a {
    let wordlist = words();
    move |indices: &[u16]| -> bool {
        if !validate_checksum(indices) {
            return false;
        }
        let mnemonic_owned: Vec<String> =
            indices.iter().map(|&i| wordlist[i as usize].to_string()).collect();
        let mnemonic_refs: Vec<&str> = mnemonic_owned.iter().map(|s| s.as_str()).collect();
        match validation {
            Some(v) => {
                let seed = mnemonic_to_seed(&mnemonic_refs, &v.passphrase);
                let addresses = derive_addresses(
                    secp,
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
            }
            None => {
                let mut g = result_lock.lock().unwrap();
                if g.is_none() {
                    *g = Some(mnemonic_owned);
                }
                found.store(true, Ordering::Relaxed);
                true
            }
        }
    }
}

/// Recover missing words at known positions (1-3 missing, checksum-only or
/// address-validated). `resume_index` is 0 for a fresh search.
pub fn recover_missing(
    req: &RecoveryRequest,
    progress: impl Fn(u64) + Sync + Send,
) -> RecoveryResult {
    recover_missing_resumable(req, 0, &AtomicBool::new(false), progress, |_| {})
}

/// Same as `recover_missing`, plus resume support. `stop` is checked
/// between chunks (e.g. wired to a Ctrl+C handler by the caller);
/// `on_chunk_complete` is called with the new watermark after each
/// completed chunk (e.g. to write a checkpoint).
pub fn recover_missing_resumable(
    req: &RecoveryRequest,
    resume_index: u64,
    stop: &AtomicBool,
    progress: impl Fn(u64) + Sync + Send,
    on_chunk_complete: impl FnMut(u64),
) -> RecoveryResult {
    let start = std::time::Instant::now();
    let Some((known_indices, missing_positions, _known_positions)) = resolve_words(req) else {
        return RecoveryResult { mnemonic: None, combinations_tested: 0, elapsed_ms: start.elapsed().as_millis(), interrupted: false };
    };
    if missing_positions.is_empty() || missing_positions.len() > 3 {
        return RecoveryResult { mnemonic: None, combinations_tested: 0, elapsed_ms: start.elapsed().as_millis(), interrupted: false };
    }

    let space = MissingSpace { known_indices, missing_positions };
    let found = AtomicBool::new(false);
    let result_lock: Mutex<Option<Vec<String>>> = Mutex::new(None);
    let secp = Secp256k1::new();
    let try_candidate = make_try_candidate(&req.validation, &secp, &found, &result_lock);

    let outcome = run_chunked_search(&space, resume_index, &found, stop, try_candidate, on_chunk_complete, progress);

    // Bound to a local before returning: rustc's borrowck cannot prove the
    // MutexGuard temporary from `.lock().unwrap()` is safe to drop when
    // this struct literal is the function's tail expression (E0597,
    // "temporary is part of an expression at the end of a block") — even
    // though `.take()` returns a fully owned value with no borrow. Binding
    // to `result` first forces the guard to drop within this `let`
    // statement, before `result_lock` itself is dropped at function end.
    let result = RecoveryResult {
        mnemonic: result_lock.lock().unwrap().take(),
        combinations_tested: outcome.tested,
        elapsed_ms: start.elapsed().as_millis(),
        interrupted: outcome.interrupted,
    };
    result
}

/// Try replacing each position with all 2048 BIP39 words (single typo).
pub fn recover_typo(
    req: &RecoveryRequest,
    progress: impl Fn(u64) + Sync + Send,
) -> RecoveryResult {
    recover_typo_resumable(req, 0, &AtomicBool::new(false), progress, |_| {})
}

/// Same as `recover_typo`, plus resume support (see `recover_missing_resumable`).
pub fn recover_typo_resumable(
    req: &RecoveryRequest,
    resume_index: u64,
    stop: &AtomicBool,
    progress: impl Fn(u64) + Sync + Send,
    on_chunk_complete: impl FnMut(u64),
) -> RecoveryResult {
    let start = std::time::Instant::now();
    let Some((base_indices, _missing_positions, _known_positions)) = resolve_words(req) else {
        return RecoveryResult { mnemonic: None, combinations_tested: 0, elapsed_ms: start.elapsed().as_millis(), interrupted: false };
    };

    let space = TypoSpace { base_indices };
    let found = AtomicBool::new(false);
    let result_lock: Mutex<Option<Vec<String>>> = Mutex::new(None);
    let secp = Secp256k1::new();
    let try_candidate = make_try_candidate(&req.validation, &secp, &found, &result_lock);

    let outcome = run_chunked_search(&space, resume_index, &found, stop, try_candidate, on_chunk_complete, progress);

    // Bound to a local before returning: rustc's borrowck cannot prove the
    // MutexGuard temporary from `.lock().unwrap()` is safe to drop when
    // this struct literal is the function's tail expression (E0597,
    // "temporary is part of an expression at the end of a block") — even
    // though `.take()` returns a fully owned value with no borrow. Binding
    // to `result` first forces the guard to drop within this `let`
    // statement, before `result_lock` itself is dropped at function end.
    let result = RecoveryResult {
        mnemonic: result_lock.lock().unwrap().take(),
        combinations_tested: outcome.tested,
        elapsed_ms: start.elapsed().as_millis(),
        interrupted: outcome.interrupted,
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::DerivationType;

    #[test]
    fn recover_missing_one_word_with_address() {
        let mut words: Vec<Option<String>> = vec![Some("abandon".to_string()); 11];
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
        assert!(!res.interrupted);
    }

    #[test]
    fn recover_missing_two_words_still_works_after_refactor() {
        let mut words: Vec<Option<String>> = vec![Some("abandon".to_string()); 10];
        words.push(None);
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
        assert!(res.mnemonic.is_some());
        assert_eq!(res.mnemonic.as_ref().unwrap()[10], "abandon");
        assert_eq!(res.mnemonic.as_ref().unwrap()[11], "about");
    }

    #[test]
    fn recover_typo_canonical_vector() {
        let words = vec![
            Some("abandon".into()), Some("abandon".into()), Some("abandon".into()),
            Some("abandon".into()), Some("abandon".into()), Some("abandon".into()),
            Some("abandon".into()), Some("abandon".into()), Some("abandon".into()),
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
        assert!(!res.interrupted);
    }
}
