# Recovery Engine Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add wrong-order (permutation) recovery, combined missing+typo search, and crash/interrupt-safe checkpoint/resume to `seedcrypt-recover`, without changing existing `missing`/`typo` behavior when the new flags are omitted.

**Architecture:** Introduce a shared `CandidateSpace` trait (index `0..total` ↔ candidate mnemonic) implemented by four space types (`MissingSpace`, `TypoSpace`, `MissingTypoSpace`, `ReorderSpace`), a generic chunked-parallel search runner that all recovery functions call, and a `Checkpoint` module (signature-verified JSON, atomic writes) that plugs into the runner for resumability. `ReorderSpace` uses a new Lehmer-code permutation module.

**Tech Stack:** Rust 2021, `rayon` (parallel iteration), `serde`/`serde_json` (checkpoint format, new deps), `ctrlc` (SIGINT handling, new dep), `sha2` (passphrase hashing, existing dep), `clap` derive (CLI), `proptest` (property tests, existing dev-dep).

**Design spec:** `docs/superpowers/specs/2026-07-16-recovery-engine-expansion-design.md`

---

## File structure

- **Create** `src/lehmer.rs` — factorial + index↔permutation bijection. No dependencies on the rest of the crate; pure math, easy to isolate and property-test.
- **Create** `src/candidate_space.rs` — the `CandidateSpace` trait and its four implementations (`MissingSpace`, `TypoSpace`, `MissingTypoSpace`, `ReorderSpace`).
- **Create** `src/search.rs` — the shared chunked-parallel search runner (`run_chunked_search`) and the shared `try_candidate` closure builder, used by every recovery function so the address-validation logic isn't duplicated four times.
- **Create** `src/checkpoint.rs` — `Checkpoint` struct, signature matching, atomic save/load.
- **Modify** `src/recovery.rs` — `recover_missing` and `recover_typo` refactored onto `MissingSpace`/`TypoSpace` + `run_chunked_search` (regression-safe); add `allow_typo` support via `MissingTypoSpace`; add `recover_reorder` via `ReorderSpace`. All three gain `resume_index`/checkpoint parameters.
- **Modify** `src/lib.rs` — export the new modules and public items.
- **Modify** `src/main.rs` — add `reorder` subcommand; add `--allow-typo` to `missing`; add `--checkpoint`/`--resume` to all three subcommands; wire `ctrlc`.
- **Modify** `Cargo.toml` — add `serde`, `serde_json`, `ctrlc`; bump version to `0.2.0` (final task).
- **Modify** `README.md` — document the three new capabilities, update the Status section (final task).

---

### Task 1: Add new dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add serde, serde_json, ctrlc to `[dependencies]`**

In `Cargo.toml`, add these lines to the `[dependencies]` section (after `thiserror = "1"`):

```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ctrlc = "3.4"
```

- [ ] **Step 2: Verify the crate still builds with the new deps resolved**

Run: `cargo build`
Expected: compiles successfully (may take a minute to fetch/compile the three new crates), no errors.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: add serde, serde_json, ctrlc dependencies"
```

---

### Task 2: Lehmer code permutation module

**Files:**
- Create: `src/lehmer.rs`
- Modify: `src/lib.rs:10-13` (add `pub mod lehmer;`)

- [ ] **Step 1: Write the failing tests**

Create `src/lehmer.rs`:

```rust
//! Factorial number system (Lehmer code) — a bijection between an integer
//! index `0..n!` and the n-th permutation of a slice, used by `reorder`
//! recovery to enumerate permutations without materializing all of them.

/// `n!` for small `n` (this crate never permutes more than 10 items, so a
/// plain u64 product is safe — 10! = 3,628,800, 20! is the u64 overflow
/// boundary and we're nowhere near it).
pub fn factorial(n: u64) -> u64 {
    (1..=n).product::<u64>().max(1)
}

/// Returns the `index`-th permutation of `items`, in the factorial number
/// system over the *given* order (not sorted order). `index` must be
/// `< factorial(items.len())` — out-of-range indices wrap via modulo in
/// debug-safe fashion by construction of callers (see `ReorderSpace`),
/// so this function does not itself validate the bound.
pub fn nth_permutation<T: Clone>(items: &[T], index: u64) -> Vec<T> {
    let mut pool: Vec<T> = items.to_vec();
    let mut result = Vec::with_capacity(items.len());
    let mut idx = index;
    for i in (1..=pool.len()).rev() {
        let f = factorial((i - 1) as u64);
        let choice = (idx / f) as usize;
        idx %= f;
        result.push(pool.remove(choice));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn factorial_known_values() {
        assert_eq!(factorial(0), 1);
        assert_eq!(factorial(1), 1);
        assert_eq!(factorial(4), 24);
        assert_eq!(factorial(10), 3_628_800);
    }

    #[test]
    fn nth_permutation_identity_at_zero() {
        let items = vec![10u16, 20, 30, 40];
        assert_eq!(nth_permutation(&items, 0), items);
    }

    #[test]
    fn nth_permutation_last_index_is_full_reverse_of_choices() {
        // For 3 items, index 5 (= 3! - 1) exhausts every "pick the last
        // remaining element" branch, which is the reverse of the input.
        let items = vec![1u16, 2, 3];
        assert_eq!(nth_permutation(&items, 5), vec![3, 2, 1]);
    }

    proptest! {
        #[test]
        fn all_permutations_are_distinct_and_same_multiset(k in 2usize..=6) {
            let items: Vec<u16> = (0..k as u16).collect();
            let total = factorial(k as u64);
            let mut seen = std::collections::HashSet::new();
            for i in 0..total {
                let perm = nth_permutation(&items, i);
                // Same multiset as the input.
                let mut sorted = perm.clone();
                sorted.sort();
                prop_assert_eq!(&sorted, &items);
                // Every index yields a distinct permutation.
                prop_assert!(seen.insert(perm));
            }
            prop_assert_eq!(seen.len() as u64, total);
        }
    }
}
```

- [ ] **Step 2: Register the module**

In `src/lib.rs`, change:

```rust
pub mod bip39;
pub mod bip32;
pub mod address;
pub mod recovery;
```

to:

```rust
pub mod bip39;
pub mod bip32;
pub mod address;
pub mod lehmer;
pub mod recovery;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test lehmer:: -- --nocapture`
Expected: `4 passed` (3 unit tests + the proptest, which itself runs 256 cases by default).

- [ ] **Step 4: Commit**

```bash
git add src/lehmer.rs src/lib.rs
git commit -m "feat: add Lehmer code permutation module for reorder recovery"
```

---

### Task 3: `CandidateSpace` trait + `MissingSpace` + `TypoSpace`

**Files:**
- Create: `src/candidate_space.rs`
- Modify: `src/lib.rs` (add `pub mod candidate_space;`)

- [ ] **Step 1: Write the failing tests**

Create `src/candidate_space.rs`:

```rust
//! `CandidateSpace` — a bijection between an integer index `0..total()` and
//! a candidate BIP39 index vector. This is what makes the chunked search
//! runner (`src/search.rs`) and checkpoint/resume (`src/checkpoint.rs`)
//! work identically across every recovery mode: each mode is just a
//! different `CandidateSpace` implementation.

/// Maps a linear index to a full-length vector of BIP39 word indices
/// (a candidate mnemonic, as `u16` indices into the 2048-word list).
pub trait CandidateSpace: Send + Sync {
    /// Total number of candidates in this space.
    fn total(&self) -> u64;
    /// The candidate at `index` (`index` must be `< total()`).
    fn candidate_at(&self, index: u64) -> Vec<u16>;
}

/// N missing words at known positions — each missing slot ranges over all
/// 2048 words. `missing_positions[i]` is the most-significant digit for
/// `i == 0`, least-significant for `i == missing_positions.len() - 1`;
/// any consistent bijection works since the search is exhaustive.
pub struct MissingSpace {
    pub known_indices: Vec<u16>,
    pub missing_positions: Vec<usize>,
}

impl CandidateSpace for MissingSpace {
    fn total(&self) -> u64 {
        2048u64.pow(self.missing_positions.len() as u32)
    }

    fn candidate_at(&self, index: u64) -> Vec<u16> {
        let mut out = self.known_indices.clone();
        let m = self.missing_positions.len();
        let mut rem = index;
        for i in (0..m).rev() {
            out[self.missing_positions[i]] = (rem % 2048) as u16;
            rem /= 2048;
        }
        out
    }
}

/// Single-typo search: try every position × every one of the 2048 words.
/// Note: unlike the original hand-rolled loop (which explicitly skipped
/// re-testing the unmodified seed after position 0), this indexed version
/// re-tests the unmodified seed once per position where the substitute
/// happens to equal the original word — up to `n - 1` harmless redundant
/// checksum checks out of tens of thousands of candidates. Traded
/// deliberately for a uniform, checkpoint-friendly indexing scheme.
pub struct TypoSpace {
    pub base_indices: Vec<u16>,
}

impl CandidateSpace for TypoSpace {
    fn total(&self) -> u64 {
        self.base_indices.len() as u64 * 2048
    }

    fn candidate_at(&self, index: u64) -> Vec<u16> {
        let pos = (index / 2048) as usize;
        let w = (index % 2048) as u16;
        let mut out = self.base_indices.clone();
        out[pos] = w;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn missing_space_total_and_bijection() {
        let space = MissingSpace {
            known_indices: vec![0u16, 0, 0, 0],
            missing_positions: vec![1, 3],
        };
        assert_eq!(space.total(), 2048 * 2048);

        let c = space.candidate_at(0);
        assert_eq!(c, vec![0, 0, 0, 0]);

        // Least-significant digit (last missing position, index 3) should
        // vary fastest.
        let c1 = space.candidate_at(1);
        assert_eq!(c1, vec![0, 0, 0, 1]);

        // Known positions (0 and 2) are never touched.
        for i in [0u64, 1, 2048, 4_194_303] {
            let c = space.candidate_at(i);
            assert_eq!(c[0], 0);
            assert_eq!(c[2], 0);
        }
    }

    #[test]
    fn missing_space_all_candidates_distinct_small() {
        let space = MissingSpace {
            known_indices: vec![0u16; 3],
            missing_positions: vec![0, 2],
        };
        let mut seen = HashSet::new();
        for i in 0..space.total() {
            assert!(seen.insert(space.candidate_at(i)));
        }
        assert_eq!(seen.len() as u64, space.total());
    }

    #[test]
    fn typo_space_total_and_positions() {
        let space = TypoSpace {
            base_indices: vec![5u16, 6, 7],
        };
        assert_eq!(space.total(), 3 * 2048);

        // index 0 => pos 0, word 0
        assert_eq!(space.candidate_at(0), vec![0, 6, 7]);
        // index 2048 => pos 1, word 0
        assert_eq!(space.candidate_at(2048), vec![5, 0, 7]);
        // index 2048 + 6 => pos 1, word 6 (unchanged — the harmless
        // redundant "no typo" case documented above)
        assert_eq!(space.candidate_at(2048 + 6), vec![5, 6, 7]);
    }
}
```

- [ ] **Step 2: Register the module**

In `src/lib.rs`:

```rust
pub mod bip39;
pub mod bip32;
pub mod address;
pub mod lehmer;
pub mod candidate_space;
pub mod recovery;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test candidate_space:: -- --nocapture`
Expected: `4 passed`.

- [ ] **Step 4: Commit**

```bash
git add src/candidate_space.rs src/lib.rs
git commit -m "feat: add CandidateSpace trait with MissingSpace and TypoSpace"
```

---

### Task 4: Shared chunked search runner

**Files:**
- Create: `src/search.rs`
- Modify: `src/lib.rs` (add `pub mod search;`)

This is the piece that makes checkpointing possible: chunks complete strictly in order (so the watermark is always a safe resume point), while candidates *within* a chunk run in parallel via rayon.

- [ ] **Step 1: Write the failing test**

Create `src/search.rs`:

```rust
//! Shared chunked-parallel search runner. Every recovery mode (missing,
//! typo, missing+typo, reorder) is a `CandidateSpace`; this runner is the
//! one place that knows how to walk one, in a checkpoint-safe order.

use crate::candidate_space::CandidateSpace;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Candidates per chunk. Chunks complete strictly in order, so "N chunks
/// completed" is always a safe resume point — at most one chunk's worth of
/// work is redone after a crash or interrupt. Not exposed as a CLI flag.
pub const CHUNK_SIZE: u64 = 100_000;

pub struct SearchOutcome {
    pub tested: u64,
    pub interrupted: bool,
}

/// Walks `space` starting at `resume_index`, calling `try_candidate` for
/// every candidate (in parallel, within each chunk) until a match is found
/// (`found` is set to `true`, e.g. inside `try_candidate`), `stop` is set
/// (e.g. by a Ctrl+C handler), or the space is exhausted.
///
/// `on_chunk_complete` is called after each fully-completed chunk with the
/// new watermark (a candidate index, not a chunk number) — the caller uses
/// this to persist a checkpoint. It is *not* called for a partial chunk
/// interrupted mid-way, which is exactly what bounds redone work to at
/// most one chunk on resume.
pub fn run_chunked_search(
    space: &dyn CandidateSpace,
    resume_index: u64,
    found: &AtomicBool,
    stop: &AtomicBool,
    try_candidate: impl Fn(&[u16]) -> bool + Sync,
    mut on_chunk_complete: impl FnMut(u64),
    progress: impl Fn(u64) + Sync,
) -> SearchOutcome {
    let total = space.total();
    let tested = AtomicU64::new(0);
    let mut chunk_start = resume_index.min(total);
    let mut interrupted = false;

    while chunk_start < total {
        if stop.load(Ordering::Relaxed) {
            interrupted = true;
            break;
        }
        let chunk_end = (chunk_start + CHUNK_SIZE).min(total);
        (chunk_start..chunk_end).into_par_iter().for_each(|i| {
            if found.load(Ordering::Relaxed) {
                return;
            }
            let candidate = space.candidate_at(i);
            try_candidate(&candidate);
            let prev = tested.fetch_add(1, Ordering::Relaxed);
            if prev % 4096 == 0 {
                progress(prev + 1);
            }
        });
        chunk_start = chunk_end;
        on_chunk_complete(chunk_start);
        if found.load(Ordering::Relaxed) {
            break;
        }
    }

    SearchOutcome {
        tested: tested.load(Ordering::Relaxed),
        interrupted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Trivial space: candidates are just `[index as u16]`.
    struct IdentitySpace(u64);
    impl CandidateSpace for IdentitySpace {
        fn total(&self) -> u64 {
            self.0
        }
        fn candidate_at(&self, index: u64) -> Vec<u16> {
            vec![index as u16]
        }
    }

    #[test]
    fn visits_every_candidate_when_no_match() {
        let space = IdentitySpace(250_000); // spans 3 chunks at CHUNK_SIZE
        let found = AtomicBool::new(false);
        let stop = AtomicBool::new(false);
        let visited: Mutex<Vec<u16>> = Mutex::new(Vec::new());

        let outcome = run_chunked_search(
            &space,
            0,
            &found,
            &stop,
            |c| {
                visited.lock().unwrap().push(c[0]);
                false
            },
            |_| {},
            |_| {},
        );

        assert_eq!(outcome.tested, 250_000);
        assert!(!outcome.interrupted);
        assert_eq!(visited.lock().unwrap().len(), 250_000);
    }

    #[test]
    fn resume_index_skips_the_prefix() {
        let space = IdentitySpace(10_000);
        let found = AtomicBool::new(false);
        let stop = AtomicBool::new(false);
        let min_seen: Mutex<Option<u16>> = Mutex::new(None);

        run_chunked_search(
            &space,
            5_000,
            &found,
            &stop,
            |c| {
                let mut m = min_seen.lock().unwrap();
                *m = Some(m.map_or(c[0], |cur| cur.min(c[0])));
                false
            },
            |_| {},
            |_| {},
        );

        assert_eq!(min_seen.lock().unwrap().unwrap(), 5_000u16);
    }

    #[test]
    fn stops_between_chunks_when_stop_flag_set() {
        let space = IdentitySpace(1_000_000); // 10 chunks
        let found = AtomicBool::new(false);
        let stop = AtomicBool::new(true); // already set before starting
        let outcome = run_chunked_search(
            &space, 0, &found, &stop, |_| false, |_| {}, |_| {},
        );
        assert!(outcome.interrupted);
        assert_eq!(outcome.tested, 0);
    }

    #[test]
    fn checkpoint_callback_receives_watermark_per_chunk() {
        let space = IdentitySpace(250_000); // 3 chunks: 100k, 100k, 50k
        let found = AtomicBool::new(false);
        let stop = AtomicBool::new(false);
        let watermarks: Mutex<Vec<u64>> = Mutex::new(Vec::new());

        run_chunked_search(
            &space,
            0,
            &found,
            &stop,
            |_| false,
            |w| watermarks.lock().unwrap().push(w),
            |_| {},
        );

        assert_eq!(
            *watermarks.lock().unwrap(),
            vec![100_000, 200_000, 250_000]
        );
    }
}
```

- [ ] **Step 2: Register the module**

In `src/lib.rs`:

```rust
pub mod bip39;
pub mod bip32;
pub mod address;
pub mod lehmer;
pub mod candidate_space;
pub mod search;
pub mod recovery;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test search:: -- --nocapture`
Expected: `4 passed`.

- [ ] **Step 4: Commit**

```bash
git add src/search.rs src/lib.rs
git commit -m "feat: add shared chunked search runner for checkpoint-safe recovery"
```

---

### Task 5: Refactor `recover_missing` and `recover_typo` onto the new abstraction

**Files:**
- Modify: `src/recovery.rs` (full rewrite of the two functions + a new shared `try_candidate` builder)

This is the regression-critical task: same inputs must produce the same *correct answer* as before (exact tested-count and timing are not guaranteed identical — they weren't deterministic before either, since "first match wins" already raced across threads).

- [ ] **Step 1: Write the failing regression test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `src/recovery.rs` (keep the two existing tests, add this one):

```rust
    #[test]
    fn recover_missing_two_words_still_works_after_refactor() {
        // Regression: same shape of request as the existing single-word
        // test, but with 2 missing words, exercising the multi-digit
        // MissingSpace indexing path.
        let mut words: Vec<Option<String>> =
            vec![Some("abandon".to_string()); 10];
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
```

- [ ] **Step 2: Run it to confirm it passes on the OLD implementation first**

Run: `cargo test recover_missing_two_words_still_works_after_refactor -- --nocapture`
Expected: PASS (this proves the test itself is correct before we touch the implementation).

- [ ] **Step 3: Replace `recover_missing` and `recover_typo` with the refactored versions**

Replace the full contents of `src/recovery.rs` with:

```rust
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

    RecoveryResult {
        mnemonic: result_lock.lock().unwrap().take(),
        combinations_tested: outcome.tested,
        elapsed_ms: start.elapsed().as_millis(),
        interrupted: outcome.interrupted,
    }
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

    RecoveryResult {
        mnemonic: result_lock.lock().unwrap().take(),
        combinations_tested: outcome.tested,
        elapsed_ms: start.elapsed().as_millis(),
        interrupted: outcome.interrupted,
    }
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
```

- [ ] **Step 4: Run all recovery + regression tests**

Run: `cargo test recover -- --nocapture`
Expected: `3 passed` (the two original vectors + the new 2-missing-word regression test), all with correct recovered mnemonics.

- [ ] **Step 5: Run the full existing test suite to confirm nothing else broke**

Run: `cargo test`
Expected: all tests pass (lehmer, candidate_space, search, bip39, recovery).

- [ ] **Step 6: Commit**

```bash
git add src/recovery.rs
git commit -m "refactor: rebuild recover_missing/recover_typo on CandidateSpace + chunked runner"
```

---

### Task 6: Combined missing+typo (`MissingTypoSpace`)

**Files:**
- Modify: `src/candidate_space.rs` (add `MissingTypoSpace`)
- Modify: `src/recovery.rs` (add `allow_typo` support, complexity guard, `use` fix from Task 5)

- [ ] **Step 1: Write the failing test for `MissingTypoSpace`**

Add to `src/candidate_space.rs`, above the existing `#[cfg(test)]` block:

```rust
/// Combined missing-words + optional single-typo-among-known-words search.
/// `combined_index = missing_index * typo_choice_space + typo_choice_index`,
/// where `typo_choice_space = 1 + known_positions.len() * 2048` (the `+1`
/// is "no typo, known words exactly as given").
pub struct MissingTypoSpace {
    pub known_indices: Vec<u16>,
    pub missing_positions: Vec<usize>,
    pub known_positions: Vec<usize>,
}

impl MissingTypoSpace {
    fn missing_space_total(&self) -> u64 {
        2048u64.pow(self.missing_positions.len() as u32)
    }

    pub fn typo_choice_space(&self) -> u64 {
        1 + self.known_positions.len() as u64 * 2048
    }
}

impl CandidateSpace for MissingTypoSpace {
    fn total(&self) -> u64 {
        self.missing_space_total() * self.typo_choice_space()
    }

    fn candidate_at(&self, index: u64) -> Vec<u16> {
        let typo_space = self.typo_choice_space();
        let missing_index = index / typo_space;
        let typo_choice_index = index % typo_space;

        let mut out = self.known_indices.clone();
        let m = self.missing_positions.len();
        let mut rem = missing_index;
        for i in (0..m).rev() {
            out[self.missing_positions[i]] = (rem % 2048) as u16;
            rem /= 2048;
        }

        if typo_choice_index > 0 {
            let c = typo_choice_index - 1;
            let which_known = (c / 2048) as usize;
            let which_word = (c % 2048) as u16;
            out[self.known_positions[which_known]] = which_word;
        }
        out
    }
}
```

Add to the `#[cfg(test)] mod tests` block in the same file:

```rust
    #[test]
    fn missing_typo_space_total_matches_formula() {
        // 1 missing position, 11 known positions (12-word seed).
        let space = MissingTypoSpace {
            known_indices: vec![0u16; 12],
            missing_positions: vec![11],
            known_positions: (0..11).collect(),
        };
        // missing_space_total = 2048, typo_choice_space = 1 + 11*2048 = 22529
        assert_eq!(space.total(), 2048 * 22_529);
    }

    #[test]
    fn missing_typo_space_index_zero_is_no_typo_first_missing_fill() {
        let space = MissingTypoSpace {
            known_indices: vec![7u16, 7, 7],
            missing_positions: vec![2],
            known_positions: vec![0, 1],
        };
        // index 0 => missing_index 0 (fills position 2 with word 0),
        // typo_choice_index 0 (no typo).
        assert_eq!(space.candidate_at(0), vec![7, 7, 0]);
    }

    #[test]
    fn missing_typo_space_covers_a_typo_case() {
        let space = MissingTypoSpace {
            known_indices: vec![7u16, 7, 7],
            missing_positions: vec![2],
            known_positions: vec![0, 1],
        };
        let typo_space = space.typo_choice_space(); // 1 + 2*2048 = 4097
        // typo_choice_index = 1 => which_known=0, which_word=0 => position
        // known_positions[0]=0 gets word 0 instead of 7.
        let idx = 0 * typo_space + 1;
        assert_eq!(space.candidate_at(idx), vec![0, 7, 0]);
    }

    #[test]
    fn missing_typo_space_all_distinct_small() {
        let space = MissingTypoSpace {
            known_indices: vec![3u16; 3],
            missing_positions: vec![1],
            known_positions: vec![0, 2],
        };
        let mut seen = HashSet::new();
        for i in 0..space.total() {
            assert!(seen.insert(space.candidate_at(i)));
        }
        assert_eq!(seen.len() as u64, space.total());
    }
```

- [ ] **Step 2: Run to verify these fail (module doesn't exist yet in the right shape)**

Run: `cargo test missing_typo_space -- --nocapture`
Expected: FAIL to compile (`MissingTypoSpace` not found) — confirms the test is exercising new code, not already-passing code.

- [ ] **Step 3: The type is now added above (Step 1 already wrote it) — run again**

Run: `cargo test missing_typo_space -- --nocapture`
Expected: `4 passed`.

- [ ] **Step 4: Wire `allow_typo` into `recover_missing`**

In `src/recovery.rs`:

1. Add `MissingTypoSpace` to the import:

```rust
use crate::candidate_space::{CandidateSpace, MissingSpace, MissingTypoSpace, TypoSpace};
```

2. Add a complexity guard constant near the top of the file (after the `use` block):

```rust
/// Above this many total candidates, a combined missing+typo search is
/// impractical (multi-hour-plus even with validation short-circuiting).
/// Plain `missing` (no --allow-typo) keeps its own existing
/// `missing_positions.len() > 3` guard, unchanged, for regression safety.
const MAX_COMBINED_CANDIDATES: u64 = 500_000_000;
```

3. Add `allow_typo: bool` to `RecoveryRequest`:

```rust
#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub seed_length: usize,
    /// `None` for missing slots, `Some(word)` for known.
    pub words: Vec<Option<String>>,
    pub validation: Option<ValidationConfig>,
    /// When `true`, `recover_missing`/`recover_missing_resumable` also
    /// tries substituting one known word (in addition to filling `?`
    /// slots). Ignored by `recover_typo`/`recover_typo_resumable`.
    pub allow_typo: bool,
}
```

4. Update `resolve_words`'s callers are unaffected (it already returns `known_positions`). Replace the body of `recover_missing_resumable` from the `let space = MissingSpace { ... };` line through the `run_chunked_search(&space, ...)` call with:

```rust
    let combined_total = if req.allow_typo {
        let typo_choice_space = 1 + known_positions.len() as u64 * 2048;
        let missing_total = 2048u64.pow(missing_positions.len() as u32);
        Some(missing_total * typo_choice_space)
    } else {
        None
    };
    if let Some(total) = combined_total {
        if total > MAX_COMBINED_CANDIDATES {
            return RecoveryResult {
                mnemonic: None,
                combinations_tested: 0,
                elapsed_ms: start.elapsed().as_millis(),
                interrupted: false,
            };
        }
    }

    let found = AtomicBool::new(false);
    let result_lock: Mutex<Option<Vec<String>>> = Mutex::new(None);
    let secp = Secp256k1::new();
    let try_candidate = make_try_candidate(&req.validation, &secp, &found, &result_lock);

    let outcome = if req.allow_typo {
        let space = MissingTypoSpace { known_indices, missing_positions, known_positions };
        run_chunked_search(&space, resume_index, &found, stop, try_candidate, on_chunk_complete, progress)
    } else {
        let space = MissingSpace { known_indices, missing_positions };
        run_chunked_search(&space, resume_index, &found, stop, try_candidate, on_chunk_complete, progress)
    };
```

5. In both `#[cfg(test)]` tests inside `recovery.rs` that construct `RecoveryRequest { .. }` (the three existing ones plus the one added in Task 5), add `allow_typo: false,` as a field.

- [ ] **Step 5: Add a test proving combined search finds a 1-missing + 1-typo case**

Add to the `#[cfg(test)] mod tests` block in `src/recovery.rs`:

```rust
    #[test]
    fn recover_missing_allow_typo_finds_combined_error() {
        // 1 missing word (position 11, the "?") AND a typo at position 10
        // ("apple" instead of "abandon") in the same search.
        let mut words: Vec<Option<String>> = vec![Some("abandon".to_string()); 10];
        words.push(Some("apple".to_string())); // typo
        words.push(None); // missing
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
            allow_typo: true,
        };
        let res = recover_missing(&req, |_| {});
        assert!(res.mnemonic.is_some(), "should find the combined match");
        assert_eq!(res.mnemonic.as_ref().unwrap()[10], "abandon");
        assert_eq!(res.mnemonic.as_ref().unwrap()[11], "about");
    }

    #[test]
    fn recover_missing_without_allow_typo_ignores_typo_positions() {
        // Same broken input as above, but allow_typo: false — the search
        // space doesn't cover fixing the typo, so it must NOT find a match
        // (regression: allow_typo: false must behave exactly as before).
        let mut words: Vec<Option<String>> = vec![Some("abandon".to_string()); 10];
        words.push(Some("apple".to_string()));
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
            allow_typo: false,
        };
        let res = recover_missing(&req, |_| {});
        assert!(res.mnemonic.is_none(), "typo-only-fixable case must not match without --allow-typo");
    }
```

- [ ] **Step 6: Run**

Run: `cargo test recover_missing -- --nocapture`
Expected: `4 passed` (one-word, two-word, combined-typo-found, combined-typo-not-found-without-flag).

- [ ] **Step 7: Run the full suite**

Run: `cargo test`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add src/candidate_space.rs src/recovery.rs
git commit -m "feat: add MissingTypoSpace and --allow-typo combined search"
```

---

### Task 7: CLI — `--allow-typo` on `missing`

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Add the flag to the `Missing` variant**

In `src/main.rs`, in the `Command` enum, change the `Missing` variant to add `allow_typo`:

```rust
    /// Recover N missing words at known positions. Use `?` for unknowns.
    Missing {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account_start: u32,
        #[arg(long, default_value_t = 0)]
        account_end: u32,
        #[arg(long, default_value_t = 0)]
        address_start: u32,
        #[arg(long, default_value_t = 9)]
        address_end: u32,
        /// Also try substituting one known word (in addition to filling
        /// `?` slots) — combined missing + typo search.
        #[arg(long)]
        allow_typo: bool,
    },
```

- [ ] **Step 2: Thread it through `main()` and `run_missing`**

In the `match cli.command` block in `main()`, update the `Command::Missing { .. }` arm's destructure and call:

```rust
        Command::Missing {
            mnemonic,
            address,
            passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
            allow_typo,
        } => run_missing(
            &mnemonic,
            address.as_deref(),
            &passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
            allow_typo,
        ),
```

Update `run_missing`'s signature and body to accept and use `allow_typo`:

```rust
fn run_missing(
    mnemonic: &str,
    address: Option<&str>,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
    allow_typo: bool,
) -> Result<()> {
    let words = parse_with_unknowns(mnemonic);
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }
    let missing_count = words.iter().filter(|w| w.is_none()).count();
    if missing_count == 0 {
        return Err(anyhow!(
            "No `?` placeholders. Use the `typo` subcommand for fully-filled seeds."
        ));
    }
    if missing_count > 3 {
        return Err(anyhow!("{missing_count} missing words is impractical."));
    }

    let validation = build_validation(
        address,
        passphrase,
        account_start,
        account_end,
        address_start,
        address_end,
    )?;

    println!(
        "{} Searching {} missing word(s) in a {}-word seed{}{}",
        style("⚙").cyan(),
        missing_count,
        n,
        if validation.is_some() { " with address validation" } else { " (checksum only)" },
        if allow_typo { ", also allowing one typo among known words" } else { "" },
    );

    let known_count = n - missing_count;
    let total: u64 = if allow_typo {
        2048u64.pow(missing_count as u32) * (1 + known_count as u64 * 2048)
    } else {
        2048u64.pow(missing_count as u32)
    };
    let pb = make_progress_bar(total);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(0));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let req = RecoveryRequest { seed_length: n, words, validation, allow_typo };
    let result = recover_missing(&req, progress);
    pb.finish_with_message("done");

    print_result(result.mnemonic, result.combinations_tested, result.elapsed_ms)
}
```

Also update the `use seedcrypt_recover::{ ... }` import line at the top of `main.rs` — it currently imports `recover_missing, recover_typo`. Leave as-is for now (Task 13 will extend it further); this task only needs `RecoveryRequest` to accept the new `allow_typo` field, which it already does from Task 6.

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: compiles. If `total` overflows the `500_000_000` guard silently instead of erroring at the CLI layer, that's fine for now — `recover_missing_resumable`'s internal guard (Task 6, Step 4) already returns an empty result rather than running forever; a friendlier CLI-level error message is a nice-to-have but not required by the spec, so it's intentionally left as "runs the progress bar to 0% then reports no match" for now.

- [ ] **Step 4: Manual smoke test**

Run:
```bash
cargo run -- missing \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon apple ?" \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 \
  --allow-typo
```
Expected output ends with:
```
═══ SEED FOUND ═══

  Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(cli): add --allow-typo flag to missing subcommand"
```

---

### Task 8: `ReorderSpace` + `recover_reorder`

**Files:**
- Modify: `src/candidate_space.rs` (add `ReorderSpace`)
- Modify: `src/recovery.rs` (add `recover_reorder`/`recover_reorder_resumable`)

- [ ] **Step 1: Write the failing test for `ReorderSpace`**

Add to `src/candidate_space.rs`, after `MissingTypoSpace`:

```rust
/// Wrong-order recovery: all words known, but the words at
/// `permute_positions` might be in the wrong order among themselves. Every
/// other position is fixed.
pub struct ReorderSpace {
    pub base_indices: Vec<u16>,
    pub permute_positions: Vec<usize>,
}

impl CandidateSpace for ReorderSpace {
    fn total(&self) -> u64 {
        crate::lehmer::factorial(self.permute_positions.len() as u64)
    }

    fn candidate_at(&self, index: u64) -> Vec<u16> {
        let subset: Vec<u16> = self
            .permute_positions
            .iter()
            .map(|&p| self.base_indices[p])
            .collect();
        let permuted = crate::lehmer::nth_permutation(&subset, index);
        let mut out = self.base_indices.clone();
        for (i, &pos) in self.permute_positions.iter().enumerate() {
            out[pos] = permuted[i];
        }
        out
    }
}
```

Add to the `#[cfg(test)]` block:

```rust
    #[test]
    fn reorder_space_total_is_factorial_of_subset_size() {
        let space = ReorderSpace {
            base_indices: vec![1u16, 2, 3, 4, 5],
            permute_positions: vec![1, 2, 4],
        };
        assert_eq!(space.total(), 6); // 3!
    }

    #[test]
    fn reorder_space_only_touches_marked_positions() {
        let space = ReorderSpace {
            base_indices: vec![10u16, 20, 30, 40],
            permute_positions: vec![1, 3],
        };
        for i in 0..space.total() {
            let c = space.candidate_at(i);
            assert_eq!(c[0], 10);
            assert_eq!(c[2], 30);
            // positions 1 and 3 together always contain {20, 40}
            let mut pair = vec![c[1], c[3]];
            pair.sort();
            assert_eq!(pair, vec![20, 40]);
        }
    }

    #[test]
    fn reorder_space_all_distinct() {
        let space = ReorderSpace {
            base_indices: vec![1u16, 2, 3, 4],
            permute_positions: vec![0, 1, 2, 3],
        };
        let mut seen = HashSet::new();
        for i in 0..space.total() {
            assert!(seen.insert(space.candidate_at(i)));
        }
        assert_eq!(seen.len() as u64, 24); // 4!
    }
```

- [ ] **Step 2: Run**

Run: `cargo test reorder_space -- --nocapture`
Expected: `3 passed`.

- [ ] **Step 3: Add `recover_reorder`/`recover_reorder_resumable` to `src/recovery.rs`**

Add near the end of `src/recovery.rs`, after `recover_typo_resumable` and before the `#[cfg(test)]` block:

```rust
/// Wrong-order recovery: `permute_positions` (0-indexed) marks the
/// positions whose words might be in the wrong order among themselves.
/// Guarded to `2..=10` positions by the caller (CLI layer) — 10! ≈ 3.6M is
/// the practical ceiling for this mode.
pub fn recover_reorder(
    words: &[String],
    permute_positions: Vec<usize>,
    validation: Option<ValidationConfig>,
    progress: impl Fn(u64) + Sync + Send,
) -> RecoveryResult {
    recover_reorder_resumable(words, permute_positions, validation, 0, &AtomicBool::new(false), progress, |_| {})
}

/// Same as `recover_reorder`, plus resume support.
pub fn recover_reorder_resumable(
    words: &[String],
    permute_positions: Vec<usize>,
    validation: Option<ValidationConfig>,
    resume_index: u64,
    stop: &AtomicBool,
    progress: impl Fn(u64) + Sync + Send,
    on_chunk_complete: impl FnMut(u64),
) -> RecoveryResult {
    let start = std::time::Instant::now();
    let map = word_index();
    let mut base_indices = Vec::with_capacity(words.len());
    for w in words {
        match map.get(w.as_str()) {
            Some(&idx) => base_indices.push(idx),
            None => {
                return RecoveryResult { mnemonic: None, combinations_tested: 0, elapsed_ms: start.elapsed().as_millis(), interrupted: false };
            }
        }
    }

    let space = ReorderSpace { base_indices, permute_positions };
    let found = AtomicBool::new(false);
    let result_lock: Mutex<Option<Vec<String>>> = Mutex::new(None);
    let secp = Secp256k1::new();
    let try_candidate = make_try_candidate(&validation, &secp, &found, &result_lock);

    let outcome = run_chunked_search(&space, resume_index, &found, stop, try_candidate, on_chunk_complete, progress);

    RecoveryResult {
        mnemonic: result_lock.lock().unwrap().take(),
        combinations_tested: outcome.tested,
        elapsed_ms: start.elapsed().as_millis(),
        interrupted: outcome.interrupted,
    }
}
```

Update the `use crate::candidate_space::{...}` import line at the top of the file to include `ReorderSpace`:

```rust
use crate::candidate_space::{CandidateSpace, MissingSpace, MissingTypoSpace, ReorderSpace, TypoSpace};
```

- [ ] **Step 4: Add an integration test using the abandon…about vector with two swapped words**

Add to the `#[cfg(test)] mod tests` block in `src/recovery.rs`:

```rust
    #[test]
    fn recover_reorder_swaps_two_words_back() {
        // Real seed: abandon×11 + about. Swap positions 10 and 11 (0-indexed)
        // so the mnemonic is given as abandon×10 + about + abandon — wrong
        // order, all words individually valid BIP39 words.
        let words: Vec<String> = vec![
            "abandon".into(), "abandon".into(), "abandon".into(), "abandon".into(),
            "abandon".into(), "abandon".into(), "abandon".into(), "abandon".into(),
            "abandon".into(), "abandon".into(),
            "about".into(),   // ← swapped
            "abandon".into(), // ← swapped
        ];
        let validation = Some(ValidationConfig {
            address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".into(),
            kind: DerivationType::EthereumStandard,
            passphrase: String::new(),
            account_start: 0,
            account_end: 0,
            address_start: 0,
            address_end: 0,
        });
        let res = recover_reorder(&words, vec![10, 11], validation, |_| {});
        assert!(res.mnemonic.is_some(), "should find the correct order");
        let m = res.mnemonic.unwrap();
        assert_eq!(m[10], "abandon");
        assert_eq!(m[11], "about");
    }
```

- [ ] **Step 5: Run**

Run: `cargo test recover_reorder -- --nocapture`
Expected: `1 passed`.

- [ ] **Step 6: Run the full suite**

Run: `cargo test`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/candidate_space.rs src/recovery.rs
git commit -m "feat: add ReorderSpace and recover_reorder for wrong-order recovery"
```

---

### Task 9: CLI — `reorder` subcommand

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Add the `Reorder` variant**

In `src/main.rs`, add to the `Command` enum (after `Typo`):

```rust
    /// Recover the correct order of a subset of positions whose words are
    /// known but possibly shuffled. All other positions are fixed.
    Reorder {
        #[arg(long)]
        mnemonic: String,
        /// 1-indexed, comma-separated positions to permute (e.g. 3,7,9,10).
        /// 2-10 positions.
        #[arg(long, value_delimiter = ',')]
        permute_positions: Vec<usize>,
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account_start: u32,
        #[arg(long, default_value_t = 0)]
        account_end: u32,
        #[arg(long, default_value_t = 0)]
        address_start: u32,
        #[arg(long, default_value_t = 9)]
        address_end: u32,
    },
```

- [ ] **Step 2: Wire it into `main()` and add `run_reorder`**

In the `match cli.command` block:

```rust
        Command::Reorder {
            mnemonic,
            permute_positions,
            address,
            passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
        } => run_reorder(
            &mnemonic,
            permute_positions,
            &address,
            &passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
        ),
```

Add the function (after `run_typo`, before `print_result`):

```rust
fn run_reorder(
    mnemonic: &str,
    permute_positions_1indexed: Vec<usize>,
    address: &str,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
) -> Result<()> {
    let words: Vec<String> = mnemonic.split_whitespace().map(|w| w.to_ascii_lowercase()).collect();
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }

    let k = permute_positions_1indexed.len();
    if k < 2 {
        return Err(anyhow!("--permute-positions needs at least 2 positions (got {k})"));
    }
    if k > 10 {
        return Err(anyhow!(
            "--permute-positions has {k} positions ({k}! candidates) — impractical. Narrow it to 10 or fewer."
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let mut permute_positions = Vec::with_capacity(k);
    for &p in &permute_positions_1indexed {
        if p == 0 || p > n {
            return Err(anyhow!("Position {p} is out of range for a {n}-word seed (must be 1..={n})"));
        }
        if !seen.insert(p) {
            return Err(anyhow!("Position {p} listed more than once in --permute-positions"));
        }
        permute_positions.push(p - 1); // convert to 0-indexed
    }

    let validation = build_validation(
        Some(address),
        passphrase,
        account_start,
        account_end,
        address_start,
        address_end,
    )?
    .ok_or_else(|| anyhow!("reorder recovery requires --address"))?;

    println!(
        "{} Searching {} permutation(s) of {} marked position(s) in a {}-word seed against {}",
        style("⚙").cyan(),
        seedcrypt_recover::lehmer::factorial(k as u64),
        k,
        n,
        style(&validation.address).yellow(),
    );

    let total = seedcrypt_recover::lehmer::factorial(k as u64);
    let pb = make_progress_bar(total);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(0));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let result = recover_reorder(&words, permute_positions, Some(validation), progress);
    pb.finish_with_message("done");

    print_result(result.mnemonic, result.combinations_tested, result.elapsed_ms)
}
```

Update the `use seedcrypt_recover::{ ... };` import block at the top of `main.rs` to add `recover_reorder`:

```rust
use seedcrypt_recover::{
    address::detect,
    recovery::{recover_missing, recover_typo, recover_reorder, RecoveryRequest, ValidationConfig},
};
```

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: compiles cleanly.

- [ ] **Step 4: Manual smoke test**

Run:
```bash
cargo run -- reorder \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon" \
  --permute-positions 11,12 \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```
Expected output ends with:
```
═══ SEED FOUND ═══

  Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

- [ ] **Step 5: Manual smoke test for the >10 guard**

Run:
```bash
cargo run -- reorder \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --permute-positions 1,2,3,4,5,6,7,8,9,10,11 \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```
Expected: `Error: --permute-positions has 11 positions (11! candidates) — impractical. Narrow it to 10 or fewer.`

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat(cli): add reorder subcommand for wrong-order recovery"
```

---

### Task 10: Checkpoint module

**Files:**
- Create: `src/checkpoint.rs`
- Modify: `src/lib.rs` (add `pub mod checkpoint;`)

- [ ] **Step 1: Write the failing tests**

Create `src/checkpoint.rs`:

```rust
//! Checkpoint file: lets a long-running search survive a crash, Ctrl+C, or
//! reboot. Stores a signature of the search parameters (so `--resume`
//! refuses to continue into a mismatched search) plus a resume index.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub mode: String,
    pub mnemonic_pattern: String,
    pub address: String,
    /// SHA-256 hex digest of the passphrase — never the plaintext, so a
    /// checkpoint file doesn't carry an extra copy of a sensitive value.
    pub passphrase_hash: String,
    pub account_start: u32,
    pub account_end: u32,
    pub address_start: u32,
    pub address_end: u32,
    pub resume_index: u64,
    pub total_candidates: u64,
    pub elapsed_ms_so_far: u128,
}

pub fn hash_passphrase(passphrase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hex::encode(hasher.finalize())
}

impl Checkpoint {
    /// True if `other`'s search parameters (everything except the mutable
    /// progress fields) match this checkpoint's.
    pub fn matches_signature(&self, other: &Checkpoint) -> bool {
        self.mode == other.mode
            && self.mnemonic_pattern == other.mnemonic_pattern
            && self.address == other.address
            && self.passphrase_hash == other.passphrase_hash
            && self.account_start == other.account_start
            && self.account_end == other.account_end
            && self.address_start == other.address_start
            && self.address_end == other.address_end
    }

    /// Atomic write: write to a `.tmp` sibling then rename over the target,
    /// so a crash mid-write never leaves a corrupt checkpoint on disk.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("Could not serialize checkpoint: {e}"))?;
        let tmp_path = path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp_path)
                .map_err(|e| anyhow!("Could not create {}: {e}", tmp_path.display()))?;
            f.write_all(json.as_bytes())
                .map_err(|e| anyhow!("Could not write {}: {e}", tmp_path.display()))?;
            f.sync_all().ok();
        }
        fs::rename(&tmp_path, path)
            .map_err(|e| anyhow!("Could not finalize checkpoint at {}: {e}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Checkpoint> {
        let data = fs::read_to_string(path)
            .map_err(|e| anyhow!("Could not read checkpoint {}: {e}", path.display()))?;
        serde_json::from_str(&data)
            .map_err(|e| anyhow!("Checkpoint file {} is corrupt or from an incompatible version: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(resume_index: u64) -> Checkpoint {
        Checkpoint {
            mode: "missing".into(),
            mnemonic_pattern: "abandon abandon ?".into(),
            address: "0xdead".into(),
            passphrase_hash: hash_passphrase(""),
            account_start: 0,
            account_end: 0,
            address_start: 0,
            address_end: 9,
            resume_index,
            total_candidates: 2048,
            elapsed_ms_so_far: 1234,
        }
    }

    #[test]
    fn hash_passphrase_is_deterministic_and_not_plaintext() {
        let h1 = hash_passphrase("correct horse battery staple");
        let h2 = hash_passphrase("correct horse battery staple");
        assert_eq!(h1, h2);
        assert_ne!(h1, "correct horse battery staple");
        assert_eq!(h1.len(), 64); // hex-encoded SHA-256
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("seedcrypt-recover-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("checkpoint_round_trip.json");

        let cp = sample(500);
        cp.save(&path).unwrap();
        let loaded = Checkpoint::load(&path).unwrap();
        assert_eq!(cp, loaded);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn matches_signature_ignores_progress_fields() {
        let a = sample(100);
        let b = sample(99_999); // different resume_index / progress
        assert!(a.matches_signature(&b));
    }

    #[test]
    fn matches_signature_detects_address_mismatch() {
        let a = sample(0);
        let mut b = sample(0);
        b.address = "0xbeef".into();
        assert!(!a.matches_signature(&b));
    }

    #[test]
    fn load_missing_file_gives_clear_error() {
        let path = std::env::temp_dir().join("seedcrypt-recover-definitely-does-not-exist.json");
        let err = Checkpoint::load(&path).unwrap_err();
        assert!(err.to_string().contains("Could not read checkpoint"));
    }

    #[test]
    fn load_corrupt_file_gives_clear_error() {
        let dir = std::env::temp_dir().join(format!("seedcrypt-recover-test-corrupt-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("corrupt.json");
        fs::write(&path, "not valid json{{{").unwrap();

        let err = Checkpoint::load(&path).unwrap_err();
        assert!(err.to_string().contains("corrupt"));

        fs::remove_file(&path).ok();
    }
}
```

- [ ] **Step 2: Register the module**

In `src/lib.rs`:

```rust
pub mod bip39;
pub mod bip32;
pub mod address;
pub mod lehmer;
pub mod candidate_space;
pub mod search;
pub mod checkpoint;
pub mod recovery;
```

- [ ] **Step 3: Run**

Run: `cargo test checkpoint:: -- --nocapture`
Expected: `6 passed`.

- [ ] **Step 4: Commit**

```bash
git add src/checkpoint.rs src/lib.rs
git commit -m "feat: add checkpoint save/load with signature verification"
```

---

### Task 11: CLI — `--checkpoint`/`--resume` on all three subcommands + Ctrl+C

**Files:**
- Modify: `src/main.rs`
- Modify: `Cargo.toml` isn't needed further (ctrlc already added in Task 1)

This is the integration task: wiring the checkpoint module and a `ctrlc`-driven stop flag into the three `run_*` functions.

- [ ] **Step 1: Add `--checkpoint`/`--resume` flags to all three `Command` variants**

In `src/main.rs`, add these two fields to `Missing`, `Typo`, and `Reorder` (each gets both):

```rust
        /// Save progress here periodically; on interrupt, resume with
        /// `--resume <this path>`. Mutually exclusive with --resume.
        #[arg(long, conflicts_with = "resume")]
        checkpoint: Option<String>,
        /// Continue a search from a checkpoint written by --checkpoint.
        /// Refuses to proceed if the checkpoint's search parameters don't
        /// match this invocation's. Mutually exclusive with --checkpoint.
        #[arg(long, conflicts_with = "checkpoint")]
        resume: Option<String>,
```

(`Typo` doesn't have `allow_typo`, so its final field list is `..., checkpoint, resume`. `Missing` and `Reorder` each get `..., allow_typo (Missing only), checkpoint, resume`.)

- [ ] **Step 2: Add a shared helper for the checkpoint/resume/ctrlc plumbing**

Add near the top of `src/main.rs`, after the existing `use` block:

```rust
use seedcrypt_recover::checkpoint::{hash_passphrase, Checkpoint};
use std::path::PathBuf;
```

Add this helper function (after `make_progress_bar`, before `run_missing`):

```rust
/// Resolves the starting index for a search: 0 for a fresh run, or the
/// saved index from `--resume`'s checkpoint after verifying its signature
/// matches the *expected* signature for this invocation. Errors out (does
/// not silently guess) on any mismatch or unreadable/corrupt file.
fn resolve_resume_index(resume_path: Option<&str>, expected: &Checkpoint) -> Result<u64> {
    let Some(path) = resume_path else { return Ok(0) };
    let loaded = Checkpoint::load(&PathBuf::from(path))?;
    if !loaded.matches_signature(expected) {
        return Err(anyhow!(
            "Checkpoint at {path} was saved for a different search (mode/mnemonic/address/passphrase/derivation config don't match this invocation). Refusing to resume."
        ));
    }
    println!(
        "{} Resuming from checkpoint: {}/{} candidates already tested ({:.1}s elapsed so far)",
        style("↻").cyan(),
        loaded.resume_index,
        loaded.total_candidates,
        loaded.elapsed_ms_so_far as f64 / 1000.0,
    );
    Ok(loaded.resume_index)
}

/// Installs a Ctrl+C handler that flips the returned `Arc<AtomicBool>` on
/// the first SIGINT. Safe to call once per process (subsequent Ctrl+C
/// presses during an in-flight write are a no-op past the first).
fn install_stop_flag() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    // Best-effort: if a handler is somehow already installed (shouldn't
    // happen — each subcommand run installs exactly one), ignore the error
    // rather than panic the whole CLI over a non-essential guard.
    let _ = ctrlc::set_handler(move || {
        stop_clone.store(true, Ordering::Relaxed);
    });
    stop
}

/// Writes (or overwrites) the checkpoint at `path` with the given progress.
/// Logs a warning instead of failing the whole search if the write fails
/// (e.g. disk full, permissions) — losing a checkpoint write is much less
/// bad than losing the whole search to a hard error mid-run.
fn checkpoint_writer(
    path: Option<String>,
    base: Checkpoint,
    start: std::time::Instant,
) -> impl FnMut(u64) {
    move |resume_index: u64| {
        let Some(path) = &path else { return };
        let mut cp = base.clone();
        cp.resume_index = resume_index;
        cp.elapsed_ms_so_far = start.elapsed().as_millis();
        if let Err(e) = cp.save(&PathBuf::from(path)) {
            eprintln!("{} Could not write checkpoint: {e}", style("⚠").yellow());
        }
    }
}
```

- [ ] **Step 3: Wire `run_missing`**

Replace `run_missing`'s signature and body with:

```rust
fn run_missing(
    mnemonic: &str,
    address: Option<&str>,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
    allow_typo: bool,
    checkpoint_path: Option<String>,
    resume_path: Option<String>,
) -> Result<()> {
    let words = parse_with_unknowns(mnemonic);
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }
    let missing_count = words.iter().filter(|w| w.is_none()).count();
    if missing_count == 0 {
        return Err(anyhow!(
            "No `?` placeholders. Use the `typo` subcommand for fully-filled seeds."
        ));
    }
    if missing_count > 3 {
        return Err(anyhow!("{missing_count} missing words is impractical."));
    }

    let validation = build_validation(address, passphrase, account_start, account_end, address_start, address_end)?;

    println!(
        "{} Searching {} missing word(s) in a {}-word seed{}{}",
        style("⚙").cyan(),
        missing_count,
        n,
        if validation.is_some() { " with address validation" } else { " (checksum only)" },
        if allow_typo { ", also allowing one typo among known words" } else { "" },
    );

    let known_count = n - missing_count;
    let total: u64 = if allow_typo {
        2048u64.pow(missing_count as u32) * (1 + known_count as u64 * 2048)
    } else {
        2048u64.pow(missing_count as u32)
    };

    let expected_sig = Checkpoint {
        mode: "missing".into(),
        mnemonic_pattern: mnemonic.to_string(),
        address: address.unwrap_or("").to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let resume_index = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

    let pb = make_progress_bar(total);
    pb.set_position(resume_index);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(resume_index));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        checkpoint_path.or(resume_path),
        expected_sig,
        std::time::Instant::now(),
    );

    let req = RecoveryRequest { seed_length: n, words, validation, allow_typo };
    let result = seedcrypt_recover::recovery::recover_missing_resumable(
        &req, resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish_with_message(if result.interrupted { "interrupted" } else { "done" });

    if result.interrupted {
        eprintln!(
            "\n{} Interrupted. Resume with:\n  seedcrypt-recover missing --mnemonic \"{mnemonic}\" {} --resume <checkpoint path>",
            style("⏸").yellow(),
            address.map(|a| format!("--address {a}")).unwrap_or_default(),
        );
        std::process::exit(130);
    }

    print_result(result.mnemonic, result.combinations_tested, result.elapsed_ms)
}
```

Update the `Command::Missing { .. }` match arm in `main()` to destructure and pass the two new fields:

```rust
        Command::Missing {
            mnemonic, address, passphrase, account_start, account_end,
            address_start, address_end, allow_typo, checkpoint, resume,
        } => run_missing(
            &mnemonic, address.as_deref(), &passphrase, account_start, account_end,
            address_start, address_end, allow_typo, checkpoint, resume,
        ),
```

- [ ] **Step 4: Wire `run_typo`**

Replace `run_typo`'s signature and body with:

```rust
fn run_typo(
    mnemonic: &str,
    address: &str,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
    checkpoint_path: Option<String>,
    resume_path: Option<String>,
) -> Result<()> {
    let words: Vec<Option<String>> = mnemonic.split_whitespace().map(|w| Some(w.to_ascii_lowercase())).collect();
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }
    let validation = build_validation(Some(address), passphrase, account_start, account_end, address_start, address_end)?
        .ok_or_else(|| anyhow!("Typo recovery requires --address"))?;

    println!(
        "{} Searching for one typo in a {}-word seed against {}",
        style("⚙").cyan(), n, style(&validation.address).yellow(),
    );

    let total = (n as u64) * 2048;

    let expected_sig = Checkpoint {
        mode: "typo".into(),
        mnemonic_pattern: mnemonic.to_string(),
        address: address.to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let resume_index = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

    let pb = make_progress_bar(total);
    pb.set_position(resume_index);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(resume_index));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        checkpoint_path.or(resume_path),
        expected_sig,
        std::time::Instant::now(),
    );

    let req = RecoveryRequest { seed_length: n, words, validation: Some(validation), allow_typo: false };
    let result = seedcrypt_recover::recovery::recover_typo_resumable(
        &req, resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish_with_message(if result.interrupted { "interrupted" } else { "done" });

    if result.interrupted {
        eprintln!(
            "\n{} Interrupted. Resume with:\n  seedcrypt-recover typo --mnemonic \"{mnemonic}\" --address {address} --resume <checkpoint path>",
            style("⏸").yellow(),
        );
        std::process::exit(130);
    }

    print_result(result.mnemonic, result.combinations_tested, result.elapsed_ms)
}
```

Update the `Command::Typo { .. }` match arm:

```rust
        Command::Typo {
            mnemonic, address, passphrase, account_start, account_end,
            address_start, address_end, checkpoint, resume,
        } => run_typo(
            &mnemonic, &address, &passphrase, account_start, account_end,
            address_start, address_end, checkpoint, resume,
        ),
```

- [ ] **Step 5: Wire `run_reorder`**

Replace `run_reorder`'s signature and body with:

```rust
fn run_reorder(
    mnemonic: &str,
    permute_positions_1indexed: Vec<usize>,
    address: &str,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
    checkpoint_path: Option<String>,
    resume_path: Option<String>,
) -> Result<()> {
    let words: Vec<String> = mnemonic.split_whitespace().map(|w| w.to_ascii_lowercase()).collect();
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }

    let k = permute_positions_1indexed.len();
    if k < 2 {
        return Err(anyhow!("--permute-positions needs at least 2 positions (got {k})"));
    }
    if k > 10 {
        return Err(anyhow!("--permute-positions has {k} positions ({k}! candidates) — impractical. Narrow it to 10 or fewer."));
    }
    let mut seen = std::collections::HashSet::new();
    let mut permute_positions = Vec::with_capacity(k);
    for &p in &permute_positions_1indexed {
        if p == 0 || p > n {
            return Err(anyhow!("Position {p} is out of range for a {n}-word seed (must be 1..={n})"));
        }
        if !seen.insert(p) {
            return Err(anyhow!("Position {p} listed more than once in --permute-positions"));
        }
        permute_positions.push(p - 1);
    }

    let validation = build_validation(Some(address), passphrase, account_start, account_end, address_start, address_end)?
        .ok_or_else(|| anyhow!("reorder recovery requires --address"))?;

    let total = seedcrypt_recover::lehmer::factorial(k as u64);
    println!(
        "{} Searching {total} permutation(s) of {k} marked position(s) in a {n}-word seed against {}",
        style("⚙").cyan(), style(&validation.address).yellow(),
    );

    let permute_positions_str = permute_positions_1indexed.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let expected_sig = Checkpoint {
        mode: "reorder".into(),
        mnemonic_pattern: format!("{mnemonic}|permute:{permute_positions_str}"),
        address: address.to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let resume_index = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

    let pb = make_progress_bar(total);
    pb.set_position(resume_index);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(resume_index));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        checkpoint_path.or(resume_path),
        expected_sig,
        std::time::Instant::now(),
    );

    let result = seedcrypt_recover::recovery::recover_reorder_resumable(
        &words, permute_positions, Some(validation), resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish_with_message(if result.interrupted { "interrupted" } else { "done" });

    if result.interrupted {
        eprintln!(
            "\n{} Interrupted. Resume with:\n  seedcrypt-recover reorder --mnemonic \"{mnemonic}\" --permute-positions {permute_positions_str} --address {address} --resume <checkpoint path>",
            style("⏸").yellow(),
        );
        std::process::exit(130);
    }

    print_result(result.mnemonic, result.combinations_tested, result.elapsed_ms)
}
```

Update the `Command::Reorder { .. }` match arm:

```rust
        Command::Reorder {
            mnemonic, permute_positions, address, passphrase, account_start,
            account_end, address_start, address_end, checkpoint, resume,
        } => run_reorder(
            &mnemonic, permute_positions, &address, &passphrase, account_start,
            account_end, address_start, address_end, checkpoint, resume,
        ),
```

- [ ] **Step 6: Consolidate the imports**

`main.rs` now calls the `_resumable` variants exclusively via their fully-qualified `seedcrypt_recover::recovery::` path (see Steps 3-5 above), so the plain `use ... recovery::{recover_missing, recover_typo}` names from the original file are now unused, and the standalone `use seedcrypt_recover::checkpoint::{hash_passphrase, Checkpoint};` line added in Step 2 needs to move into the same block instead of staying separate (two `use` paths naming the same items would fail to compile with "the name `Checkpoint` is defined multiple times").

**Delete** the standalone import line added in Step 2:

```rust
use seedcrypt_recover::checkpoint::{hash_passphrase, Checkpoint};
```

(leave the `use std::path::PathBuf;` line from Step 2 as-is — that one stays).

Then **replace** the original top-of-file import block — the one that has read `use seedcrypt_recover::{ address::detect, recovery::{recover_missing, recover_typo, recover_reorder, RecoveryRequest, ValidationConfig}, };` since Task 9 — with:

```rust
use seedcrypt_recover::{
    address::detect,
    checkpoint::{hash_passphrase, Checkpoint},
    recovery::{RecoveryRequest, ValidationConfig},
};
```

Run: `cargo build`
Expected: compiles cleanly, no warnings about unused imports.

- [ ] **Step 7: Manual smoke test — fresh checkpoint then resume**

Run a small search with `--checkpoint` (using `missing` with 1 missing word — completes almost instantly, so instead simulate interrupt-and-resume manually by resuming from a hand-crafted checkpoint file):

```bash
mkdir -p /tmp/seedcrypt-test
cat > /tmp/seedcrypt-test/cp.json <<'EOF'
{
  "mode": "missing",
  "mnemonic_pattern": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
  "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
  "passphrase_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "account_start": 0, "account_end": 0, "address_start": 0, "address_end": 9,
  "resume_index": 0, "total_candidates": 2048, "elapsed_ms_so_far": 0
}
EOF
```

Note: `passphrase_hash` above must exactly equal `hash_passphrase("")`, which is the well-known SHA-256 of the empty string: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

```bash
cargo run -- missing \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?" \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 \
  --resume /tmp/seedcrypt-test/cp.json
```
Expected: prints `Resuming from checkpoint: 0/2048 candidates already tested (0.0s elapsed so far)`, then finds the seed as usual (this particular checkpoint has `resume_index: 0`, so it's really just proving the load-and-continue path works end-to-end, not skipping anything).

- [ ] **Step 8: Manual smoke test — signature mismatch is rejected**

```bash
cargo run -- missing \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?" \
  --address 0x0000000000000000000000000000000000dEaD \
  --resume /tmp/seedcrypt-test/cp.json
```
Expected: `Error: Checkpoint at /tmp/seedcrypt-test/cp.json was saved for a different search (...). Refusing to resume.`

- [ ] **Step 9: Manual smoke test — Ctrl+C on a long search writes a resumable checkpoint**

Run a search large enough to take a few seconds (2 missing words, no address validation so it can't short-circuit early):

```bash
cargo run --release -- missing \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ? ?" \
  --checkpoint /tmp/seedcrypt-test/cp2.json
```
While it's running, press Ctrl+C. Expected: prints `Interrupted. Resume with: ...`, exits with code 130 (verify via `echo $?`), and `/tmp/seedcrypt-test/cp2.json` exists and is valid JSON (`cat /tmp/seedcrypt-test/cp2.json` shows a `resume_index` greater than 0 if at least one chunk completed before the interrupt — for a small 2-missing-word search this may complete before you can Ctrl+C in time; if so, that's fine, it proves the happy path instead).

- [ ] **Step 10: Run the full test suite**

Run: `cargo test`
Expected: all tests pass.

- [ ] **Step 11: Commit**

```bash
git add src/main.rs
git commit -m "feat(cli): wire --checkpoint/--resume and Ctrl+C handling into all subcommands"
```

---

### Task 12: README updates

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the Status section**

In `README.md`, replace:

```markdown
## Status

- ✅ BIP39 mnemonic checksum + 12/15/18/21/24-word seeds
- ✅ HD derivation (BIP32) for BIP44, BIP49, BIP84, BIP86
- ✅ Missing-word recovery (1–3 words at known positions)
- ✅ Typo correction (1 word wrong, position unknown)
- ✅ Address-based validation (early exit on match)
- ✅ Multi-core parallel search via rayon
- ⏳ Wrong-order recovery (permutations) — not yet
- ⏳ Multi-language wordlists — English only
```

with:

```markdown
## Status

- ✅ BIP39 mnemonic checksum + 12/15/18/21/24-word seeds
- ✅ HD derivation (BIP32) for BIP44, BIP49, BIP84, BIP86
- ✅ Missing-word recovery (1–3 words at known positions)
- ✅ Typo correction (1 word wrong, position unknown)
- ✅ Combined missing + typo (`missing --allow-typo`)
- ✅ Wrong-order recovery — `reorder`, up to 10 permuted positions
- ✅ Checkpoint/resume — `--checkpoint`/`--resume`, survives crash/Ctrl+C/reboot
- ✅ Address-based validation (early exit on match)
- ✅ Multi-core parallel search via rayon
- ⏳ Multi-language wordlists — English only
```

- [ ] **Step 2: Add usage examples**

In `README.md`, after the existing "### Typo correction" section and before "### With BIP39 passphrase", add:

```markdown
### Combined missing word + typo

```bash
seedcrypt-recover missing \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon apple ?" \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 \
  --allow-typo
```

Fills the `?` **and** tolerates one typo among the words you did type in — for
when you're not sure a missing word is the *only* thing wrong.

### Wrong order

```bash
seedcrypt-recover reorder \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon" \
  --permute-positions 11,12 \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

All 12 words are correct, but you suspect positions 11 and 12 (1-indexed)
got swapped. `--permute-positions` takes 2–10 positions — the tool tries
every ordering of just those words, leaving the rest fixed. (12! full-seed
permutations is infeasible; marking only the positions you actually suspect
keeps the search tractable.)

### Resuming a long search

```bash
# Start, checkpointing every ~100k candidates:
seedcrypt-recover missing --mnemonic "... ? ? ?" --address 0x... \
  --checkpoint progress.json

# If it's interrupted (Ctrl+C, crash, reboot), continue with:
seedcrypt-recover missing --mnemonic "... ? ? ?" --address 0x... \
  --resume progress.json
```

`--resume` refuses to continue if the mnemonic pattern, address, passphrase,
or derivation settings don't match what's in the checkpoint — it won't
silently resume into the wrong search.
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document reorder, --allow-typo, and --checkpoint/--resume"
```

---

### Task 13: Version bump and final verification

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Bump the version**

In `Cargo.toml`, change:

```toml
version = "0.1.0"
```

to:

```toml
version = "0.2.0"
```

- [ ] **Step 2: Full clean test run**

Run: `cargo test`
Expected: every test across every module passes — `lehmer`, `candidate_space`, `search`, `checkpoint`, `bip39`, `recovery` (including the new combined/reorder/regression tests), plus the doc-comment examples if any run as doctests.

- [ ] **Step 3: Release build sanity check**

Run: `cargo build --release`
Expected: compiles cleanly (this is the profile with `lto = "fat"`, `panic = "abort"`, `strip = true` — worth confirming it still builds under those settings after all the new code).

- [ ] **Step 4: Re-run the README's original examples to confirm zero regression**

```bash
./target/release/seedcrypt-recover missing \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?" \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```
Expected: finds `about` as the 12th word, exactly as documented before this plan.

```bash
./target/release/seedcrypt-recover typo \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandun about" \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```
Expected: finds the corrected mnemonic with `abandon` at position 11, exactly as documented before this plan.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml
git commit -m "chore: bump version to 0.2.0"
```

---

## Summary of new public API surface

- `seedcrypt_recover::lehmer::{factorial, nth_permutation}`
- `seedcrypt_recover::candidate_space::{CandidateSpace, MissingSpace, TypoSpace, MissingTypoSpace, ReorderSpace}`
- `seedcrypt_recover::search::{run_chunked_search, SearchOutcome, CHUNK_SIZE}`
- `seedcrypt_recover::checkpoint::{Checkpoint, hash_passphrase}`
- `seedcrypt_recover::recovery::{recover_missing_resumable, recover_typo_resumable, recover_reorder, recover_reorder_resumable, RecoveryRequest::allow_typo, RecoveryResult::interrupted}`
- CLI: `seedcrypt-recover reorder`, `missing --allow-typo`, `--checkpoint`/`--resume` on all three subcommands.
