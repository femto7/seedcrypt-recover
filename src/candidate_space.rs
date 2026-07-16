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
    /// `2048^missing_positions.len()`. Callers must keep
    /// `missing_positions.len()` small (in practice `<= 3-4`, matching the
    /// CLI's own guard on the `missing` subcommand) — since 2048 == 2^11,
    /// `len() >= 6` means `11 * len() >= 66`, which exceeds 64 bits and
    /// silently wraps (rather than panicking or erroring) because this
    /// crate's release profile does not enable `overflow-checks`. This
    /// matters for callers going through the `cdylib` FFI surface directly,
    /// which aren't protected by the CLI's guard.
    fn total(&self) -> u64 {
        2048u64.pow(self.missing_positions.len() as u32)
    }

    fn candidate_at(&self, index: u64) -> Vec<u16> {
        assert!(index < self.total(), "index out of range");
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
