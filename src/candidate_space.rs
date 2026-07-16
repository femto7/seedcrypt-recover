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

/// Combined missing-words + optional single-typo-among-known-words search.
/// `combined_index = missing_index * typo_choice_space + typo_choice_index`,
/// where `typo_choice_space = 1 + known_positions.len() * 2048` (the `+1`
/// is "no typo, known words exactly as given").
///
/// Note: like `TypoSpace`, this has a small amount of harmless redundancy —
/// for each `missing_index`, exactly `known_positions.len()` of the
/// `typo_choice_space` indices are self-referential (the chosen substitute
/// word equals the word already at that position), which collide with the
/// `typo_choice_index == 0` "no typo" baseline for the same `missing_index`.
/// Traded deliberately for the same uniform, checkpoint-friendly indexing
/// scheme as `TypoSpace`.
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

/// Wrong-order recovery: all words known, but the words at
/// `permute_positions` might be in the wrong order among themselves. Every
/// other position is fixed.
///
/// `permute_positions` must contain distinct, in-bounds indices into
/// `base_indices` — the caller (CLI layer) is responsible for validating
/// this; an out-of-range or duplicate index will panic.
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
    fn missing_typo_space_candidate_count_matches_documented_redundancy() {
        // NOT a strict-bijection test — MissingTypoSpace has documented,
        // intentional redundancy (see the struct's doc comment): for each
        // missing_index, exactly known_positions.len() of the
        // typo_choice_space indices are self-referential substitutions
        // that collide with the typo_choice_index == 0 baseline. This test
        // locks in the exact expected unique-candidate count given that
        // redundancy, rather than asserting a distinctness property the
        // design deliberately doesn't provide (same as TypoSpace).
        let space = MissingTypoSpace {
            known_indices: vec![3u16; 3],
            missing_positions: vec![1],
            known_positions: vec![0, 2],
        };
        let mut seen = HashSet::new();
        for i in 0..space.total() {
            seen.insert(space.candidate_at(i));
        }
        let missing_space_total = 2048u64.pow(space.missing_positions.len() as u32);
        let expected_unique = space.total() - missing_space_total * space.known_positions.len() as u64;
        assert_eq!(seen.len() as u64, expected_unique);
    }

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
}
