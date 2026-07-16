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
/// `< factorial(items.len())`. Out-of-range indices panic (via
/// `Vec::remove`'s bounds check) rather than wrapping — this function does
/// not itself validate the bound, so keeping `index` in range is the
/// caller's responsibility (see `ReorderSpace`).
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
