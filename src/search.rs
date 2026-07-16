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
