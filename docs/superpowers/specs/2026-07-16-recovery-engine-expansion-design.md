# Recovery engine expansion — design

Date: 2026-07-16
Status: approved

## Summary

Add three related capabilities to `seedcrypt-recover`, closing two items already
flagged in the README roadmap plus one new robustness feature:

1. **`reorder`** — a new subcommand for wrong-order recovery: all words known,
   a subset believed to be in the wrong order.
2. **`missing --allow-typo`** — combine the two existing search modes so a
   search can fill missing (`?`) positions *and* tolerate one typo among the
   known words in the same pass.
3. **Checkpoint/resume** — shared infrastructure so long-running searches
   (hours/days, per the existing perf table) survive a crash, Ctrl+C, or
   reboot without losing progress.

Multi-language wordlists (the other README roadmap item) is explicitly out of
scope for this round.

## CLI surface

```
seedcrypt-recover missing \
  --mnemonic "word1 word2 ? word4 ..." \
  --address <addr> \
  [--allow-typo] \
  [--checkpoint <path>] [--resume <path>]

seedcrypt-recover typo \
  --mnemonic "..." --address <addr> \
  [--checkpoint <path>] [--resume <path>]

seedcrypt-recover reorder \
  --mnemonic "word1 word2 ... word12" \
  --permute-positions 3,7,9,10 \
  --address <addr> \
  [--checkpoint <path>] [--resume <path>]
```

- `--allow-typo` (new, on `missing`): boolean. When set, in addition to
  filling `?` slots, the search also tries leaving all known words as-is OR
  substituting exactly one known word with each of its 2048 alternatives.
- `--permute-positions` (new, on `reorder`): required, 1-indexed comma list,
  ≥2 and ≤10 entries, no duplicates, all within `1..=seed_length`.
- `--checkpoint <path>` (new, all three subcommands): enables periodic
  progress persistence to `<path>`.
- `--resume <path>` (new, all three subcommands): loads a checkpoint and
  continues from its saved index. Requires the checkpoint's signature
  (mode + mnemonic pattern + address + passphrase hash + derivation config)
  to match the current invocation's args exactly, or the tool refuses to
  proceed.

No existing flag or default behavior changes for `missing`/`typo` when the
new flags are omitted — old invocations produce identical results via the
same code path.

## Candidate index abstraction

All three modes reduce to a bijection between an integer index `0..total`
and a candidate mnemonic guess, which is what makes checkpointing (below)
work identically across modes instead of needing separate resume logic per
mode:

- **`missing`**: base-2048 mixed radix over the missing slots (already how
  the nested iteration works today — just needs an explicit index→candidate
  function instead of implicit nested loops).
- **`missing --allow-typo`**: combined index = `missing_index * typo_choice_space
  + typo_choice_index`, where `typo_choice_space = 1 + known_count * 2048`
  (the `+1` is "no typo, known words as given").
- **`reorder`**: index `0..k!` maps to the *k*-th permutation of the marked
  positions via the standard **Lehmer code / factorial number system**
  algorithm — deterministic, no need to materialize all permutations, and
  naturally checkpoint-friendly.

## Checkpoint/resume architecture

`rayon` parallelizes candidate testing, so candidates do **not** complete in
strict index order — a naive "last index tested" checkpoint can silently
skip untested candidates on resume (a worker finishing index 50,000 before
another finishes 40,001 is normal, expected behavior under work-stealing).

**Chosen approach — chunked watermark:**

- Split `0..total` into fixed-size chunks (100,000 candidates — an internal
  constant, not exposed as a CLI flag in this round). Rayon parallelizes
  *within* a chunk; chunks complete strictly in order.
- Periodically (every few seconds, and on Ctrl+C) persist a checkpoint
  recording the resume index as **a plain candidate-index integer** (not a
  chunk number), so chunk size may differ between the original run and a
  resumed run without correctness issues.
- On crash/interrupt, at most one chunk's worth of already-completed work is
  redone on resume — bounded, cheap, and always correct.

**Rejected alternatives:**

- *Naive shared atomic counter* ("next index dispatched"): has the same
  skip-ahead correctness bug as no chunking, since dispatched ≠ completed
  under parallelism. Fixing it requires the same completed-prefix tracking
  chunking already gives you, so it isn't actually simpler in practice.
- *Report-only, manual `--skip N`*: trivial to build, but SIGKILL (not just
  Ctrl+C) loses the count entirely — and the multi-hour/day searches this
  feature exists to protect are exactly the ones most likely to get killed
  hard (crash, reboot, laptop closes). Too fragile for the actual use case.

**Checkpoint file** (JSON, atomic write via temp file + rename so a crash
mid-write never corrupts it): mode, mnemonic pattern as given (with `?`s or
permute-positions), address, **SHA-256 hash of the passphrase** (never
plaintext — one less sensitive value on disk), derivation config (account/
address range, derivation type), resume index, total candidate count,
cumulative elapsed time across resumes.

**Ctrl+C handling:** the `ctrlc` crate (new dependency) installs a handler
that flips an atomic stop flag. The chunk loop checks this flag between
chunks, writes a final checkpoint, prints the exact `--resume` command to
re-run, and exits with code `130` (standard "terminated by SIGINT" exit
code), distinct from the existing `1` used for "no match found".

## Error handling & safety guards

- `reorder`: reject `--permute-positions` with <2 or >10 entries (mirrors
  the existing `missing_count > 3` guard style/message), duplicates, or
  positions outside `1..=seed_length`.
- `missing --allow-typo`: compute the combined candidate count up front and
  reject with a clear estimate if it lands in the "days" tier — same spirit
  as the existing `missing_count > 3` check, extended to account for the
  typo multiplier.
- `--resume`: signature mismatch → hard error, refuse rather than guess.
  Corrupt/unreadable checkpoint file → clear error, not a panic.

## Testing

- **Lehmer code bijection**: property test (repo already has `proptest` as a
  dev-dependency) — for random `k` and random index `i < k!`, decode-then-
  encode round-trips to `i`.
- **Checkpoint round-trip**: save → load → resume produces identical results
  to an uninterrupted run on a small deterministic case.
- **Integration vectors**: reuse the README's public `abandon…about` test
  seed — one `reorder` case (swap 2 known positions), one combined
  `missing --allow-typo` case (1 missing + 1 typo) — both should recover the
  same known-good mnemonic the existing modes already prove out.
- **Regression**: existing `missing`/`typo` behavior without the new flags
  must be unchanged — verified by re-running the existing README examples
  and confirming identical output.

## Out of scope (this round)

- Multi-language BIP39 wordlists (separate README roadmap item, not
  requested here).
- Combining `reorder` with missing words in the same search (natural future
  extension given the shared candidate-index architecture, but not
  requested).
- GPU acceleration, resume across different chunk-size *and* different
  worker-count simultaneously beyond what the plain-index checkpoint already
  handles, batch/multi-address checking.
