# seedcrypt-recover

> Recover a BIP39 seed phrase with missing, mistyped or reordered words — offline, in Rust.

100% offline. No network calls anywhere in this tool or its dependencies.
Your seed never leaves your machine.

Part of [SeedCrypt](https://seedcrypt.app). If you would rather follow a guide than
a command line, start at [seedcrypt.app/recover](https://seedcrypt.app/recover).

## Download

Prebuilt binaries — no Rust toolchain needed. Grab the
[**latest release**](https://github.com/femto7/seedcrypt-recover/releases/latest):

| Platform | Archive |
|----------|---------|
| Windows (x86-64) | `seedcrypt-recover-<version>-x86_64-pc-windows-msvc.zip` |
| macOS (Apple Silicon) | `seedcrypt-recover-<version>-aarch64-apple-darwin.tar.gz` |
| macOS (Intel) | `seedcrypt-recover-<version>-x86_64-apple-darwin.tar.gz` |
| Linux (x86-64) | `seedcrypt-recover-<version>-x86_64-unknown-linux-gnu.tar.gz` |

Every archive ships with a matching `.sha256`. Verify it before you run anything
that will touch your seed:

```bash
sha256sum -c seedcrypt-recover-<version>-x86_64-unknown-linux-gnu.tar.gz.sha256
```

Prefer to build it yourself? See [Installation](#installation) — the source is
the same thing the release binaries are built from, by GitHub Actions.

## Will this work for your seed?

Read this before you spend a night on it. What you actually know decides
everything, and some cases are genuinely hopeless:

| What you know | Realistic? |
|---------------|-----------|
| All words, but one is wrong | **Yes** — seconds |
| 1 word missing, position known | **Yes** — instant |
| 2 words missing, positions known | **Yes** — minutes |
| 2 words swapped, positions suspected | **Yes** — instant |
| 3 words missing | Hours to days |
| 4+ words missing, or positions unknown | **No.** The search space explodes far past what a desktop can chew through. |
| No address from the wallet | **No.** There is nothing to validate candidates against. |

If your case falls in a **No** row, no tool will save you — including the paid
"recovery services" that take a percentage of your funds. Better to know now
than after a week of hoping.

One thing worth checking first: a single wrong word breaks the BIP39 checksum in
roughly 94% of cases on a 12-word phrase. If your wallet says *"invalid mnemonic"*
rather than showing an empty balance, you very likely have a typo — the easiest
case on this list.

## What it does

Given a partially known BIP39 seed phrase and a wallet address you control, this tool brute-forces the missing or mistyped words by validating each candidate against the address.

Two modes:

- `missing` — you know most words but **N** positions are blank (use `?`)
- `typo` — you have all 12/24 words but suspect **one is wrong**

Both modes use [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1) (FFI'd via the [`secp256k1`](https://crates.io/crates/secp256k1) crate) for the elliptic-curve math, with [`rayon`](https://crates.io/crates/rayon) for parallel iteration across CPU cores. First match wins, others stop.

## Why another recovery tool

[btcrecover](https://github.com/3rdIteration/btcrecover) is the canonical
implementation and the algorithmic reference for this project. It ships as Python
with a heavy dependency tree and no prebuilt binary — a poor fit for someone who
has just lost access to their funds and does not want to set up a Python
environment first.

seedcrypt-recover is:

- **A single binary** (~3 MB, statically linked) — download, run, done.
- **Memory-safe** — Rust's borrow checker eliminates whole classes of crypto-relevant CVEs.
- **The same speed in practice** — the hot path is `libsecp256k1` either way.
- **Reusable as a library** (`cdylib`) — the same crate can be FFI'd from Flutter / Python / Node.js / Go.

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

## Supported coins

All secp256k1-based chains. Auto-detected from address prefix.

| Coin | Derivation types | Address prefix |
|------|------------------|----------------|
| **Bitcoin** | BIP44 / BIP49 / BIP84 / BIP86 | `1…` `3…` `bc1q…` `bc1p…` |
| **Bitcoin Cash** | BIP44 (legacy form) | `1…` (or `bitcoincash:q…`) |
| **Bitcoin SV** | BIP44 | `1…` |
| **Litecoin** | BIP44 / BIP49 / BIP84 | `L…` `M…` `ltc1q…` |
| **Dogecoin** | BIP44 | `D…` |
| **Dash** | BIP44 | `X…` |
| **Zcash (transparent)** | BIP44 | `t1…` |
| **Ethereum + EVM** (BSC, Polygon, Avalanche-C, Arbitrum, Optimism, Base, …) | BIP44 | `0x…` |
| **Tron** | BIP44 | `T…` |

EVM chains share the same address as Ethereum from the same seed — just give any EVM address.

Out of scope: Solana, Cardano, Polkadot, Cosmos, Stellar (different curves — ed25519 / sr25519, not secp256k1).

## Installation

Most people should use a [prebuilt binary](#download). To build from source:

```bash
cargo install --git https://github.com/femto7/seedcrypt-recover
```

Or from a clone:

```bash
git clone https://github.com/femto7/seedcrypt-recover
cd seedcrypt-recover
cargo build --release
./target/release/seedcrypt-recover --help
```

## Usage

### Missing word(s)

```bash
seedcrypt-recover missing \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?" \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

### Typo correction

```bash
seedcrypt-recover typo \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandun about" \
  --address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

(Synthetic example using the well-known **abandon-about** BIP39 test vector — a public test seed used by every wallet for unit testing. Word 11 is intentionally typo'd `abandun` instead of `abandon`. The tool finds the substitution in seconds.)

> ⚠️ **Never share your real seed phrase or address pair publicly.** This README intentionally uses a public test vector with no funds. If you copy-paste a real example anywhere (issue, blog, support thread), assume the funds at that address are immediately drained.

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

### With BIP39 passphrase

```bash
seedcrypt-recover typo \
  --mnemonic "..." \
  --address "..." \
  --passphrase "TREZOR"
```

### Wider scan range

```bash
seedcrypt-recover typo \
  --mnemonic "..." \
  --address "..." \
  --account-end 4 \
  --address-end 49
```

## Performance

On a modern 8-core CPU, with one address checked per candidate:

| Scenario | Candidates | Wall time |
|----------|-----------:|----------:|
| 1 missing word                                | 2,048     | < 1 sec |
| 1 typo (12-word seed)                         | 24,576    | 5–15 sec |
| 1 typo (24-word seed)                         | 49,152    | 10–30 sec |
| 2 missing words at indices ≤ 100              | ~200,000  | 30–90 sec |
| 2 missing words at indices ≤ 2048             | ~4 million | 5–15 min |
| 3 missing words                               | ~8 billion | hours/days |

Roughly the same order of magnitude as btcrecover. Both use `libsecp256k1` for the heavy lifting; the wrapping language (Rust vs Python) is a rounding error.

## Security

This is a recovery tool, not a wallet. It:

- Never makes network calls.
- Doesn't write the recovered seed to disk (unless you redirect stdout).
- Doesn't run or call any binary other than what you compiled from the published source.
- Verifies every candidate by re-deriving the BIP32/secp256k1 path (no false positives — the only way to "match" is for the entire derivation to actually produce the target address).

That said: **run on an air-gapped machine** when recovering a seed that secures real funds. After recovery, **transfer funds to a new wallet**, since the recovered seed has now been in the memory of an internet-connected machine.

## Library use

The crate is also a `cdylib`, so you can call it from any language with C FFI (Flutter, Python, Node.js, Go, …).

```rust
use seedcrypt_recover::{recover_typo, RecoveryRequest, ValidationConfig, DerivationType};

let req = RecoveryRequest {
    seed_length: 12,
    words: vec![/* … */],
    validation: Some(ValidationConfig {
        address: "0x...".into(),
        kind: DerivationType::EthereumStandard,
        passphrase: String::new(),
        account_start: 0, account_end: 0,
        address_start: 0, address_end: 0,
    }),
};
let result = recover_typo(&req, |_| {});
```

## Acknowledgments

- [btcrecover](https://github.com/3rdIteration/btcrecover) by gurnec / 3rdIteration — the canonical seed recovery tool, and the algorithmic reference for this implementation.
- [Bitcoin Core's libsecp256k1](https://github.com/bitcoin-core/secp256k1) — used (via FFI) for all elliptic-curve math.
- [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) — type-safe Rust bindings to libsecp256k1 used by this crate.

## License

MIT — see [LICENSE](./LICENSE).
