// SeedCrypt Recover — fast offline BIP39 seed recovery library.
//
// This is the public library API. Wrapped by `main.rs` for the CLI binary
// and exposed via `cdylib` for FFI integration into other languages
// (Flutter, Python, Node.js, …).
//
// Threat model: 100% offline. No network calls anywhere in this crate or
// its dependencies. All seed material stays in process memory.

pub mod bip39;
pub mod bip32;
pub mod address;
pub mod lehmer;
pub mod candidate_space;
pub mod recovery;

pub use address::{AddressInfo, Coin, DerivationType};
pub use bip39::{validate_mnemonic, mnemonic_to_seed, BIP39_WORDLIST};
pub use recovery::{
    recover_missing, recover_typo, RecoveryRequest, RecoveryResult, ValidationConfig,
};
