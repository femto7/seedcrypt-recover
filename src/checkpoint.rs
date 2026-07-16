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
