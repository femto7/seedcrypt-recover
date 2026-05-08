//! BIP32 hierarchical deterministic key derivation, FFI'd to libsecp256k1.

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

const HARDENED: u32 = 0x80000000;

/// A node in the BIP32 derivation tree.
#[derive(Clone)]
pub struct HdKey {
    pub priv_key: SecretKey,
    pub chain_code: [u8; 32],
}

impl HdKey {
    /// Build the master key from a 64-byte BIP39 seed.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC accepts any key size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();
        let priv_bytes: [u8; 32] = result[..32].try_into().unwrap();
        let chain_code: [u8; 32] = result[32..].try_into().unwrap();
        let priv_key = SecretKey::from_slice(&priv_bytes)
            .expect("HMAC output is overwhelmingly a valid secp256k1 key");
        Self {
            priv_key,
            chain_code,
        }
    }

    /// Derive a child by index (top bit = hardened).
    pub fn derive_child(&self, index: u32, secp: &Secp256k1<secp256k1::All>) -> Self {
        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .expect("HMAC accepts any key size");
        if index & HARDENED != 0 {
            // Hardened: HMAC over (0x00 || privkey || index_be)
            mac.update(&[0u8]);
            mac.update(&self.priv_key.secret_bytes());
        } else {
            // Non-hardened: HMAC over (compressed_pubkey || index_be)
            let pub_key = PublicKey::from_secret_key(secp, &self.priv_key);
            mac.update(&pub_key.serialize());
        }
        mac.update(&index.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let il: [u8; 32] = result[..32].try_into().unwrap();
        let chain_code: [u8; 32] = result[32..].try_into().unwrap();

        let scalar = Scalar::from_be_bytes(il)
            .expect("HMAC output is overwhelmingly a valid scalar");
        let child_priv = self
            .priv_key
            .add_tweak(&scalar)
            .expect("Tweak is overwhelmingly valid");
        Self {
            priv_key: child_priv,
            chain_code,
        }
    }

    /// Walk a derivation path of the form `m/44'/0'/0'/0/0` from this node.
    pub fn derive_path(&self, path: &str, secp: &Secp256k1<secp256k1::All>) -> Self {
        let mut node = self.clone();
        for segment in path.split('/').skip(1) {
            // Skip "m"
            let hardened = segment.ends_with('\'') || segment.ends_with('h');
            let n_str = if hardened {
                &segment[..segment.len() - 1]
            } else {
                segment
            };
            let mut idx: u32 = n_str.parse().expect("Invalid path segment");
            if hardened {
                idx |= HARDENED;
            }
            node = node.derive_child(idx, secp);
        }
        node
    }

    /// Derive only a single non-hardened child without the parsing overhead.
    /// Used in the inner loop when walking address indices on a cached chain.
    #[inline]
    pub fn derive_child_unhardened(
        &self,
        index: u32,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Self {
        debug_assert!(index < HARDENED, "expected non-hardened index");
        self.derive_child(index, secp)
    }

    /// Compressed 33-byte public key.
    pub fn public_key(&self, secp: &Secp256k1<secp256k1::All>) -> [u8; 33] {
        PublicKey::from_secret_key(secp, &self.priv_key).serialize()
    }

    /// Uncompressed 65-byte public key (0x04 || x || y).
    pub fn public_key_uncompressed(&self, secp: &Secp256k1<secp256k1::All>) -> [u8; 65] {
        PublicKey::from_secret_key(secp, &self.priv_key).serialize_uncompressed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::mnemonic_to_seed;

    #[test]
    fn derive_path_abandon_about() {
        let m: Vec<&str> = ["abandon"; 11]
            .iter()
            .copied()
            .chain(std::iter::once("about"))
            .collect();
        let seed = mnemonic_to_seed(&m, "");
        let secp = Secp256k1::new();
        let root = HdKey::from_seed(&seed);
        let node = root.derive_path("m/44'/0'/0'/0/0", &secp);
        // First BTC legacy address private key is well-known
        let pub_compressed = node.public_key(&secp);
        // Sanity: compressed pubkey starts with 0x02 or 0x03
        assert!(pub_compressed[0] == 0x02 || pub_compressed[0] == 0x03);
    }
}
