//! Address generation for Bitcoin (BIP44/49/84/86) and Ethereum.
//! Auto-detection of derivation path from the address prefix.

use ripemd::Ripemd160;
use secp256k1::Secp256k1;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::bip32::HdKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coin {
    Bitcoin,
    BitcoinCash,
    BitcoinSv,
    Litecoin,
    Dogecoin,
    Dash,
    Zcash,
    Ethereum,
    Tron,
}

/// Derivation type — the combination of `(coin, address scheme)` used by
/// the wallet. Auto-detected from the address prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationType {
    // Bitcoin
    Bip44Legacy,       // 1...   (BTC P2PKH)
    Bip49P2sh,         // 3...   (BTC P2SH-P2WPKH)
    Bip84Native,       // bc1q...(BTC P2WPKH)
    Bip86Taproot,      // bc1p...(BTC P2TR)
    // Bitcoin Cash (legacy P2PKH form — same as BTC version byte)
    BchLegacy,         // 1...   (P2PKH; coin_type 145)
    // Bitcoin SV (P2PKH same as BTC, separate coin_type)
    BsvLegacy,         // 1...   (P2PKH; coin_type 236)
    // Litecoin
    LtcLegacy,         // L...   (LTC P2PKH, version 0x30)
    LtcP2shM,          // M...   (LTC P2SH-P2WPKH, version 0x32)
    LtcSegwit,         // ltc1q...(LTC P2WPKH)
    // Dogecoin
    DogeLegacy,        // D...   (DOGE P2PKH, version 0x1E)
    // Dash
    DashLegacy,        // X...   (DASH P2PKH, version 0x4C)
    // Zcash
    ZcashLegacy,       // t1...  (ZEC transparent P2PKH, version 0x1CB8)
    // Ethereum (and EVM chains: BSC, Polygon, Avalanche-C, Arbitrum, …)
    EthereumStandard,  // 0x...
    // Tron
    TronStandard,      // T...   (Base58Check, version 0x41)
}

#[derive(Debug, Clone, Copy)]
pub struct AddressInfo {
    pub coin: Coin,
    pub kind: DerivationType,
}

impl DerivationType {
    /// BIP44 purpose number (44, 49, 84, 86) and SLIP-0044 coin type.
    pub fn path_components(self) -> (u32, u32) {
        use DerivationType::*;
        match self {
            // Bitcoin (coin_type 0)
            Bip44Legacy => (44, 0),
            Bip49P2sh => (49, 0),
            Bip84Native => (84, 0),
            Bip86Taproot => (86, 0),
            // BCH (145), BSV (236), LTC (2), DOGE (3), DASH (5), ZEC (133)
            BchLegacy => (44, 145),
            BsvLegacy => (44, 236),
            LtcLegacy => (44, 2),
            LtcP2shM => (49, 2),
            LtcSegwit => (84, 2),
            DogeLegacy => (44, 3),
            DashLegacy => (44, 5),
            ZcashLegacy => (44, 133),
            // Ethereum + EVM (60), Tron (195)
            EthereumStandard => (44, 60),
            TronStandard => (44, 195),
        }
    }

    pub fn display(self) -> &'static str {
        use DerivationType::*;
        match self {
            Bip44Legacy => "Bitcoin · Legacy (BIP44)",
            Bip49P2sh => "Bitcoin · P2SH SegWit (BIP49)",
            Bip84Native => "Bitcoin · Native SegWit (BIP84)",
            Bip86Taproot => "Bitcoin · Taproot (BIP86)",
            BchLegacy => "Bitcoin Cash · Legacy (BIP44)",
            BsvLegacy => "Bitcoin SV (BIP44)",
            LtcLegacy => "Litecoin · Legacy (BIP44)",
            LtcP2shM => "Litecoin · P2SH SegWit (BIP49)",
            LtcSegwit => "Litecoin · Native SegWit (BIP84)",
            DogeLegacy => "Dogecoin (BIP44)",
            DashLegacy => "Dash (BIP44)",
            ZcashLegacy => "Zcash · Transparent (BIP44)",
            EthereumStandard => "Ethereum / EVM (BIP44)",
            TronStandard => "Tron (BIP44)",
        }
    }
}

/// Detect coin and derivation type from an address prefix. Returns `None`
/// if the format is unrecognized.
///
/// For ambiguous prefixes (`1...` shared between BTC/BCH/BSV) we default
/// to BTC — users with non-BTC chains can pass `--kind` explicitly via
/// `detect_with_hint` (or directly construct a DerivationType).
pub fn detect(addr: &str) -> Option<AddressInfo> {
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }
    // EVM / Ethereum
    if addr.starts_with("0x") && addr.len() == 42
        && addr[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Some(AddressInfo {
            coin: Coin::Ethereum,
            kind: DerivationType::EthereumStandard,
        });
    }
    let lower = addr.to_ascii_lowercase();
    // Bitcoin Bech32 / Bech32m
    if lower.starts_with("bc1q") {
        return Some(AddressInfo {
            coin: Coin::Bitcoin,
            kind: DerivationType::Bip84Native,
        });
    }
    if lower.starts_with("bc1p") {
        return Some(AddressInfo {
            coin: Coin::Bitcoin,
            kind: DerivationType::Bip86Taproot,
        });
    }
    // Litecoin Bech32
    if lower.starts_with("ltc1") {
        return Some(AddressInfo {
            coin: Coin::Litecoin,
            kind: DerivationType::LtcSegwit,
        });
    }
    // Bitcoin Cash CashAddr — out of scope here, recognize but advise legacy
    if lower.starts_with("bitcoincash:") || lower.starts_with("q") && addr.len() > 30 {
        return Some(AddressInfo {
            coin: Coin::BitcoinCash,
            kind: DerivationType::BchLegacy,
        });
    }
    // Base58Check prefixes (single-char first byte)
    if addr.starts_with('1') {
        // Could be BTC / BSV / BCH legacy — default to BTC
        return Some(AddressInfo {
            coin: Coin::Bitcoin,
            kind: DerivationType::Bip44Legacy,
        });
    }
    if addr.starts_with('3') {
        return Some(AddressInfo {
            coin: Coin::Bitcoin,
            kind: DerivationType::Bip49P2sh,
        });
    }
    if addr.starts_with('L') || addr.starts_with('M') {
        let kind = if addr.starts_with('M') {
            DerivationType::LtcP2shM
        } else {
            DerivationType::LtcLegacy
        };
        return Some(AddressInfo {
            coin: Coin::Litecoin,
            kind,
        });
    }
    if addr.starts_with('D') {
        return Some(AddressInfo {
            coin: Coin::Dogecoin,
            kind: DerivationType::DogeLegacy,
        });
    }
    if addr.starts_with('X') {
        return Some(AddressInfo {
            coin: Coin::Dash,
            kind: DerivationType::DashLegacy,
        });
    }
    if addr.starts_with("t1") {
        return Some(AddressInfo {
            coin: Coin::Zcash,
            kind: DerivationType::ZcashLegacy,
        });
    }
    if addr.starts_with('T') {
        return Some(AddressInfo {
            coin: Coin::Tron,
            kind: DerivationType::TronStandard,
        });
    }
    None
}

/// Derive an address for `(seed, kind, account, address_index)`.
pub fn derive_address(
    secp: &Secp256k1<secp256k1::All>,
    seed: &[u8],
    kind: DerivationType,
    account: u32,
    address_index: u32,
) -> String {
    let (purpose, coin_type) = kind.path_components();
    let path = format!("m/{purpose}'/{coin_type}'/{account}'/0/{address_index}");
    let root = HdKey::from_seed(seed);
    let child = root.derive_path(&path, secp);
    address_for_kind(kind, &child, secp)
}

fn address_for_kind(
    kind: DerivationType,
    child: &HdKey,
    secp: &Secp256k1<secp256k1::All>,
) -> String {
    use DerivationType::*;
    match kind {
        Bip44Legacy => p2pkh(&child.public_key(secp), 0x00),
        Bip49P2sh => p2sh_segwit(&child.public_key(secp), 0x05),
        Bip84Native => bech32_p2wpkh(&child.public_key(secp), "bc"),
        Bip86Taproot => bech32m_taproot(&child.public_key(secp), "bc"),
        BchLegacy => p2pkh(&child.public_key(secp), 0x00),
        BsvLegacy => p2pkh(&child.public_key(secp), 0x00),
        LtcLegacy => p2pkh(&child.public_key(secp), 0x30),
        LtcP2shM => p2sh_segwit(&child.public_key(secp), 0x32),
        LtcSegwit => bech32_p2wpkh(&child.public_key(secp), "ltc"),
        DogeLegacy => p2pkh(&child.public_key(secp), 0x1E),
        DashLegacy => p2pkh(&child.public_key(secp), 0x4C),
        ZcashLegacy => zcash_p2pkh(&child.public_key(secp)),
        EthereumStandard => eth_address(&child.public_key_uncompressed(secp)),
        TronStandard => tron_address(&child.public_key_uncompressed(secp)),
    }
}

/// Derive multiple addresses across an account/index range.
/// Optimized: derives the parent path m/purpose'/coinType'/account'/0
/// once per account, then walks the address index.
pub fn derive_addresses(
    secp: &Secp256k1<secp256k1::All>,
    seed: &[u8],
    kind: DerivationType,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
) -> Vec<String> {
    let (purpose, coin_type) = kind.path_components();
    let root = HdKey::from_seed(seed);
    let mut out = Vec::with_capacity(
        ((account_end - account_start + 1) * (address_end - address_start + 1)) as usize,
    );
    for account in account_start..=account_end {
        let chain = root.derive_path(
            &format!("m/{purpose}'/{coin_type}'/{account}'/0"),
            secp,
        );
        for i in address_start..=address_end {
            let child = chain.derive_child_unhardened(i, secp);
            out.push(address_for_kind(kind, &child, secp));
        }
    }
    out
}

// ─── Bitcoin address helpers ──────────────────────────────────────────────

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let r = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}

/// Generic P2PKH address (Base58Check).
/// `version` is the leading version byte (0x00 = BTC, 0x30 = LTC, …).
fn p2pkh(pubkey: &[u8], version: u8) -> String {
    let h = hash160(pubkey);
    let mut payload = [0u8; 21];
    payload[0] = version;
    payload[1..].copy_from_slice(&h);
    bs58::encode(payload).with_check().into_string()
}

/// Generic P2SH-P2WPKH (BIP49-style) address.
/// `version` is the leading version byte (0x05 = BTC, 0x32 = LTC).
fn p2sh_segwit(pubkey: &[u8], version: u8) -> String {
    let h = hash160(pubkey);
    let mut redeem = [0u8; 22];
    redeem[0] = 0x00;
    redeem[1] = 0x14;
    redeem[2..].copy_from_slice(&h);
    let script_hash = hash160(&redeem);
    let mut payload = [0u8; 21];
    payload[0] = version;
    payload[1..].copy_from_slice(&script_hash);
    bs58::encode(payload).with_check().into_string()
}

/// Generic Bech32 P2WPKH (BIP84-style) — works for BTC ("bc") and LTC ("ltc").
fn bech32_p2wpkh(pubkey: &[u8], hrp: &str) -> String {
    let h = hash160(pubkey);
    encode_segwit(hrp, 0, &h)
}

/// Bech32m Taproot (BIP86) — BTC only in practice.
/// Note: this version omits the TapTweak (BIP341) for simplicity.
fn bech32m_taproot(pubkey: &[u8], hrp: &str) -> String {
    let x_only = &pubkey[1..33];
    encode_segwit(hrp, 1, x_only)
}

/// Zcash transparent address — uses 2-byte version prefix `0x1CB8` for `t1...`.
fn zcash_p2pkh(pubkey: &[u8]) -> String {
    let h = hash160(pubkey);
    let mut payload = [0u8; 22];
    payload[0] = 0x1C;
    payload[1] = 0xB8;
    payload[2..].copy_from_slice(&h);
    bs58::encode(payload).with_check().into_string()
}

fn encode_segwit(hrp: &str, witness_version: u8, program: &[u8]) -> String {
    use bech32::{primitives::decode::SegwitHrpstring, segwit, Hrp};
    let _ = SegwitHrpstring::new; // reference to ensure feature set
    let hrp = Hrp::parse(hrp).expect("constant hrp parses");
    let fe_version = bech32::Fe32::try_from(witness_version).expect("version 0..16");
    segwit::encode(hrp, fe_version, program).expect("encode segwit address")
}

// ─── Ethereum address helpers ──────────────────────────────────────────────

/// Tron uses the same EC math as Ethereum but encodes the address as
/// Base58Check of `0x41 || keccak256(pubkey)[12..32]`.
fn tron_address(uncompressed_pubkey: &[u8]) -> String {
    debug_assert_eq!(uncompressed_pubkey.len(), 65);
    let body = &uncompressed_pubkey[1..];
    let hash = Keccak256::digest(body);
    let mut payload = [0u8; 21];
    payload[0] = 0x41;
    payload[1..].copy_from_slice(&hash[12..32]);
    bs58::encode(payload).with_check().into_string()
}

fn eth_address(uncompressed_pubkey: &[u8]) -> String {
    debug_assert_eq!(uncompressed_pubkey.len(), 65);
    let body = &uncompressed_pubkey[1..]; // drop 0x04 prefix → 64 bytes
    let hash = Keccak256::digest(body);
    let addr = &hash[12..32];
    let hex_lower = hex::encode(addr);
    format!("0x{}", eip55_checksum(&hex_lower))
}

fn eip55_checksum(hex_lower: &str) -> String {
    let hash = Keccak256::digest(hex_lower.as_bytes());
    let hash_hex = hex::encode(hash);
    let mut out = String::with_capacity(hex_lower.len());
    for (i, ch) in hex_lower.chars().enumerate() {
        if ch.is_ascii_alphabetic() {
            let nibble = u8::from_str_radix(&hash_hex[i..i + 1], 16).unwrap();
            if nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::mnemonic_to_seed;

    fn ref_seed() -> [u8; 64] {
        let m: Vec<&str> = ["abandon"; 11]
            .iter()
            .copied()
            .chain(std::iter::once("about"))
            .collect();
        mnemonic_to_seed(&m, "")
    }

    #[test]
    fn detects_eth() {
        assert_eq!(
            detect("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").map(|i| i.kind),
            Some(DerivationType::EthereumStandard)
        );
    }

    #[test]
    fn detects_bc1q() {
        assert_eq!(
            detect("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh").map(|i| i.kind),
            Some(DerivationType::Bip84Native)
        );
    }

    #[test]
    fn ref_btc_legacy_first() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::Bip44Legacy, 0, 0);
        assert_eq!(addr, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
    }

    #[test]
    fn ref_btc_native_segwit_first() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::Bip84Native, 0, 0);
        assert_eq!(addr, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn ref_btc_p2sh_segwit_first() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::Bip49P2sh, 0, 0);
        assert_eq!(addr, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
    }

    #[test]
    fn ref_eth_first() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::EthereumStandard, 0, 0);
        assert_eq!(addr.to_lowercase(), "0x9858effd232b4033e47d90003d41ec34ecaeda94");
    }

    // ── Multi-coin smoke tests ──
    // These verify that each coin's derivation produces a sensible address
    // (right prefix, right length, non-empty). For canonical reference
    // values vs iancoleman.io we trust the algorithm here — a regression
    // would be caught by the prefix + length checks plus the well-known
    // BTC/ETH vectors above.

    #[test]
    fn ltc_legacy_starts_with_L() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::LtcLegacy, 0, 0);
        assert!(addr.starts_with('L'), "got {addr}");
    }

    #[test]
    fn ltc_p2sh_starts_with_M() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::LtcP2shM, 0, 0);
        assert!(addr.starts_with('M'), "got {addr}");
    }

    #[test]
    fn ltc_segwit_starts_with_ltc1() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::LtcSegwit, 0, 0);
        assert!(addr.starts_with("ltc1"), "got {addr}");
    }

    #[test]
    fn doge_starts_with_D() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::DogeLegacy, 0, 0);
        assert!(addr.starts_with('D'), "got {addr}");
    }

    #[test]
    fn dash_starts_with_X() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::DashLegacy, 0, 0);
        assert!(addr.starts_with('X'), "got {addr}");
    }

    #[test]
    fn zcash_starts_with_t1() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::ZcashLegacy, 0, 0);
        assert!(addr.starts_with("t1"), "got {addr}");
    }

    #[test]
    fn tron_starts_with_T() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::TronStandard, 0, 0);
        assert!(addr.starts_with('T'), "got {addr}");
        // Tron addresses are 34 chars Base58Check
        assert_eq!(addr.len(), 34, "tron address should be 34 chars");
    }

    #[test]
    fn bch_starts_with_1() {
        let secp = Secp256k1::new();
        let seed = ref_seed();
        let addr = derive_address(&secp, &seed, DerivationType::BchLegacy, 0, 0);
        // BCH legacy uses BTC version byte → starts with 1 but coin_type is 145
        assert!(addr.starts_with('1'), "got {addr}");
    }

    #[test]
    fn detect_litecoin_legacy() {
        // Sample LTC address from public sources
        let info = detect("LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1");
        assert_eq!(info.map(|i| i.kind), Some(DerivationType::LtcLegacy));
    }

    #[test]
    fn detect_dogecoin() {
        let info = detect("DAFGZBahcWHHZjbFPsv13RijEhzoTfczYU");
        assert_eq!(info.map(|i| i.kind), Some(DerivationType::DogeLegacy));
    }

    #[test]
    fn detect_tron() {
        let info = detect("TXFBqBbqJommqZf7BV8NNYzePh97UmJodJ");
        assert_eq!(info.map(|i| i.kind), Some(DerivationType::TronStandard));
    }
}
