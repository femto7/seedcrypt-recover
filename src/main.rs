//! CLI for SeedCrypt Recover.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use seedcrypt_recover::{
    address::detect,
    recovery::{recover_missing, recover_typo, recover_reorder, RecoveryRequest, ValidationConfig},
};

#[derive(Parser, Debug)]
#[command(
    name = "seedcrypt-recover",
    version,
    author,
    about = "Fast offline BIP39 seed recovery — btcrecover equivalent in Rust."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Recover N missing words at known positions. Use `?` for unknowns.
    Missing {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account_start: u32,
        #[arg(long, default_value_t = 0)]
        account_end: u32,
        #[arg(long, default_value_t = 0)]
        address_start: u32,
        #[arg(long, default_value_t = 9)]
        address_end: u32,
        /// Also try substituting one known word (in addition to filling
        /// `?` slots) — combined missing + typo search.
        #[arg(long)]
        allow_typo: bool,
    },

    /// Find a single-word typo by trying all 2048 substitutions × N positions.
    Typo {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account_start: u32,
        #[arg(long, default_value_t = 0)]
        account_end: u32,
        #[arg(long, default_value_t = 0)]
        address_start: u32,
        #[arg(long, default_value_t = 9)]
        address_end: u32,
    },

    /// Recover the correct order of a subset of positions whose words are
    /// known but possibly shuffled. All other positions are fixed.
    Reorder {
        #[arg(long)]
        mnemonic: String,
        /// 1-indexed, comma-separated positions to permute (e.g. 3,7,9,10).
        /// 2-10 positions.
        #[arg(long, value_delimiter = ',')]
        permute_positions: Vec<usize>,
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value_t = 0)]
        account_start: u32,
        #[arg(long, default_value_t = 0)]
        account_end: u32,
        #[arg(long, default_value_t = 0)]
        address_start: u32,
        #[arg(long, default_value_t = 9)]
        address_end: u32,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Missing {
            mnemonic,
            address,
            passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
            allow_typo,
        } => run_missing(
            &mnemonic,
            address.as_deref(),
            &passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
            allow_typo,
        ),
        Command::Typo {
            mnemonic,
            address,
            passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
        } => run_typo(
            &mnemonic,
            &address,
            &passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
        ),
        Command::Reorder {
            mnemonic,
            permute_positions,
            address,
            passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
        } => run_reorder(
            &mnemonic,
            permute_positions,
            &address,
            &passphrase,
            account_start,
            account_end,
            address_start,
            address_end,
        ),
    }
}

fn parse_with_unknowns(mnemonic: &str) -> Vec<Option<String>> {
    mnemonic
        .split_whitespace()
        .map(|w| {
            if w == "?" {
                None
            } else {
                Some(w.to_ascii_lowercase())
            }
        })
        .collect()
}

fn build_validation(
    address: Option<&str>,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
) -> Result<Option<ValidationConfig>> {
    let Some(addr) = address else { return Ok(None) };
    let info = detect(addr).ok_or_else(|| {
        anyhow!("Could not detect address type. Supported: 1…, 3…, bc1q…, bc1p…, 0x…")
    })?;
    Ok(Some(ValidationConfig {
        address: addr.to_string(),
        kind: info.kind,
        passphrase: passphrase.to_string(),
        account_start,
        account_end,
        address_start,
        address_end,
    }))
}

fn make_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.cyan} [{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({per_sec}) ETA {eta}")
            .unwrap()
            .progress_chars("##-"),
    );
    pb
}

fn run_missing(
    mnemonic: &str,
    address: Option<&str>,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
    allow_typo: bool,
) -> Result<()> {
    let words = parse_with_unknowns(mnemonic);
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }
    let missing_count = words.iter().filter(|w| w.is_none()).count();
    if missing_count == 0 {
        return Err(anyhow!(
            "No `?` placeholders. Use the `typo` subcommand for fully-filled seeds."
        ));
    }
    if missing_count > 3 {
        return Err(anyhow!("{missing_count} missing words is impractical."));
    }

    let validation = build_validation(
        address,
        passphrase,
        account_start,
        account_end,
        address_start,
        address_end,
    )?;

    println!(
        "{} Searching {} missing word(s) in a {}-word seed{}{}",
        style("⚙").cyan(),
        missing_count,
        n,
        if validation.is_some() { " with address validation" } else { " (checksum only)" },
        if allow_typo { ", also allowing one typo among known words" } else { "" },
    );

    let known_count = n - missing_count;
    let total: u64 = if allow_typo {
        2048u64.pow(missing_count as u32) * (1 + known_count as u64 * 2048)
    } else {
        2048u64.pow(missing_count as u32)
    };
    let pb = make_progress_bar(total);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(0));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let req = RecoveryRequest { seed_length: n, words, validation, allow_typo };
    let result = recover_missing(&req, progress);
    pb.finish_with_message("done");

    print_result(result.mnemonic, result.combinations_tested, result.elapsed_ms)
}

fn run_typo(
    mnemonic: &str,
    address: &str,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
) -> Result<()> {
    let words: Vec<Option<String>> = mnemonic
        .split_whitespace()
        .map(|w| Some(w.to_ascii_lowercase()))
        .collect();
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }
    let validation = build_validation(
        Some(address),
        passphrase,
        account_start,
        account_end,
        address_start,
        address_end,
    )?
    .ok_or_else(|| anyhow!("Typo recovery requires --address"))?;

    println!(
        "{} Searching for one typo in a {}-word seed against {}",
        style("⚙").cyan(),
        n,
        style(&validation.address).yellow()
    );

    let total = (n as u64) * 2048;
    let pb = make_progress_bar(total);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(0));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let req = RecoveryRequest {
        seed_length: n,
        words,
        validation: Some(validation),
        allow_typo: false,
    };
    let result = recover_typo(&req, progress);
    pb.finish_with_message("done");

    print_result(result.mnemonic, result.combinations_tested, result.elapsed_ms)
}

fn run_reorder(
    mnemonic: &str,
    permute_positions_1indexed: Vec<usize>,
    address: &str,
    passphrase: &str,
    account_start: u32,
    account_end: u32,
    address_start: u32,
    address_end: u32,
) -> Result<()> {
    let words: Vec<String> = mnemonic.split_whitespace().map(|w| w.to_ascii_lowercase()).collect();
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }

    let k = permute_positions_1indexed.len();
    if k < 2 {
        return Err(anyhow!("--permute-positions needs at least 2 positions (got {k})"));
    }
    if k > 10 {
        return Err(anyhow!(
            "--permute-positions has {k} positions ({k}! candidates) — impractical. Narrow it to 10 or fewer."
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let mut permute_positions = Vec::with_capacity(k);
    for &p in &permute_positions_1indexed {
        if p == 0 || p > n {
            return Err(anyhow!("Position {p} is out of range for a {n}-word seed (must be 1..={n})"));
        }
        if !seen.insert(p) {
            return Err(anyhow!("Position {p} listed more than once in --permute-positions"));
        }
        permute_positions.push(p - 1); // convert to 0-indexed
    }

    let validation = build_validation(
        Some(address),
        passphrase,
        account_start,
        account_end,
        address_start,
        address_end,
    )?
    .ok_or_else(|| anyhow!("reorder recovery requires --address"))?;

    println!(
        "{} Searching {} permutation(s) of {} marked position(s) in a {}-word seed against {}",
        style("⚙").cyan(),
        seedcrypt_recover::lehmer::factorial(k as u64),
        k,
        n,
        style(&validation.address).yellow(),
    );

    let total = seedcrypt_recover::lehmer::factorial(k as u64);
    let pb = make_progress_bar(total);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(0));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let result = recover_reorder(&words, permute_positions, Some(validation), progress);
    pb.finish_with_message("done");

    print_result(result.mnemonic, result.combinations_tested, result.elapsed_ms)
}

fn print_result(mnemonic: Option<Vec<String>>, tested: u64, elapsed_ms: u128) -> Result<()> {
    match mnemonic {
        Some(words) => {
            println!();
            println!("{}", style("═══ SEED FOUND ═══").green().bold());
            println!();
            println!(
                "  {} {}",
                style("Mnemonic:").bold(),
                style(words.join(" ")).yellow()
            );
            println!(
                "  {} {} candidates in {:.2}s",
                style("Tested:").dim(),
                tested,
                elapsed_ms as f64 / 1000.0
            );
            Ok(())
        }
        None => {
            println!();
            println!("{}", style("No match found.").red());
            println!(
                "  Tested {} candidates in {:.2}s",
                tested,
                elapsed_ms as f64 / 1000.0
            );
            std::process::exit(1);
        }
    }
}
