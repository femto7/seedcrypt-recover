//! CLI for SeedCrypt Recover.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::path::PathBuf;

use seedcrypt_recover::{
    address::detect,
    checkpoint::{hash_mnemonic_pattern, hash_passphrase, Checkpoint},
    recovery::{RecoveryRequest, ValidationConfig},
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
        /// Save progress here periodically; on interrupt, resume with
        /// `--resume <this path>`. Mutually exclusive with --resume.
        #[arg(long, conflicts_with = "resume")]
        checkpoint: Option<String>,
        /// Continue a search from a checkpoint written by --checkpoint.
        /// Refuses to proceed if the checkpoint's search parameters don't
        /// match this invocation's. Mutually exclusive with --checkpoint.
        #[arg(long, conflicts_with = "checkpoint")]
        resume: Option<String>,
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
        /// Save progress here periodically; on interrupt, resume with
        /// `--resume <this path>`. Mutually exclusive with --resume.
        #[arg(long, conflicts_with = "resume")]
        checkpoint: Option<String>,
        /// Continue a search from a checkpoint written by --checkpoint.
        /// Refuses to proceed if the checkpoint's search parameters don't
        /// match this invocation's. Mutually exclusive with --checkpoint.
        #[arg(long, conflicts_with = "checkpoint")]
        resume: Option<String>,
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
        /// Save progress here periodically; on interrupt, resume with
        /// `--resume <this path>`. Mutually exclusive with --resume.
        #[arg(long, conflicts_with = "resume")]
        checkpoint: Option<String>,
        /// Continue a search from a checkpoint written by --checkpoint.
        /// Refuses to proceed if the checkpoint's search parameters don't
        /// match this invocation's. Mutually exclusive with --checkpoint.
        #[arg(long, conflicts_with = "checkpoint")]
        resume: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Missing {
            mnemonic, address, passphrase, account_start, account_end,
            address_start, address_end, allow_typo, checkpoint, resume,
        } => run_missing(
            &mnemonic, address.as_deref(), &passphrase, account_start, account_end,
            address_start, address_end, allow_typo, checkpoint, resume,
        ),
        Command::Typo {
            mnemonic, address, passphrase, account_start, account_end,
            address_start, address_end, checkpoint, resume,
        } => run_typo(
            &mnemonic, &address, &passphrase, account_start, account_end,
            address_start, address_end, checkpoint, resume,
        ),
        Command::Reorder {
            mnemonic, permute_positions, address, passphrase, account_start,
            account_end, address_start, address_end, checkpoint, resume,
        } => run_reorder(
            &mnemonic, permute_positions, &address, &passphrase, account_start,
            account_end, address_start, address_end, checkpoint, resume,
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

/// Resolves the starting index for a search: 0 for a fresh run, or the
/// saved index from `--resume`'s checkpoint after verifying its signature
/// matches the *expected* signature for this invocation. Errors out (does
/// not silently guess) on any mismatch or unreadable/corrupt file.
fn resolve_resume_index(resume_path: Option<&str>, expected: &Checkpoint) -> Result<u64> {
    let Some(path) = resume_path else { return Ok(0) };
    let loaded = Checkpoint::load(&PathBuf::from(path))?;
    if !loaded.matches_signature(expected) {
        return Err(anyhow!(
            "Checkpoint at {path} was saved for a different search (mode/mnemonic/address/passphrase/derivation config don't match this invocation). Refusing to resume."
        ));
    }
    println!(
        "{} Resuming from checkpoint: {}/{} candidates already tested ({:.1}s elapsed so far)",
        style("↻").cyan(),
        loaded.resume_index,
        loaded.total_candidates,
        loaded.elapsed_ms_so_far as f64 / 1000.0,
    );
    Ok(loaded.resume_index)
}

/// Installs a Ctrl+C handler that flips the returned `Arc<AtomicBool>` on
/// the first SIGINT. Safe to call once per process (subsequent Ctrl+C
/// presses during an in-flight write are a no-op past the first).
fn install_stop_flag() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    // Best-effort: if a handler is somehow already installed (shouldn't
    // happen — each subcommand run installs exactly one), ignore the error
    // rather than panic the whole CLI over a non-essential guard.
    let _ = ctrlc::set_handler(move || {
        stop_clone.store(true, Ordering::Relaxed);
    });
    stop
}

/// Writes (or overwrites) the checkpoint at `path` with the given progress.
/// Logs a warning instead of failing the whole search if the write fails
/// (e.g. disk full, permissions) — losing a checkpoint write is much less
/// bad than losing the whole search to a hard error mid-run.
fn checkpoint_writer(
    path: Option<String>,
    base: Checkpoint,
    start: std::time::Instant,
) -> impl FnMut(u64) {
    move |resume_index: u64| {
        let Some(path) = &path else { return };
        let mut cp = base.clone();
        cp.resume_index = resume_index;
        cp.elapsed_ms_so_far = start.elapsed().as_millis();
        if let Err(e) = cp.save(&PathBuf::from(path)) {
            eprintln!("{} Could not write checkpoint: {e}", style("⚠").yellow());
        }
    }
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
    checkpoint_path: Option<String>,
    resume_path: Option<String>,
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

    let expected_sig = Checkpoint {
        mode: "missing".into(),
        mnemonic_pattern_hash: hash_mnemonic_pattern(mnemonic),
        address: address.unwrap_or("").to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let resume_index = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

    let pb = make_progress_bar(total);
    pb.set_position(resume_index);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(resume_index));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        checkpoint_path.or(resume_path),
        expected_sig,
        std::time::Instant::now(),
    );

    let req = RecoveryRequest { seed_length: n, words, validation, allow_typo };
    let result = seedcrypt_recover::recovery::recover_missing_resumable(
        &req, resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish_with_message(if result.interrupted { "interrupted" } else { "done" });

    if result.interrupted {
        eprintln!(
            "\n{} Interrupted. Resume with:\n  seedcrypt-recover missing --mnemonic \"{mnemonic}\" {} --resume <checkpoint path>",
            style("⏸").yellow(),
            address.map(|a| format!("--address {a}")).unwrap_or_default(),
        );
        std::process::exit(130);
    }

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
    checkpoint_path: Option<String>,
    resume_path: Option<String>,
) -> Result<()> {
    let words: Vec<Option<String>> = mnemonic.split_whitespace().map(|w| Some(w.to_ascii_lowercase())).collect();
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return Err(anyhow!("Mnemonic must have 12/15/18/21/24 words (got {n})"));
    }
    let validation = build_validation(Some(address), passphrase, account_start, account_end, address_start, address_end)?
        .ok_or_else(|| anyhow!("Typo recovery requires --address"))?;

    println!(
        "{} Searching for one typo in a {}-word seed against {}",
        style("⚙").cyan(), n, style(&validation.address).yellow(),
    );

    let total = (n as u64) * 2048;

    let expected_sig = Checkpoint {
        mode: "typo".into(),
        mnemonic_pattern_hash: hash_mnemonic_pattern(mnemonic),
        address: address.to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let resume_index = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

    let pb = make_progress_bar(total);
    pb.set_position(resume_index);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(resume_index));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        checkpoint_path.or(resume_path),
        expected_sig,
        std::time::Instant::now(),
    );

    let req = RecoveryRequest { seed_length: n, words, validation: Some(validation), allow_typo: false };
    let result = seedcrypt_recover::recovery::recover_typo_resumable(
        &req, resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish_with_message(if result.interrupted { "interrupted" } else { "done" });

    if result.interrupted {
        eprintln!(
            "\n{} Interrupted. Resume with:\n  seedcrypt-recover typo --mnemonic \"{mnemonic}\" --address {address} --resume <checkpoint path>",
            style("⏸").yellow(),
        );
        std::process::exit(130);
    }

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
    checkpoint_path: Option<String>,
    resume_path: Option<String>,
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
        return Err(anyhow!("--permute-positions has {k} positions ({k}! candidates) — impractical. Narrow it to 10 or fewer."));
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
        permute_positions.push(p - 1);
    }

    let validation = build_validation(Some(address), passphrase, account_start, account_end, address_start, address_end)?
        .ok_or_else(|| anyhow!("reorder recovery requires --address"))?;

    let total = seedcrypt_recover::lehmer::factorial(k as u64);
    println!(
        "{} Searching {total} permutation(s) of {k} marked position(s) in a {n}-word seed against {}",
        style("⚙").cyan(), style(&validation.address).yellow(),
    );

    let permute_positions_str = permute_positions_1indexed.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let expected_sig = Checkpoint {
        mode: "reorder".into(),
        mnemonic_pattern_hash: hash_mnemonic_pattern(&format!("{mnemonic}|permute:{permute_positions_str}")),
        address: address.to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let resume_index = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

    let pb = make_progress_bar(total);
    pb.set_position(resume_index);
    let pb_clone = pb.clone();
    let last = Arc::new(AtomicU64::new(resume_index));
    let last_clone = last.clone();
    let progress = move |tested: u64| {
        let prev = last_clone.swap(tested, Ordering::Relaxed);
        if tested > prev {
            pb_clone.set_position(tested);
        }
    };

    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        checkpoint_path.or(resume_path),
        expected_sig,
        std::time::Instant::now(),
    );

    let result = seedcrypt_recover::recovery::recover_reorder_resumable(
        &words, permute_positions, Some(validation), resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish_with_message(if result.interrupted { "interrupted" } else { "done" });

    if result.interrupted {
        eprintln!(
            "\n{} Interrupted. Resume with:\n  seedcrypt-recover reorder --mnemonic \"{mnemonic}\" --permute-positions {permute_positions_str} --address {address} --resume <checkpoint path>",
            style("⏸").yellow(),
        );
        std::process::exit(130);
    }

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
