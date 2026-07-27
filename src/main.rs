//! CLI for SeedCrypt Recover.

mod ui;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::ProgressBar;
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

/// True when this process is the only one attached to its console.
///
/// On Windows that means the console was created *for us* — i.e. the exe was
/// double-clicked in Explorer. When it's launched from an existing PowerShell
/// or cmd, that shell is attached too and the count is at least 2.
#[cfg(windows)]
fn owns_console() -> bool {
    use windows_sys::Win32::System::Console::GetConsoleProcessList;
    let mut pids = [0u32; 2];
    // Returns the number of processes sharing this console. 1 == just us.
    unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) == 1 }
}

#[cfg(not(windows))]
fn owns_console() -> bool {
    // Nothing to do elsewhere: a terminal that ran the binary stays open.
    false
}

fn wait_for_enter() {
    use std::io::{BufRead, Write};
    print!("\nPress Enter to close this window...");
    let _ = std::io::stdout().flush();
    let mut discard = String::new();
    let _ = std::io::stdin().lock().read_line(&mut discard);
}

/// Shown when the exe is double-clicked instead of run from a terminal.
///
/// Without this the window opens and vanishes in the same frame, which reads
/// as "the tool is broken" — and the people reaching for a seed-recovery tool
/// are the least likely to know that a CLI needs arguments.
fn print_double_click_help() {
    ui::print_banner();

    ui::print_rule(Some("THIS PROGRAM RUNS IN A TERMINAL"));
    ui::blank();
    ui::body("Double-clicking cannot start a recovery: the program has no window");
    ui::body("of its own, and it needs to be told what to look for.");
    ui::blank();
    ui::body("1  Hold Shift, right-click an empty spot in this folder.");
    ui::body("2  Choose \"Open PowerShell window here\" or \"Open in Terminal\".");
    ui::body("3  Type one of the commands below, then press Enter.");
    ui::blank();

    ui::print_rule(Some("COMMANDS"));
    ui::blank();
    ui::kv("missing", "one or more words are gone — mark each one with ?");
    ui::kv("typo", "every word is there, but one of them is wrong");
    ui::kv("reorder", "every word is there, in the wrong order");
    ui::blank();
    ui::body("Shape of a command (backtick = continue on the next line):");
    ui::blank();
    // PowerShell continuations, not bash `\` — this screen exists to be pasted
    // into the very PowerShell window the step above tells them to open.
    println!(".\\seedcrypt-recover.exe missing `");
    println!("   --mnemonic \"the words you still have, with ? for each gap\" `");
    println!("   --address one-address-this-wallet-has-used");
    ui::blank();

    ui::print_rule(Some("MORE"));
    ui::blank();
    ui::kv("all options", ".\\seedcrypt-recover.exe --help");
    ui::kv("full guide", "https://seedcrypt.app/recover");
    ui::blank();
}

fn main() {
    // Must run before any output: decides the glyph set and asks a Windows
    // console for UTF-8.
    ui::init();

    let from_explorer = owns_console();

    // Double-clicked with no arguments: explain, and hold the window open.
    if from_explorer && std::env::args_os().len() == 1 {
        print_double_click_help();
        wait_for_enter();
        return;
    }

    ui::print_banner();

    // Matches what `fn main() -> Result<()>` printed before, so error output is
    // unchanged for terminal users.
    let code = match dispatch() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {err:?}");
            1
        }
    };

    // Any run started from Explorer (a shortcut carrying arguments, say) would
    // otherwise close before its result — including the error above — could be
    // read.
    if from_explorer {
        wait_for_enter();
    }

    std::process::exit(code);
}

fn dispatch() -> Result<()> {
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
    pb.set_style(ui::progress_style());
    pb
}

/// Resolves the starting index and previously-accumulated elapsed time for
/// a search: `(0, 0)` for a fresh run, or `(loaded.resume_index,
/// loaded.elapsed_ms_so_far)` from `--resume`'s checkpoint after verifying
/// its signature matches the *expected* signature for this invocation.
/// Returning the prior elapsed time (not just the index) lets the caller
/// accumulate it across resumes instead of restarting the clock at 0 each
/// time. Errors out (does not silently guess) on any mismatch or
/// unreadable/corrupt file.
fn resolve_resume_index(resume_path: Option<&str>, expected: &Checkpoint) -> Result<(u64, u128)> {
    let Some(path) = resume_path else { return Ok((0, 0)) };
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
    Ok((loaded.resume_index, loaded.elapsed_ms_so_far))
}

/// Installs a Ctrl+C handler that flips the returned `Arc<AtomicBool>` on
/// the first SIGINT. Safe to call once per process (subsequent Ctrl+C
/// presses during an in-flight write are a no-op past the first). Always
/// installed, even when no `--checkpoint`/`--resume` was given — this lets
/// an interrupted un-checkpointed run still report how many candidates it
/// tested (see the `run_*` functions' `result.interrupted` handling) rather
/// than dying with no summary at all under the OS's default SIGINT
/// behavior.
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
/// `base_elapsed_ms` is the elapsed time already accumulated by prior runs
/// (0 for a fresh search, or `resolve_resume_index`'s returned elapsed time
/// when resuming) — added to this run's own elapsed time so
/// `elapsed_ms_so_far` accumulates across multiple resumes instead of
/// resetting to just the current segment each time.
/// Logs a warning instead of failing the whole search if the write fails
/// (e.g. disk full, permissions) — losing a checkpoint write is much less
/// bad than losing the whole search to a hard error mid-run.
fn checkpoint_writer(
    path: Option<String>,
    base: Checkpoint,
    base_elapsed_ms: u128,
    start: std::time::Instant,
) -> impl FnMut(u64) {
    move |resume_index: u64| {
        let Some(path) = &path else { return };
        let mut cp = base.clone();
        cp.resume_index = resume_index;
        cp.elapsed_ms_so_far = base_elapsed_ms + start.elapsed().as_millis();
        if let Err(e) = cp.save(&PathBuf::from(path)) {
            eprintln!("{} Could not write checkpoint: {e}", style("⚠").yellow());
        }
    }
}

/// Renders `s` as a double-quoted, shell-safe argument for the printed
/// resume command (escapes `\`, `"`, `$`, and `` ` `` for a bash
/// double-quoted context — the README's examples are all bash, and these
/// four characters are exactly what bash still treats specially inside
/// double quotes: `\`/`"` end quoting or escape the next character, `$`
/// triggers variable/command substitution, `` ` `` triggers legacy command
/// substitution). Not a complete shell-escaping implementation (e.g.
/// interactive `!` history expansion under `set -H` is out of scope), but
/// covers the realistic risk: a user pasting an address, checkpoint path,
/// or passphrase from an untrusted source, then blindly copy-pasting this
/// tool's own suggested resume command without reading it first. Applied
/// to the address and checkpoint path too, not just the passphrase — a
/// crafted address survives this crate's coin-detection (which only checks
/// a leading-character prefix, not a full charset/length validation) and a
/// checkpoint path may contain spaces or shell metacharacters regardless
/// of malicious intent. Mnemonic words are the one exception left
/// unquoted: they come from the fixed BIP39 English wordlist and can never
/// contain any of these characters.
fn shell_quote(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
            .replace('`', "\\`")
    )
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

    let validation = build_validation(address, passphrase, account_start, account_end, address_start, address_end)?;

    let known_count = n - missing_count;
    let total: u64 = if allow_typo {
        2048u64.pow(missing_count as u32) * (1 + known_count as u64 * 2048)
    } else {
        2048u64.pow(missing_count as u32)
    };

    let mut rows = vec![(
        "unknown",
        format!("{missing_count} slot(s) marked with ?"),
    )];
    if allow_typo {
        rows.push(("also trying", "one substitution among the known words".to_string()));
    }
    if !passphrase.is_empty() {
        rows.push(("passphrase", "provided".to_string()));
    }
    ui::print_run_header("fill missing words", n, &rows, total, address, checkpoint_path.as_deref());

    let expected_sig = Checkpoint {
        mode: "missing".into(),
        mnemonic_pattern_hash: hash_mnemonic_pattern(&mnemonic.to_ascii_lowercase()),
        address: address.unwrap_or("").to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        allow_typo,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let (resume_index, base_elapsed_ms) = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

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

    // Resolved once and kept (not just moved into checkpoint_writer) so the
    // interrupted-branch message below can tell "a checkpoint was written,
    // here's the real path" apart from "no --checkpoint/--resume was given,
    // nothing was saved" — see Task 11 code review, Critical #2.
    let effective_checkpoint_path = checkpoint_path.or(resume_path);
    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        effective_checkpoint_path.clone(),
        expected_sig,
        base_elapsed_ms,
        std::time::Instant::now(),
    );

    let req = RecoveryRequest { seed_length: n, words, validation, allow_typo };
    let result = seedcrypt_recover::recovery::recover_missing_resumable(
        &req, resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish();

    if result.interrupted {
        match &effective_checkpoint_path {
            Some(path) => {
                let mut cmd = vec![
                    "seedcrypt-recover".to_string(),
                    "missing".to_string(),
                    format!("--mnemonic \"{mnemonic}\""),
                ];
                if let Some(a) = address {
                    cmd.push(format!("--address {}", shell_quote(a)));
                }
                cmd.push(format!("--passphrase {}", shell_quote(passphrase)));
                cmd.push(format!("--account-start {account_start}"));
                cmd.push(format!("--account-end {account_end}"));
                cmd.push(format!("--address-start {address_start}"));
                cmd.push(format!("--address-end {address_end}"));
                if allow_typo {
                    cmd.push("--allow-typo".to_string());
                }
                cmd.push(format!("--resume {}", shell_quote(path)));
                eprintln!(
                    "\n{} Interrupted after {} candidates tested. Resume with:\n  {}",
                    style("⏸").yellow(),
                    resume_index + result.combinations_tested,
                    cmd.join(" "),
                );
            }
            None => eprintln!(
                "\n{} Interrupted after {} candidates tested. No checkpoint was saved — pass --checkpoint <path> next time to enable resuming.",
                style("⏸").yellow(),
                resume_index + result.combinations_tested,
            ),
        }
        std::process::exit(130);
    }

    print_result(result.mnemonic, resume_index + result.combinations_tested, result.elapsed_ms, address, total, checksum_collisions(n, total))
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

    let total = (n as u64) * 2048;

    let mut rows = vec![("looking for", "one wrong word, position unknown".to_string())];
    if !passphrase.is_empty() {
        rows.push(("passphrase", "provided".to_string()));
    }
    ui::print_run_header("find a typo", n, &rows, total, Some(&validation.address), checkpoint_path.as_deref());

    let expected_sig = Checkpoint {
        mode: "typo".into(),
        mnemonic_pattern_hash: hash_mnemonic_pattern(&mnemonic.to_ascii_lowercase()),
        address: address.to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        allow_typo: false,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let (resume_index, base_elapsed_ms) = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

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

    let effective_checkpoint_path = checkpoint_path.or(resume_path);
    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        effective_checkpoint_path.clone(),
        expected_sig,
        base_elapsed_ms,
        std::time::Instant::now(),
    );

    let req = RecoveryRequest { seed_length: n, words, validation: Some(validation), allow_typo: false };
    let result = seedcrypt_recover::recovery::recover_typo_resumable(
        &req, resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish();

    if result.interrupted {
        match &effective_checkpoint_path {
            Some(path) => {
                let cmd = vec![
                    "seedcrypt-recover".to_string(),
                    "typo".to_string(),
                    format!("--mnemonic \"{mnemonic}\""),
                    format!("--address {}", shell_quote(address)),
                    format!("--passphrase {}", shell_quote(passphrase)),
                    format!("--account-start {account_start}"),
                    format!("--account-end {account_end}"),
                    format!("--address-start {address_start}"),
                    format!("--address-end {address_end}"),
                    format!("--resume {}", shell_quote(path)),
                ];
                eprintln!(
                    "\n{} Interrupted after {} candidates tested. Resume with:\n  {}",
                    style("⏸").yellow(),
                    resume_index + result.combinations_tested,
                    cmd.join(" "),
                );
            }
            None => eprintln!(
                "\n{} Interrupted after {} candidates tested. No checkpoint was saved — pass --checkpoint <path> next time to enable resuming.",
                style("⏸").yellow(),
                resume_index + result.combinations_tested,
            ),
        }
        std::process::exit(130);
    }

    print_result(result.mnemonic, resume_index + result.combinations_tested, result.elapsed_ms, Some(address), total, 0)
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

    let mut rows = vec![(
        "reordering",
        format!("{k} marked position(s), all others fixed"),
    )];
    if !passphrase.is_empty() {
        rows.push(("passphrase", "provided".to_string()));
    }
    ui::print_run_header("recover word order", n, &rows, total, Some(&validation.address), checkpoint_path.as_deref());

    let permute_positions_str = permute_positions_1indexed.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let expected_sig = Checkpoint {
        mode: "reorder".into(),
        mnemonic_pattern_hash: hash_mnemonic_pattern(&format!("{}|permute:{permute_positions_str}", mnemonic.to_ascii_lowercase())),
        address: address.to_string(),
        passphrase_hash: hash_passphrase(passphrase),
        account_start, account_end, address_start, address_end,
        allow_typo: false,
        resume_index: 0,
        total_candidates: total,
        elapsed_ms_so_far: 0,
    };
    let (resume_index, base_elapsed_ms) = resolve_resume_index(resume_path.as_deref(), &expected_sig)?;

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

    let effective_checkpoint_path = checkpoint_path.or(resume_path);
    let stop = install_stop_flag();
    let write_checkpoint = checkpoint_writer(
        effective_checkpoint_path.clone(),
        expected_sig,
        base_elapsed_ms,
        std::time::Instant::now(),
    );

    let result = seedcrypt_recover::recovery::recover_reorder_resumable(
        &words, permute_positions, Some(validation), resume_index, &stop, progress, write_checkpoint,
    );
    pb.finish();

    if result.interrupted {
        match &effective_checkpoint_path {
            Some(path) => {
                let cmd = vec![
                    "seedcrypt-recover".to_string(),
                    "reorder".to_string(),
                    format!("--mnemonic \"{mnemonic}\""),
                    format!("--permute-positions {permute_positions_str}"),
                    format!("--address {}", shell_quote(address)),
                    format!("--passphrase {}", shell_quote(passphrase)),
                    format!("--account-start {account_start}"),
                    format!("--account-end {account_end}"),
                    format!("--address-start {address_start}"),
                    format!("--address-end {address_end}"),
                    format!("--resume {}", shell_quote(path)),
                ];
                eprintln!(
                    "\n{} Interrupted after {} candidates tested. Resume with:\n  {}",
                    style("⏸").yellow(),
                    resume_index + result.combinations_tested,
                    cmd.join(" "),
                );
            }
            None => eprintln!(
                "\n{} Interrupted after {} candidates tested. No checkpoint was saved — pass --checkpoint <path> next time to enable resuming.",
                style("⏸").yellow(),
                resume_index + result.combinations_tested,
            ),
        }
        std::process::exit(130);
    }

    print_result(result.mnemonic, resume_index + result.combinations_tested, result.elapsed_ms, Some(address), total, 0)
}

/// How many *other* phrases in this search space also satisfy the BIP39
/// checksum.
///
/// The checksum is `word_count / 3` bits — 4 for a 12-word seed, 8 for 24 — so
/// roughly one candidate in `2^bits` passes it. Only ever shown to quantify how
/// weak a checksum-only hit is: "262,143 other phrases also pass this test" is
/// what stops someone acting on it; "many" is not.
fn checksum_collisions(word_count: usize, total: u64) -> u64 {
    let checksum_bits = (word_count / 3) as u32;
    (total >> checksum_bits.min(63)).saturating_sub(1)
}

/// `address` is `None` when the run had no `--address`, which is what
/// separates a verified recovery from a mere checksum hit. `total` and
/// `collisions` let the unverified case say how many other phrases would have
/// passed the same test.
fn print_result(
    mnemonic: Option<Vec<String>>,
    tested: u64,
    elapsed_ms: u128,
    address: Option<&str>,
    total: u64,
    collisions: u64,
) -> Result<()> {
    println!();
    match mnemonic {
        Some(words) => {
            let outcome = match address {
                Some(addr) => ui::Outcome::Verified { address: addr },
                None => ui::Outcome::Unverified { collisions },
            };
            ui::print_outcome(&outcome, tested, total, elapsed_ms);
            ui::print_seed(&words);
            ui::print_next_steps();
            ui::print_footer();
            Ok(())
        }
        None => {
            ui::print_outcome(&ui::Outcome::NoMatch, tested, total, elapsed_ms);
            ui::print_recovery_hints();
            std::process::exit(1);
        }
    }
}
