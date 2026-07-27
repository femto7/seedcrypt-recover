//! Terminal presentation for SeedCrypt Recover.
//!
//! Design contract — every change here must keep all four true:
//!
//! 1. **78 columns max.** A default, un-maximised PowerShell window is 80
//!    wide; a rule that soft-wraps injects a blank line and shreds the layout.
//!    The mnemonic and the resume command are the deliberate exceptions (see 3).
//! 2. **Column 0 means "copy this".** Only the recovered phrase, the resume
//!    command and the example command start at column 0. Everything else is
//!    indented, so the payload has an exclusive emphasis channel and a
//!    triple-click never picks up leading whitespace.
//! 3. **The seed phrase is never decorated.** No box characters on its line, no
//!    hyphenation, no indent — a wallet has to accept it byte-for-byte.
//! 4. **Colour never carries meaning alone.** Every state is also named in
//!    words, because `console` strips styling when piped and a legacy console
//!    may not render it at all.

use console::style;

/// Total width of the rules. 78 leaves two columns of slack inside an
/// 80-column window even when a vertical scrollbar steals one.
const W: usize = 78;
/// Column where values line up in every label/value row.
const TAB: usize = 17;

// ── Glyph set ────────────────────────────────────────────────────────────────

/// Whether the terminal can be trusted with the box-drawing/block glyphs.
///
/// Resolved once at startup by [`init`]. A legacy code page turns the wordmark
/// into several lines of mojibake — which is exactly the moment a frightened
/// user decides the binary is fake — so we fall back to a plain-ASCII face
/// rather than risk it.
static UNICODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

fn unicode() -> bool {
    UNICODE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Picks between the pretty glyph and its ASCII stand-in.
fn g(fancy: &'static str, ascii: &'static str) -> &'static str {
    if unicode() {
        fancy
    } else {
        ascii
    }
}

/// Call once, before any output.
///
/// On Windows this asks the console for UTF-8. `SetConsoleOutputCP` succeeding
/// is necessary but not sufficient — an old conhost with a raster font accepts
/// the call and still cannot draw the glyphs — so `SEEDCRYPT_ASCII=1` exists as
/// a support escape hatch for the case we cannot detect.
pub fn init() {
    if std::env::var_os("SEEDCRYPT_ASCII").is_some() {
        UNICODE.store(false, std::sync::atomic::Ordering::Relaxed);
        return;
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::SetConsoleOutputCP;
        const CP_UTF8: u32 = 65001;
        // SAFETY: no arguments, no memory touched; returns 0 on failure.
        let ok = unsafe { SetConsoleOutputCP(CP_UTF8) } != 0;
        if !ok {
            UNICODE.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

// ── Primitives ───────────────────────────────────────────────────────────────

/// A full-width horizontal rule, optionally carrying a section label.
pub fn rule(label: Option<&str>) -> String {
    let dash = g("─", "-");
    match label {
        None => dash.repeat(W),
        Some(l) => {
            // "── LABEL " then dashes out to W.
            let head = format!("{}{} {} ", dash, dash, l);
            let used = head.chars().count();
            let tail = dash.repeat(W.saturating_sub(used));
            format!("{head}{tail}")
        }
    }
}

pub fn print_rule(label: Option<&str>) {
    println!("{}", style(rule(label)).dim());
}

/// One `   label        value` row, on the fixed tab stop.
///
/// The key is padded *before* styling: ANSI escapes count toward a format
/// width, so padding a styled string silently misaligns the column the moment
/// colour is enabled.
pub fn kv(label: &str, value: &str) {
    let padded = format!("{label:<width$}", width = TAB - 3);
    println!("   {}{}", style(padded).dim(), value);
}

/// A continuation line that hangs under a `kv` value.
pub fn kv_cont(value: &str) {
    println!("   {}{}", " ".repeat(TAB - 3), style(value).dim());
}

/// Indented body prose.
pub fn body(text: &str) {
    println!("   {text}");
}

pub fn blank() {
    println!();
}

/// Seconds are useless for an overnight run — degrade to minutes, then hours.
pub fn human_time(ms: u128) -> String {
    let s = ms as f64 / 1000.0;
    if s < 60.0 {
        format!("{s:.2} s")
    } else if s < 3600.0 {
        format!("{} min {:02} s", (s / 60.0) as u64, (s % 60.0) as u64)
    } else {
        format!("{} h {:02} min", (s / 3600.0) as u64, ((s % 3600.0) / 60.0) as u64)
    }
}

/// `4194304` -> `4,194,304`. Long digit runs are unreadable without grouping.
pub fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// ── Banner ───────────────────────────────────────────────────────────────────

const WORDMARK: [&str; 5] = [
    "█████ █████ █████ ████  █████ ████  █   █ ████  █████",
    "█     █     █     █   █ █     █   █ █   █ █   █   █  ",
    "█████ ████  ████  █   █ █     ████   ███  ████    █  ",
    "    █ █     █     █   █ █     █  █    █   █       █  ",
    "█████ █████ █████ ████  █████ █   █   █   █       █  ",
];

/// The wordmark, a hairline rule, and what the tool is.
///
/// Printed once per run. Never repeated, never re-drawn under the progress bar.
pub fn print_banner() {
    blank();
    if unicode() {
        for row in WORDMARK {
            println!("{}", style(row).magenta());
        }
    } else {
        // The block face is the thing a broken code page destroys most
        // completely, so ASCII mode drops to letter-spaced caps instead.
        println!("{}", style("S E E D C R Y P T").magenta().bold());
    }

    print_rule(None);

    let version = env!("CARGO_PKG_VERSION");
    let left = format!("R E C O V E R   {}   BIP39 seed reconstruction", g("·", "-"));
    let right = format!("v{version}");
    let pad = W.saturating_sub(left.chars().count() + right.chars().count());
    println!("{}{}{}", left, " ".repeat(pad), style(right).dim());
    println!(
        "{}",
        style(format!(
            "Entirely offline {} no network access, no seed words written to disk.",
            g("—", "--")
        ))
        .dim()
    );
    blank();
}

/// The "here is what I am about to do" block.
///
/// Its real job is to let the user catch their own typo *before* a search that
/// may run overnight — so every assumption the run is making is stated, and the
/// checksum-only warning is spelled out in terms of what it means for them
/// rather than as jargon.
pub fn print_run_header(mode: &str, seed_words: usize, rows: &[(&str, String)], total: u64, address: Option<&str>, checkpoint: Option<&str>) {
    print_rule(Some("RUN"));
    blank();
    kv("mode", mode);
    kv("seed", &format!("{seed_words} words {} BIP39 English", g("·", "-")));
    for (k, v) in rows {
        kv(k, v);
    }
    match address {
        Some(addr) => {
            kv("check", "address match (definitive)");
            kv("target", addr);
        }
        None => kv("check", "BIP39 checksum only (not definitive)"),
    }
    kv("search space", &format!("{} candidates", group(total)));
    kv("workers", &format!("{} CPU threads", rayon::current_num_threads()));
    match checkpoint {
        Some(p) => kv("checkpoint", p),
        None => kv("checkpoint", "not saving progress — add --checkpoint <file>"),
    }
    blank();

    if address.is_none() {
        body("No --address given. This can only confirm that a phrase is well-formed,");
        body("not that it is yours: many different fills pass the BIP39 checksum and");
        body("the first one found is the one reported. Add --address for a definite");
        body("answer.");
        blank();
    }

    body("Press Ctrl+C at any time to stop.");
    blank();
}

// ── Result states ────────────────────────────────────────────────────────────

/// The three ways a search can end.
///
/// `Unverified` exists because a checksum-only hit is **not** a recovery: with
/// one unknown word, 2048/16 = 128 different fills pass the BIP39 checksum and
/// the tool reports whichever it reached first. Wearing the same "SEED
/// RECOVERED" language as a verified match is the single highest-stakes lie
/// this program could tell.
pub enum Outcome<'a> {
    Verified { address: &'a str },
    Unverified { collisions: u64 },
    NoMatch,
}

/// The recovered phrase: a numbered grid to transcribe from, then the raw line
/// to paste.
///
/// The grid is not ornament — the person reading it is about to copy twelve
/// words onto paper or steel, and a mis-numbered word is the exact failure that
/// brought them here.
pub fn print_seed(words: &[String]) {
    print_rule(Some("YOUR SEED PHRASE"));
    blank();
    for (i, chunk) in words.chunks(4).enumerate() {
        let mut line = String::from("  ");
        for (j, w) in chunk.iter().enumerate() {
            let n = i * 4 + j + 1;
            line.push_str(&format!("{n:>3} {w:<11}"));
        }
        println!("{}", line.trim_end());
    }
    blank();
    body("The same phrase on one line, ready to paste into your wallet:");
    blank();
    // Column 0, unstyled, unwrapped, no box characters: the one line that has
    // to survive a copy-paste byte-for-byte.
    println!("{}", style(words.join(" ")).green().bold());
    blank();
}

pub fn print_outcome(outcome: &Outcome, tested: u64, total: u64, elapsed_ms: u128) {
    print_rule(Some("RESULT"));
    blank();
    match outcome {
        Outcome::Verified { address } => {
            kv("status", &format!("{}", style("SEED RECOVERED").green().bold()));
            kv("confirmed by", "these words derive the address you gave");
            kv_cont(address);
        }
        Outcome::Unverified { collisions } => {
            kv(
                "status",
                &format!("{}", style("CANDIDATE — NOT VERIFIED").yellow().bold()),
            );
            kv("checked", "BIP39 checksum only");
            kv_cont(&format!(
                "{} other phrases also pass this test",
                group(*collisions)
            ));
        }
        // Yellow, not red: the search completed correctly and the money is not
        // gone. Red is reserved for the program actually failing.
        Outcome::NoMatch => {
            kv("status", &format!("{}", style("NO MATCH").yellow().bold()));
            kv("meaning", "every candidate was checked, none produced");
            kv_cont("your address");
        }
    }
    kv(
        "tested",
        &format!(
            "{} of {} candidates in {}",
            group(tested),
            group(total),
            human_time(elapsed_ms)
        ),
    );
    blank();
}

/// What to do the moment the phrase is on screen.
pub fn print_next_steps() {
    print_rule(Some("NEXT"));
    blank();
    body("Write these words down now, on paper or steel, and check them twice.");
    body("Nothing was saved to disk — closing this window loses them.");
    blank();
    body("If anyone else could have seen these words, move the funds to a new");
    body("wallet. A seed phrase cannot be changed, only replaced.");
    blank();
}

/// The one place the tool points back at the product.
///
/// Someone who has just recovered a seed is the most receptive person alive to
/// "store it encrypted" — so this has to read as the obvious next precaution,
/// not as an ad. Advice first, product second.
pub fn print_footer() {
    print_rule(None);
    println!("Store the backup encrypted, not in plain text — a phrase anyone can read");
    println!("is a wallet anyone can empty. SeedCrypt does that offline, on this machine:");
    println!("{}", style("https://seedcrypt.app").cyan());
    blank();
}

/// Failure is a complete answer, not a crash — say so, then give them the five
/// things that are actually worth trying.
pub fn print_recovery_hints() {
    body("This is a complete answer, not a crash. The seed is still recoverable if");
    body("one of the assumptions below is corrected.");
    blank();
    print_rule(Some("WHAT TO TRY NEXT"));
    blank();
    body("1  The coins may sit at a later account or address index.");
    body("   add  --account-end 5  --address-end 50");
    body("2  The wallet may use a passphrase (a \"25th word\").");
    body("   add  --passphrase \"your passphrase\"");
    body("3  A word you typed as known may itself be wrong.");
    body("   add  --allow-typo   (slower, but searches both at once)");
    body("4  More than one word may be missing — mark it with another ?");
    body("5  The address may belong to a different wallet than this seed.");
    blank();
    body("Worked examples for each of these:");
    println!("   {}", style("https://seedcrypt.app/recover").cyan());
    blank();
}

// ── Progress bar ─────────────────────────────────────────────────────────────

/// Template for the search bar.
///
/// `human_pos`/`human_len` group the digits. `per_sec` is deliberately absent:
/// indicatif renders it through `HumanFloatCount`, which emits
/// `412,904.1671/s` — four decimal places on an estimate is the exact texture
/// that makes software look unfinished.
pub fn progress_style() -> indicatif::ProgressStyle {
    let template = "   {bar:24} {percent:>3}%   {human_pos:>13} / {human_len:<13} eta {eta}";
    // full, intermediate, empty — the box-drawing set is outside CP437, so
    // ASCII mode has to swap it too or the bar garbles along with the banner.
    let chars = g("━╾─", "#>-");
    indicatif::ProgressStyle::with_template(template)
        .expect("static template is valid")
        .progress_chars(chars)
}
