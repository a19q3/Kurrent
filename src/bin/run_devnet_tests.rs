use serde_json::Value;
use std::{
    env, fs,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DEFAULT_OUTPUT_LINE_LIMIT: usize = 80;
const DEFAULT_OUTPUT_HEAD_LINES: usize = 48;
const DEFAULT_OUTPUT_TAIL_LINES: usize = 24;
const PRESENTATION_WIDTH: usize = 78;

// ---------------------------------------------------------------------------
// Terminal presentation layer.
//
// All screen output goes through `emit_line`/`emit_raw`. Colour is applied
// *after* wrapping, on each already-wrapped plain-text line, so the visible
// width (and therefore column alignment) is never affected by ANSI bytes.
// This is the invariant that keeps coloured output stable in a real terminal
// instead of corrupting it: wrapping runs on plain text, styling is a final,
// width-neutral pass.
// ---------------------------------------------------------------------------
mod term {
    use std::io::{self, IsTerminal};

    /// Maximum presentation width. We never render wider than this so output is
    /// readable on large terminals too.
    pub const MAX_WIDTH: usize = super::PRESENTATION_WIDTH;
    /// Floor below which we stop shrinking (very narrow terminals get clipped,
    /// not infinitely folded, to stay legible).
    pub const MIN_WIDTH: usize = 40;

    /// Effective width = min(real terminal width, MAX_WIDTH), floored. We MUST
    /// wrap to the real width: if the real terminal is narrower than our line,
    /// the terminal re-wraps it a second time and shifts/fragments the output.
    pub fn width() -> usize {
        let real = terminal_columns().unwrap_or(MAX_WIDTH);
        real.clamp(MIN_WIDTH, MAX_WIDTH)
    }

    // ANSI SGR codes. Kept tiny and explicit: no crates, no cursor movement,
    // no spinners, no live redraw. Colours are muted/terminal-default so they
    // read well in both light and dark themes and degrade gracefully.
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const CYAN: &str = "\x1b[36m";
    pub const GREEN: &str = "\x1b[32m";
    pub const RED: &str = "\x1b[31m";
    pub const YELLOW: &str = "\x1b[33m";

    #[derive(Clone, Copy)]
    pub enum Accent {
        Plain,
        Banner,
        Heading,
        StatusPass,
        StatusFail,
        StatusBoundary,
        Dim,
    }

    impl Accent {
        fn codes(self) -> &'static str {
            match self {
                Accent::Plain => "",
                Accent::Banner => CYAN,
                Accent::Heading => BOLD,
                Accent::StatusPass => GREEN,
                Accent::StatusFail => RED,
                Accent::StatusBoundary => YELLOW,
                Accent::Dim => DIM,
            }
        }
    }

    /// Colour is emitted only when stdout is an interactive terminal, so
    /// pipes/files/`script` captures stay clean and deterministic. When colour
    /// is disabled, `paint` returns plain text with zero ANSI bytes.
    fn colour_enabled() -> bool {
        io::stdout().is_terminal()
    }

    /// Read the real terminal column count via the TIOCGWINSZ ioctl. This is
    /// essential: if we wrap to a fixed width wider than the actual terminal,
    /// the terminal re-wraps our lines a second time and shifts/fragments them.
    /// Works on macOS (BSD) and Linux; returns None for non-tty stdout.
    #[cfg(unix)]
    pub fn terminal_columns() -> Option<usize> {
        // COLUMNS env is respected by shells and some tools; honour it first as
        // a user override, then fall back to the live ioctl size.
        if let Some(cols) = env_cols() {
            return Some(cols);
        }
        use std::os::unix::io::AsRawFd;
        if !io::stdout().is_terminal() {
            return None;
        }

        #[repr(C)]
        struct WinSize {
            ws_row: u16,
            ws_col: u16,
            ws_xpixel: u16,
            ws_ypixel: u16,
        }

        // FFI to ioctl. TIOCGWINSZ value differs by platform but the libc
        // constant is exposed via the standard `libc`-equivalent request on
        // unix; we use the raw syscall via a minimal extern to avoid a dep.
        extern "C" {
            fn ioctl(fd: std::os::unix::io::RawFd, request: u64, ...) -> i32;
        }

        // TIOCGWINSZ request number. 0x5413 on Linux, 0x40087468 on macOS/BSD.
        // Determine via cfg rather than hardcoding a single value.
        #[cfg(target_os = "linux")]
        const TIOCGWINSZ: u64 = 0x5413;
        #[cfg(target_os = "macos")]
        const TIOCGWINSZ: u64 = 0x40087468;
        #[cfg(target_os = "freebsd")]
        const TIOCGWINSZ: u64 = 0x40087468;
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
        const TIOCGWINSZ: u64 = 0x40087468;

        let mut ws = WinSize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let fd = io::stdout().as_raw_fd();
        // SAFETY: ioctl with TIOCGWINSZ fills the WinSize struct from the tty
        // referenced by fd. The request is read-only w.r.t. kernel state and
        // writes only into our local struct.
        let rc = unsafe { ioctl(fd, TIOCGWINSZ, &mut ws as *mut WinSize) };
        if rc == 0 && ws.ws_col > 0 {
            Some(ws.ws_col as usize)
        } else {
            None
        }
    }

    #[cfg(not(unix))]
    pub fn terminal_columns() -> Option<usize> {
        env_cols()
    }

    fn env_cols() -> Option<usize> {
        std::env::var("COLUMNS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&c| c > 0)
    }

    /// Paint a single *plain-text* line. The caller guarantees `text`
    /// contains no ANSI; we only add an optional opening code and RESET.
    pub fn paint<T: AsRef<str>>(accent: Accent, text: T) -> String {
        let text = text.as_ref();
        let open = accent.codes();
        if open.is_empty() || !colour_enabled() {
            text.to_string()
        } else {
            format!("{open}{text}{RESET}")
        }
    }

    /// Visible width of a plain-text line (no ANSI expected here). Uses
    /// `char::count`, which matches the wrapper's accounting exactly.
    pub fn visible_width(text: &str) -> usize {
        text.chars().count()
    }

    /// Strip ANSI escape sequences and every remaining control character except
    /// newline. This sanitises child process output before it reaches the screen
    /// so coloured diffs, daemon logs, carriage returns, backspaces, and stray
    /// escape sequences cannot corrupt layout or leave fragments like `[31m`.
    pub fn sanitize(text: &str) -> String {
        let stripped = strip_ansi(text);
        stripped
            .chars()
            .filter(|&c| c == '\n' || (!c.is_control()))
            .collect()
    }

    /// Remove ANSI/VT100 escape sequences. Handles CSI (`ESC [ ... letter`),
    /// charset selection (`ESC ( c`), and other `ESC`-prefixed sequences so child
    /// output like cargo's coloured diff (`ESC[31m`, `ESC(B`) leaves no `[31m`
    /// fragments.
    fn strip_ansi(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == 0x1b && i + 1 < bytes.len() {
                // ESC sequence: skip ESC + the following byte(s) that form the
                // sequence, so no partial fragment is emitted.
                let next = bytes[i + 1];
                if next == b'[' {
                    // CSI: ESC [ <params> <intermediate>* <final letter>
                    i += 2;
                    while i < bytes.len() {
                        let c = bytes[i];
                        i += 1;
                        // 0x40..=0x7e are final bytes; 0x30..=0x3f are parameter,
                        // 0x20..=0x2f intermediate — keep consuming until final.
                        if (0x40..=0x7e).contains(&c) {
                            break;
                        }
                    }
                } else if next == b'(' || next == b')' || next == b'*' || next == b'+' {
                    // Charset designator: ESC ( c — consume the designator + 1 byte.
                    i += 3;
                } else if next == b']' {
                    // OSC: ESC ] ... BEL (or ST). Consume until BEL or ESC \.
                    i += 2;
                    while i < bytes.len() && bytes[i] != 0x07 {
                        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                    if i < bytes.len() && bytes[i] == 0x07 {
                        i += 1;
                    }
                } else {
                    // Two-byte ESC sequence (e.g. ESC M, ESC =). Consume ESC + next.
                    i += 2;
                }
            } else {
                // Safe UTF-8 continuation: only push at char boundaries.
                if !(0x80..0xc0).contains(&b) {
                    out.push(text[i..].chars().next().unwrap_or_default());
                }
                i += 1;
            }
        }
        out
    }
}

/// The line terminator we emit. On a real TTY we use CRLF so the cursor always
/// returns to column 0 even when the terminal has ONLCR disabled (some PTY
/// wrappers, IDE run consoles, and custom terminals do not translate `\n` to
/// `\r\n`, which makes every line start where the previous one ended — the
/// classic "staircase" right-shift). When stdout is a file/pipe we keep plain
/// LF so captured output stays clean Unix text.
fn line_terminator() -> &'static str {
    if std::io::stdout().is_terminal() {
        "\r\n"
    } else {
        "\n"
    }
}

/// The only writer to stdout. Every visible line goes through here.
fn emit_line(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "{text}{}", line_terminator());
}

fn emit_err_line(text: &str) {
    let mut out = std::io::stderr().lock();
    let _ = writeln!(out, "{text}");
}

/// Diagnostic dump of how the runner sees the terminal. This is intentionally
/// printed even when stdout is not a TTY (e.g. piped), so you can see exactly
/// why wrapping chose a particular width.
fn print_term_debug() {
    use std::io::IsTerminal;
    let is_tty = std::io::stdout().is_terminal();
    let columns_env = std::env::var("COLUMNS").ok();
    let detected = term::terminal_columns();
    let effective = term::width();
    println!("term-debug: is_terminal(stdout) = {is_tty}");
    println!("term-debug: COLUMNS env          = {columns_env:?}");
    println!("term-debug: detected width       = {detected:?}");
    println!(
        "term-debug: effective wrap width  = {effective}  (min {} / max {})",
        term::MIN_WIDTH,
        term::MAX_WIDTH
    );
    println!(
        "term-debug: if detected width is None, the run wraps to max {}",
        term::MAX_WIDTH
    );
}

#[derive(Debug, Clone)]
struct Config {
    prepare_tools: bool,
    skip_build_checks: bool,
    verbose: bool,
    strict_production: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepClass {
    Required,
    Boundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepStatus {
    Pass,
    Fail,
    Blocked,
    Boundary,
}

#[derive(Debug, Clone)]
struct CommandSpec {
    program: String,
    args: Vec<String>,
}

#[derive(Debug, Clone)]
struct StepSpec {
    id: &'static str,
    label: &'static str,
    class: StepClass,
    description: &'static str,
    business_value: &'static str,
    command: CommandSpec,
    evidence: Vec<&'static str>,
    /// Compact steps (preparation/maintenance: fmt, clippy, build, detect-tools)
    /// render as a single line on PASS so they don't bury the business-flow
    /// steps. Failures still print the full block for debuggability.
    compact: bool,
}

#[derive(Debug, Clone)]
struct StepOutcome {
    label: String,
    business_value: String,
    status: StepStatus,
    exit_code: i32,
    duration: Duration,
}

#[derive(Debug)]
struct Runner {
    root: PathBuf,
    run_id: String,
    config: Config,
    outcomes: Vec<StepOutcome>,
    required_failures: usize,
    boundary_failures: usize,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            screen_err_line(&format!("error: {err}"));
            ExitCode::from(1)
        }
    }
}

fn real_main() -> Result<i32, String> {
    let config = parse_config()?;
    let root = repo_root()?;
    env::set_current_dir(&root)
        .map_err(|err| format!("failed to enter repository root {}: {err}", root.display()))?;

    let run_id = utc_compact_timestamp();
    let mut runner = Runner {
        root,
        run_id,
        config,
        outcomes: Vec::new(),
        required_failures: 0,
        boundary_failures: 0,
    };

    runner.print_banner()?;
    runner.run_all()?;
    runner.write_final_summary()?;

    if runner.required_failures == 0 {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn parse_config() -> Result<Config, String> {
    let mut config = Config {
        prepare_tools: env_flag("KURRENT_DEVNET_PREPARE_TOOLS"),
        skip_build_checks: env_flag("KURRENT_DEVNET_SKIP_BUILD_CHECKS"),
        verbose: env_flag("KURRENT_DEVNET_VERBOSE"),
        strict_production: env_flag("KURRENT_DEVNET_STRICT_PRODUCTION"),
    };

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--prepare-tools" => config.prepare_tools = true,
            "--skip-build-checks" => config.skip_build_checks = true,
            "--verbose" => config.verbose = true,
            "--strict-production" => config.strict_production = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            // Diagnostic: prints how the runner sees the terminal, then exits.
            // Run this exactly as you run the suite (same shell, same window) so
            // the width it reports matches what the real run will use.
            "--term-debug" => {
                print_term_debug();
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }

    Ok(config)
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn print_help() {
    println!(
        "Usage: cargo run --quiet --bin run-devnet-tests\nDirect binary: target/debug/run-devnet-tests [options]\n\nRuns the complete Kurrent local-devnet evidence suite with plain, human-readable output.\n\n{}",
        [
            "Options:",
            "  --prepare-tools       Clone/update/build the external Kaspa and LND tooling first.",
            "  --skip-build-checks   Skip cargo fmt, clippy, tests, and build checks.",
            "  --verbose             Print every command stdout/stderr line on screen; default output is screen-first and bounded for readability.",
            "  --strict-production   Treat production-readiness blockers as final failures.",
            "  -h, --help            Show this help.",
            "",
            "Environment equivalents:",
            "  KURRENT_DEVNET_PREPARE_TOOLS=1",
            "  KURRENT_DEVNET_SKIP_BUILD_CHECKS=1",
            "  KURRENT_DEVNET_VERBOSE=1",
            "  KURRENT_DEVNET_STRICT_PRODUCTION=1",
        ]
        .join("\n")
    );
}

fn repo_root() -> Result<PathBuf, String> {
    let mut dir = env::current_dir().map_err(|err| format!("failed to read cwd: {err}"))?;
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join("scripts").is_dir() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err("could not locate repository root".to_string());
        }
    }
}

impl Runner {
    fn run_all(&mut self) -> Result<(), String> {
        if self.config.prepare_tools {
            self.run_step(StepSpec {
                id: "prepare-devnet-tools",
                label: "Prepare external devnet tools",
                class: StepClass::Required,
                description: "Updates/builds the local Kaspa and LND tooling used by the live devnet workflows.",
                business_value: "Confirms the presentation has the real local Kaspa, Bitcoin, and Lightning executables needed before live service calls run.",
                command: kurrentctl("prepare-devnet-tools"),
                evidence: vec!["evidence/tool-detection.json"],
            compact: true
            })?;
            if self.stop_after_required_failure() {
                return Ok(());
            }
        }

        if self.config.skip_build_checks {
            screen_blank();
            screen_line("Build checks skipped by --skip-build-checks.");
        } else {
            for step in build_check_steps() {
                self.run_step(step)?;
                if self.stop_after_required_failure() {
                    return Ok(());
                }
            }
        }

        for step in devnet_steps() {
            self.run_step(step)?;
            if self.stop_after_required_failure() {
                return Ok(());
            }
        }

        let (status, blocker) = if self.required_failures == 0 {
            ("passed", "passed")
        } else {
            ("failed/blocked", "devnet_test_runner")
        };
        self.run_step(StepSpec {
            id: "aggregate-acceptance-report",
            label: "Write aggregate acceptance report",
            class: StepClass::Required,
            description: "Serialises the run into evidence/kurrent-acceptance.json with hashes, txids, flow states, and blockers.",
            business_value: "Collects the individual workflow artefacts into one acceptance report with hashes, transaction IDs, flow states, and blockers.",
            command: kurrentctl_args(&["write-acceptance-report", status, blocker]),
            evidence: vec!["evidence/kurrent-acceptance.json"],
            compact: false
        })?;
        if self.stop_after_required_failure() {
            return Ok(());
        }

        for step in verification_steps() {
            self.run_step(step)?;
            if self.stop_after_required_failure() {
                return Ok(());
            }
        }

        if !self.config.strict_production && !self.production_boundary_clean()? {
            screen_blank();
            print_wrapped(
                "Production readiness has blockers beyond the expected independent external security review boundary.",
            );
            self.required_failures += 1;
        }

        if self.config.strict_production && self.boundary_failures > 0 {
            self.required_failures += self.boundary_failures;
        }

        Ok(())
    }

    fn stop_after_required_failure(&self) -> bool {
        if self.required_failures == 0 {
            return false;
        }
        screen_blank();
        let msg = "Stopping after the first required failure to keep the presentation readable. Fix the failed step above, then rerun the suite.";
        for line in wrap_line(msg, term::width()) {
            screen_accent(&line, term::Accent::StatusFail);
        }
        true
    }

    fn run_step(&mut self, step: StepSpec) -> Result<(), String> {
        let number = self.outcomes.len() + 1;
        let command_line = step.command.shell_line();
        let title = format!("{number:02}. {}", step.label);

        let started = Instant::now();
        let started_at = SystemTime::now();
        let output_result = Command::new(&step.command.program)
            .args(&step.command.args)
            .current_dir(&self.root)
            .output();
        let duration = started.elapsed();

        let (exit_code, stdout, stderr, run_error) = match output_result {
            Ok(output) => (
                output.status.code().unwrap_or(1),
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
                None,
            ),
            Err(err) => (
                1,
                String::new(),
                String::new(),
                Some(format!("failed to run command: {err}")),
            ),
        };

        let status = classify_status(exit_code, step.class);

        // Compact rendering: a passing compact step (preparation/maintenance)
        // prints as a single line so it doesn't bury the business-flow steps.
        // Anything that is not a clean PASS (failure/blocked/boundary) prints the
        // full block so failures stay debuggable.
        if step.compact
            && status == StepStatus::Pass
            && !self.config.verbose
            && step.evidence.is_empty()
        {
            let tag = term::paint(status_accent(status), status_label(status));
            let line = format!("{tag} {number:02}. {} ({})", step.label, duration.as_secs());
            screen_line(&line);
        } else {
            screen_blank();
            screen_rule(term::Accent::Heading);
            screen_accent(&title, term::Accent::Heading);
            screen_rule(term::Accent::Heading);
            print_wrapped(step.description);
            print_kv("Business proof", step.business_value);
            print_kv("Step id", step.id);
            print_kv("Command", &command_line);
            print_kv("Running", step.label);

            // Build the result line as plain text, wrap to the real width, then
            // paint each wrapped line.
            let mut result_plain = format!(
                "Result: {} exit_code={} duration={}s",
                status_label(status),
                exit_code,
                duration.as_secs()
            );
            if step.class == StepClass::Boundary {
                result_plain.push_str(" boundary=true");
            }
            for line in wrap_line(&result_plain, term::width()) {
                screen_accent(&line, status_accent(status));
            }

            // Presentation rule: a passing step never dumps raw child stdout/stderr
            // to the screen. Child output is structured (JSON, daemon logs, hex) and
            // printing it turns the screen into an unreadable wall of text. Instead
            // we show only our own curated evidence snapshot below. Full child output
            // is kept on disk under evidence/ and is printed only when a step fails
            // (so failures stay debuggable) or when --verbose is set.
            let show_child_output =
                self.config.verbose || matches!(status, StepStatus::Fail | StepStatus::Blocked);
            if show_child_output {
                print_screen_output("stdout", &stdout, self.config.verbose);
                print_screen_output("stderr", &stderr, self.config.verbose);
            } else {
                summarize_child_output("stdout", &stdout);
                summarize_child_output("stderr", &stderr);
            }
            if let Some(err) = &run_error {
                screen_err_line("Runner error:");
                for line in wrap_line(err, term::width()) {
                    screen_err_line(&line);
                }
            }

            if !step.evidence.is_empty() {
                screen_accent("Evidence snapshot:", term::Accent::Heading);
                let freshness_cutoff = match status {
                    StepStatus::Pass | StepStatus::Boundary => None,
                    StepStatus::Fail | StepStatus::Blocked => Some(started_at),
                };
                let evidence_lines =
                    summarise_evidence(&self.root, &step.evidence, freshness_cutoff);
                for line in &evidence_lines {
                    print_wrapped_indent("    ", line);
                }
            }
        }

        self.outcomes.push(StepOutcome {
            label: step.label.to_string(),
            business_value: step.business_value.to_string(),
            status,
            exit_code,
            duration,
        });

        match (step.class, status) {
            (StepClass::Required, StepStatus::Pass) => {}
            (StepClass::Required, _) => self.required_failures += 1,
            (StepClass::Boundary, StepStatus::Pass) => {}
            (StepClass::Boundary, _) => self.boundary_failures += 1,
        }

        Ok(())
    }

    fn print_banner(&self) -> Result<(), String> {
        screen_blank();
        screen_accent("Kurrent local devnet test suite", term::Accent::Banner);
        screen_rule(term::Accent::Banner);
        print_kv(
            "Scope",
            "local Kaspa simnet + Bitcoin regtest/LND evidence only",
        );
        print_kv(
            "Non-claim",
            "this is not mainnet readiness and not production readiness",
        );
        print_kv("Run id", &self.run_id);
        print_kv("Repository", self.root.display().to_string());
        print_kv(
            "Output mode",
            "screen-first; this runner does not write presentation .log files",
        );
        print_kv(
            "Evidence mode",
            "audit artefacts remain under evidence/; the presentation surface is the terminal output",
        );
        print_kv(
            "Git branch",
            git_output(&self.root, &["branch", "--show-current"]),
        );
        print_kv(
            "Git head",
            git_output(&self.root, &["rev-parse", "--short=12", "HEAD"]),
        );
        Ok(())
    }

    fn write_final_summary(&self) -> Result<(), String> {
        let conclusion = if self.required_failures == 0 {
            "Local devnet conclusion: passed."
        } else {
            "Local devnet conclusion: failed or blocked; inspect the failed screen section above."
        };
        let boundary = if self.boundary_failures > 0 {
            Some("Production boundary: still reported separately; this suite does not turn a missing independent security review into a devnet failure.")
        } else {
            None
        };

        screen_blank();
        screen_accent("Run summary", term::Accent::Heading);
        screen_rule(term::Accent::Heading);
        for outcome in &self.outcomes {
            // Wrap plain text first, then colour, so ANSI never skews columns.
            let plain = format!(
                "{} exit={} seconds={} step={}",
                outcome.status.plain(),
                outcome.exit_code,
                outcome.duration.as_secs(),
                outcome.label
            );
            for line in wrap_line(&plain, term::width()) {
                screen_accent(&line, status_accent(outcome.status));
            }
        }
        let conclusion_accent = if self.required_failures == 0 {
            term::Accent::StatusPass
        } else {
            term::Accent::StatusFail
        };
        for line in wrap_line(conclusion, term::width()) {
            screen_accent(&line, conclusion_accent);
        }
        if let Some(boundary) = boundary {
            print_wrapped(boundary);
        }

        self.print_business_flow_summary();

        screen_blank();
        for line in wrap_line(
            "No presentation .log files were written by this runner.",
            term::width(),
        ) {
            screen_accent(&line, term::Accent::Dim);
        }

        Ok(())
    }

    fn print_business_flow_summary(&self) {
        screen_blank();
        screen_accent("Investor-facing business proof", term::Accent::Heading);
        screen_rule(term::Accent::Heading);
        print_wrapped(
            "This run exercised the current product story end to end: local chain execution, Lightning payment evidence, Kaspa-side settlement rules, failure handling, and audit gates.",
        );

        for outcome in self.outcomes.iter().filter(|outcome| {
            !outcome.label.starts_with("Rust formatting")
                && !outcome.label.starts_with("Clippy")
                && outcome.label != "Protocol and model tests"
                && outcome.label != "Build control binaries"
        }) {
            // Wrap the plain form (status tag + label) so ANSI bytes never
            // distort the column count, then colour each wrapped line.
            let plain = format!("{} {}", outcome.status.plain(), outcome.label);
            for line in wrap_line(&plain, term::width()) {
                screen_accent(&line, status_accent(outcome.status));
            }
            print_wrapped_indent("  proof: ", &outcome.business_value);
        }
    }

    fn production_boundary_clean(&self) -> Result<bool, String> {
        let path = self.root.join("evidence/kurrent-production-readiness.json");
        let value = match read_json(&path) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if value.get("status").and_then(Value::as_str) == Some("passed") {
            return Ok(true);
        }
        let missing_requirements = value
            .get("requirements")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter(|requirement| {
                !requirement
                    .get("present")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .filter_map(|requirement| requirement.get("id").and_then(Value::as_str))
            .collect::<Vec<_>>();
        let blockers = value
            .get("blockers")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        Ok(missing_requirements == ["external_security_review"]
            && !blockers.is_empty()
            && blockers.iter().all(|blocker| {
                blocker
                    .as_str()
                    .is_some_and(|text| text.contains("external_security_review"))
            }))
    }
}

impl CommandSpec {
    fn new(program: impl Into<String>, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }

    fn shell_line(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(shell_word)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl StepStatus {
    fn plain(self) -> &'static str {
        match self {
            StepStatus::Pass => "PASS",
            StepStatus::Fail => "FAIL",
            StepStatus::Blocked => "BLOCKED",
            StepStatus::Boundary => "BOUNDARY",
        }
    }
}

fn build_check_steps() -> Vec<StepSpec> {
    vec![
        StepSpec {
            id: "fmt-main",
            label: "Rust formatting check: main crate",
            class: StepClass::Required,
            description: "Checks that the main Kurrent crate is formatted.",
            business_value: "Shows the core codebase is clean enough to reproduce the presentation without local formatting drift.",
            command: CommandSpec::new("cargo", &["fmt", "--all", "--check"]),
            evidence: vec![],
            compact: true
        },
        StepSpec {
            id: "fmt-kaspa-driver",
            label: "Rust formatting check: Kaspa devnet driver",
            class: StepClass::Required,
            description: "Checks that the live Kaspa devnet driver is formatted.",
            business_value: "Shows the live Kaspa transaction driver is maintained as reviewable Rust code, not a throwaway presentation script.",
            command: CommandSpec::new(
                "cargo",
                &["fmt", "--manifest-path", "drivers/kaspa-devnet/Cargo.toml", "--check"],
            ),
            evidence: vec![],
            compact: true
        },
        StepSpec {
            id: "clippy-main",
            label: "Clippy check: main crate",
            class: StepClass::Required,
            description: "Runs clippy with warnings denied over the main crate and tests.",
            business_value: "Runs static Rust checks over the protocol model and control binaries before claiming the live-flow evidence.",
            command: CommandSpec::new("cargo", &["clippy", "--all-targets", "--", "-D", "warnings"]),
            evidence: vec![],
            compact: true
        },
        StepSpec {
            id: "clippy-kaspa-driver",
            label: "Clippy check: Kaspa devnet driver",
            class: StepClass::Required,
            description: "Runs clippy with warnings denied over the Kaspa devnet driver.",
            business_value: "Runs static Rust checks over the component that constructs and submits the Kaspa-side transactions.",
            command: CommandSpec::new(
                "cargo",
                &[
                    "clippy",
                    "--manifest-path",
                    "drivers/kaspa-devnet/Cargo.toml",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
            evidence: vec![],
            compact: true
        },
        StepSpec {
            id: "cargo-test",
            label: "Protocol and model tests",
            class: StepClass::Required,
            description: "Runs the Rust unit and integration tests for the protocol model.",
            business_value: "Exercises the deterministic protocol model before the live local-network workflows run.",
            command: CommandSpec::new("cargo", &["test"]),
            evidence: vec![],
            compact: true
        },
        StepSpec {
            id: "cargo-build",
            label: "Build control binaries",
            class: StepClass::Required,
            description: "Builds kurrentctl, run-devnet-tests, and the main crate artefacts used by the workflow runner.",
            business_value: "Proves the presentation is running freshly built local binaries from this repository.",
            command: CommandSpec::new("cargo", &["build"]),
            evidence: vec![],
            compact: true
        },
    ]
}

fn devnet_steps() -> Vec<StepSpec> {
    vec![
        StepSpec {
            id: "detect-tools",
            label: "Detect local devnet tooling",
            class: StepClass::Required,
            description: "Records the available Kaspa, Bitcoin, and Lightning tooling before running live flows.",
            business_value: "Shows which real local Kaspa, Bitcoin Core, and LND tools are present before any workflow evidence is produced.",
            command: kurrentctl("detect-tools"),
            evidence: vec!["evidence/tool-detection.json"],
            compact: true
        },
        StepSpec {
            id: "kaspa-devnet-probe",
            label: "Kaspa simnet probe",
            class: StepClass::Required,
            description: "Starts a reset local kaspad simnet with UTXO index and unsynchronised mining enabled, then records the daemon transcript.",
            business_value: "Starts a real local Kaspa simnet daemon and proves the Kaspa side is backed by a launched daemon transcript.",
            command: kurrentctl("run-kaspa-devnet"),
            evidence: vec!["evidence/kaspa-simnet-probe.json"],
            compact: false
        },
        StepSpec {
            id: "ln-regtest-devnet",
            label: "Lightning regtest devnet",
            class: StepClass::Required,
            description: "Starts bitcoind plus Alice and Bob LND nodes, opens a channel, pays an invoice, and records the preimage evidence.",
            business_value: "Runs real Bitcoin regtest plus two LND nodes, opens a channel, pays an invoice, and captures the payment preimage used by the cross-chain flows.",
            command: kurrentctl("run-ln-devnet"),
            evidence: vec!["evidence/ln-devnet-evidence.json"],
            compact: false
        },
        StepSpec {
            id: "state-channel-flow",
            label: "Latest-state channel live flow",
            class: StepClass::Required,
            description: "Runs the Kaspa live driver, producing state update, stale-state rejection, lane monitor, settlement eligibility, fee-sponsored displacement, factory, swap, and refund evidence.",
            business_value: "Shows the core commercial safety property: latest-state settlement succeeds while stale or wrong-lane claims are rejected.",
            command: kurrentctl("run-state-channel-flow"),
            evidence: vec![
                "evidence/kurrent-live-state-channel-evidence.json",
                "evidence/kurrent-live-lane-monitor-evidence.json",
                "evidence/kurrent-live-settlement-eligibility-evidence.json",
                "evidence/kurrent-live-fee-sponsored-displacement-evidence.json",
            ],
            compact: false
        },
        StepSpec {
            id: "factory-flow",
            label: "Factory materialisation flow",
            class: StepClass::Required,
            description: "Validates the live factory materialisation evidence and the typed factory accounting model.",
            business_value: "Shows the factory path can materialise shared state into concrete Kaspa transactions with typed accounting evidence.",
            command: kurrentctl("run-factory-flow"),
            evidence: vec![
                "evidence/kurrent-factory-flow-evidence.json",
                "evidence/kurrent-live-factory-evidence.json",
            ],
            compact: false
        },
        StepSpec {
            id: "ln-to-kaspa-flow",
            label: "LN to Kaspa atomic settlement flow",
            class: StepClass::Required,
            description: "Checks that the observed Lightning preimage unlocks the matching live Kaspa hashlock settlement path.",
            business_value: "Proves the Lightning payment secret can unlock the matching Kaspa-side settlement path in the LN-to-Kaspa direction.",
            command: kurrentctl("run-ln-to-kaspa-flow"),
            evidence: vec![
                "evidence/kurrent-ln-to-kaspa-flow-evidence.json",
                "evidence/kurrent-live-ln-to-kaspa-evidence.json",
            ],
            compact: false
        },
        StepSpec {
            id: "kaspa-to-ln-flow",
            label: "Kaspa to LN atomic settlement flow",
            class: StepClass::Required,
            description: "Checks the reverse-direction live Kaspa hashlock funding and settlement path bound to the Lightning evidence.",
            business_value: "Proves the reverse direction is bound to the same style of hashlock evidence rather than being a one-way presentation claim.",
            command: kurrentctl("run-kaspa-to-ln-flow"),
            evidence: vec![
                "evidence/kurrent-kaspa-to-ln-flow-evidence.json",
                "evidence/kurrent-live-kaspa-to-ln-evidence.json",
            ],
            compact: false
        },
        StepSpec {
            id: "refund-flow",
            label: "Refund timeout flow",
            class: StepClass::Required,
            description: "Validates early-refund rejection, mature refund acceptance, and scoped refund claim accounting.",
            business_value: "Shows the customer-safety exit path: early refund is rejected, but the mature timeout refund succeeds with scoped accounting.",
            command: kurrentctl("run-refund-flow"),
            evidence: vec![
                "evidence/kurrent-refund-flow-evidence.json",
                "evidence/kurrent-live-refund-evidence.json",
            ],
            compact: false
        },
    ]
}

fn verification_steps() -> Vec<StepSpec> {
    vec![
        StepSpec {
            id: "verify-evidence",
            label: "Verify aggregate acceptance evidence",
            class: StepClass::Required,
            description: "Replays the commit-bound evidence verifier against evidence/kurrent-acceptance.json.",
            business_value: "Checks that the run evidence is internally consistent and bound to the current repository revision.",
            command: kurrentctl("verify-evidence"),
            evidence: vec!["evidence/kurrent-acceptance.json"],
            compact: false
        },
        StepSpec {
            id: "production-target-profile",
            label: "Write production target profile",
            class: StepClass::Required,
            description: "Pins the local acceptance result, tool profile, and production gate checklist into a target profile artefact.",
            business_value: "Separates what the local devnet proves from the stronger requirements needed before any production claim.",
            command: kurrentctl("write-production-target-profile"),
            evidence: vec!["evidence/production/target-profile.json"],
            compact: false
        },
        StepSpec {
            id: "semantic-transaction-verifier",
            label: "Semantic transaction verifier",
            class: StepClass::Required,
            description: "Decodes raw transactions, scripts, witnesses, txids, outpoints, and receipt bindings rather than relying only on file hashes.",
            business_value: "Verifies transaction meaning, scripts, witnesses, outpoints, and receipt bindings instead of trusting filenames or hashes alone.",
            command: kurrentctl("run-semantic-transaction-verifier"),
            evidence: vec!["evidence/production/semantic-transaction-verifier.json"],
            compact: false
        },
        StepSpec {
            id: "adversarial-soak",
            label: "Adversarial model soak",
            class: StepClass::Required,
            description: "Runs deterministic stale-state, registry-conflict, fee-sponsor, factory, swap, refund, and evidence-tamper checks.",
            business_value: "Runs hostile scenarios against the model, including stale state, fee-sponsor displacement, refund, and evidence tampering.",
            command: kurrentctl("run-adversarial-soak"),
            evidence: vec!["evidence/production/adversarial-model-soak.json"],
            compact: false
        },
        StepSpec {
            id: "presentation-reality-verifier",
            label: "Presentation reality verifier",
            class: StepClass::Required,
            description: "Verifies that the screen presentation is backed by launched local daemons, LND payment/channel state, raw Kaspa transaction artefacts, and rejection evidence.",
            business_value: "Fails the presentation if required daemon, Lightning, transaction, hashlock, refund, semantic, or adversarial evidence is missing or superficial.",
            command: kurrentctl("verify-presentation-reality"),
            evidence: vec!["evidence/production/presentation-reality.json"],
            compact: false
        },
        StepSpec {
            id: "security-review-package",
            label: "Prepare external security-review package",
            class: StepClass::Required,
            description: "Builds the independent-review request package and hashes the artefacts that a reviewer must cover.",
            business_value: "Prepares the review scope and artefact hashes needed for an independent external security review.",
            command: kurrentctl("prepare-security-review-package"),
            evidence: vec!["evidence/production/security-review-request.json"],
            compact: false
        },
        StepSpec {
            id: "production-readiness-boundary",
            label: "Production-readiness boundary check",
            class: StepClass::Boundary,
            description: "Runs the production gate to show which requirements are satisfied and which remain non-claims, usually the independent external security review.",
            business_value: "Makes the boundary explicit: the local devnet can pass while production readiness still waits for independent review.",
            command: kurrentctl("verify-production-readiness"),
            evidence: vec!["evidence/kurrent-production-readiness.json"],
            compact: false
        },
    ]
}

fn kurrentctl(command: &'static str) -> CommandSpec {
    kurrentctl_args(&[command])
}

fn kurrentctl_args(args: &[&str]) -> CommandSpec {
    let mut all_args = vec!["run", "--quiet", "--bin", "kurrentctl", "--"];
    all_args.extend_from_slice(args);
    CommandSpec::new("cargo", &all_args)
}

fn classify_status(exit_code: i32, class: StepClass) -> StepStatus {
    if exit_code == 0 {
        StepStatus::Pass
    } else if class == StepClass::Boundary {
        StepStatus::Boundary
    } else if (10..=17).contains(&exit_code) {
        StepStatus::Blocked
    } else {
        StepStatus::Fail
    }
}

fn status_label(status: StepStatus) -> String {
    match status {
        StepStatus::Pass => "[PASS]".to_string(),
        StepStatus::Fail => "[FAIL]".to_string(),
        StepStatus::Blocked => "[BLOCKED]".to_string(),
        StepStatus::Boundary => "[BOUNDARY]".to_string(),
    }
}

fn status_accent(status: StepStatus) -> term::Accent {
    match status {
        StepStatus::Pass => term::Accent::StatusPass,
        StepStatus::Fail => term::Accent::StatusFail,
        StepStatus::Blocked => term::Accent::StatusFail,
        StepStatus::Boundary => term::Accent::StatusBoundary,
    }
}

// --- Screen helpers (all funnel through emit_line / emit_err_line) ---------

fn screen_blank() {
    emit_line("");
}

/// Emit one already-wrapped plain-text line, optionally painted with an
/// accent. Styling is applied here, *after* wrapping, so visible width is
/// never disturbed by ANSI bytes.
fn screen_line(text: &str) {
    screen_accent(text, term::Accent::Plain);
}

fn screen_accent(text: &str, accent: term::Accent) {
    emit_line(&term::paint(accent, text));
}

fn screen_err_line(text: &str) {
    emit_err_line(&term::sanitize(text));
}

/// Render a coloured banner/heading rule line.
fn screen_rule(accent: term::Accent) {
    screen_accent(&"=".repeat(term::width()), accent);
}

/// One-line placeholder shown for passing steps so the audience knows the
/// command produced output without flooding the screen with it. The full
/// content is preserved on disk under evidence/.
fn summarize_child_output(label: &str, text: &str) {
    let cleaned = term::sanitize(text);
    if cleaned.trim().is_empty() {
        return;
    }
    let lines = cleaned.lines().count().max(1);
    let bytes = cleaned.len();
    let msg = format!("Command {label}: {lines} line(s), {bytes} byte(s) (kept in evidence/)");
    // Wrap through the main wrapper so this line also obeys the real terminal
    // width and never overruns into a terminal-induced second wrap.
    for line in wrap_line(&msg, term::width()) {
        screen_accent(&line, term::Accent::Dim);
    }
}

fn print_screen_output(label: &str, text: &str, full: bool) {
    // Sanitise first: child stdout/stderr may contain carriage returns,
    // backspaces, tabs, or stray escape sequences that corrupt layout.
    let cleaned = term::sanitize(text);
    if cleaned.trim().is_empty() {
        return;
    }
    screen_accent(&format!("Command {label}:"), term::Accent::Dim);

    let lines = cleaned.lines().collect::<Vec<_>>();
    if full || lines.len() <= DEFAULT_OUTPUT_LINE_LIMIT {
        for line in lines {
            print_dim_truncated(line);
        }
        return;
    }

    for line in lines.iter().take(DEFAULT_OUTPUT_HEAD_LINES) {
        print_dim_truncated(line);
    }
    let omitted = lines
        .len()
        .saturating_sub(DEFAULT_OUTPUT_HEAD_LINES + DEFAULT_OUTPUT_TAIL_LINES);
    print_dim_truncated(&format!(
        "... {omitted} command output lines omitted from the screen view; rerun with --verbose to print every line."
    ));
    for line in lines
        .iter()
        .skip(lines.len().saturating_sub(DEFAULT_OUTPUT_TAIL_LINES))
    {
        print_dim_truncated(line);
    }
}

/// Render a child command output line. These lines are structured (JSON,
/// daemon logs, hex) so we do **not** word-wrap them — wrapping fragments
/// paths and strings into unreadable pieces like `kaspa-` + `wallet"`. Each
/// line is kept intact; if it exceeds the width it is truncated at the visible
/// boundary with an ellipsis. Full content always remains in evidence/.
fn print_dim_truncated(text: &str) {
    for line in text.lines() {
        screen_accent(&truncate_line(line, term::width()), term::Accent::Dim);
    }
}

/// Truncate a *plain-text* line to `width` visible columns. Unlike wrapping,
/// this never splits a token: long lines end with `...` at the boundary.
fn truncate_line(line: &str, width: usize) -> String {
    let count = line.chars().count();
    if count <= width {
        return line.to_string();
    }
    if width <= 3 {
        return line.chars().take(width).collect();
    }
    let keep = width - 3;
    let head: String = line.chars().take(keep).collect();
    format!("{head}...")
}

fn print_kv(label: &str, value: impl AsRef<str>) {
    let value = term::sanitize(value.as_ref());
    let label_text = format!("{label}:");
    let first_width = term::width()
        .saturating_sub(term::visible_width(&label_text) + 1)
        .max(20);
    let lines = wrap_line(&value, first_width);
    if let Some((first, rest)) = lines.split_first() {
        screen_accent(
            &format!(
                "{} {first}",
                term::paint(term::Accent::Heading, &label_text)
            ),
            term::Accent::Plain,
        );
        let indent = " ".repeat(label.chars().count() + 2);
        for line in rest {
            screen_line(&format!("{indent}{line}"));
        }
    } else {
        screen_accent(&label_text, term::Accent::Heading);
    }
}

fn print_wrapped(text: &str) {
    for line in term::sanitize(text).lines() {
        for wrapped in wrap_line(line, term::width()) {
            screen_line(&wrapped);
        }
    }
}

fn print_wrapped_indent(indent: &str, text: &str) {
    let width = term::width()
        .saturating_sub(term::visible_width(indent))
        .max(20);
    for line in term::sanitize(text).lines() {
        // Evidence lines like "  - foo: bar" carry their own sub-indent, which
        // would make wrap continuations drift to an odd column (e.g. 6) instead
        // of the block's 4-space margin. Normalise each line to left-aligned
        // content so every continuation aligns under `indent`.
        let trimmed = line.trim_start();
        for wrapped in wrap_line(trimmed, width) {
            screen_line(&format!("{indent}{wrapped}"));
        }
    }
}

/// Word-wrap a single *plain-text* line to `width`. Never sees ANSI, so its
/// `chars().count()` accounting is exactly the visible width. Long unbreakable
/// tokens (paths, hex) are broken at the width boundary so nothing overruns.
fn wrap_line(line: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return vec![String::new()];
    }

    let indent = line
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .take(width / 3)
        .collect::<String>();
    let indent_len = term::visible_width(&indent);
    let usable_width = width.saturating_sub(indent_len).max(20);
    let mut output = Vec::new();
    let mut current = indent.clone();
    let mut current_len = indent_len;

    for word in trimmed.split_whitespace() {
        for piece in split_word(word, usable_width) {
            let piece_len = term::visible_width(&piece);
            let needs_space = current_len > indent_len;
            let next_len = current_len + usize::from(needs_space) + piece_len;
            if next_len > width && current_len > indent_len {
                output.push(current);
                current = format!("{indent}{piece}");
                current_len = indent_len + piece_len;
            } else {
                if needs_space {
                    current.push(' ');
                    current_len += 1;
                }
                current.push_str(&piece);
                current_len += piece_len;
            }
        }
    }

    if current_len > indent_len || output.is_empty() {
        output.push(current);
    }
    output
}

fn split_word(word: &str, max_width: usize) -> Vec<String> {
    let max_width = max_width.max(8);
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_len = 0;
    for ch in word.chars() {
        if current_len == max_width {
            chunks.push(current);
            current = String::new();
            current_len = 0;
        }
        current.push(ch);
        current_len += 1;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn summarise_evidence(
    root: &Path,
    paths: &[&str],
    freshness_cutoff: Option<SystemTime>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for path in paths {
        let full_path = root.join(path);
        if !full_path.is_file() {
            lines.push(format!("evidence: {path} (missing)"));
            continue;
        }
        if let Some(cutoff) = freshness_cutoff {
            if !evidence_file_is_fresh(&full_path, cutoff) {
                lines.push(format!(
                    "evidence: {path} (stale from an earlier run; not shown after failed step)"
                ));
                continue;
            }
        }
        if full_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            let bytes = full_path.metadata().map(|meta| meta.len()).unwrap_or(0);
            lines.push(format!("evidence: {path}"));
            lines.push(format!("artefact bytes: {bytes}"));
            continue;
        }
        let value = match read_json(&full_path) {
            Ok(value) => value,
            Err(err) => {
                lines.push(format!("evidence: {path} (could not parse JSON: {err})"));
                continue;
            }
        };
        let name = full_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        lines.push(format!("evidence: {path}"));
        lines.push(format!("status: {}", status_of(&value)));
        push_blockers(&mut lines, &value);
        match name {
            "tool-detection.json" => summarise_tool_detection(&mut lines, &value),
            "kaspa-simnet-probe.json" => summarise_kaspa_probe(&mut lines, &value),
            "ln-devnet-evidence.json" => summarise_ln_devnet(&mut lines, &value),
            "kurrent-live-state-channel-evidence.json" => summarise_live_state(&mut lines, &value),
            "kurrent-live-lane-monitor-evidence.json" => summarise_lane_monitor(&mut lines, &value),
            "kurrent-live-settlement-eligibility-evidence.json" => {
                summarise_settlement_eligibility(&mut lines, &value);
            }
            "kurrent-live-fee-sponsored-displacement-evidence.json" => {
                summarise_fee_sponsored(&mut lines, &value);
            }
            "kurrent-live-factory-evidence.json" => summarise_factory(&mut lines, &value),
            "kurrent-live-ln-to-kaspa-evidence.json" | "kurrent-live-kaspa-to-ln-evidence.json" => {
                summarise_hashlock(&mut lines, &value);
            }
            "kurrent-live-refund-evidence.json" => summarise_refund(&mut lines, &value),
            "kurrent-acceptance.json" => summarise_acceptance(&mut lines, &value),
            "target-profile.json" => summarise_target_profile(&mut lines, &value),
            "semantic-transaction-verifier.json" => summarise_semantic_verifier(&mut lines, &value),
            "adversarial-model-soak.json" | "adversarial-mempool-soak.json" => {
                summarise_adversarial(&mut lines, &value);
            }
            "presentation-reality.json" => summarise_presentation_reality(&mut lines, &value),
            "security-review-request.json" => summarise_security_review_request(&mut lines, &value),
            "kurrent-production-readiness.json" => {
                summarise_production_readiness(&mut lines, &value)
            }
            _ => {}
        }
    }
    lines
}

fn evidence_file_is_fresh(path: &Path, cutoff: SystemTime) -> bool {
    let Ok(modified) = path.metadata().and_then(|metadata| metadata.modified()) else {
        return false;
    };
    let cutoff = cutoff.checked_sub(Duration::from_secs(2)).unwrap_or(cutoff);
    modified >= cutoff
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|err| err.to_string())?;
    serde_json::from_slice(&bytes).map_err(|err| err.to_string())
}

fn status_of(value: &Value) -> String {
    value
        .get("status")
        .or_else(|| value.get("capability_status"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn push_blockers(lines: &mut Vec<String>, value: &Value) {
    let Some(blockers) = value.get("blockers").and_then(Value::as_array) else {
        return;
    };
    if blockers.is_empty() {
        return;
    }
    lines.push("blockers:".to_string());
    for blocker in blockers.iter().take(8).filter_map(Value::as_str) {
        lines.push(format!("  - {blocker}"));
    }
    if blockers.len() > 8 {
        lines.push(format!("  - ... {} more", blockers.len() - 8));
    }
}

fn summarise_tool_detection(lines: &mut Vec<String>, value: &Value) {
    if let Some(selected) = pointer_str(value, "/selected_kaspa_repo/path") {
        lines.push(format!("selected Kaspa repo: {selected}"));
    }
    let Some(tools) = value.get("tools").and_then(Value::as_array) else {
        return;
    };
    let present = tools
        .iter()
        .filter(|tool| tool.get("path").and_then(Value::as_str).is_some())
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let absent = tools
        .iter()
        .filter(|tool| tool.get("path").and_then(Value::as_str).is_none())
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    push_wrapped_list(lines, "tool paths present", &present);
    if !absent.is_empty() {
        push_wrapped_list(lines, "tool paths absent", &absent);
    }
}

fn summarise_kaspa_probe(lines: &mut Vec<String>, value: &Value) {
    push_owned(lines, "daemon", value.get("daemon").and_then(Value::as_str));
    push_owned(
        lines,
        "network",
        value.get("network").and_then(Value::as_str),
    );
    push_owned(
        lines,
        "rpc listen",
        value.get("rpc_listen").and_then(Value::as_str),
    );
    push_u64(lines, "stdout bytes", value.get("stdout_bytes"));
    push_u64(lines, "stderr bytes", value.get("stderr_bytes"));
    if value
        .get("unsynchronised_mining")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        lines.push("unsynchronised mining: enabled".to_string());
    }
}

fn summarise_ln_devnet(lines: &mut Vec<String>, value: &Value) {
    push_short(
        lines,
        "Alice node",
        pointer_str(value, "/alice/identity_pubkey"),
        32,
    );
    push_short(
        lines,
        "Bob node",
        pointer_str(value, "/bob/identity_pubkey"),
        32,
    );
    for direction in ["ln-to-kaspa", "kaspa-to-ln"] {
        lines.push(format!("{direction} LN invoice:"));
        push_short(
            lines,
            "payment hash",
            pointer_str(value, &format!("/swaps/{direction}/payment_hash")),
            40,
        );
        push_short(
            lines,
            "preimage",
            pointer_str(value, &format!("/swaps/{direction}/preimage")),
            40,
        );
        push_u64(
            lines,
            "amount sat",
            value.pointer(&format!("/swaps/{direction}/amount_sat")),
        );
    }
    lines
        .push("atomic peg: each Kaspa swap direction binds to its own LN payment hash".to_string());
}

fn summarise_live_state(lines: &mut Vec<String>, value: &Value) {
    if let Some(profile) = value.get("network_profile").and_then(Value::as_str) {
        lines.push(format!("network profile: {profile}"));
    }
    push_short(
        lines,
        "funding outpoint",
        pointer_str(value, "/funding/outpoint"),
        56,
    );
    push_short(
        lines,
        "state update txid",
        pointer_str(value, "/state_update/txid"),
        40,
    );
    push_short(
        lines,
        "settlement txid",
        pointer_str(value, "/settlement/txid"),
        40,
    );

    // Lane enforcement — the OpTxSubnetId / KIP-21 story Kaspa-core readers
    // scrutinise: the lane is script-enforced, not merely off-chain.
    push_owned(
        lines,
        "lane binding",
        pointer_str(value, "/lane_binding/binding_status"),
    );
    push_short(
        lines,
        "expected lane id",
        pointer_str(value, "/lane_binding/expected_lane_id"),
        42,
    );
    push_short(
        lines,
        "wrong-user lane id (rejected)",
        pointer_str(value, "/lane_binding/wrong_user_lane_id"),
        42,
    );

    // Covenant + script identity pinned across every state transition.
    push_short(
        lines,
        "covenant id",
        pointer_str(value, "/funding/covenant_id"),
        40,
    );
    push_short(
        lines,
        "script covenant hash",
        pointer_str(
            value,
            "/model_validation/funding_state/script_covenant_hash",
        ),
        40,
    );

    // Principal split — the actual channel balance between participants.
    push_principal_split(
        lines,
        value.pointer("/model_validation/funding_state/principal_by_participant"),
    );

    // Stale-state rejection — old state number cannot settle.
    if let Some(status) = pointer_str(value, "/stale_state_rejection/status") {
        lines.push(format!("stale state attempt: {status}"));
    }
    if let Some(stale) = pointer_str(value, "/model_validation/stale_rejection") {
        lines.push(format!("  stale rejection: {stale}"));
    }

    // Wrong-lane rejections — negative controls proving OpTxSubnetId is enforced
    // on-chain (native lane + wrong-user lane both rejected despite valid sigs).
    let wrong = value
        .get("wrong_lane_rejections")
        .and_then(Value::as_object);
    if let Some(wrong) = wrong {
        let count = wrong.len();
        lines.push(format!("wrong-lane rejections: {count} negative controls"));
        for key in wrong.keys() {
            if let Some(s) = wrong
                .get(key)
                .and_then(|v| v.get("status"))
                .and_then(Value::as_str)
            {
                lines.push(format!("  {key}: {s}"));
            }
        }
    }
}

fn summarise_lane_monitor(lines: &mut Vec<String>, value: &Value) {
    push_owned(
        lines,
        "monitor scope",
        value.get("monitor_scope").and_then(Value::as_str),
    );
    lines.push(format!("lane events: {}", array_len(value, "lane_events")));
    lines.push(format!(
        "lane activity blocks: {}",
        array_len(value, "lane_activity_blocks")
    ));
}

fn summarise_settlement_eligibility(lines: &mut Vec<String>, value: &Value) {
    push_owned(
        lines,
        "monitor scope",
        value.get("monitor_scope").and_then(Value::as_str),
    );
    lines.push(format!("lane events: {}", array_len(value, "lane_events")));
    lines.push(format!(
        "candidate markers: {}",
        value
            .get("candidate_markers")
            .and_then(Value::as_object)
            .map(|items| items.len())
            .unwrap_or(0)
    ));
}

fn summarise_fee_sponsored(lines: &mut Vec<String>, value: &Value) {
    push_owned(
        lines,
        "monitor scope",
        value.get("monitor_scope").and_then(Value::as_str),
    );
    lines.push(format!("lane events: {}", array_len(value, "lane_events")));
    lines.push(format!(
        "sponsored markers: {}",
        value
            .get("sponsored_markers")
            .and_then(Value::as_object)
            .map(|items| items.len())
            .unwrap_or(0)
    ));
}

fn summarise_factory(lines: &mut Vec<String>, value: &Value) {
    push_short(
        lines,
        "funding outpoint",
        pointer_str(value, "/funding/outpoint"),
        56,
    );
    push_short(
        lines,
        "materialisation txid",
        pointer_str(value, "/materialisation/txid"),
        40,
    );

    // Factory leaf accounting: before has 2 virtual channels, materialisation
    // consumes the settled one (vc-1) and leaves the other (vc-2) untouched.
    let before_vcs = value
        .pointer("/model_validation/before/virtual_channels")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let after_vcs = value
        .pointer("/model_validation/after/virtual_channels")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    lines.push(format!(
        "factory virtual channels: {before_vcs} before -> {after_vcs} after materialisation"
    ));
    // Settlement outputs produced by the materialisation tx.
    push_kas(
        lines,
        "materialisation output alice",
        value.pointer("/materialisation/outputs/alice"),
    );
    push_kas(
        lines,
        "materialisation output bob",
        value.pointer("/materialisation/outputs/bob"),
    );
    push_short(
        lines,
        "plan hash",
        pointer_str(value, "/model_validation/plan/plan_hash"),
        40,
    );
}

fn summarise_hashlock(lines: &mut Vec<String>, value: &Value) {
    push_owned(lines, "flow", value.get("flow").and_then(Value::as_str));
    push_short(
        lines,
        "funding outpoint",
        pointer_str(value, "/funding/outpoint"),
        56,
    );
    push_short(
        lines,
        "settlement txid",
        pointer_str(value, "/settlement/txid"),
        40,
    );
    push_short(
        lines,
        "preimage sha256",
        value.get("preimage_sha256").and_then(Value::as_str),
        40,
    );

    // Hashlock swap evidence — the atomic peg between the LN payment hash and
    // the Kaspa HTLC covenant.
    push_owned(
        lines,
        "swap direction",
        pointer_str(value, "/model_validation/swap_evidence/direction"),
    );
    push_owned(
        lines,
        "swap recipient",
        pointer_str(value, "/model_validation/swap_evidence/recipient"),
    );
    push_short(
        lines,
        "swap id",
        pointer_str(value, "/model_validation/swap_evidence/swap_id"),
        40,
    );
    // The key binding: Kaspa preimage_hash == LN payment_hash.
    let preimage_hash = pointer_str(value, "/model_validation/swap_evidence/preimage_hash");
    let ln_payment_hash = pointer_str(value, "/model_validation/swap_evidence/ln_payment_hash");
    if let (Some(ph), Some(lh)) = (preimage_hash, ln_payment_hash) {
        if ph == lh {
            lines.push(format!(
                "atomic peg: Kaspa preimage hash == LN payment hash ({})",
                shorten(ph, 32)
            ));
        }
    }
    push_u64(
        lines,
        "LN amount sat",
        value.pointer("/model_validation/swap_evidence/ln_amount_sat"),
    );
    push_kas(
        lines,
        "Kaspa amount",
        value.pointer("/model_validation/swap_evidence/kaspa_amount_sompi"),
    );
    push_short(
        lines,
        "recipient spk hash",
        pointer_str(
            value,
            "/model_validation/swap_evidence/recipient_spk_sha256",
        ),
        40,
    );
    push_short(
        lines,
        "hashlock script hash",
        pointer_str(value, "/model_validation/swap_evidence/script_hash"),
        40,
    );
}

fn summarise_refund(lines: &mut Vec<String>, value: &Value) {
    push_short(
        lines,
        "funding outpoint",
        pointer_str(value, "/funding/outpoint"),
        56,
    );
    push_owned(
        lines,
        "early refund",
        pointer_str(value, "/early_refund_rejection/status"),
    );
    push_short(
        lines,
        "mature refund txid",
        pointer_str(value, "/refund/txid"),
        40,
    );

    // Refund safety: relative locktime (CSV) enforcement + replay protection.
    push_u64(
        lines,
        "refund locktime (DAA score)",
        value.pointer("/model_validation/refund_sequence"),
    );
    if let Some(rej) = pointer_str(value, "/model_validation/early_rejection") {
        lines.push(format!("early rejection: {rej}"));
    }
    if let Some(dup) = pointer_str(value, "/model_validation/duplicate_rejection") {
        lines.push(format!("duplicate-claim rejection: {dup}"));
    }
    push_kas(
        lines,
        "refund amount",
        value.pointer("/refund/output_value"),
    );
    push_short(
        lines,
        "refund script hash",
        pointer_str(value, "/refund/redeem_script/sha256"),
        40,
    );
}

fn summarise_acceptance(lines: &mut Vec<String>, value: &Value) {
    push_owned(
        lines,
        "network",
        value.get("network_devnet_id").and_then(Value::as_str),
    );
    if let Some(flows) = value.get("flows").and_then(Value::as_object) {
        let mut keys = flows.keys().collect::<Vec<_>>();
        keys.sort();
        for key in keys {
            let status = flows.get(key).and_then(Value::as_str).unwrap_or("unknown");
            lines.push(format!("flow {key}: {status}"));
        }
    }
    lines.push(format!(
        "raw tx files: {}",
        array_len(value, "raw_transaction_paths_and_hashes")
    ));
    lines.push(format!(
        "script files: {}",
        array_len(value, "script_paths_and_hashes")
    ));
    lines.push(format!(
        "witness files: {}",
        array_len(value, "witness_paths_and_hashes")
    ));
}

fn summarise_target_profile(lines: &mut Vec<String>, value: &Value) {
    push_short(
        lines,
        "git commit",
        value.get("git_commit").and_then(Value::as_str),
        40,
    );
    push_owned(
        lines,
        "local acceptance",
        pointer_str(value, "/local_acceptance/status"),
    );
    lines.push(format!(
        "required production gates: {}",
        array_len(value, "required_production_gates")
    ));
}

fn summarise_semantic_verifier(lines: &mut Vec<String>, value: &Value) {
    push_u64(
        lines,
        "decoded transactions",
        value.get("decoded_transactions"),
    );
    push_u64(
        lines,
        "verified hex records",
        value.get("verified_hex_records"),
    );
    let checks = value.get("checks").and_then(Value::as_array);
    lines.push(format!(
        "semantic checks: {}",
        checks.map(Vec::len).unwrap_or(0)
    ));
    if let Some(checks) = checks {
        for check in checks.iter().take(6) {
            let id = check.get("id").and_then(Value::as_str).unwrap_or("unknown");
            let status = check
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            lines.push(format!("  - {id}: {status}"));
        }
    }
}

fn summarise_adversarial(lines: &mut Vec<String>, value: &Value) {
    push_owned(
        lines,
        "seed",
        value.get("deterministic_seed").and_then(Value::as_str),
    );
    push_u64(lines, "iterations", value.get("iterations"));
    push_u64(lines, "scenario count", value.get("scenario_count"));
    push_u64(lines, "check count", value.get("check_count"));
}

fn summarise_presentation_reality(lines: &mut Vec<String>, value: &Value) {
    push_u64(lines, "checks passed", value.pointer("/summary/passed"));
    push_u64(lines, "checks failed", value.pointer("/summary/failed"));
    let Some(checks) = value.get("checks").and_then(Value::as_array) else {
        return;
    };
    for check in checks.iter().take(10) {
        let id = check.get("id").and_then(Value::as_str).unwrap_or("unknown");
        let status = check
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        lines.push(format!("  - {id}: {status}"));
    }
    if checks.len() > 10 {
        lines.push(format!("  - ... {} more", checks.len() - 10));
    }
}

fn summarise_security_review_request(lines: &mut Vec<String>, value: &Value) {
    push_owned(
        lines,
        "review type required",
        value.get("review_type_required").and_then(Value::as_str),
    );
    lines.push(format!(
        "required scope count: {}",
        array_len(value, "required_scope")
    ));
    lines.push(format!(
        "reviewed artefacts: {}",
        array_len(value, "reviewed_artifacts")
    ));
}

fn summarise_production_readiness(lines: &mut Vec<String>, value: &Value) {
    push_owned(
        lines,
        "acceptance status",
        value.get("acceptance_status").and_then(Value::as_str),
    );
    let Some(requirements) = value.get("requirements").and_then(Value::as_array) else {
        return;
    };
    let present = requirements
        .iter()
        .filter(|item| {
            item.get("present")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let missing = requirements
        .iter()
        .filter(|item| {
            !item
                .get("present")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    lines.push(format!(
        "production evidence present: {}",
        non_empty_join(&present, "none")
    ));
    if !missing.is_empty() {
        lines.push(format!(
            "production evidence still required: {}",
            non_empty_join(&missing, "none")
        ));
    }
}

fn pointer_str<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    value.pointer(path).and_then(Value::as_str)
}

fn array_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn push_short(lines: &mut Vec<String>, label: &str, value: Option<&str>, width: usize) {
    if let Some(value) = value {
        lines.push(format!("{label}: {}", shorten(value, width)));
    }
}

fn push_owned(lines: &mut Vec<String>, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        lines.push(format!("{label}: {value}"));
    }
}

fn push_u64(lines: &mut Vec<String>, label: &str, value: Option<&Value>) {
    if let Some(value) = value.and_then(Value::as_u64) {
        lines.push(format!("{label}: {value}"));
    }
}

/// Format a sompi amount (1 KAS = 1e8 sompi) as a human-readable KAS value.
fn format_kas(sompi: u64) -> String {
    let kas = sompi as f64 / 100_000_000.0;
    format!("{kas:.4} KAS")
}

/// Push a labelled sompi amount as a human-readable KAS value.
fn push_kas(lines: &mut Vec<String>, label: &str, value: Option<&Value>) {
    if let Some(v) = value.and_then(Value::as_u64) {
        lines.push(format!("{label}: {} ({v} sompi)", format_kas(v)));
    }
}

/// Push a participant principal split as "name: X KAS" per entry.
fn push_principal_split(lines: &mut Vec<String>, participants: Option<&Value>) {
    let Some(obj) = participants.and_then(Value::as_object) else {
        return;
    };
    for (name, amount) in obj {
        if let Some(v) = amount.as_u64() {
            lines.push(format!("  {name}: {} ({v} sompi)", format_kas(v)));
        }
    }
}

fn shorten(value: &str, width: usize) -> String {
    let count = value.chars().count();
    if count <= width {
        return value.to_string();
    }
    if width <= 12 {
        return value.chars().take(width).collect();
    }
    // Char-based so multibyte boundaries never panic.
    let head = width.saturating_sub(11);
    let tail = 8;
    let head_str: String = value.chars().take(head).collect();
    let tail_str: String = value.chars().skip(count - tail).collect();
    format!("{head_str}...{tail_str}")
}

fn non_empty_join(values: &[&str], fallback: &str) -> String {
    if values.is_empty() {
        fallback.to_string()
    } else {
        values.join(", ")
    }
}

/// Build a labelled list as a single plain-text line and push it. The caller's
/// wrapper handles all width/indent logic uniformly at render time, so this
/// function must NOT pre-wrap or add its own continuation indent — doing so
/// produces mismatched indent columns on the screen.
fn push_wrapped_list(lines: &mut Vec<String>, label: &str, values: &[&str]) {
    if values.is_empty() {
        lines.push(format!("{label}: none"));
        return;
    }
    let joined = values.join(", ");
    lines.push(format!("{label}: {joined}"));
}

fn shell_word(word: &str) -> String {
    if word
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='))
    {
        word.to_string()
    } else {
        format!("{word:?}")
    }
}

fn git_output(root: &Path, args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn utc_compact_timestamp() -> String {
    let (year, month, day, hour, minute, second) = utc_parts();
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

fn utc_parts() -> (i32, u32, u32, u32, u32, u32) {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = (seconds_of_day / 3_600) as u32;
    let minute = ((seconds_of_day % 3_600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    (year, month, day, hour, minute, second)
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}
