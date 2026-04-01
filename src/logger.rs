//! Colorized, timestamped structured logger.

use chrono::Local;
use colored::*;
use serde::Serialize;
use std::{fs, io::Write, path::PathBuf};

// ── Result record (used for JSON output) ─────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TestResult {
    pub timestamp:  String,
    pub action:     String,
    pub server:     String,
    pub port:       u16,
    pub tls_mode:   String,
    pub success:    bool,
    pub duration_ms: u128,
    pub message:    String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:      Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<String>,
}

// ── Logger ────────────────────────────────────────────────────────────────────

pub struct Logger {
    pub verbose:  u8,
    pub json:     bool,
    pub color:    bool,
    pub log_file: Option<PathBuf>,
}

impl Logger {
    pub fn new(verbose: u8, json: bool, color: bool, log_file: Option<PathBuf>) -> Self {
        Self { verbose, json, color, log_file }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn ts(&self) -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
    }

    fn append_log(&self, line: &str) {
        if let Some(p) = &self.log_file {
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{}", line);
            }
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// ASCII + color banner.
    pub fn banner(&self) {
        if self.json { return; }
        let art = concat!(
            "\n  ███████╗███╗   ███╗ █████╗ ██╗██╗      ████████╗███████╗███████╗████████╗███████╗██████╗ \n",
            "  ██╔════╝████╗ ████║██╔══██╗██║██║      ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n",
            "  █████╗  ██╔████╔██║███████║██║██║         ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝\n",
            "  ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║         ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗\n",
            "  ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗    ██║   ███████╗███████║   ██║   ███████╗██║  ██║\n",
            "  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
        );

        if self.color {
            println!("{}", art.cyan().bold());
            println!(
                "  {}  ·  {}  ·  {}\n",
                format!("v{}", env!("CARGO_PKG_VERSION")).bright_white().bold(),
                "Hadi Cahyadi <cumulus13@gmail.com>".bright_black(),
                "github.com/cumulus13/email-tester".bright_black(),
            );
        } else {
            println!("\n  EMAIL-TESTER v{}", env!("CARGO_PKG_VERSION"));
            println!("  Hadi Cahyadi <cumulus13@gmail.com>");
            println!("  https://github.com/cumulus13/email-tester\n");
        }
    }

    /// Bold section header with double-line border.
    pub fn header(&self, text: &str) {
        if self.json { return; }
        let bar = "═".repeat(64);
        if self.color {
            println!("\n{}", bar.cyan().bold());
            println!("  {}", text.cyan().bold());
            println!("{}\n", bar.cyan().bold());
        } else {
            println!("\n{}\n  {}\n{}\n", bar, text, bar);
        }
        self.append_log(&format!("=== {} ===", text));
    }

    /// Sub-section marker.
    pub fn section(&self, text: &str) {
        if self.json { return; }
        if self.color {
            println!("\n  {} {}", "▶".yellow().bold(), text.yellow().bold());
        } else {
            println!("\n  >> {}", text);
        }
    }

    /// Green tick — success line.
    pub fn ok(&self, msg: &str) {
        if self.json { return; }
        let ts = self.ts();
        if self.color {
            println!(
                "  {} {} {}",
                "✓".green().bold(),
                format!("[{}]", ts).bright_black(),
                msg.green()
            );
        } else {
            println!("  [OK]   [{}] {}", ts, msg);
        }
        self.append_log(&format!("[OK]    [{}] {}", ts, msg));
    }

    /// Red cross — failure line (written to stderr + log).
    pub fn fail(&self, msg: &str) {
        let ts = self.ts();
        if !self.json {
            if self.color {
                eprintln!(
                    "  {} {} {}",
                    "✗".red().bold(),
                    format!("[{}]", ts).bright_black(),
                    msg.red().bold()
                );
            } else {
                eprintln!("  [FAIL] [{}] {}", ts, msg);
            }
        }
        self.append_log(&format!("[FAIL]  [{}] {}", ts, msg));
    }

    /// Yellow warning.
    pub fn warn(&self, msg: &str) {
        if self.json { return; }
        let ts = self.ts();
        if self.color {
            println!(
                "  {} {} {}",
                "⚠".yellow().bold(),
                format!("[{}]", ts).bright_black(),
                msg.yellow()
            );
        } else {
            println!("  [WARN] [{}] {}", ts, msg);
        }
        self.append_log(&format!("[WARN]  [{}] {}", ts, msg));
    }

    /// Dimmed debug line (requires -vv or higher).
    pub fn debug(&self, msg: &str) {
        if self.verbose < 2 || self.json { return; }
        let ts = self.ts();
        if self.color {
            println!(
                "  {} {} {}",
                "·".bright_black(),
                format!("[{}]", ts).bright_black(),
                msg.bright_black()
            );
        } else {
            println!("  [DBG]  [{}] {}", ts, msg);
        }
    }

    /// Key-value info row (no status icon).
    pub fn info_kv(&self, label: &str, value: &str) {
        if self.json { return; }
        if self.color {
            println!("    {:26} {}", label.bright_white(), value.white());
        } else {
            println!("    {:26} {}", label, value);
        }
        self.append_log(&format!("[INFO]  {:26} {}", label, value));
    }

    /// Key-value row with green/red status icon.
    pub fn status_kv(&self, label: &str, value: &str, ok: bool) {
        if self.json { return; }
        let (icon, val_s) = if ok {
            (
                if self.color { "✓".green().to_string() } else { "ok".to_string() },
                if self.color { value.green().to_string() } else { value.to_string() },
            )
        } else {
            (
                if self.color { "✗".red().to_string() } else { "!!".to_string() },
                if self.color { value.red().to_string() } else { value.to_string() },
            )
        };
        if self.color {
            println!("    {} {:24} {}", icon, label.bright_white(), val_s);
        } else {
            println!("    [{}] {:24} {}", icon, label, value);
        }
    }

    /// Numbered step indicator.
    pub fn step(&self, i: u32, total: u32, msg: &str) {
        if self.json { return; }
        if self.color {
            println!(
                "  {} [{}/{}] {}",
                "→".bright_blue().bold(),
                i.to_string().bright_blue(),
                total.to_string().bright_blue(),
                msg.white()
            );
        } else {
            println!("  [{}/{}] {}", i, total, msg);
        }
    }

    /// Thin horizontal rule.
    pub fn sep(&self) {
        if self.json { return; }
        if self.color {
            println!("  {}", "─".repeat(60).bright_black());
        } else {
            println!("  {}", "─".repeat(60));
        }
    }

    /// Final result summary (human or JSON).
    pub fn print_result(&self, r: &TestResult) {
        if self.json {
            println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
            return;
        }
        self.sep();
        if r.success {
            self.ok(&r.message);
        } else {
            self.fail(&r.message);
            if let Some(e) = &r.error {
                self.fail(&format!("  Detail : {}", e));
            }
        }
        if self.verbose > 0 {
            self.info_kv("Duration", &format!("{} ms", r.duration_ms));
            if let Some(rsp) = &r.server_response {
                self.info_kv("Server reply", rsp);
            }
        }
        self.sep();
    }
}
