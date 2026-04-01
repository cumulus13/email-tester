// ============================================================
//  email-tester  –  Robust SMTP Email Tester
//  Author  : Hadi Cahyadi <cumulus13@gmail.com>
//  Home    : https://github.com/cumulus13/email-tester
//  License : MIT
// ============================================================

use anyhow::{Context, Result};
use chrono::Local;
use clap::{ArgAction, Parser, Subcommand};
use colored::*;
use lettre::{
    message::{header::ContentType, Attachment, MultiPart, SinglePart},
    transport::smtp::{
        authentication::{Credentials, Mechanism},
        client::{Tls, TlsParameters},
        extension::ClientId,
        PoolConfig,
    },
    Message, SmtpTransport, Transport,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

// ─── Constants ─────────────────────────────────────────────
const DEFAULT_SERVER:  &str = "222.222.222.5";
const DEFAULT_PORT:    u16  = 25;
const DEFAULT_TIMEOUT: u64  = 30;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_AUTHOR:  &str = "Hadi Cahyadi <cumulus13@gmail.com>";

// ─── Config file ───────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct Config {
    #[serde(default)] server:   ServerConfig,
    #[serde(default)] auth:     AuthConfig,
    #[serde(default)] defaults: DefaultsConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ServerConfig { host: String, port: u16, timeout: u64 }
impl Default for ServerConfig {
    fn default() -> Self {
        Self { host: DEFAULT_SERVER.to_string(), port: DEFAULT_PORT, timeout: DEFAULT_TIMEOUT }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct AuthConfig {
    username:  Option<String>,
    password:  Option<String>,
    mechanism: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DefaultsConfig { from: Option<String>, from_name: Option<String>, subject: String, body: String }
impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            from:      None,
            from_name: Some("Email Tester".into()),
            subject:   "SMTP Test Email".into(),
            body:      "This is a test email sent by email-tester.\nhttps://github.com/cumulus13/email-tester".into(),
        }
    }
}

// ─── TLS mode ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum TlsMode { None, StartTls, Tls }

impl FromStr for TlsMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "none" | "plain" | "no"  => Ok(TlsMode::None),
            "starttls" | "start"     => Ok(TlsMode::StartTls),
            "tls" | "ssl" | "smtps"  => Ok(TlsMode::Tls),
            _ => anyhow::bail!("Unknown TLS mode '{}'. Use: none, starttls, tls", s),
        }
    }
}

impl std::fmt::Display for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsMode::None     => write!(f, "Plain (no encryption)"),
            TlsMode::StartTls => write!(f, "STARTTLS"),
            TlsMode::Tls      => write!(f, "TLS/SSL (SMTPS)"),
        }
    }
}

impl TlsMode {
    /// Return a hint about what port is typical for this mode
    fn typical_port(&self) -> &'static str {
        match self {
            TlsMode::None     => "25 or 2525",
            TlsMode::StartTls => "587",
            TlsMode::Tls      => "465",
        }
    }

    /// Warn if the combination of port+tls looks wrong
    fn port_mismatch_hint(&self, port: u16) -> Option<String> {
        match self {
            TlsMode::Tls if port == 25 || port == 587 =>
                Some(format!(
                    "Using --tls tls (implicit SSL) on port {} is unusual. \
                     Port 465 is standard for SMTPS. \
                     For port 25/587 try --tls none or --tls starttls.", port
                )),
            TlsMode::StartTls if port == 465 =>
                Some(format!(
                    "Using --tls starttls on port 465 is unusual. \
                     Port 465 normally uses implicit TLS (--tls tls). \
                     For STARTTLS use port 587."
                )),
            TlsMode::None if port == 465 =>
                Some(format!(
                    "Port 465 usually requires implicit TLS. \
                     Try --tls tls instead of --tls none."
                )),
            _ => None,
        }
    }
}

// ─── Auth Mechanism ────────────────────────────────────────

#[derive(Debug, Clone)]
enum AuthMech { Plain, Login }

impl FromStr for AuthMech {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "PLAIN" => Ok(AuthMech::Plain),
            "LOGIN" => Ok(AuthMech::Login),
            _ => anyhow::bail!("Unknown auth mechanism '{}'. Use: PLAIN, LOGIN", s),
        }
    }
}

impl AuthMech {
    fn to_mechanism(&self) -> Mechanism {
        match self { AuthMech::Plain => Mechanism::Plain, AuthMech::Login => Mechanism::Login }
    }
    fn label(&self) -> &'static str {
        match self { AuthMech::Plain => "PLAIN", AuthMech::Login => "LOGIN" }
    }
}

// ─── Error diagnosis ───────────────────────────────────────

fn diagnose_error(err: &str, server: &str, port: u16, tls: &TlsMode, has_auth: bool) -> Vec<String> {
    let mut hints: Vec<String> = Vec::new();

    // TLS handshake on a plain port (the exact problem we saw in the logs)
    if err.contains("improper command pipelining")
        || err.contains("The token supplied to the function is invalid")
        || err.contains("os error -2146893048")
        || err.contains("wrong version number")
        || err.contains("tls handshake")
        || err.contains("record layer failure")
    {
        if *tls == TlsMode::Tls && (port == 25 || port == 587) {
            hints.push(format!(
                "Server rejected implicit TLS on port {}. \
                 Port {} does not wrap connections in SSL from the start.",
                port, port
            ));
            hints.push(format!(
                "Fix: use --tls starttls (for port 587) or --tls none (for port 25 relay)."
            ));
        } else if *tls == TlsMode::None && port == 465 {
            hints.push("Port 465 requires implicit TLS. Fix: add --tls tls".into());
        } else {
            hints.push("TLS negotiation failed — the server and client disagree on the TLS mode.".into());
            hints.push(format!("Try: --tls none   (port {})", port));
            hints.push(format!("     --tls starttls  (port 587)"));
            hints.push(format!("     --tls tls        (port 465)"));
        }
    }

    // SASL / auth failures
    if err.contains("SASL") || err.contains("no SASL authentication mechanisms")
        || err.contains("Authentication") || err.contains("535")
        || err.contains("454") || err.contains("503")
    {
        hints.push("SMTP authentication failed or is not available on this server/port.".into());
        if has_auth {
            hints.push("If this is an internal relay server, try removing -u/-P (no auth needed).".into());
            hints.push("Check that Dovecot/auth backend is running on the mail server.".into());
        }
        if *tls == TlsMode::None {
            hints.push("Many servers refuse PLAIN/LOGIN auth without TLS. Try --tls starttls.".into());
        }
    }

    // Connection refused / timeout
    if err.contains("Connection refused") {
        hints.push(format!("Port {} is not accepting connections on {}.", port, server));
        hints.push("Check firewall rules and that the SMTP service is listening.".into());
        hints.push(format!("Typical ports: 25 (relay), 465 (SMTPS), 587 (submission)"));
    }
    if err.contains("timed out") || err.contains("Connection error: timed out") {
        hints.push(format!("Connection to {}:{} timed out.", server, port));
        hints.push("Check network routing, firewall, and that the server is up.".into());
        hints.push("Increase timeout with --timeout <seconds> if on a slow link.".into());
    }

    // Certificate errors
    if err.contains("certificate") || err.contains("Certificate") || err.contains("verify failed") {
        hints.push("TLS certificate verification failed.".into());
        hints.push("The server may use a self-signed cert. email-tester accepts self-signed certs by default.".into());
        hints.push("Ensure the server name matches what's in the cert, or use an IP address.".into());
    }

    hints
}

// ─── CLI ───────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "email-tester",
    version = APP_VERSION,
    author = APP_AUTHOR,
    about = "Robust SMTP email tester with colorized output and detailed logging",
    after_help = "EXAMPLES:\n\
  # Relay (no auth, no TLS) — typical internal server on port 25\n\
  email-tester send -s 222.222.222.5 --tls none -t user@example.com\n\n\
  # Relay with auth over plain SMTP (Postfix+Dovecot on port 25)\n\
  email-tester send -s mail.corp.com --tls none -u user@corp.com -P pass -t dest@corp.com\n\n\
  # Submission port 587 with STARTTLS + auth\n\
  email-tester send -s mail.corp.com -p 587 --tls starttls -u user@corp.com --ask-password -t dest@corp.com\n\n\
  # SMTPS port 465 (implicit TLS)\n\
  email-tester send -s mail.corp.com -p 465 --tls tls -u user@corp.com --ask-password -t dest@corp.com\n\n\
  # Open relay (no credentials at all)\n\
  email-tester send -s 192.168.1.1 --tls none --no-auth -t user@local.com\n\n\
  # Ping server\n\
  email-tester ping -s mail.corp.com -p 25 -n 5\n\n\
  # Show server info + port guide\n\
  email-tester info\n\n\
  # Save defaults to ~/.email-tester.toml\n\
  email-tester -s mail.corp.com -p 587 --tls starttls config --save\n"
)]
struct Cli {
    /// SMTP server hostname or IP  [env: SMTP_SERVER]  [default: 222.222.222.5]
    #[arg(short='s', long="server", env="SMTP_SERVER", global=true)]
    server: Option<String>,

    /// SMTP port  [env: SMTP_PORT]  [default: 25]
    #[arg(short='p', long="port", env="SMTP_PORT", global=true)]
    port: Option<u16>,

    /// SMTP auth username  [env: SMTP_USERNAME]
    #[arg(short='u', long="username", env="SMTP_USERNAME", global=true)]
    username: Option<String>,

    /// SMTP auth password  [env: SMTP_PASSWORD]
    #[arg(short='P', long="password", env="SMTP_PASSWORD", global=true, hide_env_values=true)]
    password: Option<String>,

    /// TLS mode: none | starttls | tls  [env: SMTP_TLS]  [default: none]
    #[arg(long="tls", env="SMTP_TLS", default_value="none", global=true)]
    tls: String,

    /// Connection timeout in seconds  [env: SMTP_TIMEOUT]
    #[arg(long="timeout", env="SMTP_TIMEOUT", default_value_t=DEFAULT_TIMEOUT, global=true)]
    timeout: u64,

    /// Auth mechanism: PLAIN | LOGIN  [env: SMTP_AUTH_MECH]
    #[arg(long="auth-mech", env="SMTP_AUTH_MECH", default_value="PLAIN", global=true)]
    auth_mech: String,

    /// Skip authentication even if username is provided (open relay mode)
    #[arg(long="no-auth", global=true)]
    no_auth: bool,

    /// Accept invalid/self-signed TLS certificates (default: already accepted)
    #[arg(long="insecure", global=true)]
    insecure: bool,

    /// Path to TOML config file  [default: ~/.email-tester.toml]
    #[arg(long="config", global=true)]
    config: Option<PathBuf>,

    /// Increase verbosity  (-v info, -vv debug, -vvv trace)
    #[arg(short='v', long="verbose", action=ArgAction::Count, global=true)]
    verbose: u8,

    /// Output results as JSON
    #[arg(long="json", global=true)]
    json: bool,

    /// Disable ANSI color output  [env: NO_COLOR]
    #[arg(long="no-color", env="NO_COLOR", global=true)]
    no_color: bool,

    /// Append structured log to file  [env: EMAIL_TESTER_LOG]
    #[arg(long="log-file", env="EMAIL_TESTER_LOG", global=true)]
    log_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Send a test email  [alias: s]
    #[command(alias="s")]
    Send {
        /// Recipient(s) — required, repeatable
        #[arg(short='t', long="to", required=true, num_args=1..)]
        to: Vec<String>,
        /// CC recipient(s)
        #[arg(long="cc", num_args=0..)]
        cc: Vec<String>,
        /// BCC recipient(s)
        #[arg(long="bcc", num_args=0..)]
        bcc: Vec<String>,
        /// Sender address  [env: SMTP_FROM]
        #[arg(short='f', long="from", env="SMTP_FROM")]
        from: Option<String>,
        /// Sender display name
        #[arg(long="from-name", env="SMTP_FROM_NAME", default_value="Email Tester")]
        from_name: String,
        /// Email subject
        #[arg(short='S', long="subject", default_value="SMTP Test Email")]
        subject: String,
        /// Plain-text body
        #[arg(short='b', long="body")]
        body: Option<String>,
        /// HTML body: inline HTML or path to .html file
        #[arg(long="html")]
        html: Option<String>,
        /// File attachment(s)
        #[arg(short='a', long="attach", num_args=0..)]
        attachments: Vec<PathBuf>,
        /// Reply-To address
        #[arg(long="reply-to")]
        reply_to: Option<String>,
        /// Custom headers in Key:Value format
        #[arg(long="header", num_args=0..)]
        headers: Vec<String>,
        /// Attempt count with exponential back-off [default: 1]
        #[arg(long="retries", default_value_t=1)]
        retries: u32,
        /// Prompt for password interactively (hidden input)
        #[arg(long="ask-password")]
        ask_password: bool,
    },

    /// Test SMTP connectivity without sending email  [alias: p]
    #[command(alias="p")]
    Ping {
        /// Number of probes
        #[arg(short='n', long="count", default_value_t=3)]
        count: u32,
    },

    /// Validate address + check SMTP reachability  [alias: v]
    #[command(alias="v")]
    Verify {
        /// E-mail address to verify
        email: String,
    },

    /// Show server info, port guide, env reference  [alias: i]
    #[command(alias="i")]
    Info,

    /// Manage ~/.email-tester.toml defaults
    Config {
        /// Persist current CLI options as defaults
        #[arg(long="save")]
        save: bool,
        /// Show current effective config
        #[arg(long="show")]
        show: bool,
        /// Reset to built-in defaults
        #[arg(long="reset")]
        reset: bool,
    },
}

// ─── JSON result ───────────────────────────────────────────

#[derive(Debug, Serialize)]
struct TestResult {
    timestamp:   String,
    action:      String,
    server:      String,
    port:        u16,
    tls_mode:    String,
    success:     bool,
    duration_ms: u128,
    message:     String,
    #[serde(skip_serializing_if="Option::is_none")]
    server_reply: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    error:        Option<String>,
    #[serde(skip_serializing_if="Vec::is_empty")]
    hints:        Vec<String>,
    #[serde(skip_serializing_if="Vec::is_empty")]
    recipients:   Vec<String>,
}

// ─── Logger ────────────────────────────────────────────────

struct Log { verbose: u8, json: bool, color: bool, file: Option<PathBuf> }

impl Log {
    fn new(verbose: u8, json: bool, color: bool, file: Option<PathBuf>) -> Self {
        Self { verbose, json, color, file }
    }
    fn ts(&self) -> String { Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string() }
    fn append(&self, line: &str) {
        if let Some(p) = &self.file {
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{}", line);
            }
        }
    }

    fn banner(&self) {
        if self.json { return; }
        if self.color {
            println!("{}", concat!(
                "\n",
                "  ███████╗███╗   ███╗ █████╗ ██╗██╗           ████████╗███████╗███████╗████████╗███████╗██████╗ \n",
                "  ██╔════╝████╗ ████║██╔══██╗██║██║           ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n",
                "  █████╗  ██╔████╔██║███████║██║██║              ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝\n",
                "  ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║              ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗\n",
                "  ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗         ██║   ███████╗███████║   ██║   ███████╗██║  ██║\n",
                "  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝        ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
            ).cyan().bold().to_string());
            println!(
                "  {}  {}  {}\n",
                format!("v{}", APP_VERSION).white().bold(),
                "Hadi Cahyadi <cumulus13@gmail.com>".dimmed(),
                "github.com/cumulus13/email-tester".dimmed()
            );
        } else {
            println!("\n  EMAIL-TESTER v{} | Hadi Cahyadi | github.com/cumulus13/email-tester\n", APP_VERSION);
        }
    }

    fn header(&self, text: &str) {
        if self.json { return; }
        let line = "═".repeat(64);
        if self.color {
            println!("\n{}", line.cyan().bold());
            println!("  {}", text.cyan().bold());
            println!("{}", line.cyan().bold());
        } else {
            println!("\n{}\n  {}\n{}", line, text, line);
        }
        self.append(&format!("=== {} ===", text));
    }
    fn section(&self, text: &str) {
        if self.json { return; }
        if self.color { println!("\n  {} {}", "▶".yellow().bold(), text.yellow().bold()); }
        else          { println!("\n  >> {}", text); }
    }
    fn sep(&self) {
        if self.json { return; }
        if self.color { println!("  {}", "─".repeat(60).dimmed()); }
        else          { println!("  {}", "─".repeat(60)); }
    }
    fn ok(&self, msg: &str) {
        if self.json { return; }
        let ts = self.ts();
        if self.color {
            println!("  {} {} {}", "✓".green().bold(), format!("[{}]", ts).dimmed(), msg.green().bold());
        } else {
            println!("  [OK]   [{}] {}", ts, msg);
        }
        self.append(&format!("[OK]    [{}] {}", ts, msg));
    }
    fn fail(&self, msg: &str) {
        let ts = self.ts();
        if !self.json {
            if self.color {
                eprintln!("  {} {} {}", "✗".red().bold(), format!("[{}]", ts).dimmed(), msg.red().bold());
            } else {
                eprintln!("  [FAIL] [{}] {}", ts, msg);
            }
        }
        self.append(&format!("[FAIL]  [{}] {}", ts, msg));
    }
    fn warn(&self, msg: &str) {
        if self.json { return; }
        let ts = self.ts();
        if self.color {
            println!("  {} {} {}", "⚠".yellow().bold(), format!("[{}]", ts).dimmed(), msg.yellow());
        } else {
            println!("  [WARN] [{}] {}", ts, msg);
        }
        self.append(&format!("[WARN]  [{}] {}", ts, msg));
    }
    fn hint(&self, msg: &str) {
        if self.json { return; }
        if self.color {
            println!("  {} {}", "💡".bright_yellow().to_string(), msg.bright_yellow());
        } else {
            println!("  [HINT] {}", msg);
        }
        self.append(&format!("[HINT]  {}", msg));
    }
    fn debug(&self, msg: &str) {
        if self.verbose < 2 || self.json { return; }
        let ts = self.ts();
        if self.color { println!("  {} {} {}", "·".dimmed(), format!("[{}]", ts).dimmed(), msg.dimmed()); }
        else          { println!("  [DBG]  [{}] {}", ts, msg); }
    }
    fn info_line(&self, msg: &str) {
        if self.verbose < 1 || self.json { return; }
        let ts = self.ts();
        if self.color {
            println!("  {} {} {}", "ℹ".bright_blue().bold(), format!("[{}]", ts).dimmed(), msg.white());
        } else {
            println!("  [INFO] [{}] {}", ts, msg);
        }
        self.append(&format!("[INFO]  [{}] {}", ts, msg));
    }
    fn kv(&self, label: &str, value: &str) {
        if self.json { return; }
        if self.color { println!("    {:24} {}", label.bright_white(), value.white()); }
        else          { println!("    {:24} {}", label, value); }
        self.append(&format!("[KV]    {:24} {}", label, value));
    }
    fn kvs(&self, label: &str, value: &str, good: bool) {
        if self.json { return; }
        let icon = if good {
            if self.color { "✓".green().to_string() } else { "ok".to_string() }
        } else {
            if self.color { "✗".red().to_string() } else { "!!".to_string() }
        };
        if self.color {
            println!("    {} {:24} {}",
                icon, label.bright_white(),
                if good { value.green().to_string() } else { value.red().to_string() }
            );
        } else {
            println!("    [{}] {:24} {}", icon, label, value);
        }
    }
    fn step(&self, i: u32, total: u32, msg: &str) {
        if self.json { return; }
        if self.color {
            println!("  {} [{}/{}] {}",
                "→".bright_blue().bold(),
                i.to_string().bright_blue(),
                total.to_string().bright_blue(),
                msg.white()
            );
        } else {
            println!("  [{}/{}] {}", i, total, msg);
        }
    }
    fn print_result(&self, r: &TestResult) {
        if self.json {
            println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
            return;
        }
        self.sep();
        if r.success { self.ok(&r.message); }
        else {
            self.fail(&r.message);
            if let Some(e) = &r.error { self.fail(&format!("  Detail : {}", e)); }
        }
        if self.verbose > 0 {
            self.kv("Duration:", &format!("{} ms", r.duration_ms));
            if let Some(reply) = &r.server_reply { self.kv("Server reply:", reply); }
        }
        if !r.hints.is_empty() {
            println!();
            for h in &r.hints { self.hint(h); }
        }
        self.sep();
    }
}

// ─── SMTP transport builder ────────────────────────────────

fn make_transport(
    server: &str, port: u16,
    tls: &TlsMode, timeout: u64,
    creds: Option<(&str, &str)>,
    mech: &AuthMech,
    log: &Log,
) -> Result<SmtpTransport> {
    log.debug(&format!("Building transport  {}:{}  [{}]  auth={}", server, port, tls, creds.is_some()));
    let dur   = Duration::from_secs(timeout);
    let hello = ClientId::Domain(
        hostname::get().ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string())
    );

    let apply_creds = |mut b: lettre::transport::smtp::SmtpTransportBuilder| {
        if let Some((u, p)) = creds {
            b = b
                .credentials(Credentials::new(u.to_string(), p.to_string()))
                .authentication(vec![mech.to_mechanism()]);
        }
        b.build()
    };

    let transport = match tls {
        TlsMode::None => {
            apply_creds(
                SmtpTransport::builder_dangerous(server)
                    .port(port)
                    .timeout(Some(dur))
                    .hello_name(hello)
                    .pool_config(PoolConfig::new().max_size(1))
            )
        }
        TlsMode::StartTls => {
            let tls_p = TlsParameters::builder(server.to_string())
                .dangerous_accept_invalid_certs(true)
                .dangerous_accept_invalid_hostnames(true)
                .build()?;
            apply_creds(
                SmtpTransport::starttls_relay(server)?
                    .port(port)
                    .tls(Tls::Required(tls_p))
                    .timeout(Some(dur))
                    .hello_name(hello)
                    .pool_config(PoolConfig::new().max_size(1))
            )
        }
        TlsMode::Tls => {
            let tls_p = TlsParameters::builder(server.to_string())
                .dangerous_accept_invalid_certs(true)
                .dangerous_accept_invalid_hostnames(true)
                .build()?;
            apply_creds(
                SmtpTransport::relay(server)?
                    .port(port)
                    .tls(Tls::Wrapper(tls_p))
                    .timeout(Some(dur))
                    .hello_name(hello)
                    .pool_config(PoolConfig::new().max_size(1))
            )
        }
    };
    Ok(transport)
}

// ─── cmd_ping ──────────────────────────────────────────────

fn cmd_ping(server: &str, port: u16, tls: &TlsMode, timeout: u64, count: u32, log: &Log, json: bool) -> Result<()> {
    log.header(&format!("SMTP Ping  ▶  {}:{}", server, port));
    log.section("Parameters");
    log.kv("Server:",  server);
    log.kv("Port:",    &port.to_string());
    log.kv("TLS:",     &tls.to_string());
    log.kv("Timeout:", &format!("{} s", timeout));
    log.kv("Count:",   &count.to_string());

    if let Some(h) = tls.port_mismatch_hint(port) { log.warn(&h); }

    log.section("Probing…");
    let mut timings: Vec<(bool, u128)> = Vec::new();
    for i in 1..=count {
        log.step(i, count, "Connecting…");
        let t0 = Instant::now();
        let res = make_transport(server, port, tls, timeout, None, &AuthMech::Plain, log)
            .and_then(|tr| tr.test_connection().map_err(|e| anyhow::anyhow!("{}", e)));
        let ms = t0.elapsed().as_millis();
        match res {
            Ok(true)  => { log.ok(&format!("seq={} time={} ms", i, ms)); timings.push((true, ms)); }
            Ok(false) => { log.fail(&format!("seq={} time={} ms  No response", i, ms)); timings.push((false, ms)); }
            Err(e)    => {
                log.fail(&format!("seq={} time={} ms  {}", i, ms, e));
                let hints = diagnose_error(&e.to_string(), server, port, tls, false);
                for h in &hints { log.hint(h); }
                timings.push((false, ms));
            }
        }
        if i < count { std::thread::sleep(Duration::from_millis(500)); }
    }

    log.section("Statistics");
    let ok  = timings.iter().filter(|(s,_)| *s).count() as u32;
    let bad = count - ok;
    let ms_list: Vec<u128> = timings.iter().map(|(_,m)| *m).collect();
    let avg = if ms_list.is_empty() { 0 } else { ms_list.iter().sum::<u128>() / ms_list.len() as u128 };
    let min = ms_list.iter().copied().min().unwrap_or(0);
    let max = ms_list.iter().copied().max().unwrap_or(0);

    log.kvs("Transmitted:", &count.to_string(), true);
    log.kvs("Received:",    &ok.to_string(),    ok > 0);
    log.kvs("Lost:", &format!("{} ({:.0}%)", bad, bad as f64 / count as f64 * 100.0), bad == 0);
    log.kvs("Min RTT:", &format!("{} ms", min), true);
    log.kvs("Avg RTT:", &format!("{} ms", avg), true);
    log.kvs("Max RTT:", &format!("{} ms", max), true);

    if json {
        println!("{}", serde_json::to_string_pretty(&TestResult {
            timestamp: Local::now().to_rfc3339(), action: "ping".into(),
            server: server.to_string(), port, tls_mode: tls.to_string(),
            success: ok == count, duration_ms: avg,
            message: format!("{}/{} pings successful", ok, count),
            server_reply: None, error: None, hints: vec![], recipients: vec![],
        })?);
    }
    Ok(())
}

// ─── cmd_info ──────────────────────────────────────────────

fn cmd_info(server: &str, port: u16, tls: &TlsMode, timeout: u64, log: &Log) -> Result<()> {
    log.header(&format!("SMTP Server Info  ▶  {}:{}", server, port));

    if let Some(h) = tls.port_mismatch_hint(port) { log.warn(&h); }

    log.section("Parameters");
    log.kv("Server:",   server);
    log.kv("Port:",     &port.to_string());
    log.kv("TLS Mode:", &tls.to_string());
    log.kv("Timeout:",  &format!("{} s", timeout));

    log.section("Connectivity");
    let t0 = Instant::now();
    match make_transport(server, port, tls, timeout, None, &AuthMech::Plain, log)
        .and_then(|tr| tr.test_connection().map_err(|e| anyhow::anyhow!("{}", e)))
    {
        Ok(true)  => log.ok(&format!("Connection established in {} ms", t0.elapsed().as_millis())),
        Ok(false) => log.fail("Server refused connection"),
        Err(e) => {
            log.fail(&format!("Error: {}", e));
            for h in diagnose_error(&e.to_string(), server, port, tls, false) { log.hint(&h); }
        }
    }

    log.section("Well-Known SMTP Ports");
    log.kvs("25   SMTP",       "Server relay, plain or STARTTLS. No client auth on most setups.", port == 25);
    log.kvs("465  SMTPS",      "Implicit TLS (--tls tls). Legacy but widely used.",               port == 465);
    log.kvs("587  Submission", "Client auth + STARTTLS (--tls starttls). Modern standard.",        port == 587);
    log.kvs("2525 Alt",        "Alternative submission, same as 587.",                             port == 2525);

    log.section("TLS Mode Guide");
    log.kv("--tls none",     "Plain SMTP — use for port 25 internal relay / open relay");
    log.kv("--tls starttls", "STARTTLS upgrade after EHLO — use for port 587 submission");
    log.kv("--tls tls",      "Implicit TLS from byte 1 (SMTPS) — use for port 465 only");

    log.section("Auth Guide");
    log.kv("--no-auth",        "Skip auth entirely — for open relay servers");
    log.kv("--auth-mech PLAIN","RFC 4616 PLAIN (default, works for most modern servers)");
    log.kv("--auth-mech LOGIN","Legacy LOGIN — needed for some Exchange / Office 365 configs");
    log.kv("--ask-password",   "Interactive hidden password prompt (do not put in shell history)");

    log.section("Common Failure Causes");
    log.kv("TLS on port 25",     "Use --tls none or --tls starttls for port 25");
    log.kv("SASL unavailable",   "Dovecot auth socket not running — check mail server health");
    log.kv("535 Auth failed",    "Wrong username/password, or PLAIN blocked without TLS");
    log.kv("Connection refused", "Wrong port, firewall blocking, or service not running");

    log.section("Environment Variables");
    log.kv("SMTP_SERVER",      &format!("[default: {}]", DEFAULT_SERVER));
    log.kv("SMTP_PORT",        &format!("[default: {}]", DEFAULT_PORT));
    log.kv("SMTP_USERNAME",    "Auth username");
    log.kv("SMTP_PASSWORD",    "Auth password (hidden in --help)");
    log.kv("SMTP_TLS",         "none | starttls | tls");
    log.kv("SMTP_FROM",        "Default sender address");
    log.kv("SMTP_AUTH_MECH",   "PLAIN | LOGIN");
    log.kv("NO_COLOR",         "Disable ANSI colors");
    log.kv("EMAIL_TESTER_LOG", "Append log to this file path");

    Ok(())
}

// ─── cmd_verify ────────────────────────────────────────────

fn cmd_verify(server: &str, port: u16, tls: &TlsMode, timeout: u64, email: &str, log: &Log) -> Result<()> {
    log.header(&format!("Verify  ▶  {}", email));
    log.section("Address Format");

    let at   = email.chars().filter(|c| *c == '@').count();
    let good = at == 1 && {
        let p: Vec<&str> = email.split('@').collect();
        !p[0].is_empty() && p[1].contains('.')
    };
    log.kvs("RFC 5321 format:", if good { "Valid" } else { "Invalid" }, good);

    if good {
        let p: Vec<&str> = email.split('@').collect();
        log.kv("Local part:", p[0]);
        log.kv("Domain:",     p[1]);
        log.section("SMTP Reachability");
        log.warn("Note: full mailbox verification requires MAIL FROM + RCPT TO — most servers block this");
        let t0 = Instant::now();
        match make_transport(server, port, tls, timeout, None, &AuthMech::Plain, log)
            .and_then(|tr| tr.test_connection().map_err(|e| anyhow::anyhow!("{}", e)))
        {
            Ok(true)  => log.ok(&format!("SMTP server reachable in {} ms", t0.elapsed().as_millis())),
            Ok(false) => log.fail("Server refused connection"),
            Err(e) => {
                log.fail(&format!("Connect error: {}", e));
                for h in diagnose_error(&e.to_string(), server, port, tls, false) { log.hint(&h); }
            }
        }
    }
    Ok(())
}

// ─── cmd_send ──────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_send(
    server: &str, port: u16, tls: &TlsMode, timeout: u64,
    creds: Option<(&str, &str)>, mech: &AuthMech,
    to: &[String], cc: &[String], bcc: &[String],
    from: &str, from_name: &str, subject: &str,
    body_plain: &str, body_html: Option<&str>,
    attachments: &[PathBuf], reply_to: Option<&str>,
    custom_headers: &[String],
    retries: u32, log: &Log, json: bool,
) -> Result<bool> {
    log.header(&format!("Send Email  ▶  {}:{}", server, port));

    // Warn about suspicious port/TLS combos before we try
    if let Some(h) = tls.port_mismatch_hint(port) { log.warn(&h); }

    log.section("Connection");
    log.kvs("Server:",   server, true);
    log.kvs("Port:",     &port.to_string(), true);
    log.kvs("TLS Mode:", &tls.to_string(), true);
    log.kvs("Timeout:",  &format!("{} s", timeout), true);
    let auth_str = if creds.is_some() {
        format!("Yes ({})", mech.label())
    } else {
        "No (open relay)".to_string()
    };
    log.kvs("Auth:", &auth_str, true);

    log.section("Message");
    log.kvs("From:",    &format!("{} <{}>", from_name, from), true);
    for a in to  { log.kvs("To:",  a, true); }
    for a in cc  { log.kvs("CC:",  a, true); }
    for a in bcc { log.kvs("BCC:", a, true); }
    log.kvs("Subject:",  subject, true);
    log.kvs("Has HTML:", if body_html.is_some() { "Yes" } else { "No" }, true);
    if !attachments.is_empty() { log.kvs("Attachments:", &attachments.len().to_string(), true); }

    // Build message
    log.section("Building Message");
    let from_full = format!("{} <{}>", from_name, from);
    let mut mb = Message::builder()
        .from(from_full.parse().context("Invalid From address")?)
        .subject(subject);
    for a in to  { mb = mb.to(a.parse().context(format!("Invalid To: {}",  a))?); }
    for a in cc  { mb = mb.cc(a.parse().context(format!("Invalid CC: {}",  a))?); }
    for a in bcc { mb = mb.bcc(a.parse().context(format!("Invalid BCC: {}", a))?); }
    if let Some(rt) = reply_to { mb = mb.reply_to(rt.parse().context("Invalid Reply-To")?); }
    for h in custom_headers {
        let p: Vec<&str> = h.splitn(2, ':').collect();
        if p.len() == 2 { log.debug(&format!("Custom header: {} = {}", p[0].trim(), p[1].trim())); }
        else            { log.warn(&format!("Malformed header ignored: '{}'", h)); }
    }

    let email = if attachments.is_empty() {
        match body_html {
            Some(h) => mb.multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(body_plain.to_string()))
                    .singlepart(SinglePart::html(h.to_string()))
            )?,
            None => mb.body(body_plain.to_string())?,
        }
    } else {
        let inner = match body_html {
            Some(h) => MultiPart::alternative()
                .singlepart(SinglePart::plain(body_plain.to_string()))
                .singlepart(SinglePart::html(h.to_string())),
            None => MultiPart::alternative()
                .singlepart(SinglePart::plain(body_plain.to_string())),
        };
        let mut mp = MultiPart::mixed().multipart(inner);
        for path in attachments {
            if !path.exists() { log.warn(&format!("Attachment not found: {}", path.display())); continue; }
            let data  = fs::read(path).context(format!("Cannot read: {}", path.display()))?;
            let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let ct    = ContentType::parse("application/octet-stream").unwrap();
            mp = mp.singlepart(Attachment::new(fname).body(data, ct));
            log.debug(&format!("Attached: {}", path.display()));
        }
        mb.multipart(mp)?
    };
    log.ok("Message built successfully");

    // Deliver with retries
    let mut success       = false;
    let mut last_err:     Option<String> = None;
    let mut last_hints:   Vec<String>    = Vec::new();
    let mut server_reply: Option<String> = None;
    let total_t0 = Instant::now();

    for attempt in 1..=retries {
        if retries > 1 { log.step(attempt, retries, &format!("Attempt {}/{}", attempt, retries)); }
        log.section(&format!("Connecting to {}:{}", server, port));
        let t0 = Instant::now();

        match make_transport(server, port, tls, timeout, creds, mech, log) {
            Ok(tr) => {
                log.ok("Transport ready");
                log.section("Delivering…");
                match tr.send(&email) {
                    Ok(resp) => {
                        let ms   = t0.elapsed().as_millis();
                        let code = resp.code().to_string();
                        log.ok(&format!("Delivered! SMTP {} in {} ms", code, ms));
                        let replies: Vec<&str> = resp.message().collect();
                        if let Some(m) = replies.first() {
                            server_reply = Some(m.to_string());
                            log.info_line(&format!("Server reply: {}", m));
                        }
                        success = true;
                        break;
                    }
                    Err(e) => {
                        let s = format!("{}", e);
                        log.fail(&format!("Send failed ({} ms): {}", t0.elapsed().as_millis(), s));
                        let hints = diagnose_error(&s, server, port, tls, creds.is_some());
                        for h in &hints { log.hint(h); }
                        last_hints = hints;
                        last_err   = Some(s);
                        if attempt < retries {
                            let wait = 2u64.pow(attempt - 1);
                            log.warn(&format!("Back-off: retrying in {} s…", wait));
                            std::thread::sleep(Duration::from_secs(wait));
                        }
                    }
                }
            }
            Err(e) => {
                let s = format!("{}", e);
                log.fail(&format!("Transport error: {}", s));
                let hints = diagnose_error(&s, server, port, tls, creds.is_some());
                for h in &hints { log.hint(h); }
                last_hints = hints;
                last_err   = Some(s);
                if attempt < retries { std::thread::sleep(Duration::from_secs(2)); }
            }
        }
    }

    let total_ms = total_t0.elapsed().as_millis();
    let result = TestResult {
        timestamp:    Local::now().to_rfc3339(),
        action:       "send".into(),
        server:       server.to_string(),
        port,
        tls_mode:     tls.to_string(),
        success,
        duration_ms:  total_ms,
        message:      if success {
            format!("Email delivered to {} recipient(s) in {} ms", to.len(), total_ms)
        } else {
            format!("Delivery failed after {} attempt(s)", retries)
        },
        server_reply,
        error:       last_err,
        hints:       last_hints,
        recipients:  to.to_vec(),
    };
    log.print_result(&result);
    if json { println!("{}", serde_json::to_string_pretty(&result)?); }
    Ok(success)
}

// ─── Config helpers ────────────────────────────────────────

fn config_path(ov: Option<&PathBuf>) -> PathBuf {
    ov.cloned().unwrap_or_else(|| {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".email-tester.toml")
    })
}
fn load_config(p: &Path) -> Config {
    if p.exists() {
        fs::read_to_string(p).ok().and_then(|s| toml::from_str(&s).ok()).unwrap_or_default()
    } else { Config::default() }
}
fn save_config(p: &Path, cfg: &Config) -> Result<()> {
    fs::write(p, toml::to_string_pretty(cfg).context("Config serialize failed")?)
        .context(format!("Cannot write: {}", p.display()))
}

// ─── main ──────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.no_color { colored::control::set_override(false); }

    let level = match cli.verbose { 0 => "warn", 1 => "info", 2 => "debug", _ => "trace" };
    env_logger::Builder::new()
        .filter_level(level.parse().unwrap_or(log::LevelFilter::Warn))
        .format_timestamp_millis().init();

    let log = Log::new(cli.verbose, cli.json, !cli.no_color, cli.log_file.clone());
    log.banner();

    let cfg_path = config_path(cli.config.as_ref());
    let cfg      = load_config(&cfg_path);

    let server  = cli.server.clone().unwrap_or_else(|| cfg.server.host.clone());
    let port    = cli.port.unwrap_or(cfg.server.port);
    let timeout = cli.timeout;
    let tls: TlsMode  = cli.tls.parse()?;
    let mech: AuthMech = cli.auth_mech.parse()?;

    if !cli.json {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        if !cli.no_color {
            println!("  {} {}  {}  {}\n",
                "⏱".dimmed(), ts.dimmed(),
                format!("{}:{}", server, port).bright_cyan(),
                tls.to_string().bright_yellow()
            );
        } else {
            println!("  [{}]  {}:{}  {}\n", ts, server, port, tls);
        }
    }

    match &cli.command {
        Commands::Ping { count } => {
            cmd_ping(&server, port, &tls, timeout, *count, &log, cli.json)?;
        }
        Commands::Info => {
            cmd_info(&server, port, &tls, timeout, &log)?;
        }
        Commands::Verify { email } => {
            cmd_verify(&server, port, &tls, timeout, email, &log)?;
        }
        Commands::Config { save, show, reset } => {
            if *reset {
                save_config(&cfg_path, &Config::default())?;
                log.ok(&format!("Config reset to defaults: {}", cfg_path.display()));
            } else if *save {
                save_config(&cfg_path, &Config {
                    server: ServerConfig { host: server.clone(), port, timeout },
                    auth:   AuthConfig { username: cli.username.clone(), password: None, mechanism: Some(cli.auth_mech.clone()) },
                    defaults: cfg.defaults.clone(),
                })?;
                log.ok(&format!("Config saved → {}", cfg_path.display()));
            } else if *show {
                log.header("Effective Configuration");
                log.kv("Config file:", &cfg_path.display().to_string());
                log.kv("Server:",      &server);
                log.kv("Port:",        &port.to_string());
                log.kv("TLS Mode:",    &tls.to_string());
                log.kv("Timeout:",     &format!("{} s", timeout));
                log.kv("Auth Mech:",   &cli.auth_mech);
                if let Some(u) = &cli.username { log.kv("Username:", u); }
                if let Some(f) = &cfg.defaults.from { log.kv("Def. From:", f); }
                log.kv("Def. Subject:", &cfg.defaults.subject);
            } else {
                log.header("Configuration");
                log.kv("Config file:", &cfg_path.display().to_string());
                log.kv("--save",  "Persist current settings as defaults");
                log.kv("--show",  "Display current effective config");
                log.kv("--reset", "Restore all built-in defaults");
            }
        }
        Commands::Send {
            to, cc, bcc, from, from_name, subject, body, html,
            attachments, reply_to, headers, retries, ask_password,
        } => {
            let from_addr = from.clone()
                .or_else(|| cfg.defaults.from.clone())
                .or_else(|| cli.username.clone())
                .unwrap_or_else(|| format!("noreply@{}", server));

            // Resolve password
            let mut password = cli.password.clone();
            if cli.username.is_some() && password.is_none() && !cli.no_auth {
                if *ask_password {
                    let prompt = format!("  Password for {}: ",
                        cli.username.as_deref().unwrap_or("user"));
                    password = Some(rpassword::prompt_password(prompt).unwrap_or_default());
                } else {
                    password = std::env::var("SMTP_PASSWORD").ok();
                    if password.is_none() {
                        log.warn("Username set but no password found — add -P, set SMTP_PASSWORD, or use --ask-password");
                        log.warn("If this is an open relay, add --no-auth to skip authentication");
                    }
                }
            }

            // Build creds: skip if --no-auth
            let creds: Option<(&str, &str)> = if cli.no_auth {
                log.info_line("--no-auth: skipping authentication");
                None
            } else {
                match (&cli.username, &password) {
                    (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
                    _ => None,
                }
            };

            let body_text = body.clone().unwrap_or_else(|| cfg.defaults.body.clone());
            let html_content: Option<String> = html.as_ref().and_then(|h| {
                if Path::new(h).exists() {
                    fs::read_to_string(h)
                        .map_err(|e| { log.warn(&format!("Cannot read HTML file: {}", e)); e })
                        .ok()
                } else { Some(h.clone()) }
            });

            let ok = cmd_send(
                &server, port, &tls, timeout, creds, &mech,
                to, cc, bcc, &from_addr, from_name, subject,
                &body_text, html_content.as_deref(),
                attachments, reply_to.as_deref(), headers,
                *retries, &log, cli.json,
            )?;

            if !ok { std::process::exit(1); }
        }
    }
    Ok(())
}
