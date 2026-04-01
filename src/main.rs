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
const DEFAULT_SERVER: &str = "222.222.222.5";
const DEFAULT_SMTP_PORT: u16 = 25;
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_AUTHOR: &str = "Hadi Cahyadi <cumulus13@gmail.com>";

// ─── Config ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct Config {
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    auth: AuthConfig,
    #[serde(default)]
    defaults: DefaultsConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ServerConfig {
    host: String,
    port: u16,
    timeout: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_SERVER.to_string(),
            port: DEFAULT_SMTP_PORT,
            timeout: DEFAULT_TIMEOUT_SECS,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct AuthConfig {
    username: Option<String>,
    password: Option<String>,
    mechanism: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DefaultsConfig {
    from: Option<String>,
    from_name: Option<String>,
    subject: String,
    body: String,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            from: None,
            from_name: Some("Email Tester".to_string()),
            subject: "SMTP Test Email".to_string(),
            body: "This is a test email sent by email-tester.\nhttps://github.com/cumulus13/email-tester".to_string(),
        }
    }
}

// ─── TLS Mode ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum TlsMode { None, StartTls, Tls }

impl FromStr for TlsMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "none" | "plain" | "no"          => Ok(TlsMode::None),
            "starttls" | "start"             => Ok(TlsMode::StartTls),
            "tls"  | "ssl" | "smtps"         => Ok(TlsMode::Tls),
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

// ─── Auth Mechanism ────────────────────────────────────────

#[derive(Debug, Clone)]
enum AuthMech { Plain, Login }

impl FromStr for AuthMech {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "PLAIN"              => Ok(AuthMech::Plain),
            "LOGIN"              => Ok(AuthMech::Login),
            _ => anyhow::bail!("Unknown auth mechanism '{}'. Use: PLAIN, LOGIN", s),
        }
    }
}

impl AuthMech {
    fn to_mechanism(&self) -> Mechanism {
        match self {
            AuthMech::Plain => Mechanism::Plain,
            AuthMech::Login => Mechanism::Login,
        }
    }
    fn label(&self) -> &'static str {
        match self {
            AuthMech::Plain => "PLAIN",
            AuthMech::Login => "LOGIN",
        }
    }
}

// ─── CLI ───────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "email-tester",
    version = APP_VERSION,
    author = APP_AUTHOR,
    about = "Robust SMTP email tester with colorized output and detailed logging",
    after_help = "EXAMPLES:\n\
  # Quick send with defaults\n\
  email-tester send -t user@example.com\n\n\
  # Custom server + port + STARTTLS + auth\n\
  email-tester send -s mail.example.com -p 587 --tls starttls -u admin --ask-password -t user@example.com\n\n\
  # TLS/SMTPS on port 465\n\
  email-tester send -s mail.example.com -p 465 --tls tls -u admin -t user@example.com\n\n\
  # Ping connectivity test (5 probes)\n\
  email-tester ping -s mail.example.com -n 5\n\n\
  # Server capabilities\n\
  email-tester info\n\n\
  # Save current settings as default config\n\
  email-tester -s mail.example.com -p 587 config --save\n\n\
  # Verify address format + server reachability\n\
  email-tester verify user@example.com\n\n\
  # Full send: HTML, attachment, CC, retry 3x, verbose, log to file\n\
  email-tester -vv --log-file /tmp/smtp.log send \\\n\
      -s mail.example.com -p 587 --tls starttls \\\n\
      -f sender@example.com --from-name \"My App\" \\\n\
      -t alice@example.com --cc bob@example.com \\\n\
      -S \"Hello\" -b \"Plain body\" --html \"<b>Hello</b>\" \\\n\
      -a report.pdf --retries 3\n"
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
    #[arg(long="timeout", env="SMTP_TIMEOUT", default_value_t=DEFAULT_TIMEOUT_SECS, global=true)]
    timeout: u64,

    /// Auth mechanism: PLAIN | LOGIN  [env: SMTP_AUTH_MECH]
    #[arg(long="auth-mech", env="SMTP_AUTH_MECH", default_value="PLAIN", global=true)]
    auth_mech: String,

    /// Path to TOML config file  [default: ~/.email-tester.toml]
    #[arg(long="config", global=true)]
    config: Option<PathBuf>,

    /// Increase verbosity (-v info, -vv debug)
    #[arg(short='v', long="verbose", action=ArgAction::Count, global=true)]
    verbose: u8,

    /// Output all results as JSON
    #[arg(long="json", global=true)]
    json: bool,

    /// Disable ANSI color output  [env: NO_COLOR]
    #[arg(long="no-color", env="NO_COLOR", global=true)]
    no_color: bool,

    /// Append log entries to this file  [env: EMAIL_TESTER_LOG]
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
        /// Recipient(s) [required]
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
        /// Sender display name  [env: SMTP_FROM_NAME]
        #[arg(long="from-name", env="SMTP_FROM_NAME", default_value="Email Tester")]
        from_name: String,
        /// Email subject
        #[arg(short='S', long="subject", default_value="SMTP Test Email")]
        subject: String,
        /// Plain-text body
        #[arg(short='b', long="body")]
        body: Option<String>,
        /// HTML body: inline HTML string or path to .html file
        #[arg(long="html")]
        html: Option<String>,
        /// File attachment(s)
        #[arg(short='a', long="attach", num_args=0..)]
        attachments: Vec<PathBuf>,
        /// Reply-To address
        #[arg(long="reply-to")]
        reply_to: Option<String>,
        /// Custom header(s) in key:value format
        #[arg(long="header", num_args=0..)]
        headers: Vec<String>,
        /// Delivery attempt count (exponential back-off on retry)
        #[arg(long="retries", default_value_t=1)]
        retries: u32,
        /// Prompt for password interactively (hides input)
        #[arg(long="ask-password")]
        ask_password: bool,
    },

    /// Test SMTP connectivity (no email sent)  [alias: p]
    #[command(alias="p")]
    Ping {
        /// Number of probes
        #[arg(short='n', long="count", default_value_t=3)]
        count: u32,
    },

    /// Verify address format + server reachability  [alias: v]
    #[command(alias="v")]
    Verify {
        /// E-mail address to check
        email: String,
    },

    /// Manage ~/.email-tester.toml configuration
    Config {
        /// Persist CLI options as new defaults
        #[arg(long="save")]
        save: bool,
        /// Display effective configuration
        #[arg(long="show")]
        show: bool,
        /// Reset to built-in defaults
        #[arg(long="reset")]
        reset: bool,
    },

    /// Show server info / well-known port guide  [alias: i]
    #[command(alias="i")]
    Info,
}

// ─── Result record (JSON output) ───────────────────────────

#[derive(Debug, Serialize)]
struct TestResult {
    timestamp: String,
    action: String,
    server: String,
    port: u16,
    tls_mode: String,
    success: bool,
    duration_ms: u128,
    message: String,
    #[serde(skip_serializing_if="Option::is_none")]
    server_reply: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if="Vec::is_empty")]
    recipients: Vec<String>,
}

// ─── Logger ────────────────────────────────────────────────

struct Log {
    verbose: u8,
    json: bool,
    color: bool,
    file: Option<PathBuf>,
}

impl Log {
    fn new(verbose: u8, json: bool, color: bool, file: Option<PathBuf>) -> Self {
        Self { verbose, json, color, file }
    }

    fn ts(&self) -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
    }

    fn append(&self, line: &str) {
        if let Some(p) = &self.file {
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{}", line);
            }
        }
    }

    // ── Banner ──────────────────────────────────────────

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

    // ── Section separators ──────────────────────────────

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
        if self.color {
            println!("\n  {} {}", "▶".yellow().bold(), text.yellow().bold());
        } else {
            println!("\n  >> {}", text);
        }
    }

    fn sep(&self) {
        if self.json { return; }
        if self.color {
            println!("  {}", "─".repeat(60).dimmed());
        } else {
            println!("  {}", "─".repeat(60));
        }
    }

    // ── Status lines ────────────────────────────────────

    fn ok(&self, msg: &str) {
        if self.json { return; }
        let ts = self.ts();
        if self.color {
            println!(
                "  {} {} {}",
                "✓".green().bold(),
                format!("[{}]", ts).dimmed(),
                msg.green().bold()
            );
        } else {
            println!("  [OK]   [{}] {}", ts, msg);
        }
        self.append(&format!("[OK]    [{}] {}", ts, msg));
    }

    fn fail(&self, msg: &str) {
        let ts = self.ts();
        if !self.json {
            if self.color {
                eprintln!(
                    "  {} {} {}",
                    "✗".red().bold(),
                    format!("[{}]", ts).dimmed(),
                    msg.red().bold()
                );
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
            println!(
                "  {} {} {}",
                "⚠".yellow().bold(),
                format!("[{}]", ts).dimmed(),
                msg.yellow()
            );
        } else {
            println!("  [WARN] [{}] {}", ts, msg);
        }
        self.append(&format!("[WARN]  [{}] {}", ts, msg));
    }

    fn debug(&self, msg: &str) {
        if self.verbose < 2 || self.json { return; }
        let ts = self.ts();
        if self.color {
            println!(
                "  {} {} {}",
                "·".dimmed(),
                format!("[{}]", ts).dimmed(),
                msg.dimmed()
            );
        } else {
            println!("  [DBG]  [{}] {}", ts, msg);
        }
    }

    fn info(&self, msg: &str) {
        if self.verbose < 1 || self.json { return; }
        let ts = self.ts();
        if self.color {
            println!(
                "  {} {} {}",
                "ℹ".bright_blue().bold(),
                format!("[{}]", ts).dimmed(),
                msg.white()
            );
        } else {
            println!("  [INFO] [{}] {}", ts, msg);
        }
        self.append(&format!("[INFO]  [{}] {}", ts, msg));
    }

    // ── Key-value pairs ─────────────────────────────────

    fn kv(&self, label: &str, value: &str) {
        if self.json { return; }
        if self.color {
            println!("    {:24} {}", label.bright_white(), value.white());
        } else {
            println!("    {:24} {}", label, value);
        }
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
            println!(
                "    {} {:24} {}",
                icon,
                label.bright_white(),
                if good { value.green().to_string() } else { value.red().to_string() }
            );
        } else {
            println!("    [{}] {:24} {}", icon, label, value);
        }
    }

    fn step(&self, i: u32, total: u32, msg: &str) {
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

    // ── Final result ────────────────────────────────────

    fn result(&self, r: &TestResult) {
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
            self.kv("Duration:", &format!("{} ms", r.duration_ms));
            if let Some(reply) = &r.server_reply {
                self.kv("Server reply:", reply);
            }
        }
        self.sep();
    }
}

// ─── SMTP transport factory ────────────────────────────────

fn make_transport(
    server: &str,
    port: u16,
    tls: &TlsMode,
    timeout: u64,
    creds: Option<(&str, &str)>,
    mech: &AuthMech,
    log: &Log,
) -> Result<SmtpTransport> {
    log.debug(&format!("Building transport  {}:{}  [{}]", server, port, tls));
    let dur = Duration::from_secs(timeout);

    let hello = {
        let hn = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string());
        ClientId::Domain(hn)
    };

    let build = |mut b: lettre::transport::smtp::SmtpTransportBuilder| {
        if let Some((u, p)) = creds {
            b = b
                .credentials(Credentials::new(u.to_string(), p.to_string()))
                .authentication(vec![mech.to_mechanism()]);
        }
        b.build()
    };

    let transport = match tls {
        TlsMode::None => {
            let b = SmtpTransport::builder_dangerous(server)
                .port(port)
                .timeout(Some(dur))
                .hello_name(hello)
                .pool_config(PoolConfig::new().max_size(1));
            build(b)
        }
        TlsMode::StartTls => {
            let tls_p = TlsParameters::builder(server.to_string())
                .dangerous_accept_invalid_certs(true)
                .dangerous_accept_invalid_hostnames(true)
                .build()?;
            let b = SmtpTransport::starttls_relay(server)?
                .port(port)
                .tls(Tls::Required(tls_p))
                .timeout(Some(dur))
                .hello_name(hello)
                .pool_config(PoolConfig::new().max_size(1));
            build(b)
        }
        TlsMode::Tls => {
            let tls_p = TlsParameters::builder(server.to_string())
                .dangerous_accept_invalid_certs(true)
                .dangerous_accept_invalid_hostnames(true)
                .build()?;
            let b = SmtpTransport::relay(server)?
                .port(port)
                .tls(Tls::Wrapper(tls_p))
                .timeout(Some(dur))
                .hello_name(hello)
                .pool_config(PoolConfig::new().max_size(1));
            build(b)
        }
    };
    Ok(transport)
}

// ─── Command: ping ─────────────────────────────────────────

fn cmd_ping(
    server: &str, port: u16, tls: &TlsMode,
    timeout: u64, count: u32,
    log: &Log, json: bool,
) -> Result<()> {
    log.header(&format!("SMTP Ping  ▶  {}:{}", server, port));
    log.section("Parameters");
    log.kv("Server:", server);
    log.kv("Port:", &port.to_string());
    log.kv("TLS:", &tls.to_string());
    log.kv("Timeout:", &format!("{} s", timeout));
    log.kv("Count:", &count.to_string());
    log.section("Probing…");

    let mut timings: Vec<(bool, u128)> = Vec::new();

    for i in 1..=count {
        log.step(i, count, "Connecting…");
        let t0 = Instant::now();
        let res = make_transport(server, port, tls, timeout, None, &AuthMech::Plain, log)
            .and_then(|tr| tr.test_connection().map_err(|e| anyhow::anyhow!("{}", e)));
        let ms = t0.elapsed().as_millis();
        match res {
            Ok(true)  => { log.ok(&format!("seq={} time={} ms  Connected", i, ms)); timings.push((true, ms)); }
            Ok(false) => { log.fail(&format!("seq={} time={} ms  No response", i, ms)); timings.push((false, ms)); }
            Err(e)    => { log.fail(&format!("seq={} time={} ms  {}", i, ms, e)); timings.push((false, ms)); }
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
        let r = TestResult {
            timestamp:  Local::now().to_rfc3339(),
            action:     "ping".into(),
            server:     server.to_string(),
            port,
            tls_mode:   tls.to_string(),
            success:    ok == count,
            duration_ms: avg,
            message:    format!("{}/{} pings successful", ok, count),
            server_reply: None,
            error: None,
            recipients: vec![],
        };
        println!("{}", serde_json::to_string_pretty(&r)?);
    }
    Ok(())
}

// ─── Command: info ─────────────────────────────────────────

fn cmd_info(server: &str, port: u16, tls: &TlsMode, timeout: u64, log: &Log) -> Result<()> {
    log.header(&format!("SMTP Server Info  ▶  {}:{}", server, port));
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
        Err(e)    => log.fail(&format!("Error: {}", e)),
    }

    log.section("Well-Known SMTP Ports");
    log.kvs("25   SMTP",        "Server-to-server relay (plain)",        port == 25);
    log.kvs("465  SMTPS",       "Implicit TLS (legacy submission)",       port == 465);
    log.kvs("587  Submission",  "Client submission + STARTTLS",           port == 587);
    log.kvs("2525 Alt",         "Alternative submission port",            port == 2525);

    log.section("TLS Mode Reference");
    log.kv("none",     "Unencrypted — use for port 25 relay or local testing");
    log.kv("starttls", "Upgrade to TLS after EHLO — standard for port 587");
    log.kv("tls",      "Implicit TLS (SMTPS) from first byte — use for port 465");

    log.section("Authentication Mechanisms");
    log.kv("PLAIN",   "Base64-encoded username + password (RFC 4616)");
    log.kv("LOGIN",   "Older challenge-response variant (Office 365 / Exchange)");

    log.section("Environment Variables");
    log.kv("SMTP_SERVER",   &format!("Override default server [{}]", DEFAULT_SERVER));
    log.kv("SMTP_PORT",     &format!("Override default port   [{}]", DEFAULT_SMTP_PORT));
    log.kv("SMTP_USERNAME", "Auth username");
    log.kv("SMTP_PASSWORD", "Auth password (hidden)");
    log.kv("SMTP_TLS",      "TLS mode  (none|starttls|tls)");
    log.kv("SMTP_FROM",     "Sender address");
    log.kv("NO_COLOR",      "Disable ANSI color output");
    log.kv("EMAIL_TESTER_LOG", "Append log to this file path");

    Ok(())
}

// ─── Command: verify ───────────────────────────────────────

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

        log.section("MX / SMTP Reachability");
        log.warn("Note: full RCPT TO probing requires connect + EHLO + MAIL FROM — most servers block it");
        let t0 = Instant::now();
        match make_transport(server, port, tls, timeout, None, &AuthMech::Plain, log)
            .and_then(|tr| tr.test_connection().map_err(|e| anyhow::anyhow!("{}", e)))
        {
            Ok(true)  => log.ok(&format!("SMTP server reachable in {} ms — cannot confirm mailbox without RCPT TO", t0.elapsed().as_millis())),
            Ok(false) => log.fail("Server refused connection"),
            Err(e)    => log.fail(&format!("Connect error: {}", e)),
        }
    }
    Ok(())
}

// ─── Command: send ─────────────────────────────────────────

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

    // ── Connection info ──────────────────────────────
    log.section("Connection");
    log.kvs("Server:",   server, true);
    log.kvs("Port:",     &port.to_string(), true);
    log.kvs("TLS Mode:", &tls.to_string(), true);
    log.kvs("Timeout:",  &format!("{} s", timeout), true);
    let auth_str = if creds.is_some() { format!("Yes ({})", mech.label()) } else { "No (open relay)".to_string() };
    log.kvs("Auth:", &auth_str, true);

    // ── Message info ─────────────────────────────────
    log.section("Message");
    log.kvs("From:",    &format!("{} <{}>", from_name, from), true);
    for a in to  { log.kvs("To:",  a, true); }
    for a in cc  { log.kvs("CC:",  a, true); }
    for a in bcc { log.kvs("BCC:", a, true); }
    log.kvs("Subject:",     subject, true);
    log.kvs("Has HTML:",    if body_html.is_some() { "Yes" } else { "No" }, true);
    if !attachments.is_empty() { log.kvs("Attachments:", &attachments.len().to_string(), true); }
    if !custom_headers.is_empty() { log.kvs("Custom hdrs:", &custom_headers.len().to_string(), true); }

    // ── Build message ────────────────────────────────
    log.section("Building Message");

    let from_full = format!("{} <{}>", from_name, from);
    let mut mb = Message::builder()
        .from(from_full.parse().context("Invalid From address")?)
        .subject(subject);

    for a in to  { mb = mb.to(a.parse().context(format!("Invalid To: {}",  a))?); }
    for a in cc  { mb = mb.cc(a.parse().context(format!("Invalid CC: {}",  a))?); }
    for a in bcc { mb = mb.bcc(a.parse().context(format!("Invalid BCC: {}", a))?); }
    if let Some(rt) = reply_to {
        mb = mb.reply_to(rt.parse().context("Invalid Reply-To")?);
    }
    for h in custom_headers {
        let p: Vec<&str> = h.splitn(2, ':').collect();
        if p.len() == 2 {
            log.debug(&format!("Custom header: {} = {}", p[0].trim(), p[1].trim()));
        } else {
            log.warn(&format!("Ignored malformed header: '{}'", h));
        }
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
            if !path.exists() {
                log.warn(&format!("Attachment not found, skipping: {}", path.display()));
                continue;
            }
            let data  = fs::read(path).context(format!("Cannot read: {}", path.display()))?;
            let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let ct    = ContentType::parse("application/octet-stream").unwrap();
            mp = mp.singlepart(Attachment::new(fname).body(data, ct));
            log.debug(&format!("Attached: {}", path.display()));
        }
        mb.multipart(mp)?
    };

    log.ok("Message built successfully");

    // ── Deliver with retries ─────────────────────────
    let mut success = false;
    let mut last_err: Option<String> = None;
    let mut server_reply: Option<String> = None;
    let total_t0 = Instant::now();

    for attempt in 1..=retries {
        if retries > 1 {
            log.step(attempt, retries, &format!("Attempt {}/{}", attempt, retries));
        }

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
                            log.info(&format!("Server reply: {}", m));
                        }
                        success = true;
                        break;
                    }
                    Err(e) => {
                        let s = format!("{}", e);
                        log.fail(&format!("Send failed ({} ms): {}", t0.elapsed().as_millis(), s));
                        last_err = Some(s);
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
                last_err = Some(s);
                if attempt < retries {
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }

    let total_ms = total_t0.elapsed().as_millis();
    let result = TestResult {
        timestamp:   Local::now().to_rfc3339(),
        action:      "send".into(),
        server:      server.to_string(),
        port,
        tls_mode:    tls.to_string(),
        success,
        duration_ms: total_ms,
        message:     if success {
            format!("Email delivered to {} recipient(s) in {} ms", to.len(), total_ms)
        } else {
            format!("Delivery failed after {} attempt(s)", retries)
        },
        server_reply,
        error: last_err,
        recipients: to.to_vec(),
    };
    log.result(&result);
    if json { println!("{}", serde_json::to_string_pretty(&result)?); }
    Ok(success)
}

// ─── Config helpers ────────────────────────────────────────

fn config_path(ov: Option<&PathBuf>) -> PathBuf {
    ov.cloned().unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".email-tester.toml")
    })
}

fn load_config(p: &Path) -> Config {
    if p.exists() {
        fs::read_to_string(p)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Config::default()
    }
}

fn save_config(p: &Path, cfg: &Config) -> Result<()> {
    let s = toml::to_string_pretty(cfg)
        .context("Failed to serialize config")?;
    fs::write(p, s).context(format!("Cannot write config: {}", p.display()))?;
    Ok(())
}

// ─── main ──────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    // env_logger (respects RUST_LOG; we set a sensible default from -v flags)
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    env_logger::Builder::new()
        .filter_level(level.parse().unwrap_or(log::LevelFilter::Warn))
        .format_timestamp_millis()
        .init();

    let log = Log::new(cli.verbose, cli.json, !cli.no_color, cli.log_file.clone());
    log.banner();

    // ── Load config, then overlay CLI/env ────────────
    let cfg_path = config_path(cli.config.as_ref());
    let cfg      = load_config(&cfg_path);

    let server  = cli.server.clone().unwrap_or_else(|| cfg.server.host.clone());
    let port    = cli.port.unwrap_or(cfg.server.port);
    let timeout = cli.timeout;
    let tls: TlsMode = cli.tls.parse()?;
    let mech: AuthMech = cli.auth_mech.parse()?;

    // ── Print effective server line ───────────────────
    if !cli.json {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        if !cli.no_color {
            println!(
                "  {} {}  {}  {}\n",
                "⏱".dimmed(),
                ts.dimmed(),
                format!("{}:{}", server, port).bright_cyan(),
                tls.to_string().bright_yellow()
            );
        } else {
            println!("  [{}]  {}:{}  {}\n", ts, server, port, tls);
        }
    }

    // ── Dispatch ─────────────────────────────────────
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
                let new_cfg = Config {
                    server: ServerConfig { host: server.clone(), port, timeout },
                    auth:   AuthConfig {
                        username:  cli.username.clone(),
                        password:  None,               // never persist password
                        mechanism: Some(cli.auth_mech.clone()),
                    },
                    defaults: cfg.defaults.clone(),
                };
                save_config(&cfg_path, &new_cfg)?;
                log.ok(&format!("Config saved → {}", cfg_path.display()));
            } else if *show {
                log.header("Effective Configuration");
                log.kv("Config file:", &cfg_path.display().to_string());
                log.kv("Server:",     &server);
                log.kv("Port:",       &port.to_string());
                log.kv("TLS Mode:",   &tls.to_string());
                log.kv("Timeout:",    &format!("{} s", timeout));
                log.kv("Auth Mech:",  &cli.auth_mech);
                if let Some(u) = &cli.username        { log.kv("Username:",   u); }
                if let Some(f) = &cfg.defaults.from   { log.kv("Def. From:",  f); }
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
            // Resolve From address: CLI → config default → username → auto
            let from_addr = from.clone()
                .or_else(|| cfg.defaults.from.clone())
                .or_else(|| cli.username.clone())
                .unwrap_or_else(|| format!("noreply@{}", server));

            // Resolve password: CLI → env → interactive prompt
            let mut password = cli.password.clone();
            if cli.username.is_some() && password.is_none() {
                if *ask_password {
                    let prompt = if !cli.no_color {
                        format!("  {} Password for {}: ", "🔐".yellow(), cli.username.as_deref().unwrap_or("user"))
                    } else {
                        format!("  Password for {}: ", cli.username.as_deref().unwrap_or("user"))
                    };
                    password = Some(rpassword::prompt_password(prompt).unwrap_or_default());
                } else {
                    password = std::env::var("SMTP_PASSWORD").ok();
                    if password.is_none() {
                        log.warn("Username supplied but no password found (use -P, SMTP_PASSWORD env, or --ask-password)");
                    }
                }
            }

            let creds: Option<(&str, &str)> = match (&cli.username, &password) {
                (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
                _ => None,
            };

            // Resolve body
            let body_text = body.clone()
                .unwrap_or_else(|| cfg.defaults.body.clone());

            // HTML: file path or inline HTML string
            let html_content: Option<String> = html.as_ref().and_then(|h| {
                if Path::new(h).exists() {
                    fs::read_to_string(h)
                        .map_err(|e| { log.warn(&format!("Cannot read HTML file: {}", e)); e })
                        .ok()
                } else {
                    Some(h.clone())
                }
            });

            let ok = cmd_send(
                &server, port, &tls, timeout,
                creds, &mech,
                to, cc, bcc,
                &from_addr, from_name, subject,
                &body_text, html_content.as_deref(),
                attachments, reply_to.as_deref(), headers,
                *retries, &log, cli.json,
            )?;

            if !ok { std::process::exit(1); }
        }
    }

    Ok(())
}
