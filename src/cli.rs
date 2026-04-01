// File: src\cli.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-04-01
// Description: CLI argument definitions using clap derive.
// License: MIT

//! CLI argument definitions using clap derive.

use clap::{ArgAction, Parser, Subcommand};
use std::path::PathBuf;

const BANNER: &str = "\
  ███████╗███╗   ███╗ █████╗ ██╗██╗      ████████╗███████╗███████╗████████╗███████╗██████╗
  ██╔════╝████╗ ████║██╔══██╗██║██║      ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  █████╗  ██╔████╔██║███████║██║██║         ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
  ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║         ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
  ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗    ██║   ███████╗███████║   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

  Hadi Cahyadi <cumulus13@gmail.com> · https://github.com/cumulus13/email-tester";

#[derive(Parser, Debug)]
#[command(
    name        = "email-tester",
    version     = env!("CARGO_PKG_VERSION"),
    author      = "Hadi Cahyadi <cumulus13@gmail.com>",
    about       = "Robust SMTP email tester — colorized output, detailed logging, flexible config",
    long_about  = BANNER,
    after_help  = "\
EXAMPLES:
  # Quick relay test (uses default server 222.222.222.5:25)
  email-tester send -t user@example.com

  # Custom server + port + STARTTLS + auth
  email-tester send -s mail.example.com -p 587 --tls starttls \\
      -u admin@example.com --ask-password -t user@example.com

  # Send with CC, custom subject and HTML file
  email-tester send -s mx.corp.local -p 25 \\
      -t alice@corp.com --cc bob@corp.com \\
      -S 'Weekly Report' --html /tmp/report.html

  # Send with attachment, retry 3 times
  email-tester send -t ops@example.com -a /tmp/log.tar.gz --retries 3

  # Test connectivity (5 pings)
  email-tester ping -n 5 -s mail.example.com -p 25

  # Show SMTP server capabilities
  email-tester info -s mail.example.com -p 25

  # Verify address format + reachability
  email-tester verify user@example.com

  # Save current flags as default config
  email-tester -s mail.corp.local -p 587 --tls starttls config --save

  # Pipe-friendly JSON output + log to file
  email-tester --json --log-file /var/log/email-tester.log \\
      send -t ops@example.com

ENVIRONMENT VARIABLES:
  SMTP_SERVER      Override default server
  SMTP_PORT        Override default port
  SMTP_USERNAME    Auth username
  SMTP_PASSWORD    Auth password (avoid --password on CLI)
  SMTP_TLS         TLS mode: none | starttls | tls
  SMTP_TIMEOUT     Timeout in seconds
  SMTP_AUTH_MECH   Auth mechanism: PLAIN | LOGIN | CRAM-MD5
  SMTP_FROM        Default sender address
  NO_COLOR         Disable colored output (any non-empty value)
  EMAIL_TESTER_LOG Append-mode log file path
"
)]
pub struct Cli {
    /// SMTP server hostname or IP  [env: SMTP_SERVER]  [default: 222.222.222.5]
    #[arg(short = 's', long = "server", env = "SMTP_SERVER", global = true,
          value_name = "HOST")]
    pub server: Option<String>,

    /// SMTP port  [env: SMTP_PORT]  [default: 25]
    #[arg(short = 'p', long = "port", env = "SMTP_PORT", global = true,
          value_name = "PORT")]
    pub port: Option<u16>,

    /// Username for SMTP authentication  [env: SMTP_USERNAME]
    #[arg(short = 'u', long = "username", env = "SMTP_USERNAME", global = true,
          value_name = "USER")]
    pub username: Option<String>,

    /// Password for SMTP authentication  [env: SMTP_PASSWORD]
    #[arg(short = 'P', long = "password", env = "SMTP_PASSWORD", global = true,
          hide_env_values = true, value_name = "PASS")]
    pub password: Option<String>,

    /// TLS mode: none | starttls | tls  [env: SMTP_TLS]
    #[arg(long = "tls", env = "SMTP_TLS", default_value = "none", global = true,
          value_name = "MODE")]
    pub tls: String,

    /// Connection + response timeout in seconds  [env: SMTP_TIMEOUT]
    #[arg(long = "timeout", env = "SMTP_TIMEOUT", default_value_t = 30u64,
          global = true, value_name = "SECS")]
    pub timeout: u64,

    /// SMTP auth mechanism: PLAIN | LOGIN | CRAM-MD5  [env: SMTP_AUTH_MECH]
    #[arg(long = "auth-mech", env = "SMTP_AUTH_MECH", default_value = "PLAIN",
          global = true, value_name = "MECH")]
    pub auth_mech: String,

    /// Path to TOML config file  [default: ~/.email-tester.toml]
    #[arg(long = "config", global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Increase verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Output results as JSON (machine-readable)
    #[arg(long = "json", global = true)]
    pub json: bool,

    /// Disable all ANSI color output  [env: NO_COLOR]
    #[arg(long = "no-color", env = "NO_COLOR", global = true)]
    pub no_color: bool,

    /// Append diagnostic log to FILE  [env: EMAIL_TESTER_LOG]
    #[arg(long = "log-file", env = "EMAIL_TESTER_LOG", global = true,
          value_name = "FILE")]
    pub log_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Send a test email through the SMTP server  [alias: s]
    #[command(alias = "s")]
    Send {
        /// Recipient(s)  (repeat for multiple)
        #[arg(short = 't', long = "to", required = true, num_args = 1..,
              value_name = "ADDR")]
        to: Vec<String>,

        /// CC recipient(s)
        #[arg(long = "cc", num_args = 0.., value_name = "ADDR")]
        cc: Vec<String>,

        /// BCC recipient(s)
        #[arg(long = "bcc", num_args = 0.., value_name = "ADDR")]
        bcc: Vec<String>,

        /// Sender address  [env: SMTP_FROM]  [default: noreply@<server>]
        #[arg(short = 'f', long = "from", env = "SMTP_FROM", value_name = "ADDR")]
        from: Option<String>,

        /// Sender display name  [env: SMTP_FROM_NAME]
        #[arg(long = "from-name", env = "SMTP_FROM_NAME",
              default_value = "Email Tester", value_name = "NAME")]
        from_name: String,

        /// Email subject
        #[arg(short = 'S', long = "subject",
              default_value = "SMTP Test Email", value_name = "TEXT")]
        subject: String,

        /// Plain-text body (use config default when omitted)
        #[arg(short = 'b', long = "body", value_name = "TEXT")]
        body: Option<String>,

        /// HTML body — inline HTML string OR path to .html file
        #[arg(long = "html", value_name = "HTML|FILE")]
        html: Option<String>,

        /// Attach FILE(s) to the email  (repeat for multiple)
        #[arg(short = 'a', long = "attach", num_args = 0..,
              value_name = "FILE")]
        attachments: Vec<std::path::PathBuf>,

        /// Reply-To address
        #[arg(long = "reply-to", value_name = "ADDR")]
        reply_to: Option<String>,

        /// Extra header in KEY:VALUE format  (repeat for multiple)
        #[arg(long = "header", num_args = 0.., value_name = "KEY:VALUE")]
        headers: Vec<String>,

        /// Retry count on failure (exponential back-off)
        #[arg(long = "retries", default_value_t = 1u32, value_name = "N")]
        retries: u32,

        /// Prompt interactively for password (hides input)
        #[arg(long = "ask-password")]
        ask_password: bool,
    },

    /// Test TCP + SMTP handshake without sending mail  [alias: p]
    #[command(alias = "p")]
    Ping {
        /// How many probes to send
        #[arg(short = 'n', long = "count", default_value_t = 3u32, value_name = "N")]
        count: u32,
    },

    /// Validate email format and check server reachability  [alias: v]
    #[command(alias = "v")]
    Verify {
        /// Email address to inspect
        email: String,
    },

    /// Show SMTP server greeting & capabilities  [alias: i]
    #[command(alias = "i")]
    Info,

    /// Manage persistent configuration
    Config {
        /// Save current flags as default config (~/.email-tester.toml)
        #[arg(long = "save")]
        save: bool,

        /// Print effective configuration
        #[arg(long = "show")]
        show: bool,

        /// Reset config file to factory defaults
        #[arg(long = "reset")]
        reset: bool,
    },
}
