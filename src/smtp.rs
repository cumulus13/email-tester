//! File: src\smtp.rs
//! Author: Hadi Cahyadi <cumulus13@gmail.com>
//! Date: 2026-04-01
//! Description: SMTP transport helpers and high-level commands.
//! License: MIT

//! SMTP transport helpers and high-level commands.

use anyhow::{Context, Result};
use chrono::Local;
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
use std::{fs, path::PathBuf, str::FromStr, time::{Duration, Instant}};

use crate::logger::{Logger, TestResult};

// ── TLS Mode ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum TlsMode {
    None,
    StartTls,
    Tls,
}

impl FromStr for TlsMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "none" | "plain" | "no" | "off" => Ok(TlsMode::None),
            "starttls" | "start" | "opportunistic" => Ok(TlsMode::StartTls),
            "tls" | "ssl" | "smtps" | "implicit" => Ok(TlsMode::Tls),
            other => anyhow::bail!(
                "Unknown TLS mode '{}'. Valid values: none, starttls, tls", other
            ),
        }
    }
}

impl std::fmt::Display for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsMode::None     => write!(f, "Plain (no encryption)"),
            TlsMode::StartTls => write!(f, "STARTTLS (opportunistic)"),
            TlsMode::Tls      => write!(f, "Implicit TLS / SMTPS"),
        }
    }
}

// ── Auth Mechanism ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AuthMech {
    Plain,
    Login,
    CramMd5,
}

impl FromStr for AuthMech {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "PLAIN"            => Ok(AuthMech::Plain),
            "LOGIN"            => Ok(AuthMech::Login),
            "CRAM-MD5" | "CRAMMD5" => Ok(AuthMech::CramMd5),
            other => anyhow::bail!(
                "Unknown auth mechanism '{}'. Valid values: PLAIN, LOGIN, CRAM-MD5", other
            ),
        }
    }
}

impl std::fmt::Display for AuthMech {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMech::Plain   => write!(f, "PLAIN"),
            AuthMech::Login   => write!(f, "LOGIN"),
            AuthMech::CramMd5 => write!(f, "CRAM-MD5"),
        }
    }
}

// ── Transport factory ─────────────────────────────────────────────────────────

pub fn build_transport(
    server:  &str,
    port:    u16,
    tls:     &TlsMode,
    timeout: u64,
    creds:   Option<(&str, &str)>,
    mech:    &AuthMech,
    log:     &Logger,
) -> Result<SmtpTransport> {
    log.debug(&format!(
        "build_transport  server={server}  port={port}  tls={tls}  auth={}",
        if creds.is_some() { mech.to_string() } else { "none".to_string() }
    ));

    let dur = Duration::from_secs(timeout);
    let hello = ClientId::Domain(
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string()),
    );

    let mechanisms: Vec<Mechanism> = match mech {
        AuthMech::Plain   => vec![Mechanism::Plain],
        AuthMech::Login   => vec![Mechanism::Login],
        AuthMech::CramMd5 => vec![Mechanism::CramMd5],
    };

    let transport = match tls {
        TlsMode::None => {
            let mut b = SmtpTransport::builder_dangerous(server)
                .port(port)
                .timeout(Some(dur))
                .hello_name(hello)
                .pool_config(PoolConfig::new().max_size(1));
            if let Some((u, p)) = creds {
                b = b
                    .credentials(Credentials::new(u.to_string(), p.to_string()))
                    .authentication(mechanisms);
            }
            b.build()
        }

        TlsMode::StartTls => {
            let tls_p = TlsParameters::builder(server.to_string())
                .dangerous_accept_invalid_certs(true)
                .dangerous_accept_invalid_hostnames(true)
                .build()?;
            let mut b = SmtpTransport::starttls_relay(server)?
                .port(port)
                .tls(Tls::Required(tls_p))
                .timeout(Some(dur))
                .hello_name(hello)
                .pool_config(PoolConfig::new().max_size(1));
            if let Some((u, p)) = creds {
                b = b
                    .credentials(Credentials::new(u.to_string(), p.to_string()))
                    .authentication(mechanisms);
            }
            b.build()
        }

        TlsMode::Tls => {
            let tls_p = TlsParameters::builder(server.to_string())
                .dangerous_accept_invalid_certs(true)
                .dangerous_accept_invalid_hostnames(true)
                .build()?;
            let mut b = SmtpTransport::relay(server)?
                .port(port)
                .tls(Tls::Wrapper(tls_p))
                .timeout(Some(dur))
                .hello_name(hello)
                .pool_config(PoolConfig::new().max_size(1));
            if let Some((u, p)) = creds {
                b = b
                    .credentials(Credentials::new(u.to_string(), p.to_string()))
                    .authentication(mechanisms);
            }
            b.build()
        }
    };

    Ok(transport)
}

// ── PING ──────────────────────────────────────────────────────────────────────

pub fn cmd_ping(
    server:  &str,
    port:    u16,
    tls:     &TlsMode,
    timeout: u64,
    count:   u32,
    log:     &Logger,
    json:    bool,
) -> Result<()> {
    log.header(&format!("SMTP Ping  ▶  {}:{}", server, port));
    log.section("Parameters");
    log.info_kv("Server",   server);
    log.info_kv("Port",     &port.to_string());
    log.info_kv("TLS",      &tls.to_string());
    log.info_kv("Timeout",  &format!("{} s", timeout));
    log.info_kv("Count",    &count.to_string());
    log.section("Pinging");

    let mut results: Vec<(bool, u128)> = Vec::with_capacity(count as usize);

    for i in 1..=count {
        log.step(i, count, "Connecting...");
        let start = Instant::now();

        let outcome = build_transport(server, port, tls, timeout, None, &AuthMech::Plain, log)
            .and_then(|t| t.test_connection().map_err(|e| anyhow::anyhow!("{}", e)));
        let ms = start.elapsed().as_millis();

        match outcome {
            Ok(true)  => { log.ok(&format!("seq={i}  time={ms} ms")); results.push((true,  ms)); }
            Ok(false) => { log.fail(&format!("seq={i}  time={ms} ms  No response"));    results.push((false, ms)); }
            Err(e)    => { log.fail(&format!("seq={i}  time={ms} ms  {e}"));            results.push((false, ms)); }
        }

        if i < count {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    // Statistics
    log.section("Statistics");
    let ok      = results.iter().filter(|(s, _)| *s).count() as u32;
    let loss    = count - ok;
    let times: Vec<u128> = results.iter().map(|(_, ms)| *ms).collect();
    let avg_ms  = if !times.is_empty() { times.iter().sum::<u128>() / times.len() as u128 } else { 0 };
    let min_ms  = times.iter().copied().min().unwrap_or(0);
    let max_ms  = times.iter().copied().max().unwrap_or(0);
    let pct_ok  = (ok as f64 / count as f64) * 100.0;
    let pct_loss = (loss as f64 / count as f64) * 100.0;

    log.status_kv("Transmitted", &count.to_string(),                           true);
    log.status_kv("Received",    &format!("{ok} ({pct_ok:.0}%)"),              ok > 0);
    log.status_kv("Lost",        &format!("{loss} ({pct_loss:.0}%)"),          loss == 0);
    log.status_kv("Min RTT",     &format!("{min_ms} ms"),                      true);
    log.status_kv("Avg RTT",     &format!("{avg_ms} ms"),                      true);
    log.status_kv("Max RTT",     &format!("{max_ms} ms"),                      true);

    if json {
        let r = TestResult {
            timestamp:       Local::now().to_rfc3339(),
            action:          "ping".into(),
            server:          server.to_string(),
            port,
            tls_mode:        tls.to_string(),
            success:         ok == count,
            duration_ms:     avg_ms,
            message:         format!("{ok}/{count} pings successful"),
            server_response: None,
            error:           if loss > 0 { Some(format!("{loss} probe(s) failed")) } else { None },
            recipients:      vec![],
        };
        println!("{}", serde_json::to_string_pretty(&r)?);
    }
    Ok(())
}

// ── INFO ──────────────────────────────────────────────────────────────────────

pub fn cmd_info(
    server:  &str,
    port:    u16,
    tls:     &TlsMode,
    timeout: u64,
    log:     &Logger,
) -> Result<()> {
    log.header(&format!("SMTP Server Info  ▶  {}:{}", server, port));

    log.section("Parameters");
    log.info_kv("Server",  server);
    log.info_kv("Port",    &port.to_string());
    log.info_kv("TLS",     &tls.to_string());
    log.info_kv("Timeout", &format!("{} s", timeout));

    log.section("Connectivity");
    let start = Instant::now();
    let r = build_transport(server, port, tls, timeout, None, &AuthMech::Plain, log)
        .and_then(|t| t.test_connection().map_err(|e| anyhow::anyhow!("{}", e)));
    let ms = start.elapsed().as_millis();

    match r {
        Ok(true)  => log.ok(&format!("Connected in {} ms", ms)),
        Ok(false) => log.fail("Connection refused"),
        Err(e)    => log.fail(&format!("Error: {e}")),
    }

    log.section("Port Reference");
    log.status_kv("25   SMTP",        "Server-to-server relay (no encryption)", port == 25);
    log.status_kv("465  SMTPS",       "Implicit TLS from connect (legacy)",     port == 465);
    log.status_kv("587  Submission",  "STARTTLS client submission",             port == 587);
    log.status_kv("2525 Alt SMTP",    "Alternative submission port",            port == 2525);

    log.section("TLS Mode Guide");
    log.info_kv("none",     "Port 25 — plain relay, no encryption");
    log.info_kv("starttls", "Port 587 — plain connect then upgrade to TLS");
    log.info_kv("tls",      "Port 465 — TLS-wrapped from the very first byte");

    log.section("Auth Mechanisms");
    log.info_kv("PLAIN",    "Base64 username + password (requires TLS)");
    log.info_kv("LOGIN",    "Two-step Base64 challenge (older clients)");
    log.info_kv("CRAM-MD5", "Challenge-response, password never sent in clear");

    Ok(())
}

// ── VERIFY ────────────────────────────────────────────────────────────────────

pub fn cmd_verify(
    server:  &str,
    port:    u16,
    tls:     &TlsMode,
    timeout: u64,
    email:   &str,
    log:     &Logger,
) -> Result<()> {
    log.header(&format!("Address Verify  ▶  {}", email));

    log.section("RFC 5321 Format Check");
    let at_count = email.chars().filter(|c| *c == '@').count();
    let valid = at_count == 1 && {
        let parts: Vec<&str> = email.split('@').collect();
        !parts[0].is_empty() && parts[1].contains('.')
    };
    log.status_kv("Format", if valid { "Valid" } else { "Invalid" }, valid);

    if !valid {
        log.fail("Address format is invalid — aborting verify.");
        return Ok(());
    }

    let parts: Vec<&str> = email.split('@').collect();
    log.info_kv("Local part", parts[0]);
    log.info_kv("Domain",     parts[1]);

    // Extra heuristics
    let has_dot_local = parts[0].contains('.');
    let tld_len = parts[1].split('.').last().map(|s| s.len()).unwrap_or(0);
    log.status_kv("Local has dot",  if has_dot_local { "Yes" } else { "No" }, true);
    log.status_kv("TLD length",     &tld_len.to_string(), tld_len >= 2);

    log.section("SMTP Reachability");
    log.warn("Most servers block RCPT TO probing for privacy — only connectivity is checked.");

    let start = Instant::now();
    match build_transport(server, port, tls, timeout, None, &AuthMech::Plain, log)
        .and_then(|t| t.test_connection().map_err(|e| anyhow::anyhow!("{}", e)))
    {
        Ok(true)  => log.ok(&format!("MX/SMTP server reachable  ({} ms)", start.elapsed().as_millis())),
        Ok(false) => log.fail(&format!("Server {}:{} refused connection", server, port)),
        Err(e)    => log.fail(&format!("Connect error: {e}")),
    }

    Ok(())
}

// ── SEND ──────────────────────────────────────────────────────────────────────

/// All parameters needed for a send operation.
pub struct SendParams {
    pub server:      String,
    pub port:        u16,
    pub tls:         TlsMode,
    pub timeout:     u64,
    pub creds:       Option<(String, String)>,
    pub mech:        AuthMech,
    pub to:          Vec<String>,
    pub cc:          Vec<String>,
    pub bcc:         Vec<String>,
    pub from:        String,
    pub from_name:   String,
    pub subject:     String,
    pub body:        String,
    pub html:        Option<String>,
    pub attachments: Vec<PathBuf>,
    pub reply_to:    Option<String>,
    pub headers:     Vec<String>,
    pub retries:     u32,
}

/// Returns `true` on success, `false` on final failure.
pub fn cmd_send(p: &SendParams, log: &Logger, json: bool) -> Result<bool> {
    log.header(&format!("Send Email  ▶  {}:{}", p.server, p.port));

    log.section("Connection");
    log.status_kv("Server",   &p.server, true);
    log.status_kv("Port",     &p.port.to_string(), true);
    log.status_kv("TLS",      &p.tls.to_string(), true);
    log.status_kv("Timeout",  &format!("{} s", p.timeout), true);
    log.status_kv("Auth",     if p.creds.is_some() {
        &format!("Yes ({})", p.mech)
    } else {
        "No (open relay)"
    }, true);

    log.section("Envelope");
    log.status_kv("From",     &format!("{} <{}>", p.from_name, p.from), true);
    for a in &p.to  { log.status_kv("To",  a, true); }
    for a in &p.cc  { log.status_kv("CC",  a, true); }
    for a in &p.bcc { log.status_kv("BCC", a, true); }
    log.status_kv("Subject",  &p.subject, true);
    if !p.attachments.is_empty() {
        log.status_kv("Attachments", &p.attachments.len().to_string(), true);
    }
    if !p.headers.is_empty() {
        log.status_kv("Extra headers", &p.headers.len().to_string(), true);
    }

    // ── Build message ─────────────────────────────────────────────────────────
    log.section("Building Message");

    let from_full = format!("{} <{}>", p.from_name, p.from);
    let mut mb = Message::builder()
        .from(from_full.parse().context("Invalid From address")?)
        .subject(&*p.subject);

    for a in &p.to  { mb = mb.to(a.parse().context(format!("Invalid To: {a}"))?);  }
    for a in &p.cc  { mb = mb.cc(a.parse().context(format!("Invalid CC: {a}"))?);  }
    for a in &p.bcc { mb = mb.bcc(a.parse().context(format!("Invalid BCC: {a}"))?); }
    if let Some(rt) = &p.reply_to {
        mb = mb.reply_to(rt.parse().context("Invalid Reply-To")?);
    }
    for h in &p.headers {
        let parts: Vec<&str> = h.splitn(2, ':').collect();
        if parts.len() == 2 {
            log.debug(&format!("Extra header: '{}' = '{}'", parts[0].trim(), parts[1].trim()));
        } else {
            log.warn(&format!("Ignoring malformed header: '{}'", h));
        }
    }

    let email = if p.attachments.is_empty() {
        match &p.html {
            Some(html) => mb.multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(p.body.clone()))
                    .singlepart(SinglePart::html(html.clone())),
            )?,
            None => mb.body(p.body.clone())?,
        }
    } else {
        let body_part = match &p.html {
            Some(html) => SinglePart::html(html.clone()),
            None       => SinglePart::plain(p.body.clone()),
        };
        let mut mp = MultiPart::mixed().singlepart(body_part);
        for path in &p.attachments {
            if !path.exists() {
                log.warn(&format!("Attachment not found, skipping: {}", path.display()));
                continue;
            }
            let data  = fs::read(path)
                .context(format!("Cannot read attachment: {}", path.display()))?;
            let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let ct    = ContentType::parse("application/octet-stream").unwrap();
            mp = mp.singlepart(Attachment::new(fname).body(data, ct));
            log.debug(&format!("Attached: {}", path.display()));
        }
        mb.multipart(mp)?
    };

    log.ok("Message constructed");

    // ── Send with retry ───────────────────────────────────────────────────────
    let mut success  = false;
    let mut last_err: Option<String> = None;
    let mut srv_response: Option<String> = None;
    let total_start  = Instant::now();
    let creds_ref    = p.creds.as_ref().map(|(u, pw)| (u.as_str(), pw.as_str()));

    for attempt in 1..=p.retries {
        if p.retries > 1 {
            log.step(attempt, p.retries, &format!("Attempt {}/{}", attempt, p.retries));
        }

        log.section(&format!("Connecting to {}:{}", p.server, p.port));
        let attempt_start = Instant::now();

        match build_transport(&p.server, p.port, &p.tls, p.timeout, creds_ref, &p.mech, log) {
            Err(e) => {
                log.fail(&format!("Transport error: {e}"));
                last_err = Some(e.to_string());
                if attempt < p.retries { std::thread::sleep(Duration::from_secs(2)); }
                continue;
            }
            Ok(transport) => {
                log.ok("Transport ready");
                log.section("Delivering...");

                match transport.send(&email) {
                    Ok(resp) => {
                        let ms  = attempt_start.elapsed().as_millis();
                        let code: String = resp.code().to_string();
                        log.ok(&format!("Delivered  SMTP {}  in {} ms", code, ms));
                        let msgs: Vec<&str> = resp.message().collect();
                        if let Some(m) = msgs.first() {
                            srv_response = Some(m.to_string());
                            log.info_kv("Server reply", m);
                        }
                        success = true;
                        break;
                    }
                    Err(e) => {
                        let ms = attempt_start.elapsed().as_millis();
                        let es = format!("{}", e);
                        log.fail(&format!("Send failed ({ms} ms): {es}"));
                        last_err = Some(es);
                        if attempt < p.retries {
                            let wait = 2u64.pow(attempt - 1);
                            log.warn(&format!("Back-off: retrying in {wait} s…"));
                            std::thread::sleep(Duration::from_secs(wait));
                        }
                    }
                }
            }
        }
    }

    let total_ms = total_start.elapsed().as_millis();
    let result = TestResult {
        timestamp:       Local::now().to_rfc3339(),
        action:          "send".into(),
        server:          p.server.clone(),
        port:            p.port,
        tls_mode:        p.tls.to_string(),
        success,
        duration_ms:     total_ms,
        message: if success {
            format!("Email delivered to {} recipient(s) in {} ms", p.to.len(), total_ms)
        } else {
            format!("Delivery failed after {} attempt(s)", p.retries)
        },
        server_response: srv_response,
        error:           last_err,
        recipients:      p.to.clone(),
    };

    log.print_result(&result);
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(success)
}
