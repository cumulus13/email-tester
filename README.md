# email-tester

**Robust, colorized SMTP email tester with detailed logging, flexible server configuration, and a rich CLI.**

```
  ███████╗███╗   ███╗ █████╗ ██╗██╗           ████████╗███████╗███████╗████████╗███████╗██████╗
  ██╔════╝████╗ ████║██╔══██╗██║██║           ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  █████╗  ██╔████╔██║███████║██║██║              ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
  ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║              ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
  ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗         ██║   ███████╗███████║   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝        ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

| | |
|---|---|
| **Author** | Hadi Cahyadi \<cumulus13@gmail.com\> |
| **Home** | https://github.com/cumulus13/email-tester |
| **License** | MIT |
| **Default server** | `222.222.222.5` |
| **Default port** | `25` (SMTP) |

---

## Features

- 🎨 **Colorized output** – green/red/yellow status, timestamps, section headers
- 📡 **SMTP Ping** – test connectivity with RTT statistics (min/avg/max)
- 📧 **Send** – plain text, HTML/multipart, attachments, CC/BCC, Reply-To, custom headers
- 🔒 **All TLS modes** – plain, STARTTLS, implicit TLS (SMTPS)
- 🔑 **Authentication** – PLAIN, LOGIN; password via flag, env var, or interactive prompt
- 🔁 **Retry** – configurable attempt count with exponential back-off
- 📋 **JSON output** – `--json` for machine-readable results (CI/CD friendly)
- 🗂 **Config file** – persist defaults in `~/.email-tester.toml`
- 📝 **Log file** – append structured log to any file with `--log-file`
- ✅ **Address verify** – RFC 5321 format check + server reachability probe
- 🛠 **Server info** – well-known port guide + TLS/auth reference

---

## Installation

### From source (requires Rust ≥ 1.80)

```bash
git clone https://github.com/cumulus13/email-tester
cd email-tester
cargo build --release
# binary: target/release/email-tester
sudo cp target/release/email-tester /usr/local/bin/
```

### From crates.io

```bash
cargo install email-tester
```

---

## Quick Start

```bash
# Test connectivity to default server (222.222.222.5:25)
email-tester ping

# Send with explicit server
email-tester send -s mail.example.com -t you@example.com

# Authenticated send over STARTTLS
email-tester send -s mail.example.com -p 587 --tls starttls \
    -u myuser --ask-password -t you@example.com

# Full diagnostic
email-tester -vv info
```

---

## Subcommands

### `send` — Send a test email

```
email-tester send [OPTIONS] --to <TO>...
```

| Flag | Short | Description |
|------|-------|-------------|
| `--to` | `-t` | Recipient(s) — required, repeatable |
| `--cc` | | CC recipient(s) |
| `--bcc` | | BCC recipient(s) |
| `--from` | `-f` | Sender address |
| `--from-name` | | Sender display name [default: "Email Tester"] |
| `--subject` | `-S` | Subject line [default: "SMTP Test Email"] |
| `--body` | `-b` | Plain-text body |
| `--html` | | HTML body — inline string or path to `.html` file |
| `--attach` | `-a` | File attachment(s), repeatable |
| `--reply-to` | | Reply-To address |
| `--header` | | Custom header(s) in `Key:Value` format |
| `--retries` | | Attempt count with exponential back-off [default: 1] |
| `--ask-password` | | Prompt for password interactively (hidden input) |

**Examples:**

```bash
# Minimal — relay mode, no auth
email-tester send -s 192.168.1.1 -t ops@example.com

# Auth + STARTTLS + custom subject + body
email-tester send \
  -s smtp.gmail.com -p 587 --tls starttls \
  -u me@gmail.com --ask-password \
  -t friend@example.com \
  -S "Hello from email-tester" \
  -b "Testing 1 2 3"

# Multi-recipient + CC + HTML + attachment
email-tester send \
  -s mail.corp.com -p 465 --tls tls \
  -u alerts@corp.com -P "$SMTP_PASS" \
  -t alice@corp.com -t bob@corp.com \
  --cc manager@corp.com \
  -S "Weekly Report" \
  --html report.html \
  -a /tmp/report.pdf \
  --retries 3

# Login auth mechanism (Office 365 / Exchange)
email-tester send \
  -s smtp.office365.com -p 587 --tls starttls \
  --auth-mech LOGIN -u user@company.com -P "$PASS" \
  -t dest@company.com
```

---

### `ping` — Test SMTP connectivity

```
email-tester ping [-n COUNT]
```

Sends EHLO probes and reports min/avg/max RTT and loss percentage.

```bash
email-tester ping -s mail.example.com -p 25 -n 5
```

---

### `verify` — Validate address + check reachability

```
email-tester verify <EMAIL>
```

Validates RFC 5321 format and tests whether the SMTP server is reachable.

```bash
email-tester verify user@example.com
```

---

### `info` — Server info and reference

```
email-tester info [-s SERVER] [-p PORT]
```

Displays connectivity test, well-known port guide, TLS mode reference, auth mechanism guide, and all supported environment variables.

---

### `config` — Manage configuration

```
email-tester config [--save | --show | --reset]
```

Config file lives at `~/.email-tester.toml` by default (override with `--config`).

```bash
# Save current CLI options as defaults
email-tester -s mail.example.com -p 587 --tls starttls config --save

# Show effective config
email-tester config --show

# Reset to built-in defaults
email-tester config --reset
```

**Sample `~/.email-tester.toml`:**

```toml
[server]
host = "222.222.222.5"
port = 25
timeout = 30

[auth]
username = "myuser"
# password is never saved — use SMTP_PASSWORD env var

[defaults]
from = "noreply@example.com"
from_name = "My App"
subject = "SMTP Test"
body = "Automated test message."
```

---

## Global Options

| Flag | Short | Env var | Description |
|------|-------|---------|-------------|
| `--server` | `-s` | `SMTP_SERVER` | SMTP host [default: `222.222.222.5`] |
| `--port` | `-p` | `SMTP_PORT` | SMTP port [default: `25`] |
| `--username` | `-u` | `SMTP_USERNAME` | Auth username |
| `--password` | `-P` | `SMTP_PASSWORD` | Auth password (never logged) |
| `--tls` | | `SMTP_TLS` | `none` / `starttls` / `tls` [default: `none`] |
| `--timeout` | | `SMTP_TIMEOUT` | Seconds [default: `30`] |
| `--auth-mech` | | `SMTP_AUTH_MECH` | `PLAIN` / `LOGIN` [default: `PLAIN`] |
| `--config` | | | Config file path |
| `--verbose` | `-v` | | `-v` info, `-vv` debug |
| `--json` | | | Machine-readable JSON output |
| `--no-color` | | `NO_COLOR` | Disable ANSI colors |
| `--log-file` | | `EMAIL_TESTER_LOG` | Append log entries to file |

---

## JSON Output

Use `--json` for CI/CD integration. All subcommands emit a single JSON object:

```json
{
  "timestamp": "2025-01-01T12:00:00+00:00",
  "action": "send",
  "server": "mail.example.com",
  "port": 587,
  "tls_mode": "STARTTLS",
  "success": true,
  "duration_ms": 312,
  "message": "Email delivered to 2 recipient(s) in 312 ms",
  "server_reply": "OK: queued as ABCD1234",
  "recipients": ["alice@example.com", "bob@example.com"]
}
```

Exit code is `0` on success, `1` on failure.

---

## TLS Mode Reference

| Mode | Flag | Port | Description |
|------|------|------|-------------|
| Plain | `none` | 25 | No encryption — server-to-server relay, local testing |
| STARTTLS | `starttls` | 587 | Upgrades plain connection to TLS after EHLO |
| Implicit TLS | `tls` | 465 | TLS from first byte (SMTPS / legacy SSL) |

---

## License

MIT — see [LICENSE](LICENSE)

## 👤 Author
        
[Hadi Cahyadi](mailto:cumulus13@gmail.com)
    

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)