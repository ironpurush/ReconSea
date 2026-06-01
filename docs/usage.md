# ReconSea — Usage Guide

## Quick Start

```bash
reconsea scan example.com
```

That's it. ReconSea runs all modules, shows live progress in the terminal, and writes a full HTML report to `reports/example.com/report.html`.

---

## Command Reference

### `reconsea scan <target>`

Run a full reconnaissance scan.

```bash
# Basic scan
reconsea scan example.com

# Deep scan (more depth, larger wordlists, slower)
reconsea scan example.com --deep

# Custom threads and timeout
reconsea scan example.com --threads 200 --timeout 20

# Custom output path
reconsea scan example.com --output /home/user/client-report.html

# Route through Burp Suite proxy
reconsea scan example.com --proxy http://127.0.0.1:8080

# Custom User-Agent (evade some WAFs)
reconsea scan example.com --user-agent "Googlebot/2.1"

# Combine flags
reconsea scan api.example.com --deep --threads 150 --proxy http://127.0.0.1:8080 --output /tmp/api-report.html
```

**Flags:**

| Flag | Short | Default | Description |
|---|---|---|---|
| `--threads` | `-t` | `50` | Concurrent HTTP workers |
| `--deep` | `-d` | `false` | Enable deep scan (4-level crawl, extended wordlists) |
| `--output` | `-o` | auto | HTML report path |
| `--timeout` | | `15` | HTTP request timeout (seconds) |
| `--proxy` | | — | HTTP/HTTPS proxy URL |
| `--user-agent` | | ReconSea | Custom User-Agent string |

---

### `reconsea dashboard`

Launch a local web server to browse all your reports.

```bash
# Default: http://127.0.0.1:8080
reconsea dashboard

# Custom port
reconsea dashboard --port 9090

# Bind to all interfaces (shows external access warning)
reconsea dashboard --host 0.0.0.0
```

Open your browser at: **http://localhost:8080/reports/**

---

### `reconsea doctor`

Check that all system dependencies are present.

```bash
reconsea doctor
```

---

### `reconsea update`

Pull the latest code from GitHub and rebuild.

```bash
reconsea update
```

---

### `reconsea version`

Print version, author, and build info.

```bash
reconsea version
```

---

### `reconsea uninstall`

Remove the binary from your system with confirmation prompt.

```bash
reconsea uninstall
```

---

## Terminal Output

ReconSea **never** prints scan results to the terminal. The terminal only shows:

- Startup banner
- Scan progress with animated bars and live counters
- Current module/task
- Final summary statistics
- Report location

Example terminal session:
```
  ⚓  ReconSea — Breaking the internet to make it unbreakable

  [*] Target   : https://example.com
  [*] Threads  : 50
  [*] Deep     : false

  ┌─ Asset Discovery ────────────────────────────────────────────
  [*] Target domain: example.com
  [*] Querying certificate transparency logs …
  [+] CT logs returned 47 names
  [*] Starting DNS brute-force (50 workers) …
  [+] DNS brute-force found 12 names

  [████████████░░░░░░░░░░░░░░░░░░░░░░░░░░] 31%  Resolving…  Live: 23

  ┌─ Scan Complete ───────────────────────────────────────────────
  │  Target                  example.com
  │  Duration                2m34s
  │  Risk                    Medium (35/100)
  │  Subdomains              59
  │  Live Hosts              23
  │  Endpoints               412
  │  Parameters              87
  │  Secrets                 2 (1 critical)
  │  Directories             34
  │  Findings                8
  └─────────────────────────────────────────────────────────────

  [+] Report → reports/example.com/report.html
```

---

## Output Files

| File | Description |
|---|---|
| `report.html` | Interactive HTML report (open in browser) |
| `report.json` | Complete scan data as JSON |
| `assets.json` | Subdomains and live hosts |
| `endpoints.json` | All discovered endpoints |
| `secrets.json` | Credential findings |
| `dns.json` | DNS records |

---

## Tips

**Increase threads for faster scans:**
```bash
reconsea scan example.com --threads 200
```

**Use `--deep` for bug bounty programs** — discovers more endpoints and paths.

**Combine with Burp Suite** to inspect traffic:
```bash
reconsea scan example.com --proxy http://127.0.0.1:8080
```

**Re-open old reports** any time by opening the HTML file in your browser:
```bash
firefox reports/example.com/report.html
```

**Export data** using the Download buttons inside the HTML report (JSON or CSV).
