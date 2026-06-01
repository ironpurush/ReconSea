# ⚓ ReconSea

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-00d4ff?style=for-the-badge&logo=go" />
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=for-the-badge&logo=go" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/github/actions/workflow/status/IronPurush/reconsea/build.yml?style=for-the-badge&label=CI" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" />
</p>

<p align="center">
  <strong>Breaking the internet to make it unbreakable</strong><br/>
  A modern, high-speed reconnaissance automation framework for Ethical Hackers,<br/>
  Security Researchers, Red Teamers, and Bug Bounty Hunters.
</p>

---

## 🚀 Features

| Category | Capabilities |
|---|---|
| **Asset Discovery** | Subdomain enumeration (CT logs + brute-force), live host probing, CDN detection, wildcard detection |
| **Web Fingerprinting** | Technology stack, frameworks, CMS, WAF detection, security header grading |
| **Crawling** | Deep BFS crawling, JavaScript URL extraction, API endpoint detection |
| **Parameter Discovery** | GET / POST / JSON parameter extraction with deduplication |
| **Secret Detection** | AWS keys, GitHub tokens, JWTs, Stripe keys, OAuth tokens, private keys, database URLs |
| **Directory Busting** | Fast concurrent directory enumeration with smart wordlists |
| **DNS Intelligence** | A/AAAA/MX/TXT/NS/SOA records, SPF/DMARC analysis, zone transfer testing, ASN lookup |
| **SSL/TLS Analysis** | Certificate grading, expiry checks, cipher analysis, TLS version detection |
| **HTML Report** | Professional, interactive report with dark/light mode, charts, DataTables, JSON/CSV export |

## 📦 Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/IronPurush/reconsea.git
cd reconsea
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

Supports: **Kali Linux**, **Ubuntu**, **Debian**, **Parrot OS**

### Manual Build

```bash
git clone https://github.com/IronPurush/reconsea.git
cd reconsea
go mod download
make build
sudo make install
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/IronPurush/reconsea/releases):

```bash
# Linux amd64
curl -L https://github.com/IronPurush/reconsea/releases/latest/download/reconsea-linux-amd64-v1.0.0.tar.gz | tar xz
sudo install -m755 reconsea-linux-amd64 /usr/local/bin/reconsea
```

## 🎯 Usage

### Basic Scan
```bash
reconsea scan example.com
```

### Deep Scan
```bash
reconsea scan example.com --deep
```

### Custom Threads & Output
```bash
reconsea scan example.com --threads 100 --output /tmp/myreport.html
```

### With Proxy (Burp Suite)
```bash
reconsea scan example.com --proxy http://127.0.0.1:8080
```

### Launch Dashboard
```bash
reconsea dashboard                     # localhost:8080
reconsea dashboard --host 0.0.0.0     # all interfaces (shows warning)
reconsea dashboard --port 9090        # custom port
```

### Other Commands
```bash
reconsea doctor      # check system health & dependencies
reconsea update      # pull latest and rebuild
reconsea version     # print version info
reconsea uninstall   # remove ReconSea
```

## 📁 Output Structure

```
reports/
└── example.com/
    ├── report.html     ← Main interactive HTML report
    ├── report.json     ← Full scan data (JSON)
    ├── assets.json     ← Subdomains + live hosts
    ├── endpoints.json  ← All discovered URLs
    ├── secrets.json    ← Credential findings
    └── dns.json        ← DNS records
```

## 📊 HTML Report

The report is a **fully standalone** HTML file — no server needed. Open it in any browser.

Features:
- 🌙 Dark / ☀️ Light mode toggle
- 📊 Interactive charts (risk gauge, severity breakdown, asset pie)
- 🔍 Searchable, sortable DataTables for every finding type
- 📥 One-click JSON and CSV export
- 📱 Responsive and mobile-friendly
- 🔗 Clickable URLs throughout
- 🚨 Color-coded severity levels

## 🛡️ Ethics & Legal

> **ReconSea is for authorized security testing only.**
>
> Only scan targets you own or have explicit written permission to test.
> Unauthorized scanning may be illegal in your jurisdiction.

## 🏗️ Architecture

```
ReconSea/
├── cmd/reconsea/       # CLI entry point (Cobra)
├── internal/
│   ├── scanner/        # Scan orchestrator
│   ├── modules/
│   │   ├── subdomain/  # CT logs + DNS brute-force
│   │   ├── fingerprint/# Tech/WAF/header detection
│   │   ├── crawler/    # BFS + JS crawling
│   │   ├── params/     # Parameter extraction
│   │   ├── secrets/    # Credential detection
│   │   ├── dirbuster/  # Directory enumeration
│   │   ├── dns/        # DNS intelligence
│   │   └── ssl/        # TLS analysis
│   ├── report/         # HTML report generator
│   ├── dashboard/      # Local web dashboard
│   └── ui/             # Terminal progress/colours
└── pkg/
    ├── types/          # Shared data structures
    └── utils/          # HTTP client, helpers
```

## ⚙️ Configuration Flags

| Flag | Default | Description |
|---|---|---|
| `--threads` / `-t` | `50` | Concurrent workers |
| `--deep` / `-d` | `false` | Deep scan (more wordlists, higher depth) |
| `--output` / `-o` | `reports/<target>/report.html` | Report output path |
| `--timeout` | `15` | HTTP timeout (seconds) |
| `--proxy` | — | HTTP proxy URL |
| `--user-agent` | ReconSea default | Custom User-Agent |

## 🔧 Development

```bash
# Run tests
make test

# With coverage
make coverage

# Lint
make lint

# Format
make fmt

# Cross-compile all platforms
make cross

# Build release archives
make release
```

## 📄 License

MIT License — see [LICENSE](LICENSE)

## 👤 Author

**Sagar Jondhale (IronPurush)**

> Built for the Ethical Hacking and Bug Bounty Community

- GitHub: [@IronPurush](https://github.com/IronPurush)
- Project: [github.com/IronPurush/reconsea](https://github.com/IronPurush/reconsea)

---

<p align="center">
  <strong>⚓ ReconSea</strong> — Breaking the internet to make it unbreakable
</p>
