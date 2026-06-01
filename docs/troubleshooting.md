# ReconSea — Troubleshooting Guide

## `reconsea: command not found`

**Cause:** `/usr/local/bin` is not in your PATH.

**Fix:**
```bash
export PATH=$PATH:/usr/local/bin
# Make permanent:
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc && source ~/.bashrc
# Or for zsh (Kali default):
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.zshrc && source ~/.zshrc
```

---

## `go: command not found` during build

**Cause:** Go is not installed or not in PATH.

**Fix:**
```bash
# Run the installer which auto-installs Go:
sudo ./scripts/install.sh

# Or install Go manually:
sudo apt-get install -y golang-go

# Or install the latest Go:
curl -fsSL https://go.dev/dl/go1.22.4.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
export PATH=$PATH:/usr/local/go/bin
```

---

## `go: module not found` / dependency errors

**Fix:**
```bash
cd reconsea
go clean -modcache
go mod download
go mod tidy
make build
```

---

## Build fails with permission errors

**Fix:**
```bash
# Ensure write access to build dir
chmod -R u+w .
make build

# If installing globally:
sudo make install
```

---

## SSL certificate errors when scanning

ReconSea intentionally disables SSL verification during recon to inspect misconfigured or self-signed certificates. If you see TLS errors in output, these are from the target, not from ReconSea itself.

---

## Scan is very slow

**Fixes:**
1. Increase threads: `--threads 200`
2. Reduce timeout: `--timeout 10`
3. Skip deep mode (remove `--deep`)
4. Check DNS resolution speed: `dig example.com @8.8.8.8`
5. Check proxy latency if using `--proxy`

---

## No subdomains found

**Possible causes:**
- Target has no Certificate Transparency records yet
- Target blocks AXFR
- DNS rate limiting

**Fix:**
```bash
# Try manually querying CT logs:
curl "https://crt.sh/?q=%.example.com&output=json" | jq '.[].name_value'
```

---

## Report not generated

**Check:**
```bash
ls -la reports/example.com/

# Check for write permissions:
mkdir -p reports/example.com && touch reports/example.com/test && rm reports/example.com/test
```

---

## WAF blocking scans

ReconSea respects rate limits intelligently but some aggressive WAFs may block scanning.

**Workarounds:**
```bash
# Reduce rate
reconsea scan example.com --threads 10 --timeout 30

# Rotate User-Agent
reconsea scan example.com --user-agent "Mozilla/5.0 (compatible; Googlebot/2.1)"

# Route through Burp (to see WAF responses)
reconsea scan example.com --proxy http://127.0.0.1:8080
```

---

## `dial tcp: lookup <host>: no such host`

**Cause:** DNS resolution failed.

**Fix:**
```bash
# Test DNS yourself:
dig example.com
nslookup example.com 8.8.8.8

# Check your DNS resolver:
cat /etc/resolv.conf

# Try a public resolver:
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

---

## Port 8080 already in use (dashboard)

```bash
reconsea dashboard --port 8181
# Or find what's using 8080:
sudo lsof -i :8080
```

---

## PEP 668 error (`externally-managed-environment`)

ReconSea is a pure Go binary and does **not** require Python at runtime. If you see this error from another tool, use:
```bash
pip install <package> --break-system-packages
# Or:
pipx install <package>
```

---

## Running `reconsea doctor`

Always run `reconsea doctor` first to diagnose issues:
```bash
reconsea doctor
```

---

## Still stuck?

Open an issue at: https://github.com/IronPurush/reconsea/issues

Include:
1. OS and version (`cat /etc/os-release`)
2. Go version (`go version`)
3. ReconSea version (`reconsea version`)
4. Full error output
