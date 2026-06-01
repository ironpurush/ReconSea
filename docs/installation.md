# ReconSea — Installation Guide

## Supported Platforms

| OS | Version | Status |
|---|---|---|
| Kali Linux | 2023.x, 2024.x | ✅ Fully supported |
| Ubuntu | 22.04, 24.04 LTS | ✅ Fully supported |
| Debian | 11, 12 | ✅ Fully supported |
| Parrot OS | 5.x, 6.x | ✅ Fully supported |
| macOS | 12+ (Intel + Apple Silicon) | ✅ Supported |
| Windows | 10/11 (WSL2) | ⚠️ Via WSL2 |

## Prerequisites

- **Go 1.21+** (auto-installed by `install.sh` if missing)
- **Git**
- **curl**
- Internet access during installation

## Method 1 — Automated Installer (Recommended)

```bash
git clone https://github.com/IronPurush/reconsea.git
cd reconsea
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

The installer will:
1. Detect your OS and architecture
2. Install Go 1.22 if not present or outdated
3. Download all Go module dependencies
4. Build the `reconsea` binary
5. Install it to `/usr/local/bin/reconsea`
6. Create the `reports/` output directory

## Method 2 — Manual Build

```bash
# 1. Clone
git clone https://github.com/IronPurush/reconsea.git
cd reconsea

# 2. Install Go (if needed)
#    https://go.dev/doc/install

# 3. Download dependencies
go mod download

# 4. Build
make build
# Binary: build/reconsea

# 5. Install globally
sudo make install
# Installed to: /usr/local/bin/reconsea
```

## Method 3 — Pre-built Binary

```bash
# Linux amd64
VER="v1.0.0"
curl -L "https://github.com/IronPurush/reconsea/releases/download/${VER}/reconsea-linux-amd64-${VER}.tar.gz" \
  | tar xz
sudo install -m755 reconsea-linux-amd64 /usr/local/bin/reconsea
reconsea version
```

## Verifying Installation

```bash
reconsea doctor
```

Expected output:
```
  [+] Go runtime    go version go1.22.x linux/amd64
  [+] Git           git version 2.x.x
  [+] curl          curl 8.x.x
  ...
```

## PATH Setup

If `reconsea` is not found after install:

```bash
# Add to current session
export PATH=$PATH:/usr/local/bin

# Make permanent (bash)
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc

# Make permanent (zsh / Kali default)
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.zshrc
source ~/.zshrc
```

## Updating

```bash
cd reconsea
git pull origin main
make build
sudo make install

# Or use the built-in command:
reconsea update
```

## Uninstalling

```bash
reconsea uninstall

# Or manually:
sudo rm /usr/local/bin/reconsea
```

## Python PEP 668 Note

On newer Debian/Ubuntu/Kali systems with PEP 668 (externally managed Python), the installer uses `pipx` or `--break-system-packages` only when absolutely required. ReconSea itself is a pure Go binary and does **not** depend on Python at runtime.

## Docker (Optional)

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download && go build -trimpath -ldflags "-s -w" -o reconsea ./cmd/reconsea

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/reconsea /usr/local/bin/reconsea
ENTRYPOINT ["reconsea"]
```

```bash
docker build -t reconsea .
docker run --rm reconsea scan example.com
```
