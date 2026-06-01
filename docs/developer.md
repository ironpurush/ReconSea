# ReconSea — Developer Documentation

## Architecture Overview

ReconSea is a modular Go application. Every reconnaissance capability lives in its own package under `internal/modules/`. The scanner orchestrates all modules concurrently and pipes results into the report generator.

```
cmd/reconsea/main.go          ← Cobra CLI commands
internal/scanner/scanner.go   ← Orchestrates all modules
internal/modules/*/           ← Individual recon modules
internal/report/report.go     ← HTML report generator
internal/report/templates/    ← Embedded HTML template
internal/dashboard/           ← Local HTTP dashboard
internal/ui/progress.go       ← Terminal output / progress
pkg/types/types.go            ← Shared data structures
pkg/utils/utils.go            ← HTTP client, helpers
```

## Data Flow

```
main.go
  └── scanner.Run()
        ├── subdomain.Scan()    → []Subdomain
        ├── probeLiveHosts()    → []LiveHost
        ├── fingerprint.Scan()  → []Technology, *WAFInfo, []SecurityHeader
        ├── ssl.Scan()          → *SSLInfo, []Finding
        ├── crawler.Scan()      → []Endpoint
        ├── dirbuster.Scan()    → []Directory
        ├── params.Scan()       → []Parameter
        ├── secrets.Scan()      → []Secret
        ├── dns.Scan()          → []DNSRecord, []Finding
        └── report.Generate()  → report.html + *.json
```

## Module API Contract

Every module follows this signature pattern:

```go
// Scan runs the module against target and returns typed results.
// - ctx:  respect cancellation
// - target: normalized URL (https://example.com)
// - opts:   ScanOptions with threads, timeout, proxy, etc.
func Scan(ctx context.Context, target string, opts types.ScanOptions) (ResultType, error)
```

Modules:
- **must** check `ctx.Done()` in long loops
- **must** log progress using `ui.Section()`, `ui.Info()`, `ui.Success()`
- **must not** print scan data to stdout
- **should** use `utils.WorkerPool()` for concurrency
- **should** return partial results on error (don't abort everything)

## Adding a New Module

### 1. Create the package

```bash
mkdir internal/modules/mymodule
touch internal/modules/mymodule/mymodule.go
```

### 2. Implement the Scan function

```go
package mymodule

import (
    "context"
    "github.com/IronPurush/reconsea/internal/ui"
    "github.com/IronPurush/reconsea/pkg/types"
)

type MyResult struct {
    URL   string `json:"url"`
    Value string `json:"value"`
}

func Scan(ctx context.Context, target string, opts types.ScanOptions) ([]MyResult, error) {
    ui.Section("My Module")
    ui.Info("Scanning %s …", target)

    // ... implementation ...

    ui.Success("Found %d results", len(results))
    return results, nil
}
```

### 3. Add the result type to `pkg/types/types.go`

```go
type MyResult struct {
    URL   string `json:"url"`
    Value string `json:"value"`
}

// In ScanResult:
type ScanResult struct {
    // ...
    MyResults []MyResult `json:"my_results"`
}
```

### 4. Wire it into the scanner

```go
// internal/scanner/scanner.go
import "github.com/IronPurush/reconsea/internal/modules/mymodule"

// In Run():
myResults, _ := mymodule.Scan(ctx, target, opts)
result.MyResults = myResults
```

### 5. Add a section to the HTML report template

```html
<!-- internal/report/templates/report.html -->
<section id="mymodule" class="mb-5">
  <div class="section-title">My Module ({{len .MyResults}})</div>
  <div class="rs-card">
    <table id="tblMyModule" class="table table-sm w-100">
      <thead><tr><th>URL</th><th>Value</th></tr></thead>
      <tbody>
        {{range .MyResults}}
        <tr><td>{{.URL}}</td><td>{{.Value}}</td></tr>
        {{end}}
      </tbody>
    </table>
  </div>
</section>
```

### 6. Add sidebar link

```html
<li class="nav-item">
  <a class="nav-link" href="#mymodule"><i class="bi bi-star"></i> My Module</a>
</li>
```

## Key Packages & Conventions

### `pkg/utils`

```go
// Create an HTTP client (reuse across requests)
client := utils.NewHTTPClient(opts.Timeout, opts.Proxy)

// Safe GET — never panics, returns empty on error
body, status, headers, err := utils.SafeGet(client, url, userAgent)

// Concurrent worker pool (generic)
utils.WorkerPool(ctx, items, opts.Threads, func(item T) { ... })

// URL helpers
utils.NormalizeTarget("example.com")  // → "https://example.com"
utils.ExtractHostname("https://example.com/path")  // → "example.com"
utils.MaskSecret("ghp_abc123...")  // → "ghp_****...23"
```

### `internal/ui`

```go
ui.Section("Module Name")          // ┌─ Module Name ──────────────
ui.Info("Loading %d items", n)     // [*] Loading 42 items
ui.Success("Found %d results", n)  // [+] Found 42 results
ui.Warn("Timeout: %s", url)        // [!] Timeout: ...
ui.Error("Failed: %v", err)        // [✗] Failed: ...
ui.Result("Subdomains", "42")      // │  Subdomains:    42
ui.SectionEnd()                    // └──────────────────────────

// Progress bar
prog := ui.NewProgress(total, "Task label")
prog.AddCounter("Found")
prog.Increment(1)
prog.IncrementCounter("Found", 1)
prog.Finish()
```

## Testing

```bash
# Run all tests
make test

# Run with race detector
go test ./... -race

# Run a specific package
go test ./internal/modules/subdomain/... -v

# Coverage report
make coverage
open coverage.html
```

### Writing Tests

```go
// internal/modules/mymodule/mymodule_test.go
package mymodule

import (
    "context"
    "testing"
    "github.com/IronPurush/reconsea/pkg/types"
)

func TestScan(t *testing.T) {
    opts := types.ScanOptions{
        Threads: 5,
        Timeout: 10,
    }
    results, err := Scan(context.Background(), "https://example.com", opts)
    if err != nil {
        t.Fatalf("Scan failed: %v", err)
    }
    t.Logf("Got %d results", len(results))
}
```

## Code Style

- Follow standard Go conventions (`gofmt`, `golint`)
- Error messages: lowercase, no trailing period
- All exported functions have doc comments
- No `panic()` — always return errors
- Context must be the first argument in every function that does I/O
- Use `//nolint:gosec` with a comment when intentionally skipping security lints (e.g. `InsecureSkipVerify` for recon)

## Linting

```bash
make lint
# Uses golangci-lint with config in .golangci.yml
```

## Release Process

1. Bump version in `pkg/types/types.go`
2. Update `CHANGELOG.md`
3. Commit and tag: `git tag v1.x.x && git push --tags`
4. GitHub Actions automatically builds and publishes the release
