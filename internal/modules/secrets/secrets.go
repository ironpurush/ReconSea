package secrets

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
)

// secretPattern describes a single secret type with its regex and severity.
type secretPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string // critical | high | medium | low
}

var patterns = []secretPattern{
	// Cloud Providers
	{Name: "AWS Access Key", Severity: "critical",
		Regex: regexp.MustCompile(`(?i)(AKIA|AIPA|ASIA|AROA|AIDA)[A-Z0-9]{16}`)},
	{Name: "AWS Secret Key", Severity: "critical",
		Regex: regexp.MustCompile(`(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`)},
	{Name: "Google API Key", Severity: "high",
		Regex: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{Name: "Google OAuth Token", Severity: "high",
		Regex: regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`)},
	{Name: "Azure Storage Key", Severity: "critical",
		Regex: regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{88}`)},

	// Source Code / VCS
	{Name: "GitHub Token (Classic)", Severity: "critical",
		Regex: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
	{Name: "GitHub Fine-Grained Token", Severity: "critical",
		Regex: regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`)},
	{Name: "GitLab Token", Severity: "critical",
		Regex: regexp.MustCompile(`glpat-[0-9a-zA-Z\-_]{20}`)},

	// Payment
	{Name: "Stripe Secret Key", Severity: "critical",
		Regex: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{Name: "Stripe Publishable Key", Severity: "medium",
		Regex: regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`)},
	{Name: "PayPal / Braintree Access Token", Severity: "critical",
		Regex: regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`)},

	// Messaging
	{Name: "Slack Bot Token", Severity: "high",
		Regex: regexp.MustCompile(`xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}`)},
	{Name: "Slack User Token", Severity: "high",
		Regex: regexp.MustCompile(`xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9a-f]{32}`)},
	{Name: "Slack Webhook URL", Severity: "high",
		Regex: regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}`)},
	{Name: "Twilio Account SID", Severity: "high",
		Regex: regexp.MustCompile(`AC[a-z0-9]{32}`)},

	// Auth / Identity
	{Name: "JWT Token", Severity: "medium",
		Regex: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)},
	{Name: "Basic Auth Credentials", Severity: "high",
		Regex: regexp.MustCompile(`(?i)(?:username|user|login|passwd|password)\s*[:=]\s*['"]?[^\s'"]{4,}['"]?`)},
	{Name: "Bearer Token", Severity: "medium",
		Regex: regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}`)},

	// Crypto / PKI
	{Name: "RSA Private Key", Severity: "critical",
		Regex: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`)},
	{Name: "EC Private Key", Severity: "critical",
		Regex: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`)},
	{Name: "PGP Private Key", Severity: "critical",
		Regex: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`)},

	// Database
	{Name: "Database Connection String", Severity: "critical",
		Regex: regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis|mssql):\/\/[^\s'"]+`)},

	// Generic high-entropy secrets
	{Name: "Generic API Key", Severity: "medium",
		Regex: regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['"]?[0-9a-zA-Z]{20,}['"]?`)},
	{Name: "Generic Secret", Severity: "medium",
		Regex: regexp.MustCompile(`(?i)secret\s*[:=]\s*['"]?[0-9a-zA-Z]{20,}['"]?`)},
	{Name: "Generic Token", Severity: "low",
		Regex: regexp.MustCompile(`(?i)token\s*[:=]\s*['"]?[0-9a-zA-Z\-_]{20,}['"]?`)},
}

// Scan fetches JS/text resources from the endpoint list and searches for secrets.
func Scan(ctx context.Context, endpoints []types.Endpoint, opts types.ScanOptions) ([]types.Secret, error) {
	ui.Section("Secret Discovery")

	client := utils.NewHTTPClient(opts.Timeout, opts.Proxy)
	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64) ReconSea/1.0"
	}

	// Filter JS and likely text resources
	var targets []types.Endpoint
	for _, ep := range endpoints {
		if isTextResource(ep.URL) {
			targets = append(targets, ep)
		}
	}

	ui.Info("Scanning %d JS/text files for secrets …", len(targets))
	prog := ui.NewProgress(len(targets), "Scanning for secrets")
	prog.AddCounter("Secrets")

	var (
		mu   sync.Mutex
		all  []types.Secret
		seen = make(map[string]bool)
	)

	utils.WorkerPool(ctx, targets, opts.Threads, func(ep types.Endpoint) {
		defer prog.Increment(1)
		body, _, _, err := utils.SafeGet(client, ep.URL, ua)
		if err != nil {
			return
		}
		found := scanBody(body, ep.URL)
		mu.Lock()
		for _, s := range found {
			k := s.Type + "|" + s.Masked
			if !seen[k] {
				seen[k] = true
				all = append(all, s)
				prog.IncrementCounter("Secrets", 1)
			}
		}
		mu.Unlock()
	})

	prog.Finish()

	critical := 0
	for _, s := range all {
		if s.Severity == "critical" {
			critical++
		}
	}
	ui.Success("Found %d secrets (%d critical)", len(all), critical)
	return all, nil
}

func scanBody(body, sourceURL string) []types.Secret {
	lines := strings.Split(body, "\n")
	var found []types.Secret

	for lineNum, line := range lines {
		for _, p := range patterns {
			match := p.Regex.FindString(line)
			if match == "" {
				continue
			}
			found = append(found, types.Secret{
				Type:     p.Name,
				Value:    match,
				Masked:   utils.MaskSecret(match),
				URL:      sourceURL,
				Line:     lineNum + 1,
				Severity: p.Severity,
			})
		}
	}
	return found
}

func isTextResource(u string) bool {
	lower := strings.ToLower(strings.Split(u, "?")[0])
	for _, ext := range []string{".js", ".json", ".txt", ".xml", ".yaml", ".yml", ".env", ".config"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	// Also check bare API paths
	return strings.Contains(lower, "/api/") || strings.Contains(lower, "/config")
}
