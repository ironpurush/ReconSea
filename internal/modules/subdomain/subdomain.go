package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
)

// crtEntry is a row returned by crt.sh.
type crtEntry struct {
	NameValue string `json:"name_value"`
}

// knownCDNs maps CNAME suffixes to CDN vendor names.
var knownCDNs = map[string]string{
	"cloudfront.net":        "Amazon CloudFront",
	"azureedge.net":         "Azure CDN",
	"akamaiedge.net":        "Akamai",
	"akamaized.net":         "Akamai",
	"fastly.net":            "Fastly",
	"cdnjs.cloudflare.com":  "Cloudflare",
	"cloudflare.net":        "Cloudflare",
	"cdn.jsdelivr.net":      "jsDelivr",
	"r.cloudfront.net":      "Amazon CloudFront",
	"trafficmanager.net":    "Azure Traffic Manager",
	"googleplex.com":        "Google",
	"ghs.googlehosted.com":  "Google Sites",
}

// Scan discovers subdomains for the given base domain.
func Scan(ctx context.Context, target string, opts types.ScanOptions) ([]types.Subdomain, error) {
	domain := utils.ExtractHostname(utils.NormalizeTarget(target))

	ui.Section("Asset Discovery")
	ui.Info("Target domain: %s", domain)

	// Phase 1: certificate transparency
	ui.Info("Querying certificate transparency logs …")
	ctNames, err := queryCRT(ctx, domain)
	if err != nil {
		ui.Warn("CT log query failed: %v", err)
	}
	ui.Success("CT logs returned %d names", len(ctNames))

	// Phase 2: DNS brute-force
	ui.Info("Starting DNS brute-force (%d workers) …", opts.Threads)
	wordlist := commonSubdomains()
	bruteNames := dnsbrute(ctx, domain, wordlist, opts.Threads)
	ui.Success("DNS brute-force found %d names", len(bruteNames))

	// Merge & deduplicate
	allNames := utils.Unique(append(ctNames, bruteNames...))

	// Phase 3: resolve + wildcard detection + CDN
	wildcard := detectWildcard(ctx, domain)
	if wildcard != "" {
		ui.Warn("Wildcard DNS detected: %s → filtering positives", wildcard)
	}

	prog := ui.NewProgress(len(allNames), "Resolving subdomains")
	prog.AddCounter("Live")

	var (
		mu      sync.Mutex
		results []types.Subdomain
	)

	utils.WorkerPool(ctx, allNames, opts.Threads, func(name string) {
		defer prog.Increment(1)
		sub := resolve(ctx, name, domain, wildcard)
		if sub == nil {
			return
		}
		prog.IncrementCounter("Live", 1)
		mu.Lock()
		results = append(results, *sub)
		mu.Unlock()
	})
	prog.Finish()

	ui.Success("Resolved %d live subdomains", len(results))
	return results, nil
}

// queryCRT fetches names from crt.sh for the given domain.
func queryCRT(ctx context.Context, domain string) ([]string, error) {
	u := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	client := &http.Client{Timeout: 30 * time.Second}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "ReconSea/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var names []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if strings.HasSuffix(name, "."+domain) || name == domain {
				if _, ok := seen[name]; !ok {
					seen[name] = struct{}{}
					names = append(names, name)
				}
			}
		}
	}
	return names, nil
}

// detectWildcard resolves a random non-existent subdomain; returns the IP if wildcard exists.
func detectWildcard(ctx context.Context, domain string) string {
	probe := fmt.Sprintf("thissubdomaindoesnotexist123456789.%s", domain)
	ips, _ := net.DefaultResolver.LookupHost(ctx, probe)
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// dnsbrute performs concurrent DNS brute-forcing.
func dnsbrute(ctx context.Context, domain string, words []string, workers int) []string {
	var (
		mu   sync.Mutex
		hits []string
	)
	utils.WorkerPool(ctx, words, workers, func(word string) {
		fqdn := word + "." + domain
		ips, _ := net.DefaultResolver.LookupHost(ctx, fqdn)
		if len(ips) > 0 {
			mu.Lock()
			hits = append(hits, fqdn)
			mu.Unlock()
		}
	})
	return hits
}

// resolve performs a full DNS resolution and CDN check for a name.
func resolve(ctx context.Context, name, domain, wildcardIP string) *types.Subdomain {
	ips, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil || len(ips) == 0 {
		return nil
	}
	// Filter wildcard hits
	if wildcardIP != "" {
		allWild := true
		for _, ip := range ips {
			if ip != wildcardIP {
				allWild = false
				break
			}
		}
		if allWild {
			return nil
		}
	}

	sub := &types.Subdomain{
		Name:   name,
		IPs:    ips,
		Status: "live",
		Source: "discovery",
	}

	// CDN via CNAME
	if cnames, err := net.DefaultResolver.LookupCNAME(ctx, name); err == nil {
		sub.CNAME = cnames
		for suffix, vendor := range knownCDNs {
			if strings.HasSuffix(strings.ToLower(cnames), "."+suffix) {
				sub.CDN = vendor
				break
			}
		}
	}
	_ = domain
	return sub
}

// commonSubdomains returns the embedded brute-force word list.
func commonSubdomains() []string {
	return []string{
		"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
		"smtp", "secure", "vpn", "m", "shop", "ftp", "api", "api2", "admin",
		"administrador", "portal", "developer", "dev", "staging", "test",
		"beta", "alpha", "demo", "cdn", "static", "assets", "media", "img",
		"images", "upload", "uploads", "download", "downloads", "s3", "bucket",
		"backup", "db", "database", "mysql", "redis", "mongo", "app", "apps",
		"login", "auth", "sso", "oauth", "id", "identity", "account", "accounts",
		"support", "help", "helpdesk", "desk", "service", "services",
		"mobile", "ios", "android", "status", "monitor", "monitoring",
		"health", "ping", "internal", "intranet", "corp", "corporate",
		"git", "gitlab", "github", "bitbucket", "svn", "jenkins", "jira",
		"confluence", "wiki", "docs", "documentation", "kb", "knowledge",
		"forum", "forums", "community", "chat", "slack", "meet", "video",
		"vc", "conference", "webinar", "crm", "erp", "salesforce", "hubspot",
		"billing", "pay", "payment", "payments", "checkout", "store",
		"marketplace", "hub", "connect", "integration", "integrations",
		"kafka", "rabbitmq", "elastic", "elasticsearch", "kibana", "grafana",
		"prometheus", "vault", "consul", "terraform", "ansible", "puppet",
		"chef", "k8s", "kubernetes", "docker", "registry", "artifacts",
		"nexus", "artifactory", "sonar", "sonarqube", "sentry",
		"api-gateway", "gateway", "proxy", "edge", "v1", "v2", "v3",
		"ws", "wss", "socket", "websocket", "push", "events", "stream",
		"data", "analytics", "metrics", "logs", "logging", "audit",
		"scheduler", "cron", "worker", "queue", "jobs", "tasks",
		"notification", "notifications", "notify", "webhook", "webhooks",
		"callback", "return", "redirect", "old", "new", "archive",
		"2", "3", "01", "02", "prod", "production", "canary", "live",
	}
}
