package scanner

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/IronPurush/reconsea/internal/modules/crawler"
	"github.com/IronPurush/reconsea/internal/modules/dirbuster"
	"github.com/IronPurush/reconsea/internal/modules/dns"
	"github.com/IronPurush/reconsea/internal/modules/fingerprint"
	"github.com/IronPurush/reconsea/internal/modules/params"
	"github.com/IronPurush/reconsea/internal/modules/secrets"
	"github.com/IronPurush/reconsea/internal/modules/ssl"
	"github.com/IronPurush/reconsea/internal/modules/subdomain"
	"github.com/IronPurush/reconsea/internal/report"
	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
)

// Run executes the full ReconSea scan pipeline.
func Run(ctx context.Context, opts types.ScanOptions) error {
	start := time.Now()
	if opts.Threads <= 0 {
		opts.Threads = 50
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15
	}

	target := utils.NormalizeTarget(opts.Target)
	host := utils.ExtractHostname(target)

	ui.PrintBanner(types.Version)
	ui.Info("Target   : %s", target)
	ui.Info("Threads  : %d", opts.Threads)
	ui.Info("Deep     : %v", opts.Deep)
	ui.Info("Started  : %s", start.Format("2006-01-02 15:04:05"))
	fmt.Println()

	result := &types.ScanResult{
		Target:    host,
		StartTime: start,
	}

	// ── Phase 1: Asset Discovery ──────────────────────────────────────────
	subs, err := subdomain.Scan(ctx, target, opts)
	if err != nil {
		ui.Warn("Subdomain module error: %v", err)
	}
	result.Subdomains = subs
	result.LiveHosts = probeLiveHosts(ctx, subs, target, opts)

	// ── Phase 2: Fingerprinting + SSL (parallel) ──────────────────────────
	var (
		wg         sync.WaitGroup
		fpTechs    []types.Technology
		fpWAF      *types.WAFInfo
		fpSecHdrs  []types.SecurityHeader
		sslInfo    *types.SSLInfo
		sslFinds   []types.Finding
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		fpTechs, fpWAF, fpSecHdrs, _ = fingerprint.Scan(ctx, target, opts)
	}()
	go func() {
		defer wg.Done()
		sslInfo, sslFinds, _ = ssl.Scan(ctx, target, opts)
	}()
	wg.Wait()

	result.Technologies = fpTechs
	result.WAF = fpWAF
	result.SecHeaders = fpSecHdrs
	result.SSL = sslInfo

	// ── Phase 3: Crawl + Directory (parallel) ─────────────────────────────
	var (
		endpoints []types.Endpoint
		dirs      []types.Directory
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		endpoints, _ = crawler.Scan(ctx, target, opts)
	}()
	go func() {
		defer wg.Done()
		dirs, _ = dirbuster.Scan(ctx, target, opts)
	}()
	wg.Wait()
	result.Endpoints = endpoints
	result.Directories = dirs

	// ── Phase 4: Parameters + Secrets (parallel) ──────────────────────────
	var (
		parameters  []types.Parameter
		secretsList []types.Secret
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		parameters, _ = params.Scan(ctx, endpoints, opts)
	}()
	go func() {
		defer wg.Done()
		secretsList, _ = secrets.Scan(ctx, endpoints, opts)
	}()
	wg.Wait()
	result.Parameters = parameters
	result.Secrets = secretsList

	// ── Phase 5: DNS ──────────────────────────────────────────────────────
	dnsRecs, dnsFinds, _ := dns.Scan(ctx, target, opts)
	result.DNSRecords = dnsRecs

	// ── Aggregate findings ────────────────────────────────────────────────
	result.Findings = append(result.Findings, sslFinds...)
	result.Findings = append(result.Findings, dnsFinds...)
	result.Findings = append(result.Findings, analyseFindings(result)...)
	sortFindings(result.Findings)

	// ── Stats & risk ──────────────────────────────────────────────────────
	result.Stats = computeStats(result)
	result.RiskScore, result.RiskLevel = computeRisk(result)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(start).Round(time.Second).String()

	// ── Write report ──────────────────────────────────────────────────────
	outputPath := opts.Output
	if outputPath == "" {
		outputPath = filepath.Join("reports", host, "report.html")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	if err := report.Generate(result, outputPath); err != nil {
		return fmt.Errorf("report generation: %w", err)
	}

	printSummary(result, outputPath)
	return nil
}

// probeLiveHosts checks all subdomains for live HTTP services.
func probeLiveHosts(ctx context.Context, subs []types.Subdomain, target string, opts types.ScanOptions) []types.LiveHost {
	ui.Section("Live Host Probing")
	client := utils.NewHTTPClient(opts.Timeout, opts.Proxy)
	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64) ReconSea/1.0"
	}

	urlSet := map[string]bool{target: true}
	for _, sub := range subs {
		for _, scheme := range []string{"https://", "http://"} {
			urlSet[scheme+sub.Name] = true
		}
	}
	var urls []string
	for u := range urlSet {
		urls = append(urls, u)
	}

	prog := ui.NewProgress(len(urls), "Probing hosts")
	prog.AddCounter("Live")

	var (
		mu      sync.Mutex
		results []types.LiveHost
	)

	utils.WorkerPool(ctx, urls, opts.Threads, func(u string) {
		defer prog.Increment(1)
		body, status, headers, err := utils.SafeGet(client, u, ua)
		if err != nil || status == 0 {
			return
		}
		lh := types.LiveHost{
			URL:        u,
			StatusCode: status,
			Title:      utils.ExtractTitle(body),
			Server:     headers.Get("Server"),
			Length:     len(body),
			Headers:    headersToMap(headers),
		}
		if ip, err := utils.ResolveIP(utils.ExtractHostname(u)); err == nil {
			lh.IP = ip
		}
		mu.Lock()
		results = append(results, lh)
		prog.IncrementCounter("Live", 1)
		mu.Unlock()
	})

	prog.Finish()
	ui.Success("Found %d live hosts", len(results))
	return results
}

func headersToMap(h http.Header) map[string]string {
	keys := []string{"Server","X-Powered-By","Content-Type","Content-Security-Policy",
		"X-Frame-Options","Strict-Transport-Security","CF-RAY","X-Amz-Cf-Id"}
	m := make(map[string]string, len(keys))
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			m[k] = v
		}
	}
	return m
}

func analyseFindings(r *types.ScanResult) []types.Finding {
	var f []types.Finding
	for _, ep := range r.Endpoints {
		if ep.Sensitive && ep.Status == 200 {
			f = append(f, types.Finding{
				Title:       "Exposed Sensitive Endpoint",
				Severity:    "high",
				Description: fmt.Sprintf("Sensitive endpoint accessible: %s", ep.URL),
				URL:         ep.URL,
				Type:        "exposure",
			})
		}
	}
	for _, s := range r.Secrets {
		if s.Severity == "critical" {
			f = append(f, types.Finding{
				Title:       fmt.Sprintf("Leaked %s", s.Type),
				Severity:    "critical",
				Description: fmt.Sprintf("Credential found in %s (line %d): %s", s.URL, s.Line, s.Masked),
				URL:         s.URL,
				Type:        "secret",
			})
		}
	}
	for _, sh := range r.SecHeaders {
		if sh.Score < 50 {
			f = append(f, types.Finding{
				Title:       "Poor Security Headers",
				Severity:    "medium",
				Description: fmt.Sprintf("%s is missing: %s", sh.URL, strings.Join(sh.Missing, ", ")),
				URL:         sh.URL,
				Type:        "headers",
			})
		}
	}
	return f
}

func sortFindings(findings []types.Finding) {
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(findings, func(i, j int) bool {
		return order[findings[i].Severity] < order[findings[j].Severity]
	})
}

func computeStats(r *types.ScanResult) types.Statistics {
	s := types.Statistics{
		TotalSubdomains: len(r.Subdomains),
		LiveHosts:       len(r.LiveHosts),
		TotalEndpoints:  len(r.Endpoints),
		TotalParameters: len(r.Parameters),
		TotalSecrets:    len(r.Secrets),
		TotalDirs:       len(r.Directories),
		TotalFindings:   len(r.Findings),
	}
	for _, sec := range r.Secrets {
		if sec.Severity == "critical" {
			s.CriticalSecrets++
		}
	}
	for _, f := range r.Findings {
		switch f.Severity {
		case "high":
			s.HighFindings++
		case "medium":
			s.MediumFindings++
		case "low":
			s.LowFindings++
		}
	}
	return s
}

func computeRisk(r *types.ScanResult) (int, string) {
	score := r.Stats.CriticalSecrets*30 + r.Stats.HighFindings*20 +
		r.Stats.MediumFindings*10 + r.Stats.LowFindings*5
	if score > 100 {
		score = 100
	}
	switch {
	case score >= 75:
		return score, "Critical"
	case score >= 50:
		return score, "High"
	case score >= 25:
		return score, "Medium"
	default:
		return score, "Low"
	}
}

func printSummary(r *types.ScanResult, reportPath string) {
	fmt.Println()
	ui.Section("Scan Complete")
	ui.Result("Target",     r.Target)
	ui.Result("Duration",   r.Duration)
	ui.Result("Risk",       fmt.Sprintf("%s (%d/100)", r.RiskLevel, r.RiskScore))
	ui.Result("Subdomains", fmt.Sprintf("%d", r.Stats.TotalSubdomains))
	ui.Result("Live Hosts", fmt.Sprintf("%d", r.Stats.LiveHosts))
	ui.Result("Endpoints",  fmt.Sprintf("%d", r.Stats.TotalEndpoints))
	ui.Result("Parameters", fmt.Sprintf("%d", r.Stats.TotalParameters))
	ui.Result("Secrets",    fmt.Sprintf("%d (%d critical)", r.Stats.TotalSecrets, r.Stats.CriticalSecrets))
	ui.Result("Directories",fmt.Sprintf("%d", r.Stats.TotalDirs))
	ui.Result("Findings",   fmt.Sprintf("%d", r.Stats.TotalFindings))
	ui.SectionEnd()
	fmt.Println()
	ui.Success("Report → %s", reportPath)
	fmt.Println()
}
