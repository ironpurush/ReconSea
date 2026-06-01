package crawler

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
)

var (
	reJSURL   = regexp.MustCompile(`(?:"|')((?:https?://|/)[^"'<>\s]{3,})(?:"|')`)
	reAPIPath = regexp.MustCompile(`(?i)(?:"|')(/(?:api|v\d+|graphql|rest|gql|rpc)[^"'<>\s]*)(?:"|')`)
	reSrcTag  = regexp.MustCompile(`(?i)src=["']([^"']+\.js[^"']*)["']`)

	sensitiveKeywords = []string{
		"/admin", "/dashboard", "/config", "/backup", "/debug",
		"/.env", "/.git", "/api/v1", "/api/v2", "/api/v3",
		"/swagger", "/graphql", "/actuator", "/health", "/metrics",
		"/console", "/phpinfo", "/phpmyadmin", "/wp-login", "/setup",
		"/token", "/secret", "/private", "/internal", "/upload",
	}
)

type queueItem struct {
	rawURL string
	depth  int
}

// Scan crawls the target and returns discovered endpoints.
func Scan(ctx context.Context, target string, opts types.ScanOptions) ([]types.Endpoint, error) {
	client := utils.NewHTTPClient(opts.Timeout, opts.Proxy)
	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64) ReconSea/1.0"
	}

	base := utils.NormalizeTarget(target)
	baseHost := utils.ExtractHostname(base)

	ui.Section("Crawling Engine")
	maxDepth := 2
	if opts.Deep {
		maxDepth = 4
	}
	ui.Info("Crawl depth: %d  |  workers: %d", maxDepth, opts.Threads)

	prog := ui.NewProgress(0, "Crawling")
	prog.AddCounter("Endpoints")
	prog.AddCounter("JS Files")

	var (
		mu      sync.Mutex
		visited = make(map[string]bool)
		results []types.Endpoint
		jsFiles []string
	)

	queue := []queueItem{{rawURL: base, depth: 0}}
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			prog.Finish()
			return dedup(results), nil
		default:
		}

		item := queue[0]
		queue = queue[1:]

		mu.Lock()
		if visited[item.rawURL] || item.depth > maxDepth {
			mu.Unlock()
			continue
		}
		visited[item.rawURL] = true
		mu.Unlock()

		wg.Add(1)
		sem <- struct{}{}
		go func(it queueItem) {
			defer wg.Done()
			defer func() { <-sem }()

			body, status, _, err := utils.SafeGet(client, it.rawURL, ua)
			if err != nil {
				return
			}

			ep := types.Endpoint{
				URL:       it.rawURL,
				Method:    "GET",
				Status:    status,
				Source:    "crawl",
				Sensitive: isSensitive(it.rawURL),
			}
			mu.Lock()
			results = append(results, ep)
			prog.IncrementCounter("Endpoints", 1)

			// Collect JS files
			for _, js := range extractJS(body, it.rawURL) {
				if !visited[js] {
					jsFiles = append(jsFiles, js)
					prog.IncrementCounter("JS Files", 1)
				}
			}

			// Queue child links
			if it.depth < maxDepth {
				for _, link := range utils.ExtractURLsFromBody(body, it.rawURL) {
					if sameHost(link, baseHost) && !visited[link] {
						queue = append(queue, queueItem{rawURL: link, depth: it.depth + 1})
					}
				}
			}
			mu.Unlock()
		}(item)
		wg.Wait()
	}

	// Scan JS for extra endpoints
	ui.Info("Scanning %d JS files for endpoints …", len(jsFiles))
	jsEPs := scanJS(ctx, client, ua, jsFiles, baseHost)
	results = append(results, jsEPs...)

	all := dedup(results)
	prog.Finish()
	ui.Success("Discovered %d unique endpoints", len(all))
	return all, nil
}

func scanJS(ctx context.Context, client *http.Client, ua string, files []string, baseHost string) []types.Endpoint {
	var (
		mu  sync.Mutex
		eps []types.Endpoint
	)
	for _, jsURL := range files {
		select {
		case <-ctx.Done():
			return eps
		default:
		}
		body, _, _, err := utils.SafeGet(client, jsURL, ua)
		if err != nil {
			continue
		}
		for _, m := range reJSURL.FindAllStringSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			u := resolveURL(m[1], baseHost)
			if sameHost(u, baseHost) {
				mu.Lock()
				eps = append(eps, types.Endpoint{URL: u, Method: "GET", Source: "js", Sensitive: isSensitive(u)})
				mu.Unlock()
			}
		}
		for _, m := range reAPIPath.FindAllStringSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			u := "https://" + baseHost + m[1]
			mu.Lock()
			eps = append(eps, types.Endpoint{URL: u, Method: "GET", Source: "js", Sensitive: isSensitive(u)})
			mu.Unlock()
		}
	}
	return eps
}

func extractJS(body, pageURL string) []string {
	var files []string
	for _, m := range reSrcTag.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		src := resolveURL(m[1], utils.ExtractHostname(pageURL))
		if strings.HasSuffix(strings.Split(src, "?")[0], ".js") {
			files = append(files, src)
		}
	}
	return files
}

func resolveURL(raw, baseHost string) string {
	if strings.HasPrefix(raw, "//") {
		return "https:" + raw
	}
	if strings.HasPrefix(raw, "/") {
		return "https://" + baseHost + raw
	}
	return raw
}

func sameHost(rawURL, host string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Hostname() == host
}

func isSensitive(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func dedup(eps []types.Endpoint) []types.Endpoint {
	seen := make(map[string]bool)
	var out []types.Endpoint
	for _, e := range eps {
		if !seen[e.URL] {
			seen[e.URL] = true
			out = append(out, e)
		}
	}
	return out
}
