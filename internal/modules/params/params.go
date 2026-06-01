package params

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
)

var (
	reFormInput = regexp.MustCompile(`(?i)<input[^>]+name=["']([^"']+)["']`)
	reFormSel   = regexp.MustCompile(`(?i)<select[^>]+name=["']([^"']+)["']`)
	reJSONKey   = regexp.MustCompile(`["']([a-zA-Z_][a-zA-Z0-9_]{1,50})["']\s*:`)
)

// Scan extracts GET, POST, and JSON parameters from the crawled endpoint list.
func Scan(ctx context.Context, endpoints []types.Endpoint, opts types.ScanOptions) ([]types.Parameter, error) {
	ui.Section("Parameter Discovery")
	ui.Info("Extracting parameters from %d endpoints …", len(endpoints))

	client := utils.NewHTTPClient(opts.Timeout, opts.Proxy)
	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64) ReconSea/1.0"
	}

	prog := ui.NewProgress(len(endpoints), "Extracting params")
	prog.AddCounter("Params")

	var (
		mu   sync.Mutex
		all  []types.Parameter
		seen = make(map[string]bool)
	)

	addParam := func(p types.Parameter) {
		k := p.URL + "|" + p.Type + "|" + p.Name
		mu.Lock()
		defer mu.Unlock()
		if !seen[k] {
			seen[k] = true
			all = append(all, p)
			prog.IncrementCounter("Params", 1)
		}
	}

	utils.WorkerPool(ctx, endpoints, opts.Threads, func(ep types.Endpoint) {
		defer prog.Increment(1)

		// GET params from URL query string
		if u, err := url.Parse(ep.URL); err == nil {
			for key := range u.Query() {
				addParam(types.Parameter{Name: key, URL: ep.URL, Type: "GET", Source: "url"})
			}
		}

		body, _, _, err := utils.SafeGet(client, ep.URL, ua)
		if err != nil {
			return
		}

		// POST params from HTML forms
		for _, m := range reFormInput.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 {
				addParam(types.Parameter{Name: m[1], URL: ep.URL, Type: "POST", Source: "form"})
			}
		}
		for _, m := range reFormSel.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 {
				addParam(types.Parameter{Name: m[1], URL: ep.URL, Type: "POST", Source: "form"})
			}
		}

		// JSON body keys from API endpoints
		if isAPIURL(ep.URL) {
			for _, m := range reJSONKey.FindAllStringSubmatch(body, -1) {
				if len(m) >= 2 && validJSONKey(m[1]) {
					addParam(types.Parameter{Name: m[1], URL: ep.URL, Type: "JSON", Source: "api"})
				}
			}
		}
	})

	prog.Finish()
	ui.Success("Found %d unique parameters", len(all))
	return all, nil
}

func isAPIURL(u string) bool {
	lower := strings.ToLower(u)
	for _, seg := range []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"} {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

var noiseKeys = map[string]bool{
	"true": true, "false": true, "null": true, "undefined": true,
}

func validJSONKey(k string) bool {
	return !noiseKeys[strings.ToLower(k)] && len(k) >= 2 && len(k) <= 40
}
