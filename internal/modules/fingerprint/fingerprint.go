package fingerprint

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
)

type techSignature struct {
	Name     string
	Category string
	Headers  map[string]string
	Body     []string
}

var signatures = []techSignature{
	{Name: "WordPress", Category: "CMS", Body: []string{"/wp-content/", "/wp-includes/", "wp-json"}},
	{Name: "Drupal", Category: "CMS", Body: []string{"Drupal", "/sites/all/"}, Headers: map[string]string{"X-Generator": "Drupal"}},
	{Name: "Joomla", Category: "CMS", Body: []string{"/components/com_", "Joomla"}},
	{Name: "Magento", Category: "CMS", Body: []string{"Mage.", "var/cache/magento"}},
	{Name: "Shopify", Category: "CMS", Body: []string{"cdn.shopify.com", "Shopify.theme"}},
	{Name: "Ghost", Category: "CMS", Body: []string{"ghost.io", "content/themes/casper"}},
	{Name: "Next.js", Category: "JS Framework", Body: []string{"__NEXT_DATA__", "/_next/"}},
	{Name: "Nuxt.js", Category: "JS Framework", Body: []string{"__NUXT__", "/_nuxt/"}},
	{Name: "React", Category: "JS Framework", Body: []string{"react-dom", "__react"}},
	{Name: "Vue.js", Category: "JS Framework", Body: []string{"vue.min.js", "Vue.component", "__vue__"}},
	{Name: "Angular", Category: "JS Framework", Body: []string{"ng-version=", "ng-app"}},
	{Name: "Svelte", Category: "JS Framework", Body: []string{"__svelte"}},
	{Name: "Nginx", Category: "Web Server", Headers: map[string]string{"Server": "nginx"}},
	{Name: "Apache", Category: "Web Server", Headers: map[string]string{"Server": "Apache"}},
	{Name: "IIS", Category: "Web Server", Headers: map[string]string{"Server": "Microsoft-IIS"}},
	{Name: "LiteSpeed", Category: "Web Server", Headers: map[string]string{"Server": "LiteSpeed"}},
	{Name: "Caddy", Category: "Web Server", Headers: map[string]string{"Server": "Caddy"}},
	{Name: "PHP", Category: "Language", Headers: map[string]string{"X-Powered-By": "PHP"}},
	{Name: "ASP.NET", Category: "Language", Headers: map[string]string{"X-Powered-By": "ASP.NET"}},
	{Name: "Node.js/Express", Category: "Framework", Headers: map[string]string{"X-Powered-By": "Express"}},
	{Name: "Laravel", Category: "Framework", Body: []string{"laravel_session", "XSRF-TOKEN"}},
	{Name: "Django", Category: "Framework", Body: []string{"csrfmiddlewaretoken", "__admin_media_prefix__"}},
	{Name: "Ruby on Rails", Category: "Framework", Body: []string{"authenticity_token"}},
	{Name: "Cloudflare", Category: "CDN", Headers: map[string]string{"CF-RAY": ""}},
	{Name: "Amazon CloudFront", Category: "CDN", Headers: map[string]string{"X-Amz-Cf-Id": ""}},
	{Name: "Fastly", Category: "CDN", Headers: map[string]string{"X-Served-By": ""}},
	{Name: "Google Analytics", Category: "Analytics", Body: []string{"google-analytics.com", "gtag("}},
	{Name: "jQuery", Category: "JS Library", Body: []string{"jquery.min.js", "jQuery("}},
	{Name: "Bootstrap", Category: "CSS Framework", Body: []string{"bootstrap.min.css", "bootstrap.min.js"}},
	{Name: "Tailwind CSS", Category: "CSS Framework", Body: []string{"tailwind.min.css", "tailwindcss"}},
}

type wafSig struct {
	Name    string
	Vendor  string
	Headers map[string]string
	Body    []string
}

var wafs = []wafSig{
	{Name: "Cloudflare", Vendor: "Cloudflare Inc.", Headers: map[string]string{"CF-RAY": "", "Server": "cloudflare"}},
	{Name: "AWS WAF", Vendor: "Amazon", Body: []string{"AWS WAF blocked"}},
	{Name: "ModSecurity", Vendor: "TrustWave", Headers: map[string]string{"X-Mod-Security-Message": ""}},
	{Name: "Sucuri", Vendor: "GoDaddy", Headers: map[string]string{"X-Sucuri-ID": ""}},
	{Name: "Imperva Incapsula", Vendor: "Imperva", Headers: map[string]string{"X-Iinfo": ""}},
	{Name: "Akamai Kona", Vendor: "Akamai", Body: []string{"Access Denied - Powered by Akamai"}},
	{Name: "F5 BIG-IP ASM", Vendor: "F5 Networks", Headers: map[string]string{"X-WA-Info": ""}},
	{Name: "Barracuda WAF", Vendor: "Barracuda Networks", Body: []string{"barra_counter_session"}},
}

var importantHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"X-XSS-Protection",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
}

// Scan performs web fingerprinting on target.
func Scan(ctx context.Context, target string, opts types.ScanOptions) ([]types.Technology, *types.WAFInfo, []types.SecurityHeader, error) {
	client := utils.NewHTTPClient(opts.Timeout, opts.Proxy)
	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64) ReconSea/1.0"
	}

	ui.Section("Web Fingerprinting")
	ui.Info("Analysing technologies, WAF, and security headers …")

	urls := []string{
		utils.NormalizeTarget(target),
		utils.NormalizeTarget(target) + "/robots.txt",
	}

	var (
		mu         sync.Mutex
		techMap    = make(map[string]types.Technology)
		secHeaders []types.SecurityHeader
		wafInfo    *types.WAFInfo
	)

	for _, u := range urls {
		select {
		case <-ctx.Done():
			break
		default:
		}
		body, status, headers, err := utils.SafeGet(client, u, ua)
		if err != nil || status == 0 {
			continue
		}
		detected := detectTech(body, headers)
		mu.Lock()
		for _, t := range detected {
			if _, exists := techMap[t.Name]; !exists {
				techMap[t.Name] = t
			}
		}
		if wafInfo == nil {
			wafInfo = detectWAF(headers, body)
		}
		sh := analyseSecHeaders(u, headers)
		secHeaders = append(secHeaders, sh)
		mu.Unlock()
	}

	techs := make([]types.Technology, 0, len(techMap))
	for _, t := range techMap {
		techs = append(techs, t)
	}

	ui.Success("Detected %d technologies", len(techs))
	if wafInfo != nil && wafInfo.Detected {
		ui.Warn("WAF detected: %s (%s)", wafInfo.Name, wafInfo.Vendor)
	} else {
		ui.Info("No WAF detected")
	}

	return techs, wafInfo, secHeaders, nil
}

func detectTech(body string, headers http.Header) []types.Technology {
	var results []types.Technology
	for _, sig := range signatures {
		confidence := 0
		for hName, hVal := range sig.Headers {
			got := headers.Get(hName)
			if got != "" && (hVal == "" || strings.Contains(strings.ToLower(got), strings.ToLower(hVal))) {
				confidence += 70
			}
		}
		for _, bStr := range sig.Body {
			if strings.Contains(body, bStr) {
				confidence += 50
				break
			}
		}
		if confidence > 0 {
			if confidence > 100 {
				confidence = 100
			}
			results = append(results, types.Technology{
				Name: sig.Name, Category: sig.Category, Confidence: confidence,
			})
		}
	}
	return results
}

func detectWAF(headers http.Header, body string) *types.WAFInfo {
	for _, w := range wafs {
		for hName, hVal := range w.Headers {
			got := headers.Get(hName)
			if got != "" && (hVal == "" || strings.Contains(strings.ToLower(got), strings.ToLower(hVal))) {
				return &types.WAFInfo{Detected: true, Name: w.Name, Vendor: w.Vendor}
			}
		}
		for _, bStr := range w.Body {
			if strings.Contains(body, bStr) {
				return &types.WAFInfo{Detected: true, Name: w.Name, Vendor: w.Vendor}
			}
		}
	}
	return &types.WAFInfo{Detected: false}
}

func analyseSecHeaders(u string, headers http.Header) types.SecurityHeader {
	present := make(map[string]string)
	var missing []string
	for _, h := range importantHeaders {
		if v := headers.Get(h); v != "" {
			present[h] = v
		} else {
			missing = append(missing, h)
		}
	}
	score := int(float64(len(present)) / float64(len(importantHeaders)) * 100)
	return types.SecurityHeader{URL: u, Present: present, Missing: missing, Score: score, Grade: scoreGrade(score)}
}

func scoreGrade(s int) string {
	switch {
	case s >= 90:
		return "A+"
	case s >= 80:
		return "A"
	case s >= 70:
		return "B"
	case s >= 60:
		return "C"
	case s >= 50:
		return "D"
	default:
		return "F"
	}
}
