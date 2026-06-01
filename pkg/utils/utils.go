package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	reURL     = regexp.MustCompile(`https?://[^\s"'<>)]+`)
	reRelPath = regexp.MustCompile(`(?:href|src|action|data-url|data-src)=["']([^"']+)["']`)
)

// NewHTTPClient returns a pre-configured *http.Client.
func NewHTTPClient(timeoutSec int, proxy string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 100,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeoutSec) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// SafeGet performs an HTTP GET and returns body/status/headers.
func SafeGet(client *http.Client, rawURL, userAgent string) (body string, status int, headers http.Header, err error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	headers = resp.Header
	buf := make([]byte, 2<<20)
	n, _ := resp.Body.Read(buf)
	body = string(buf[:n])
	err = nil
	return
}

// ExtractURLsFromBody returns URLs from an HTML body relative to baseURL.
func ExtractURLsFromBody(body, baseURL string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, u := range reURL.FindAllString(body, -1) {
		u = strings.TrimRight(u, ".,;\"'\\")
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	base, err := url.Parse(baseURL)
	if err == nil {
		for _, m := range reRelPath.FindAllStringSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			raw := m[1]
			if strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") {
				continue
			}
			ref, err := url.Parse(raw)
			if err != nil {
				continue
			}
			abs := base.ResolveReference(ref).String()
			if _, ok := seen[abs]; !ok {
				seen[abs] = struct{}{}
				out = append(out, abs)
			}
		}
	}
	return out
}

// ExtractTitle parses <title> from HTML.
func ExtractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	if m := re.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// NormalizeTarget ensures https:// prefix.
func NormalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
		t = "https://" + t
	}
	return strings.TrimSuffix(t, "/")
}

// StripScheme removes http(s):// from a URL string.
func StripScheme(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return strings.TrimSuffix(u, "/")
}

// ExtractHostname returns the hostname from a URL.
func ExtractHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

// ExtractDomain returns the base domain (last two labels).
func ExtractDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ResolveIP resolves the first IP for a hostname.
func ResolveIP(hostname string) (string, error) {
	ips, err := net.DefaultResolver.LookupHost(context.Background(), hostname)
	if err != nil || len(ips) == 0 {
		return "", err
	}
	return ips[0], nil
}

// Unique deduplicates a string slice preserving order.
func Unique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// WorkerPool runs fn(item) concurrently with up to workers goroutines.
func WorkerPool[T any](ctx context.Context, items []T, workers int, fn func(T)) {
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, item := range items {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(it)
		}(item)
	}
	wg.Wait()
}

// MaskSecret masks all but first/last 4 chars.
func MaskSecret(s string) string {
	r := []rune(s)
	if len(r) <= 8 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:4]) + strings.Repeat("*", len(r)-8) + string(r[len(r)-4:])
}

// IsPrintable returns true if all runes are printable.
func IsPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
