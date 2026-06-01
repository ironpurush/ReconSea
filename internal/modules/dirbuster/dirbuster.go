package dirbuster

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
)

// Scan performs directory and file enumeration on the target.
func Scan(ctx context.Context, target string, opts types.ScanOptions) ([]types.Directory, error) {
	ui.Section("Directory Discovery")

	client := utils.NewHTTPClient(opts.Timeout, opts.Proxy)
	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64) ReconSea/1.0"
	}

	base := utils.NormalizeTarget(target)
	wordlist := buildWordlist(opts.Deep)
	ui.Info("Probing %d paths (%d workers) …", len(wordlist), opts.Threads)

	prog := ui.NewProgress(len(wordlist), "Directory scan")
	prog.AddCounter("Found")

	var (
		mu      sync.Mutex
		results []types.Directory
	)

	utils.WorkerPool(ctx, wordlist, opts.Threads, func(path string) {
		defer prog.Increment(1)
		fullURL := fmt.Sprintf("%s/%s", strings.TrimRight(base, "/"), strings.TrimLeft(path, "/"))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", ua)

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if !interestingStatus(resp.StatusCode) {
			return
		}

		buf := make([]byte, 512*1024)
		n, _ := resp.Body.Read(buf)
		body := string(buf[:n])

		dir := types.Directory{
			URL:        fullURL,
			StatusCode: resp.StatusCode,
			Length:     n,
			Title:      utils.ExtractTitle(body),
		}
		mu.Lock()
		results = append(results, dir)
		prog.IncrementCounter("Found", 1)
		mu.Unlock()
	})

	prog.Finish()
	ui.Success("Found %d interesting paths", len(results))
	return results, nil
}

func interestingStatus(code int) bool {
	switch code {
	case 200, 201, 204, 301, 302, 307, 308, 401, 403:
		return true
	}
	return false
}

// buildWordlist returns the directory enumeration wordlist.
// When deep=true a larger set is used.
func buildWordlist(deep bool) []string {
	base := []string{
		// Common directories
		"admin", "administrator", "login", "wp-admin", "wp-login.php",
		"api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
		"dashboard", "console", "panel", "manage", "management",
		"config", "configuration", "settings", "setup", "install",
		"backup", "backups", ".backup", "bkp",
		"upload", "uploads", "files", "file", "media", "assets", "static",
		"images", "img", "css", "js", "fonts",
		"docs", "documentation", "doc", "help", "support",
		"dev", "development", "staging", "test", "demo", "beta",
		"old", "archive", "bak", "tmp", "temp",
		"src", "source", "code", "git", ".git", ".svn", ".hg",
		"health", "status", "ping", "info", "version",
		"metrics", "actuator", "debug", "trace",
		"logs", "log", "error", "errors",
		"user", "users", "account", "accounts", "profile", "profiles",
		"auth", "oauth", "sso", "token", "tokens",
		"secret", "secrets", "private", "internal",
		"search", "query", "filter",
		"sitemap.xml", "robots.txt", "favicon.ico", "crossdomain.xml",
		"phpinfo.php", "info.php", "test.php", "debug.php",
		".env", ".env.local", ".env.production", ".env.backup",
		"web.config", "wp-config.php", "config.php", "database.php",
		"server-status", "server-info",
		"swagger", "swagger-ui", "swagger-ui.html", "swagger.json",
		"openapi.json", "openapi.yaml", "api-docs",
		"phpmyadmin", "pma", "dbadmin", "adminer.php",
		"jenkins", "jira", "confluence", "gitlab", "bitbucket",
		"s3", "bucket", "storage", "cdn", "downloads",
		"checkout", "cart", "payment", "billing",
		"cron", "schedule", "job", "queue", "worker",
		"socket", "ws", "websocket",
	}

	if !deep {
		return base
	}

	extra := []string{
		"api/v4", "api/v5", "api/internal", "api/admin", "api/auth",
		"api/users", "api/products", "api/orders", "api/payments",
		"v1/users", "v2/users", "v1/auth", "v2/auth",
		"backend", "frontend", "service", "services", "microservice",
		"cache", "redis", "memcache", "session", "sessions",
		"db", "database", "mongo", "mysql", "postgres",
		"ssh", "ftp", "sftp", "smtp", "imap",
		"admin/login", "admin/dashboard", "admin/users", "admin/config",
		"administrator/login", "administrator/index.php",
		"wp-content", "wp-includes", "wp-admin/admin-ajax.php",
		"joomla", "drupal", "magento", "shopify", "woocommerce",
		"cgi-bin", "cgi", "scripts", "shell.php", "cmd.php",
		"index.php", "index.html", "index.asp", "index.aspx",
		"default.php", "default.html", "default.asp",
		"main.php", "home.php", "start.php",
		"include", "includes", "inc", "lib", "library", "vendor",
		"composer.json", "package.json", "yarn.lock", "Gemfile",
		"Makefile", "Dockerfile", ".dockerignore", ".gitignore",
		"readme.txt", "readme.md", "README.md", "CHANGELOG.md",
		"LICENSE", "COPYING", "AUTHORS",
		"test/", "tests/", "spec/", "specs/",
		"phpunit.xml", "jest.config.js", ".travis.yml",
		"firebase.json", "vercel.json", "netlify.toml",
	}

	return append(base, extra...)
}
