package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IronPurush/reconsea/internal/ui"
)

// Config holds dashboard server settings.
type Config struct {
	Host       string
	Port       int
	ReportsDir string
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Host:       "127.0.0.1",
		Port:       8080,
		ReportsDir: "reports",
	}
}

// Serve starts the local dashboard HTTP server.
func Serve(ctx context.Context, cfg Config) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	if cfg.Host == "0.0.0.0" {
		ui.Warn("Dashboard is accessible from external networks.")
		ui.Warn("Do not expose this on untrusted networks without additional access controls.")
	}

	mux := http.NewServeMux()

	// Root → redirect to report index
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/reports/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	// Serve the reports directory
	mux.Handle("/reports/", http.StripPrefix("/reports/", http.FileServer(http.Dir(cfg.ReportsDir))))

	// API: list available scan targets
	mux.HandleFunc("/api/targets", func(w http.ResponseWriter, r *http.Request) {
		targets, err := listTargets(cfg.ReportsDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"targets":%s}`, toJSONArray(targets))
	})

	// API: health check
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","time":"%s"}`, time.Now().UTC().Format(time.RFC3339))
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Shutdown on context cancel
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	ui.Section("Dashboard")
	ui.Success("ReconSea dashboard running at http://%s/reports/", addr)
	ui.Info("Press Ctrl+C to stop")
	fmt.Println()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("dashboard server: %w", err)
	}
	return nil
}

// listTargets enumerates subdirectories in the reports folder.
func listTargets(reportsDir string) ([]string, error) {
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var targets []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only include dirs that contain a report.html
		reportFile := filepath.Join(reportsDir, e.Name(), "report.html")
		if _, err := os.Stat(reportFile); err == nil {
			targets = append(targets, e.Name())
		}
	}
	return targets, nil
}

func toJSONArray(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteString("[")
	for i, item := range items {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"`)
		sb.WriteString(strings.ReplaceAll(item, `"`, `\"`))
		sb.WriteString(`"`)
	}
	sb.WriteString("]")
	return sb.String()
}
