package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "embed"

	"github.com/IronPurush/reconsea/pkg/types"
)

//go:embed templates/report.html
var reportTemplate string

// templateData wraps ScanResult with extra fields for the HTML template.
type templateData struct {
	*types.ScanResult
	Version   string
	Author    string
	Community string
	JSONData  template.JS
}

// Generate renders the HTML report and companion JSON/CSV files.
func Generate(result *types.ScanResult, outputPath string) error {
	// ── Companion JSON ────────────────────────────────────────────────────
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	dir := filepath.Dir(outputPath)
	jsonPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
		return fmt.Errorf("write json: %w", err)
	}

	// ── Template functions ────────────────────────────────────────────────
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"upper": strings.ToUpper,
		"join":  strings.Join,
		"not": func(b bool) bool { return !b },
		"statusBadge": func(s string) template.HTML {
			switch s {
			case "live":
				return `<span class="badge badge-low">Live</span>`
			case "dead":
				return `<span class="badge bg-secondary">Dead</span>`
			case "wildcard":
				return `<span class="badge badge-medium">Wildcard</span>`
			default:
				return template.HTML(`<span class="badge bg-secondary">` + s + `</span>`)
			}
		},
		"scBadge": func(code int) template.HTML {
			class := "text-muted"
			switch {
			case code >= 200 && code < 300:
				class = "sc-2xx"
			case code >= 300 && code < 400:
				class = "sc-3xx"
			case code >= 400 && code < 500:
				class = "sc-4xx"
			case code >= 500:
				class = "sc-5xx"
			}
			return template.HTML(fmt.Sprintf(`<span class="%s fw-semibold">%d</span>`, class, code))
		},
		"typeBadge": func(t string) template.HTML {
			color := "bg-primary"
			switch t {
			case "POST":
				color = "bg-warning text-dark"
			case "JSON":
				color = "bg-info text-dark"
			}
			return template.HTML(fmt.Sprintf(`<span class="badge %s">%s</span>`, color, t))
		},
		"severityColor": func(sev string) string {
			switch strings.ToLower(sev) {
			case "critical":
				return "#ef4444"
			case "high":
				return "#f97316"
			case "medium":
				return "#f59e0b"
			default:
				return "#10b981"
			}
		},
		"now": func() string { return time.Now().Format("2006-01-02 15:04:05 UTC") },
	}

	// ── Render ────────────────────────────────────────────────────────────
	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	data := templateData{
		ScanResult: result,
		Version:    types.Version,
		Author:     types.Author,
		Community:  types.Community,
		JSONData:   template.JS(jsonBytes),
	}

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	// ── Sub-reports ───────────────────────────────────────────────────────
	writeJSON(filepath.Join(dir, "assets.json"), map[string]interface{}{
		"subdomains": result.Subdomains,
		"live_hosts": result.LiveHosts,
	})
	writeJSON(filepath.Join(dir, "endpoints.json"), result.Endpoints)
	writeJSON(filepath.Join(dir, "secrets.json"), result.Secrets)
	writeJSON(filepath.Join(dir, "dns.json"), result.DNSRecords)

	return nil
}

func writeJSON(path string, v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o644)
}
