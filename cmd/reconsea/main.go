package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/IronPurush/reconsea/internal/dashboard"
	"github.com/IronPurush/reconsea/internal/scanner"
	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "reconsea",
	Short: "ReconSea — Breaking the internet to make it unbreakable",
	Long: `
  ⚓  ReconSea v` + types.Version + `
  Modern reconnaissance automation framework for Ethical Hackers,
  Security Researchers, Red Teamers, and Bug Bounty Hunters.

  By ` + types.Author + `
  ` + types.GitHub,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// ── scan ──────────────────────────────────────────────────────────────────

var (
	scanThreads int
	scanDeep    bool
	scanOutput  string
	scanTimeout int
	scanProxy   string
	scanUA      string
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Run a full reconnaissance scan against a target",
	Example: `  reconsea scan example.com
  reconsea scan example.com --deep
  reconsea scan example.com --threads 100
  reconsea scan example.com --output /tmp/report.html`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		opts := types.ScanOptions{
			Target:    args[0],
			Threads:   scanThreads,
			Deep:      scanDeep,
			Output:    scanOutput,
			Timeout:   scanTimeout,
			Proxy:     scanProxy,
			UserAgent: scanUA,
		}
		return scanner.Run(ctx, opts)
	},
}

// ── dashboard ─────────────────────────────────────────────────────────────

var (
	dashHost string
	dashPort int
)

var dashCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Launch the local web dashboard",
	Example: `  reconsea dashboard
  reconsea dashboard --host 0.0.0.0 --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		cfg := dashboard.Config{
			Host:       dashHost,
			Port:       dashPort,
			ReportsDir: "reports",
		}
		return dashboard.Serve(ctx, cfg)
	},
}

// ── doctor ────────────────────────────────────────────────────────────────

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check dependencies and system health",
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.PrintBanner(types.Version)
		ui.Section("System Health Check")

		checks := []struct {
			name string
			cmd  string
			args []string
		}{
			{"Go runtime", "go", []string{"version"}},
			{"Git", "git", []string{"--version"}},
			{"curl", "curl", []string{"--version"}},
			{"nmap", "nmap", []string{"--version"}},
			{"Python3", "python3", []string{"--version"}},
		}

		allOK := true
		for _, c := range checks {
			out, err := exec.Command(c.cmd, c.args...).CombinedOutput()
			if err != nil {
				ui.Error("%-12s not found", c.name)
				allOK = false
			} else {
				line := firstLine(string(out))
				ui.Success("%-12s %s", c.name, line)
			}
		}

		fmt.Println()
		ui.Result("OS",           runtime.GOOS+"/"+runtime.GOARCH)
		ui.Result("Go version",   runtime.Version())
		ui.Result("ReconSea",     "v"+types.Version)
		ui.SectionEnd()

		if !allOK {
			fmt.Println()
			ui.Warn("Some dependencies are missing. Run: ./scripts/install.sh")
		}
		return nil
	},
}

// ── update ────────────────────────────────────────────────────────────────

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update ReconSea to the latest version",
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.PrintBanner(types.Version)
		ui.Info("Pulling latest version from GitHub …")

		out, err := exec.Command("git", "pull", "origin", "main").CombinedOutput()
		if err != nil {
			ui.Error("git pull failed: %v\n%s", err, string(out))
			return err
		}
		ui.Success("Repository updated")

		ui.Info("Rebuilding binary …")
		out, err = exec.Command("make", "build").CombinedOutput()
		if err != nil {
			ui.Error("Build failed: %v\n%s", err, string(out))
			return err
		}
		ui.Success("ReconSea updated successfully")
		return nil
	},
}

// ── uninstall ─────────────────────────────────────────────────────────────

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove ReconSea from the system",
	RunE: func(cmd *cobra.Command, args []string) error {
		ui.PrintBanner(types.Version)
		ui.Warn("This will remove the ReconSea binary from your PATH.")
		fmt.Print("  Continue? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			ui.Info("Cancelled.")
			return nil
		}
		out, err := exec.Command("bash", "scripts/uninstall.sh").CombinedOutput()
		if err != nil {
			ui.Error("Uninstall failed: %v\n%s", err, string(out))
			return err
		}
		ui.Success("ReconSea uninstalled.")
		return nil
	},
}

// ── version ───────────────────────────────────────────────────────────────

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		ui.PrintBanner(types.Version)
		fmt.Printf("  Version    : %s\n", types.Version)
		fmt.Printf("  Author     : %s\n", types.Author)
		fmt.Printf("  Repository : %s\n", types.GitHub)
		fmt.Printf("  Go version : %s\n", runtime.Version())
		fmt.Printf("  OS/Arch    : %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Println()
	},
}

// ── wiring ────────────────────────────────────────────────────────────────

func init() {
	// scan flags
	scanCmd.Flags().IntVarP(&scanThreads, "threads", "t", 50, "Number of concurrent workers")
	scanCmd.Flags().BoolVarP(&scanDeep, "deep", "d", false, "Enable deep scan mode (more thorough, slower)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output HTML report path (default: reports/<target>/report.html)")
	scanCmd.Flags().IntVar(&scanTimeout, "timeout", 15, "HTTP request timeout in seconds")
	scanCmd.Flags().StringVar(&scanProxy, "proxy", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)")
	scanCmd.Flags().StringVar(&scanUA, "user-agent", "", "Custom User-Agent string")

	// dashboard flags
	dashCmd.Flags().StringVar(&dashHost, "host", "127.0.0.1", "Interface to bind the dashboard")
	dashCmd.Flags().IntVar(&dashPort, "port", 8080, "Port for the dashboard server")

	// register commands
	rootCmd.AddCommand(scanCmd, dashCmd, doctorCmd, updateCmd, uninstallCmd, versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "\n  Error: %v\n\n", err)
		os.Exit(1)
	}
}

func firstLine(s string) string {
	for _, line := range splitLines(s) {
		line = trimSpace(line)
		if line != "" {
			return line
		}
	}
	return s
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
