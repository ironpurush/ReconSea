package ui

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// ─── Colours ────────────────────────────────────────────────────────────────

var (
	cyan    = color.New(color.FgCyan, color.Bold)
	green   = color.New(color.FgGreen, color.Bold)
	yellow  = color.New(color.FgYellow)
	red     = color.New(color.FgRed, color.Bold)
	magenta = color.New(color.FgMagenta, color.Bold)
	white   = color.New(color.FgWhite)
	dim     = color.New(color.Faint)
)

// ─── Banner ─────────────────────────────────────────────────────────────────

// PrintBanner prints the startup banner.
func PrintBanner(version string) {
	banner := `
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗███████╗ █████╗ 
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗█████╗  ███████║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██╔══╝  ██╔══██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝`

	cyan.Println(banner)
	fmt.Println()
	magenta.Printf("  ⚓  Breaking the internet to make it unbreakable\n")
	dim.Printf("  v%s  |  By Sagar Jondhale (IronPurush)  |  Bug Bounty & Red Team Toolkit\n", version)
	fmt.Println()
	fmt.Println(strings.Repeat("─", 72))
	fmt.Println()
}

// ─── Progress ────────────────────────────────────────────────────────────────

// Progress is a thread-safe, animated terminal progress tracker.
type Progress struct {
	mu          sync.Mutex
	out         io.Writer
	total       int
	current     int64
	task        string
	startTime   time.Time
	counters    map[string]*int64
	width       int
	stopCh      chan struct{}
	stopped     bool
}

// NewProgress creates a new Progress display.
func NewProgress(total int, task string) *Progress {
	p := &Progress{
		out:       os.Stdout,
		total:     total,
		task:      task,
		startTime: time.Now(),
		counters:  make(map[string]*int64),
		width:     40,
		stopCh:    make(chan struct{}),
	}
	go p.render()
	return p
}

// AddCounter registers a named counter displayed alongside the bar.
func (p *Progress) AddCounter(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var v int64
	p.counters[name] = &v
}

// Increment increments the main progress by n.
func (p *Progress) Increment(n int) {
	atomic.AddInt64(&p.current, int64(n))
}

// IncrementCounter increments a named counter by n.
func (p *Progress) IncrementCounter(name string, n int) {
	p.mu.Lock()
	ptr, ok := p.counters[name]
	p.mu.Unlock()
	if ok {
		atomic.AddInt64(ptr, int64(n))
	}
}

// SetTask updates the current task label.
func (p *Progress) SetTask(task string) {
	p.mu.Lock()
	p.task = task
	p.mu.Unlock()
}

// Finish stops the progress display and prints a final line.
func (p *Progress) Finish() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	close(p.stopCh)
	p.mu.Unlock()
	// Final render
	p.draw()
	fmt.Fprintln(p.out)
}

func (p *Progress) render() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.draw()
		}
	}
}

func (p *Progress) draw() {
	p.mu.Lock()
	task := p.task
	counters := make(map[string]int64, len(p.counters))
	for k, v := range p.counters {
		counters[k] = atomic.LoadInt64(v)
	}
	p.mu.Unlock()

	cur := atomic.LoadInt64(&p.current)
	pct := 0.0
	if p.total > 0 {
		pct = math.Min(float64(cur)/float64(p.total)*100, 100)
	}

	filled := int(pct / 100 * float64(p.width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)

	elapsed := time.Since(p.startTime)
	var eta string
	if pct > 0 && pct < 100 {
		remaining := time.Duration(float64(elapsed) / pct * (100 - pct))
		eta = fmt.Sprintf(" ETA %s", remaining.Round(time.Second))
	}

	// Build counter string
	var counterParts []string
	for name, val := range counters {
		counterParts = append(counterParts, fmt.Sprintf("%s: %d", name, val))
	}
	counterStr := ""
	if len(counterParts) > 0 {
		counterStr = "  " + strings.Join(counterParts, "  |  ")
	}

	line := fmt.Sprintf("\r  \033[36m[%s]\033[0m \033[1m%.0f%%\033[0m  %s%s%s          ",
		bar, pct, task, eta, counterStr)
	fmt.Fprint(p.out, line)
}

// ─── Logging Helpers ─────────────────────────────────────────────────────────

func Info(format string, a ...interface{}) {
	fmt.Printf("  \033[36m[*]\033[0m "+format+"\n", a...)
}

func Success(format string, a ...interface{}) {
	green.Printf("  [+] "+format+"\n", a...)
}

func Warn(format string, a ...interface{}) {
	yellow.Printf("  [!] "+format+"\n", a...)
}

func Error(format string, a ...interface{}) {
	red.Printf("  [✗] "+format+"\n", a...)
}

func Section(title string) {
	fmt.Println()
	cyan.Printf("  ┌─ %s ", title)
	fmt.Println(strings.Repeat("─", max(0, 58-len(title))))
}

func Result(label, value string) {
	fmt.Printf("  │  %-24s %s\n", label+":", value)
}

func SectionEnd() {
	fmt.Println("  └" + strings.Repeat("─", 61))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
