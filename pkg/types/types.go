package types

import "time"

// Version info
const (
	Version   = "1.0.0"
	Author    = "Sagar Jondhale (IronPurush)"
	Tagline   = "Breaking the internet to make it unbreakable"
	GitHub    = "https://github.com/IronPurush/reconsea"
	Community = "Built for the Ethical Hacking and Bug Bounty Community"
)

// ScanResult is the top-level container for all scan data.
type ScanResult struct {
	Target       string           `json:"target"`
	StartTime    time.Time        `json:"start_time"`
	EndTime      time.Time        `json:"end_time"`
	Duration     string           `json:"duration"`
	Subdomains   []Subdomain      `json:"subdomains"`
	LiveHosts    []LiveHost       `json:"live_hosts"`
	Technologies []Technology     `json:"technologies"`
	SecHeaders   []SecurityHeader `json:"security_headers"`
	WAF          *WAFInfo         `json:"waf"`
	SSL          *SSLInfo         `json:"ssl"`
	Endpoints    []Endpoint       `json:"endpoints"`
	Parameters   []Parameter      `json:"parameters"`
	Secrets      []Secret         `json:"secrets"`
	DNSRecords   []DNSRecord      `json:"dns_records"`
	Directories  []Directory      `json:"directories"`
	Stats        Statistics       `json:"statistics"`
	RiskScore    int              `json:"risk_score"`
	RiskLevel    string           `json:"risk_level"`
	Findings     []Finding        `json:"interesting_findings"`
}

// Subdomain represents a discovered subdomain.
type Subdomain struct {
	Name     string   `json:"name"`
	IPs      []string `json:"ips"`
	Status   string   `json:"status"` // live | dead | wildcard
	CDN      string   `json:"cdn,omitempty"`
	Source   string   `json:"source"`
	CNAME    string   `json:"cname,omitempty"`
}

// LiveHost represents a reachable HTTP(S) endpoint.
type LiveHost struct {
	URL        string            `json:"url"`
	IP         string            `json:"ip"`
	StatusCode int               `json:"status_code"`
	Title      string            `json:"title"`
	Server     string            `json:"server"`
	Length     int               `json:"content_length"`
	Tech       []string          `json:"technologies"`
	Headers    map[string]string `json:"headers"`
}

// Technology represents a detected technology stack item.
type Technology struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category"`
	Confidence int    `json:"confidence"`
}

// SecurityHeader holds per-URL security header analysis.
type SecurityHeader struct {
	URL     string            `json:"url"`
	Present map[string]string `json:"present"`
	Missing []string          `json:"missing"`
	Score   int               `json:"score"`
	Grade   string            `json:"grade"`
}

// WAFInfo describes WAF detection results.
type WAFInfo struct {
	Detected bool   `json:"detected"`
	Name     string `json:"name"`
	Vendor   string `json:"vendor"`
}

// SSLInfo describes SSL/TLS certificate details.
type SSLInfo struct {
	Domain    string    `json:"domain"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	Version   uint16    `json:"tls_version"`
	DNSNames  []string  `json:"dns_names"`
	IsExpired bool      `json:"is_expired"`
	DaysLeft  int       `json:"days_left"`
	Grade     string    `json:"grade"`
	Protocol  string    `json:"protocol"`
}

// Endpoint represents a discovered URL/endpoint.
type Endpoint struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	Status    int    `json:"status"`
	Source    string `json:"source"` // crawl | js | dirb
	Sensitive bool   `json:"sensitive"`
}

// Parameter represents a discovered HTTP parameter.
type Parameter struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Type   string `json:"type"` // GET | POST | JSON
	Source string `json:"source"`
}

// Secret represents a discovered secret/credential.
type Secret struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Masked   string `json:"masked"`
	URL      string `json:"url"`
	Line     int    `json:"line"`
	Severity string `json:"severity"` // critical | high | medium | low
}

// DNSRecord represents a single DNS record.
type DNSRecord struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl"`
}

// Directory represents a discovered path on the target.
type Directory struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Length     int    `json:"content_length"`
	Title      string `json:"title,omitempty"`
}

// Finding represents an interesting security finding.
type Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	URL         string `json:"url,omitempty"`
	Type        string `json:"type"`
}

// Statistics is a scan summary counter set.
type Statistics struct {
	TotalSubdomains int `json:"total_subdomains"`
	LiveHosts       int `json:"live_hosts"`
	TotalEndpoints  int `json:"total_endpoints"`
	TotalParameters int `json:"total_parameters"`
	TotalSecrets    int `json:"total_secrets"`
	TotalDirs       int `json:"total_directories"`
	TotalFindings   int `json:"total_findings"`
	CriticalSecrets int `json:"critical_secrets"`
	HighFindings    int `json:"high_findings"`
	MediumFindings  int `json:"medium_findings"`
	LowFindings     int `json:"low_findings"`
}

// ModuleResult is passed back over a channel by each module goroutine.
type ModuleResult struct {
	Module string
	Data   interface{}
	Err    error
}

// ScanOptions carries all runtime configuration for a scan.
type ScanOptions struct {
	Target    string
	Threads   int
	Deep      bool
	Output    string
	Timeout   int
	Wordlist  string
	UserAgent string
	Proxy     string
	NoColor   bool
	Debug     bool
	ResumeID  string
}
