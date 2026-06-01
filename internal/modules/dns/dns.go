package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
	"github.com/miekg/dns"
)

// Scan collects DNS intelligence for the target domain.
func Scan(ctx context.Context, target string, opts types.ScanOptions) ([]types.DNSRecord, []types.Finding, error) {
	domain := utils.ExtractHostname(utils.NormalizeTarget(target))
	ui.Section("DNS Intelligence")
	ui.Info("Collecting DNS records for: %s", domain)

	var (
		records  []types.DNSRecord
		findings []types.Finding
	)

	// Resolve nameservers
	nameservers, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err == nil {
		for _, ns := range nameservers {
			records = append(records, types.DNSRecord{Domain: domain, Type: "NS", Value: ns.Host, TTL: 0})
		}
	}

	// Standard record lookups via miekg/dns
	resolver := "8.8.8.8:53"
	c := new(dns.Client)
	c.Timeout = time.Duration(opts.Timeout) * time.Second

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeCNAME, dns.TypeSOA} {
		recs, err := queryDNS(c, resolver, domain, qtype)
		if err != nil {
			continue
		}
		records = append(records, recs...)
	}

	// SPF analysis
	spfFindings := analyseSPF(records, domain)
	findings = append(findings, spfFindings...)

	// DMARC
	dmarcRecs, _ := queryDNS(c, resolver, "_dmarc."+domain, dns.TypeTXT)
	records = append(records, dmarcRecs...)
	if len(dmarcRecs) == 0 {
		findings = append(findings, types.Finding{
			Title:       "Missing DMARC Record",
			Severity:    "medium",
			Description: fmt.Sprintf("No DMARC record found for %s. This may allow email spoofing.", domain),
			Type:        "dns",
		})
	}

	// WHOIS / ASN via rdap.org
	asnInfo := lookupASN(domain)
	if asnInfo != "" {
		records = append(records, types.DNSRecord{Domain: domain, Type: "ASN", Value: asnInfo})
	}

	// Zone transfer attempt (informational)
	for _, ns := range nameservers {
		if canZoneTransfer(domain, ns.Host+":53") {
			findings = append(findings, types.Finding{
				Title:       "DNS Zone Transfer Allowed",
				Severity:    "high",
				Description: fmt.Sprintf("DNS zone transfer allowed on nameserver: %s", ns.Host),
				Type:        "dns",
			})
		}
	}

	ui.Success("Collected %d DNS records, %d findings", len(records), len(findings))
	return records, findings, nil
}

func queryDNS(c *dns.Client, resolver, domain string, qtype uint16) ([]types.DNSRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, resolver)
	if err != nil {
		return nil, err
	}

	var records []types.DNSRecord
	for _, ans := range r.Answer {
		rec := parseRR(ans, domain)
		if rec != nil {
			records = append(records, *rec)
		}
	}
	return records, nil
}

func parseRR(rr dns.RR, domain string) *types.DNSRecord {
	hdr := rr.Header()
	rec := &types.DNSRecord{
		Domain: domain,
		TTL:    hdr.Ttl,
	}

	switch v := rr.(type) {
	case *dns.A:
		rec.Type, rec.Value = "A", v.A.String()
	case *dns.AAAA:
		rec.Type, rec.Value = "AAAA", v.AAAA.String()
	case *dns.MX:
		rec.Type = "MX"
		rec.Value = fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *dns.TXT:
		rec.Type = "TXT"
		rec.Value = strings.Join(v.Txt, " ")
	case *dns.CNAME:
		rec.Type, rec.Value = "CNAME", v.Target
	case *dns.NS:
		rec.Type, rec.Value = "NS", v.Ns
	case *dns.SOA:
		rec.Type = "SOA"
		rec.Value = fmt.Sprintf("%s %s %d", v.Ns, v.Mbox, v.Serial)
	default:
		return nil
	}
	return rec
}

func analyseSPF(records []types.DNSRecord, domain string) []types.Finding {
	var findings []types.Finding
	hasSPF := false

	for _, r := range records {
		if r.Type == "TXT" && strings.HasPrefix(r.Value, "v=spf1") {
			hasSPF = true
			if strings.Contains(r.Value, "+all") {
				findings = append(findings, types.Finding{
					Title:       "Permissive SPF Record (+all)",
					Severity:    "high",
					Description: "SPF record uses '+all' which allows any server to send email on behalf of this domain.",
					Type:        "dns",
				})
			}
		}
	}

	if !hasSPF {
		findings = append(findings, types.Finding{
			Title:       "Missing SPF Record",
			Severity:    "medium",
			Description: fmt.Sprintf("No SPF record found for %s. This may allow email spoofing.", domain),
			Type:        "dns",
		})
	}
	return findings
}

type rdapResponse struct {
	Handle      string `json:"handle"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Name         string `json:"name"`
	Country      string `json:"country"`
}

func lookupASN(domain string) string {
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return ""
	}

	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://rdap.arin.net/registry/ip/%s", ips[0])
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var data rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	if data.Name != "" {
		return fmt.Sprintf("Name: %s | Country: %s | Range: %s-%s", data.Name, data.Country, data.StartAddress, data.EndAddress)
	}
	return ""
}

func canZoneTransfer(domain, server string) bool {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	ch, err := t.In(m, server)
	if err != nil {
		return false
	}
	for env := range ch {
		if env.Error == nil && len(env.RR) > 0 {
			return true
		}
	}
	return false
}
