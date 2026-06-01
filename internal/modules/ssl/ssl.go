package ssl

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/IronPurush/reconsea/internal/ui"
	"github.com/IronPurush/reconsea/pkg/types"
	"github.com/IronPurush/reconsea/pkg/utils"
)

// Scan performs TLS analysis on the target and returns SSLInfo.
func Scan(ctx context.Context, target string, opts types.ScanOptions) (*types.SSLInfo, []types.Finding, error) {
	host := utils.ExtractHostname(utils.NormalizeTarget(target))
	addr := host + ":443"

	ui.Section("SSL/TLS Analysis")
	ui.Info("Analysing TLS configuration for %s …", host)

	dialer := tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 — intentional for cert inspection
			MinVersion:         tls.VersionSSL30,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		ui.Warn("TLS connection failed: %v", err)
		return nil, nil, err
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, nil, fmt.Errorf("no peer certificates returned")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(cert.NotAfter)

	info := &types.SSLInfo{
		Domain:    host,
		ValidFrom: cert.NotBefore,
		ValidTo:   cert.NotAfter,
		Issuer:    cert.Issuer.CommonName,
		Subject:   cert.Subject.CommonName,
		Version:   state.Version,
		DNSNames:  cert.DNSNames,
		IsExpired: isExpired,
		DaysLeft:  daysLeft,
		Protocol:  tlsVersionName(state.Version),
		Grade:     grade(state),
	}

	findings := analyseFindings(info, state)
	ui.Success("TLS grade: %s  |  Expires: %s (%d days)", info.Grade, cert.NotAfter.Format("2006-01-02"), daysLeft)

	return info, findings, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

func grade(state tls.ConnectionState) string {
	// TLS 1.3 = A+, TLS 1.2 = A, TLS 1.1 = B, TLS 1.0 = C
	switch state.Version {
	case tls.VersionTLS13:
		return "A+"
	case tls.VersionTLS12:
		return "A"
	case tls.VersionTLS11:
		return "B"
	case tls.VersionTLS10:
		return "C"
	default:
		return "F"
	}
}

func analyseFindings(info *types.SSLInfo, state tls.ConnectionState) []types.Finding {
	var findings []types.Finding

	if info.IsExpired {
		findings = append(findings, types.Finding{
			Title:       "SSL Certificate Expired",
			Severity:    "critical",
			Description: fmt.Sprintf("The SSL certificate for %s expired on %s.", info.Domain, info.ValidTo.Format("2006-01-02")),
			Type:        "ssl",
		})
	} else if info.DaysLeft <= 30 {
		sev := "high"
		if info.DaysLeft <= 7 {
			sev = "critical"
		}
		findings = append(findings, types.Finding{
			Title:       "SSL Certificate Expiring Soon",
			Severity:    sev,
			Description: fmt.Sprintf("SSL certificate expires in %d days (%s).", info.DaysLeft, info.ValidTo.Format("2006-01-02")),
			Type:        "ssl",
		})
	}

	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		findings = append(findings, types.Finding{
			Title:       "Outdated TLS Version",
			Severity:    "high",
			Description: fmt.Sprintf("Server supports deprecated TLS version: %s. Upgrade to TLS 1.2 or 1.3.", info.Protocol),
			Type:        "ssl",
		})
	}

	// Check for wildcard cert
	for _, name := range info.DNSNames {
		if strings.HasPrefix(name, "*.") {
			findings = append(findings, types.Finding{
				Title:       "Wildcard SSL Certificate",
				Severity:    "low",
				Description: fmt.Sprintf("Wildcard certificate found: %s. Compromise of the private key affects all subdomains.", name),
				Type:        "ssl",
			})
			break
		}
	}

	return findings
}
