"""
ReconSea - Report Generation Engine
HTML, JSON, and CSV reports
"""
import json
import csv
import io
from datetime import datetime
from typing import Dict
from app.core.models import ScanResult
from app.services.storage import save_report


def generate_all_reports(result: ScanResult):
    generate_json_report(result)
    generate_csv_report(result)
    generate_html_report(result)


def generate_json_report(result: ScanResult):
    data = result.to_dict()
    data["_meta"] = {
        "tool": "ReconSea", "version": "1.0.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "created_by": "Sagar Jondhale aka IronPurush",
        "stats": result.stats,
    }
    save_report(result.config.scan_id, "json", json.dumps(data, indent=2, default=str))


def generate_csv_report(result: ScanResult):
    out = io.StringIO()
    w = csv.writer(out)

    w.writerow(["## SUBDOMAINS"])
    w.writerow(["Host", "IP", "Source", "Is Live"])
    for sd in result.subdomains:
        w.writerow([sd.host, sd.ip or "", sd.source, str(sd.is_live or "")])
    w.writerow([])

    w.writerow(["## LIVE HOSTS"])
    w.writerow(["URL", "Host", "Status Code", "Title", "Server", "Technologies", "IP"])
    for lh in result.live_hosts:
        w.writerow([lh.url, lh.host, lh.status_code, lh.title, lh.server, "; ".join(lh.technologies), lh.ip])
    w.writerow([])

    w.writerow(["## DISCOVERED PATHS"])
    w.writerow(["URL", "Path", "Status Code", "Content Length", "Interesting", "Severity", "Reason"])
    for p in result.paths:
        w.writerow([p.url, p.path, p.status_code, p.content_length, str(p.interesting), p.severity, p.reason])
    w.writerow([])

    w.writerow(["## PARAMETERIZED ENDPOINTS"])
    w.writerow(["URL", "Host", "Parameters", "Method", "Tags"])
    for pu in result.parameters:
        w.writerow([pu.url, pu.host, "; ".join(pu.parameters), pu.method, "; ".join(pu.tags)])
    w.writerow([])

    w.writerow(["## TECHNOLOGIES"])
    w.writerow(["Host", "URL", "Technology", "Category", "Version", "Confidence"])
    for t in result.technologies:
        w.writerow([t.host, t.url, t.name, t.category, t.version, t.confidence])
    w.writerow([])

    w.writerow(["## JS FILES"])
    w.writerow(["URL", "Host", "Size (bytes)"])
    for jf in result.js_files:
        w.writerow([jf.url, jf.host, jf.size])
    w.writerow([])

    w.writerow(["## POTENTIAL FINDINGS"])
    w.writerow(["URL", "Host", "Type", "Pattern", "Evidence (Redacted)", "Severity", "Confidence", "Line"])
    for sf in result.secret_findings:
        w.writerow([sf.url, sf.host, sf.finding_type, sf.pattern, sf.evidence, sf.severity, sf.confidence, sf.line_number])

    save_report(result.config.scan_id, "csv", out.getvalue())


def generate_html_report(result: ScanResult):
    s = result.stats
    target = result.config.target
    scan_id = result.config.scan_id
    scan_date = (result.config.created_at or "")[:10]
    duration = f"{result.duration_seconds:.1f}s" if result.duration_seconds else "N/A"

    def sev_badge(sev):
        colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#f59e0b", "low": "#10b981", "info": "#00d4ff"}
        c = colors.get(sev, "#64748b")
        text_c = "#000" if sev in ("medium", "low", "info") else "#fff"
        return f'<span style="background:{c};color:{text_c};font-size:10px;font-weight:800;padding:2px 7px;border-radius:4px;letter-spacing:.4px">{sev.upper()}</span>'

    def conf_badge(conf):
        colors = {"high": "#10b981", "medium": "#f59e0b", "low": "#64748b"}
        c = colors.get(conf, "#64748b")
        return f'<span style="background:{c}22;color:{c};font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px">{conf.upper()}</span>'

    def sc_badge(code):
        c = int(code) if code else 0
        if 200 <= c < 300:   col, bg = "#10b981", "rgba(16,185,129,.15)"
        elif 300 <= c < 400: col, bg = "#f59e0b", "rgba(245,158,11,.15)"
        elif 400 <= c < 500: col, bg = "#ef4444", "rgba(239,68,68,.15)"
        elif c >= 500:       col, bg = "#a78bfa", "rgba(124,58,237,.15)"
        else:                col, bg = "#64748b", "rgba(100,116,139,.1)"
        return f'<span style="background:{bg};color:{col};font-family:monospace;font-size:11px;font-weight:700;padding:2px 8px;border-radius:5px">{c}</span>'

    def tag_chip(tag):
        cols = {"open-redirect": "#ef4444", "idor": "#f59e0b", "lfi": "#ef4444", "rce": "#ef4444", "interesting": "#00d4ff"}
        k = tag.replace("-candidate", "").split("-")[0]
        c = cols.get(k, "#64748b")
        return f'<span style="background:{c}22;color:{c};font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;margin:1px 2px;display:inline-block">{tag}</span>'

    # Build table rows
    sd_rows = "".join(f"<tr><td class='mono'>{sd.host}</td><td class='mono'>{sd.ip or '—'}</td><td><span class='chip'>{sd.source}</span></td><td>{'🟢' if sd.is_live else ('🔴' if sd.is_live is False else '⚪')}</td></tr>" for sd in result.subdomains[:500])
    lh_rows = "".join(f"<tr><td><a href='{lh.url}' target='_blank' class='url-link'>{lh.url}</a></td><td>{sc_badge(lh.status_code)}</td><td>{lh.title[:60] or '—'}</td><td class='mono' style='font-size:11px'>{lh.server or '—'}</td><td>{''.join(f'<span class=\"chip\">{t}</span>' for t in lh.technologies[:4]) or '—'}</td><td class='mono'>{lh.ip or '—'}</td></tr>" for lh in result.live_hosts[:200])
    path_rows = "".join(f"<tr><td><a href='{p.url}' target='_blank' class='url-link'>{'⭐ ' if p.interesting else ''}{p.path}</a></td><td>{sc_badge(p.status_code)}</td><td class='mono'>{p.content_length}</td><td>{sev_badge(p.severity) if p.interesting else '—'}</td><td style='font-size:12px;color:#64748b'>{p.reason or '—'}</td></tr>" for p in result.paths[:300])
    param_rows = "".join(f"<tr><td><a href='{pu.url}' target='_blank' class='url-link'>{pu.url[:80]}</a></td><td class='mono'>{', '.join(pu.parameters[:8])}</td><td>{''.join(tag_chip(t) for t in pu.tags) or '—'}</td></tr>" for pu in result.parameters[:200])
    tech_seen = set()
    tech_rows_list = []
    for t in result.technologies:
        k = f"{t.host}:{t.name}"
        if k not in tech_seen:
            tech_seen.add(k)
            tech_rows_list.append(f"<tr><td class='mono'>{t.host}</td><td><strong>{t.name}</strong></td><td><span class='chip'>{t.category}</span></td><td>{conf_badge(t.confidence)}</td></tr>")
    tech_rows = "".join(tech_rows_list[:200])
    js_rows = "".join(f"<tr><td><a href='{jf.url}' target='_blank' class='url-link'>{jf.url[-80:]}</a></td><td class='mono'>{jf.host}</td><td>{f'{jf.size/1024:.1f} KB' if jf.size else '—'}</td></tr>" for jf in result.js_files[:100])
    secret_rows = "".join(f"<tr><td><a href='{sf.url}' target='_blank' class='url-link'>{sf.url[-60:]}</a></td><td>{sf.pattern}</td><td>{sev_badge(sf.severity)}</td><td>{conf_badge(sf.confidence)}</td><td class='mono evidence'>{sf.evidence[:100]}</td><td class='mono'>{sf.line_number or '—'}</td></tr>" for sf in result.secret_findings[:100])
    error_rows = "".join(f"<tr><td><span class='chip'>{e.module}</span></td><td>{e.message[:200]}</td><td>{'Recoverable' if e.recoverable else 'Fatal'}</td></tr>" for e in result.errors)

    def section(id_, title, count, table_html, empty_msg="No data"):
        return f"""
        <div class="section" id="{id_}">
          <div class="section-header">
            <div class="section-title">{title}</div>
            <span class="section-count">{count}</span>
          </div>
          {table_html if count else f"<div class='empty-state'>{empty_msg}</div>"}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ReconSea Report — {target}</title>
<style>
:root{{--bg:#080c14;--surface:#0d1320;--card:#111927;--border:#1c2a40;--accent:#00d4ff;--purple:#7c3aed;--text:#e2e8f0;--muted:#64748b;--green:#10b981;--red:#ef4444;--yellow:#f59e0b}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
.mono{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.85em}}
::-webkit-scrollbar{{width:5px;height:5px}}::-webkit-scrollbar-track{{background:var(--surface)}}::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
.report-header{{background:linear-gradient(135deg,#0a0d14,#111827,#0f1a2e);border-bottom:1px solid var(--border);padding:40px 40px 28px;position:relative;overflow:hidden}}
.report-header::before{{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.06),transparent 60%)}}
.logo{{font-size:26px;font-weight:900;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}}
.tagline{{color:var(--muted);font-size:12px;letter-spacing:2px;text-transform:uppercase;margin-bottom:20px}}
.scan-meta{{display:flex;gap:28px;flex-wrap:wrap}}
.meta-label{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:3px}}
.meta-value{{font-size:15px;font-weight:600}}
.meta-value.target{{color:var(--accent);font-size:20px;font-family:monospace}}
nav{{position:sticky;top:0;z-index:100;background:rgba(13,19,32,.95);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:0 40px;display:flex;gap:0;overflow-x:auto}}
nav a{{color:var(--muted);padding:13px 15px;font-size:12.5px;font-weight:500;white-space:nowrap;border-bottom:2px solid transparent;transition:all .2s}}
nav a:hover{{color:var(--text);text-decoration:none;border-bottom-color:var(--accent)}}
.container{{max-width:1400px;margin:0 auto;padding:0 40px 80px}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;padding:28px 0}}
.stat-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px 14px;text-align:center}}
.stat-num{{font-size:30px;font-weight:800;color:var(--accent);font-family:monospace}}
.stat-label{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:4px;font-weight:600}}
.section{{margin-top:44px}}
.section-header{{display:flex;align-items:center;gap:12px;padding-bottom:14px;border-bottom:1px solid var(--border);margin-bottom:20px}}
.section-title{{font-size:19px;font-weight:700}}
.section-count{{background:var(--purple);color:#fff;font-size:11px;font-weight:700;padding:2px 10px;border-radius:999px}}
.table-wrap{{overflow-x:auto;border-radius:10px;border:1px solid var(--border)}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
thead th{{background:var(--surface);padding:10px 14px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap}}
tbody tr{{border-bottom:1px solid var(--border)}}
tbody tr:last-child{{border-bottom:none}}
tbody tr:hover{{background:rgba(255,255,255,.02)}}
tbody td{{padding:10px 14px;vertical-align:top}}
.url-link{{color:var(--accent);font-family:monospace;font-size:11.5px;word-break:break-all}}
.chip{{display:inline-block;background:rgba(255,255,255,.07);color:var(--muted);font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;margin:1px}}
.evidence{{word-break:break-all;max-width:280px;color:var(--muted);font-size:11px}}
.empty-state{{text-align:center;padding:40px;color:var(--muted);font-size:13px}}
.caution{{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.2);border-radius:8px;padding:12px 16px;font-size:12.5px;color:var(--yellow);margin-bottom:16px}}
footer{{border-top:1px solid var(--border);padding:28px 40px;text-align:center;color:var(--muted);font-size:12.5px;background:var(--surface)}}
footer strong{{color:var(--text)}}
@media(max-width:768px){{.report-header,.container{{padding:20px 16px}}nav{{padding:0 16px}}.stats-grid{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
<header class="report-header">
  <div class="logo">ReconSea</div>
  <div class="tagline">Navigate the Attack Surface</div>
  <div class="scan-meta">
    <div><div class="meta-label">Target</div><div class="meta-value target">{target}</div></div>
    <div><div class="meta-label">Scan ID</div><div class="meta-value">{scan_id}</div></div>
    <div><div class="meta-label">Date</div><div class="meta-value">{scan_date}</div></div>
    <div><div class="meta-label">Duration</div><div class="meta-value">{duration}</div></div>
    <div><div class="meta-label">Status</div><div class="meta-value">{result.config.status.upper()}</div></div>
  </div>
</header>
<nav>
  <a href="#summary">Summary</a><a href="#subdomains">Subdomains</a><a href="#live-hosts">Live Hosts</a>
  <a href="#paths">Paths</a><a href="#parameters">Parameters</a><a href="#technology">Technology</a>
  <a href="#js">JavaScript</a><a href="#secrets">Findings</a><a href="#errors">Errors</a>
</nav>
<div class="container">
  <div id="summary">
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-num">{s['subdomains']}</div><div class="stat-label">Subdomains</div></div>
      <div class="stat-card"><div class="stat-num">{s['live_hosts']}</div><div class="stat-label">Live Hosts</div></div>
      <div class="stat-card"><div class="stat-num">{s['paths']}</div><div class="stat-label">Paths Found</div></div>
      <div class="stat-card"><div class="stat-num">{s['interesting_paths']}</div><div class="stat-label">Interesting</div></div>
      <div class="stat-card"><div class="stat-num">{s['crawled_endpoints']}</div><div class="stat-label">Endpoints</div></div>
      <div class="stat-card"><div class="stat-num">{s['parameters']}</div><div class="stat-label">Param URLs</div></div>
      <div class="stat-card"><div class="stat-num">{s['technologies']}</div><div class="stat-label">Tech IDs</div></div>
      <div class="stat-card"><div class="stat-num">{s['js_files']}</div><div class="stat-label">JS Files</div></div>
      <div class="stat-card"><div class="stat-num" style="color:var(--red)">{s['secret_findings']}</div><div class="stat-label">Findings</div></div>
      <div class="stat-card"><div class="stat-num" style="color:var(--red)">{s['high_severity_secrets']}</div><div class="stat-label">High Sev</div></div>
    </div>
  </div>

  {section("subdomains","Attack Surface — Subdomains",len(result.subdomains),"<div class='table-wrap'><table><thead><tr><th>Host</th><th>IP</th><th>Source</th><th>Live</th></tr></thead><tbody>"+sd_rows+"</tbody></table></div>","No subdomains discovered")}
  {section("live-hosts","Live Web Assets",len(result.live_hosts),"<div class='table-wrap'><table><thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Technologies</th><th>IP</th></tr></thead><tbody>"+lh_rows+"</tbody></table></div>","No live hosts found")}
  {section("paths","Discovered Paths",len(result.paths),"<div class='table-wrap'><table><thead><tr><th>Path</th><th>Status</th><th>Length</th><th>Severity</th><th>Reason</th></tr></thead><tbody>"+path_rows+"</tbody></table></div>","No paths discovered")}
  {section("parameters","Parameterized Endpoints",len(result.parameters),"<div class='table-wrap'><table><thead><tr><th>URL</th><th>Parameters</th><th>Tags</th></tr></thead><tbody>"+param_rows+"</tbody></table></div>","No parameterized endpoints found")}
  {section("technology","Technology Stack",len(result.technologies),"<div class='table-wrap'><table><thead><tr><th>Host</th><th>Technology</th><th>Category</th><th>Confidence</th></tr></thead><tbody>"+tech_rows+"</tbody></table></div>","No technologies identified")}
  {section("js","JavaScript Files",len(result.js_files),"<div class='table-wrap'><table><thead><tr><th>URL</th><th>Host</th><th>Size</th></tr></thead><tbody>"+js_rows+"</tbody></table></div>","No JavaScript files analyzed")}

  <div class="section" id="secrets">
    <div class="section-header">
      <div class="section-title">JavaScript Intelligence — Potential Findings</div>
      <span class="section-count">{len(result.secret_findings)}</span>
    </div>
    <div class="caution">⚠ All findings require manual verification. Evidence values are partially redacted. Confidence levels indicate pattern match quality, not confirmed secrets.</div>
    {"<div class='table-wrap'><table><thead><tr><th>Source URL</th><th>Pattern</th><th>Severity</th><th>Confidence</th><th>Evidence (Redacted)</th><th>Line</th></tr></thead><tbody>"+secret_rows+"</tbody></table></div>" if result.secret_findings else "<div class='empty-state'>No potential findings detected</div>"}
  </div>

  {section("errors","Errors / Skipped",len(result.errors),"<div class='table-wrap'><table><thead><tr><th>Module</th><th>Error</th><th>Type</th></tr></thead><tbody>"+error_rows+"</tbody></table></div>","✓ No errors during scan")}
</div>

<footer>
  <strong>ReconSea</strong> — Navigate the Attack Surface &nbsp;|&nbsp;
  Created by <strong>Sagar Jondhale aka IronPurush</strong> &nbsp;|&nbsp;
  Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
  <br><span style="font-size:11px;opacity:.5;margin-top:4px;display:block">For authorized security testing only.</span>
</footer>
</body>
</html>"""

    save_report(result.config.scan_id, "html", html)
