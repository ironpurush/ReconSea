"""
ReconSea - JavaScript Intelligence Module
Discovers JS files and scans for secrets, tokens, API keys, internal endpoints
"""
import asyncio
import re
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Set, Tuple
from app.core.models import JSFile, SecretFinding

TIMEOUT = 10
UA = "Mozilla/5.0 ReconSea/1.0"

SECRET_PATTERNS = [
    {"type": "api_key",       "name": "Generic API Key",      "severity": "high",     "confidence": "medium", "pattern": r'(?i)(?:api[_-]?key|apikey)["\s]*[=:]["\s]*([a-zA-Z0-9_\-]{20,60})'},
    {"type": "api_key",       "name": "Google API Key",       "severity": "high",     "confidence": "high",   "pattern": r'AIza[0-9A-Za-z\-_]{35}'},
    {"type": "token",         "name": "JWT Token",            "severity": "high",     "confidence": "high",   "pattern": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'},
    {"type": "api_key",       "name": "AWS Access Key",       "severity": "critical", "confidence": "high",   "pattern": r'(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}'},
    {"type": "api_key",       "name": "Stripe API Key",       "severity": "critical", "confidence": "high",   "pattern": r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'},
    {"type": "api_key",       "name": "SendGrid API Key",     "severity": "high",     "confidence": "high",   "pattern": r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'},
    {"type": "api_key",       "name": "GitHub Token",         "severity": "high",     "confidence": "high",   "pattern": r'(?:ghp|ghs|gho|ghu|ghr)_[A-Za-z0-9]{36,}'},
    {"type": "api_key",       "name": "Slack Webhook",        "severity": "medium",   "confidence": "high",   "pattern": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'},
    {"type": "api_key",       "name": "Mailchimp API Key",    "severity": "high",     "confidence": "high",   "pattern": r'[0-9a-f]{32}-us[0-9]{1,2}'},
    {"type": "token",         "name": "Bearer Token",         "severity": "high",     "confidence": "medium", "pattern": r'(?i)bearer\s+([a-zA-Z0-9\._\-]{20,200})'},
    {"type": "auth_string",   "name": "Secret Variable",      "severity": "medium",   "confidence": "low",    "pattern": r'(?i)(?:secret|private[_-]?key|client[_-]?secret)["\s]*[=:]["\s]*["\']([a-zA-Z0-9_\-\.]{10,80})["\']'},
    {"type": "bucket",        "name": "AWS S3 Bucket",        "severity": "medium",   "confidence": "high",   "pattern": r's3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9._-]+)'},
    {"type": "bucket",        "name": "GCS Bucket",           "severity": "medium",   "confidence": "high",   "pattern": r'storage\.googleapis\.com/([a-z0-9._-]+)'},
    {"type": "internal_url",  "name": "Internal IP URL",      "severity": "medium",   "confidence": "high",   "pattern": r'https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?'},
    {"type": "internal_url",  "name": "Localhost URL",        "severity": "low",      "confidence": "high",   "pattern": r'https?://(?:localhost|127\.0\.0\.1)(?::\d+)?'},
    {"type": "sensitive_keyword","name":"Debug Mode Flag",    "severity": "low",      "confidence": "medium", "pattern": r'(?i)(?:DEBUG|TESTING)\s*[=:]\s*[Tt]rue'},
]

JS_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)


def mask_secret(text: str) -> str:
    if len(text) <= 20:
        return text[:4] + "***" + text[-3:]
    return text[:12] + "[REDACTED]" + text[-6:]


def extract_js_urls(html: str, base_url: str) -> Set[str]:
    js_urls = set()
    p = urllib.parse.urlparse(base_url)
    origin = f"{p.scheme}://{p.netloc}"
    for m in JS_SRC_RE.finditer(html):
        src = m.group(1).strip()
        if src.startswith("//"):
            src = p.scheme + ":" + src
        elif src.startswith("/"):
            src = origin + src
        elif not src.startswith("http"):
            src = urllib.parse.urljoin(base_url, src)
        sp = urllib.parse.urlparse(src)
        if sp.netloc == p.netloc or not sp.netloc:
            js_urls.add(src)
    return js_urls


def scan_for_secrets(url: str, content: str) -> List[SecretFinding]:
    findings = []
    lines = content.split("\n")
    parsed = urllib.parse.urlparse(url)
    for rule in SECRET_PATTERNS:
        try:
            pattern = re.compile(rule["pattern"])
            for i, line in enumerate(lines[:2000]):
                for match in pattern.finditer(line):
                    evidence = mask_secret(match.group(0)[:200])
                    findings.append(SecretFinding(
                        url=url, host=parsed.netloc,
                        finding_type=rule["type"], pattern=rule["name"],
                        evidence=evidence, confidence=rule["confidence"],
                        severity=rule["severity"], line_number=i + 1,
                    ))
        except re.error:
            continue
    return findings


async def fetch_js(url: str) -> str:
    loop = asyncio.get_event_loop()

    def _fetch():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read(500000).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    return await loop.run_in_executor(None, _fetch)


async def run_js_intelligence(
    live_hosts: list, crawled_endpoints: list, emit_progress=None, max_js_files: int = 30
) -> Tuple[List[JSFile], List[SecretFinding]]:
    js_files = []
    secret_findings = []
    js_urls: Set[str] = set()
    semaphore = asyncio.Semaphore(10)

    for ep in crawled_endpoints:
        url = ep.url if hasattr(ep, "url") else ep.get("url", "")
        ep_type = ep.endpoint_type if hasattr(ep, "endpoint_type") else ep.get("endpoint_type", "")
        if ep_type == "js" and url:
            js_urls.add(url)

    async def discover_from_host(lh):
        url = lh.url if hasattr(lh, "url") else lh.get("url", "")
        status = lh.status_code if hasattr(lh, "status_code") else lh.get("status_code", 0)
        if not url or status not in range(200, 400):
            return
        async with semaphore:
            loop = asyncio.get_event_loop()
            def _f():
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": UA})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        return resp.read(100000).decode("utf-8", errors="ignore"), resp.url
                except Exception:
                    return "", url
            body, final_url = await loop.run_in_executor(None, _f)
            if body:
                js_urls.update(extract_js_urls(body, final_url))

    await asyncio.gather(*[discover_from_host(lh) for lh in live_hosts[:10]], return_exceptions=True)

    if emit_progress:
        await emit_progress(f"Discovered {len(js_urls)} JavaScript files to analyze")

    async def analyze_js(url: str):
        async with semaphore:
            content = await fetch_js(url)
            if not content:
                return
            parsed = urllib.parse.urlparse(url)
            js_files.append(JSFile(url=url, host=parsed.netloc, size=len(content.encode("utf-8"))))
            findings = scan_for_secrets(url, content)
            secret_findings.extend(findings)
            if emit_progress:
                msg = f"⚠ {len(findings)} findings in: {url}" if findings else f"Analyzed: {url}"
                await emit_progress(msg)

    await asyncio.gather(*[analyze_js(u) for u in list(js_urls)[:max_js_files]], return_exceptions=True)

    if emit_progress:
        await emit_progress(f"JS Intelligence complete: {len(js_files)} files, {len(secret_findings)} findings")

    return js_files, secret_findings
