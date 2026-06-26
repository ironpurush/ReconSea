"""
ReconSea - Live Host & HTTP Profiling Module
"""
import asyncio
import re
import socket
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Optional
from app.core.models import LiveHost, now_iso

TIMEOUT = 8
UA = "Mozilla/5.0 ReconSea/1.0"

TECH_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
    "Drupal": [r"Drupal", r"sites/all"],
    "Joomla": [r"Joomla!", r"option=com_"],
    "Laravel": [r"laravel_session", r"Laravel"],
    "Django": [r"csrfmiddlewaretoken", r"Django"],
    "React": [r"__REACT", r"_reactRootContainer"],
    "Vue.js": [r"__vue__", r"vue\.min\.js"],
    "Angular": [r"ng-version", r"ng-app"],
    "jQuery": [r"jquery\.min\.js", r"jQuery v"],
    "Bootstrap": [r"bootstrap\.min\.css"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache"],
    "IIS": [r"Microsoft-IIS", r"ASP\.NET"],
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "PHP": [r"\.php", r"X-Powered-By: PHP"],
    "Node.js": [r"X-Powered-By: Express"],
    "Tomcat": [r"Apache Tomcat", r"JSESSIONID"],
    "Shopify": [r"cdn\.shopify\.com"],
    "Spring": [r"SPRING_SECURITY", r"spring"],
}


def detect_technologies(headers: dict, body: str) -> List[str]:
    found = []
    combined = " ".join(str(v) for v in headers.values()) + " " + body[:5000]
    for tech, patterns in TECH_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                found.append(tech)
                break
    return list(set(found))


def extract_title(body: str) -> str:
    m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r'\s+', ' ', m.group(1).strip())[:200]
    return ""


async def probe_url(url: str) -> Optional[LiveHost]:
    loop = asyncio.get_event_loop()

    def _probe():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body_bytes = resp.read(50000)
                body = body_bytes.decode("utf-8", errors="ignore")
                headers = dict(resp.headers)
                return {"status": resp.status, "headers": headers, "body": body,
                        "final_url": resp.url, "content_length": len(body_bytes)}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "headers": dict(e.headers) if e.headers else {},
                    "body": "", "final_url": url, "content_length": 0}
        except Exception:
            return None

    result = await loop.run_in_executor(None, _probe)
    if not result:
        return None

    parsed = urllib.parse.urlparse(url)
    techs = detect_technologies(result["headers"], result["body"])
    title = extract_title(result["body"])
    redirect_url = result["final_url"] if result["final_url"] != url else ""
    ip = ""
    try:
        ip = socket.gethostbyname(parsed.hostname or "")
    except Exception:
        pass

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    server = result["headers"].get("Server", result["headers"].get("server", ""))

    return LiveHost(
        url=url, host=parsed.hostname or url,
        status_code=result["status"], title=title,
        content_length=result["content_length"], technologies=techs,
        scheme=parsed.scheme, port=port, redirect_url=redirect_url,
        ip=ip, server=server,
    )


async def run_live_hosts(subdomains: list, emit_progress=None) -> List[LiveHost]:
    results = []
    semaphore = asyncio.Semaphore(20)
    seen_urls = set()

    urls_to_probe = []
    for sd in subdomains:
        host = sd.host if hasattr(sd, "host") else sd.get("host", "")
        if host:
            urls_to_probe.append(f"https://{host}")
            urls_to_probe.append(f"http://{host}")

    async def probe(url: str):
        async with semaphore:
            if url in seen_urls:
                return
            seen_urls.add(url)
            try:
                lh = await probe_url(url)
                if lh and lh.status_code > 0:
                    results.append(lh)
                    if emit_progress:
                        await emit_progress(f"[{lh.status_code}] {lh.url} - {lh.title or 'no title'}")
            except Exception:
                pass

    await asyncio.gather(*[probe(u) for u in urls_to_probe], return_exceptions=True)
    results.sort(key=lambda x: (x.status_code, x.url))
    return results
