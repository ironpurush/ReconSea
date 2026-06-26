"""
ReconSea - Path / Content Discovery Module
"""
import asyncio
import urllib.request
import urllib.error
import urllib.parse
from typing import List
from app.core.models import DiscoveredPath, now_iso

TIMEOUT = 6
UA = "Mozilla/5.0 ReconSea/1.0"

PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator", "/dashboard", "/panel",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/cpanel", "/phpmyadmin",
    "/login", "/login.php", "/signin", "/auth", "/auth/login",
    "/api", "/api/v1", "/api/v2", "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json", "/api-docs",
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.json", "/config.yml", "/configuration.php",
    "/.git", "/.git/HEAD", "/.git/config", "/.svn", "/.htaccess", "/.htpasswd",
    "/web.config", "/wp-config.php", "/database.yml",
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/status", "/health", "/healthz", "/ping",
    "/debug", "/phpinfo.php", "/info.php", "/server-status",
    "/actuator", "/actuator/health", "/actuator/env", "/metrics",
    "/logs", "/uploads", "/upload", "/files",
    "/xmlrpc.php", "/sitemap.xml", "/robots.txt", "/.well-known/security.txt",
    "/wp-json/wp/v2/users", "/composer.json", "/package.json",
]

SEVERITY_MAP = {
    ".env": "high", ".git": "high", "wp-config": "high", "config.php": "high",
    "phpinfo": "medium", "backup": "high", ".sql": "high", ".htpasswd": "high",
    "swagger": "low", "graphql": "low", "actuator/env": "high",
    "actuator": "medium", "admin": "low", "phpmyadmin": "high",
    "debug": "medium", "server-status": "medium", "xmlrpc": "low",
}

INTERESTING_KEYWORDS = [
    "admin", "login", "dashboard", "panel", ".env", ".git", "config",
    "backup", "phpinfo", "debug", "actuator", "swagger", "graphql",
    "phpmyadmin", "cpanel", "wp-admin",
]


def get_severity(path: str):
    path_lower = path.lower()
    for kw, sev in SEVERITY_MAP.items():
        if kw in path_lower:
            return True, sev, f"Sensitive path: {kw}"
    for kw in INTERESTING_KEYWORDS:
        if kw in path_lower:
            return True, "info", f"Interesting: {kw}"
    return False, "info", ""


async def probe_path(base_url: str, path: str):
    loop = asyncio.get_event_loop()
    url = base_url.rstrip("/") + path

    def _probe():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                ct = resp.headers.get("Content-Type", "")
                content = resp.read(1000)
                return resp.status, len(content), ct
        except urllib.error.HTTPError as e:
            return e.code, 0, ""
        except Exception:
            return 0, 0, ""

    return await loop.run_in_executor(None, _probe)


async def run_path_discovery(live_hosts: list, emit_progress=None, max_hosts: int = 10) -> List[DiscoveredPath]:
    results = []
    semaphore = asyncio.Semaphore(25)

    hosts_to_scan = []
    for lh in live_hosts:
        url = lh.url if hasattr(lh, "url") else lh.get("url", "")
        status = lh.status_code if hasattr(lh, "status_code") else lh.get("status_code", 0)
        if url and 200 <= status < 400:
            hosts_to_scan.append(url)
        if len(hosts_to_scan) >= max_hosts:
            break

    if not hosts_to_scan and live_hosts:
        for lh in live_hosts[:max_hosts]:
            url = lh.url if hasattr(lh, "url") else lh.get("url", "")
            if url:
                hosts_to_scan.append(url)

    async def check_path(base_url: str, path: str):
        async with semaphore:
            status, length, ct = await probe_path(base_url, path)
            if status in (0, 404, 400):
                return
            is_interesting, severity, reason = get_severity(path)
            full_url = base_url.rstrip("/") + path
            parsed = urllib.parse.urlparse(base_url)
            dp = DiscoveredPath(
                url=full_url, path=path, status_code=status,
                content_length=length, content_type=ct,
                interesting=is_interesting or status in (200, 201, 301, 302),
                severity=severity, reason=reason,
            )
            results.append(dp)
            if emit_progress:
                await emit_progress(f"[{status}] {path} on {parsed.netloc}")

    tasks = [check_path(base_url, path) for base_url in hosts_to_scan for path in PATHS]
    await asyncio.gather(*tasks, return_exceptions=True)
    results.sort(key=lambda x: (not x.interesting, x.status_code))
    return results
