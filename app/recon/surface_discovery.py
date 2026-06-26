"""
ReconSea - Surface Discovery Module
Subdomain enumeration via crt.sh, HackerTarget, and DNS brute-force
"""
import asyncio
import re
import socket
import json
import urllib.request
import urllib.error
from typing import List, Set
from app.core.models import Subdomain, now_iso

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "beta",
    "app", "portal", "shop", "blog", "docs", "support", "help", "status",
    "cdn", "static", "media", "assets", "img", "login", "auth", "dashboard",
    "panel", "cms", "m", "mobile", "secure", "ssl", "vpn", "git", "gitlab",
    "jenkins", "ci", "db", "smtp", "ns1", "ns2", "dns", "internal", "intranet",
    "corp", "office", "dev1", "dev2", "test1", "stage", "uat", "qa", "backup",
    "api1", "api2", "rest", "graphql", "monitoring", "grafana", "kibana",
]


async def resolve_host(hostname: str):
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, socket.gethostbyname, hostname)
        return True, result
    except Exception:
        return False, ""


async def fetch_crt_sh(domain: str) -> Set[str]:
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconSea/1.0"})
        loop = asyncio.get_event_loop()

        def _fetch():
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return resp.read().decode("utf-8")
            except Exception:
                return ""

        raw = await loop.run_in_executor(None, _fetch)
        if raw:
            for entry in json.loads(raw):
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower().lstrip("*.")
                    if line.endswith(f".{domain}") or line == domain:
                        if re.match(r'^[a-zA-Z0-9._-]+$', line):
                            subdomains.add(line)
    except Exception:
        pass
    return subdomains


async def fetch_hackertarget(domain: str) -> Set[str]:
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconSea/1.0"})
        loop = asyncio.get_event_loop()

        def _fetch():
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.read().decode("utf-8")
            except Exception:
                return ""

        raw = await loop.run_in_executor(None, _fetch)
        for line in raw.strip().split("\n"):
            parts = line.split(",")
            if parts:
                host = parts[0].strip().lower()
                if (host.endswith(f".{domain}") or host == domain) and re.match(r'^[a-zA-Z0-9._-]+$', host):
                    subdomains.add(host)
    except Exception:
        pass
    return subdomains


async def brute_force_subdomains(domain: str, emit_progress=None) -> Set[str]:
    found = set()
    semaphore = asyncio.Semaphore(50)

    async def check(sub):
        async with semaphore:
            hostname = f"{sub}.{domain}"
            alive, ip = await resolve_host(hostname)
            if alive:
                found.add(hostname)
                if emit_progress:
                    await emit_progress(f"Found: {hostname} ({ip})")

    await asyncio.gather(*[check(s) for s in COMMON_SUBDOMAINS], return_exceptions=True)
    return found


async def run_surface_discovery(domain: str, emit_progress=None) -> List[Subdomain]:
    all_hosts: dict = {}

    def add(host: str, source: str, ip: str = ""):
        host = host.strip().lower().rstrip(".")
        if not host:
            return
        if host not in all_hosts:
            all_hosts[host] = Subdomain(host=host, source=source, ip=ip or None)
        else:
            existing = all_hosts[host]
            if source not in existing.source:
                existing.source += f", {source}"
            if ip and not existing.ip:
                existing.ip = ip

    if emit_progress:
        await emit_progress("Querying certificate transparency logs...")
    crt_hosts = await fetch_crt_sh(domain)
    for h in crt_hosts:
        add(h, "crt.sh")
    if emit_progress:
        await emit_progress(f"crt.sh: {len(crt_hosts)} hosts found")

    if emit_progress:
        await emit_progress("Querying HackerTarget...")
    ht_hosts = await fetch_hackertarget(domain)
    for h in ht_hosts:
        add(h, "hackertarget")
    if emit_progress:
        await emit_progress(f"HackerTarget: {len(ht_hosts)} hosts found")

    if emit_progress:
        await emit_progress("Running DNS brute-force...")
    bf_hosts = await brute_force_subdomains(domain, emit_progress)
    for h in bf_hosts:
        add(h, "dns-brute")

    # Resolve all
    semaphore = asyncio.Semaphore(30)

    async def resolve(host: str):
        async with semaphore:
            if not all_hosts[host].ip:
                alive, ip = await resolve_host(host)
                all_hosts[host].ip = ip if alive else None
                all_hosts[host].is_live = alive

    await asyncio.gather(*[resolve(h) for h in list(all_hosts)], return_exceptions=True)

    alive, ip = await resolve_host(domain)
    if domain not in all_hosts:
        add(domain, "base-target", ip)
    all_hosts[domain].is_live = alive

    results = list(all_hosts.values())
    results.sort(key=lambda x: x.host)
    return results
