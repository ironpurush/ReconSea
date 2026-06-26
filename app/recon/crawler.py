"""
ReconSea - Crawl / Endpoint Discovery Module
"""
import asyncio
import re
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Set, Dict
from app.core.models import CrawledEndpoint

TIMEOUT = 8
UA = "Mozilla/5.0 ReconSea/1.0"
MAX_DEPTH = 2
MAX_PAGES = 40

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
SRC_RE = re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)
ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.I)
INPUT_RE = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
FORM_RE = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
JS_PATH_RE = re.compile(r'["\'](/(?:api|v\d|rest|graphql)[^"\']{0,100})["\']')


def classify(url: str) -> str:
    if re.search(r'\.js(\?|$)', url, re.I):
        return "js"
    if re.search(r'/api/|/v\d+/|/rest/|/graphql|\.json$', url, re.I):
        return "api"
    if re.search(r'\.(png|jpg|gif|svg|ico|css|woff|woff2)$', url, re.I):
        return "asset"
    return "page"


def extract_forms(body: str) -> List[Dict]:
    forms = []
    for m in FORM_RE.finditer(body):
        fh = m.group(0)
        am = ACTION_RE.search(fh)
        mm = re.search(r'method=["\']([^"\']+)["\']', fh, re.I)
        inputs = INPUT_RE.findall(fh)
        forms.append({"action": am.group(1) if am else "", "method": (mm.group(1).upper() if mm else "GET"), "inputs": inputs[:10]})
    return forms[:5]


def extract_urls(body: str, base_url: str) -> Set[str]:
    urls = set()
    p = urllib.parse.urlparse(base_url)
    origin = f"{p.scheme}://{p.netloc}"
    for pattern in [HREF_RE, SRC_RE, ACTION_RE]:
        for m in pattern.finditer(body):
            url = m.group(1).strip()
            if url.startswith(("javascript:", "mailto:", "#", "data:")):
                continue
            if url.startswith("//"):
                url = p.scheme + ":" + url
            elif url.startswith("/"):
                url = origin + url
            elif not url.startswith("http"):
                url = urllib.parse.urljoin(base_url, url)
            urls.add(url)
    for m in JS_PATH_RE.finditer(body):
        urls.add(origin + m.group(1))
    return urls


async def fetch_page(url: str):
    loop = asyncio.get_event_loop()

    def _fetch():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read(150000).decode("utf-8", errors="ignore"), dict(resp.headers)
        except Exception:
            return "", {}

    return await loop.run_in_executor(None, _fetch)


async def crawl_host(base_url: str, emit_progress=None) -> List[CrawledEndpoint]:
    results = []
    visited: Set[str] = set()
    queue = [(base_url, 0, "")]
    p = urllib.parse.urlparse(base_url)
    base_domain = p.netloc
    sem = asyncio.Semaphore(8)

    async def process(url: str, depth: int, source: str):
        if url in visited or len(visited) >= MAX_PAGES:
            return []
        visited.add(url)
        async with sem:
            body, headers = await fetch_page(url)
        if not body:
            return []
        ep_type = classify(url)
        forms = extract_forms(body) if ep_type == "page" else []
        results.append(CrawledEndpoint(url=url, source_url=source, endpoint_type=ep_type, forms=forms))
        if emit_progress:
            await emit_progress(f"Crawled [{ep_type}]: {url}")
        if depth >= MAX_DEPTH:
            return []
        child_urls = []
        for new_url in extract_urls(body, url):
            try:
                np = urllib.parse.urlparse(new_url)
                if np.netloc == base_domain and new_url not in visited:
                    child_urls.append((new_url, depth + 1, url))
            except Exception:
                pass
        return child_urls

    while queue and len(visited) < MAX_PAGES:
        batch, queue = queue[:8], queue[8:]
        tasks = [process(u, d, s) for u, d, s in batch]
        child_lists = await asyncio.gather(*tasks, return_exceptions=True)
        for children in child_lists:
            if isinstance(children, list):
                queue.extend(children)

    return results


async def run_crawler(live_hosts: list, emit_progress=None, max_hosts: int = 5) -> List[CrawledEndpoint]:
    results = []
    to_crawl = []
    for lh in live_hosts:
        url = lh.url if hasattr(lh, "url") else lh.get("url", "")
        status = lh.status_code if hasattr(lh, "status_code") else lh.get("status_code", 0)
        if url and 200 <= status < 400:
            to_crawl.append(url)
        if len(to_crawl) >= max_hosts:
            break

    for host_url in to_crawl:
        if emit_progress:
            await emit_progress(f"Starting crawl: {host_url}")
        results.extend(await crawl_host(host_url, emit_progress))

    seen = set()
    deduped = []
    for ep in results:
        if ep.url not in seen:
            seen.add(ep.url)
            deduped.append(ep)
    return deduped
