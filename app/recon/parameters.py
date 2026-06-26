"""
ReconSea - Parameter Discovery Module
"""
import re
import urllib.parse
from typing import List, Set
from app.core.models import ParameterizedURL

INTERESTING_PARAMS = {
    "id", "user", "uid", "userid", "user_id", "username", "name", "email",
    "q", "query", "search", "s", "url", "uri", "link", "redirect", "next",
    "return", "goto", "file", "path", "dir", "include", "page", "template",
    "cmd", "exec", "command", "token", "key", "api_key", "apikey", "secret",
    "auth", "password", "callback", "jsonp", "format", "type", "lang",
    "debug", "admin", "action", "sort", "order", "limit", "offset",
    "category", "cat", "tag", "filter", "view", "data", "input",
    "from", "to", "start", "end", "date", "host", "server", "ip", "load", "module",
}


def extract_params(url: str) -> List[str]:
    try:
        parsed = urllib.parse.urlparse(url)
        return list(urllib.parse.parse_qs(parsed.query).keys())
    except Exception:
        return []


async def run_parameter_discovery(crawled_endpoints: list, live_hosts: list, emit_progress=None) -> List[ParameterizedURL]:
    results = []
    seen: Set[str] = set()
    all_urls = []

    for ep in crawled_endpoints:
        url = ep.url if hasattr(ep, "url") else ep.get("url", "")
        src = ep.source_url if hasattr(ep, "source_url") else ep.get("source_url", "")
        if url:
            all_urls.append((url, src))

    for lh in live_hosts:
        url = lh.url if hasattr(lh, "url") else lh.get("url", "")
        if url:
            all_urls.append((url, ""))

    for url, source_url in all_urls:
        params = extract_params(url)
        if not params:
            continue
        parsed = urllib.parse.urlparse(url)
        pattern_key = f"{parsed.netloc}{parsed.path}?{','.join(sorted(params))}"
        if pattern_key in seen:
            continue
        seen.add(pattern_key)

        lower_params = {p.lower() for p in params}
        tags = []
        if lower_params & INTERESTING_PARAMS:
            tags.append("interesting")
        if lower_params & {"redirect", "url", "uri", "next", "return", "goto"}:
            tags.append("open-redirect-candidate")
        if lower_params & {"id", "uid", "user_id", "userid"}:
            tags.append("idor-candidate")
        if lower_params & {"file", "path", "include", "dir", "template", "load"}:
            tags.append("lfi-candidate")
        if lower_params & {"cmd", "exec", "command", "run"}:
            tags.append("rce-candidate")

        results.append(ParameterizedURL(
            url=url, host=parsed.netloc,
            parameters=params, source_url=source_url, tags=tags,
        ))

        if emit_progress and tags:
            await emit_progress(f"Interesting params [{', '.join(params)}]: {url}")

    if emit_progress:
        await emit_progress(f"Found {len(results)} parameterized endpoints")

    results.sort(key=lambda x: (len(x.tags) == 0, -len(x.parameters)))
    return results
