"""
ReconSea - Technology Fingerprinting Module
"""
import asyncio
import re
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Dict, Set
from app.core.models import Technology

TIMEOUT = 8
UA = "Mozilla/5.0 ReconSea/1.0"

TECH_RULES = [
    {"name": "WordPress",     "category": "cms",       "patterns": [r"wp-content", r"wp-includes", r"WordPress", r"/wp-json/"]},
    {"name": "Drupal",        "category": "cms",       "patterns": [r"Drupal", r"sites/all", r"drupal\.js"]},
    {"name": "Joomla",        "category": "cms",       "patterns": [r"Joomla!", r"/components/com_", r"option=com_"]},
    {"name": "Ghost",         "category": "cms",       "patterns": [r"ghost\.js", r"ghost/api"]},
    {"name": "Shopify",       "category": "cms",       "patterns": [r"cdn\.shopify\.com", r"myshopify\.com"]},
    {"name": "Magento",       "category": "cms",       "patterns": [r"Mage\.", r"magento", r"/skin/frontend/"]},
    {"name": "Laravel",       "category": "framework", "patterns": [r"laravel_session", r"Laravel"],        "header_patterns": {}},
    {"name": "Django",        "category": "framework", "patterns": [r"csrfmiddlewaretoken"]},
    {"name": "Ruby on Rails", "category": "framework", "patterns": [r"_rails_"],                            "header_patterns": {"X-Powered-By": r"Phusion"}},
    {"name": "Flask",         "category": "framework", "patterns": [r"Werkzeug"]},
    {"name": "Express.js",    "category": "framework", "patterns": [],                                      "header_patterns": {"X-Powered-By": r"Express"}},
    {"name": "Next.js",       "category": "framework", "patterns": [r"__NEXT_DATA__", r"_next/static"]},
    {"name": "Nuxt.js",       "category": "framework", "patterns": [r"__NUXT__", r"_nuxt/"]},
    {"name": "ASP.NET",       "category": "framework", "patterns": [r"__VIEWSTATE", r"aspnetForm"],         "header_patterns": {"X-Powered-By": r"ASP\.NET"}},
    {"name": "Spring Boot",   "category": "framework", "patterns": [r"spring", r"SPRING_SECURITY"]},
    {"name": "Symfony",       "category": "framework", "patterns": [r"symfony", r"sf_redirect"]},
    {"name": "React",         "category": "library",   "patterns": [r"__REACT", r"_reactRootContainer", r"react\.min\.js"]},
    {"name": "Vue.js",        "category": "library",   "patterns": [r"__vue__", r"vue\.min\.js", r"v-bind:"]},
    {"name": "Angular",       "category": "library",   "patterns": [r"ng-version", r"angular\.min\.js", r"ng-app"]},
    {"name": "jQuery",        "category": "library",   "patterns": [r"jquery\.min\.js", r"jQuery v\d"]},
    {"name": "Bootstrap",     "category": "library",   "patterns": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"]},
    {"name": "Nginx",         "category": "server",    "patterns": [],                                      "header_patterns": {"Server": r"nginx"}},
    {"name": "Apache",        "category": "server",    "patterns": [],                                      "header_patterns": {"Server": r"Apache"}},
    {"name": "Microsoft IIS", "category": "server",    "patterns": [],                                      "header_patterns": {"Server": r"Microsoft-IIS"}},
    {"name": "LiteSpeed",     "category": "server",    "patterns": [],                                      "header_patterns": {"Server": r"LiteSpeed"}},
    {"name": "Caddy",         "category": "server",    "patterns": [],                                      "header_patterns": {"Server": r"Caddy"}},
    {"name": "PHP",           "category": "language",  "patterns": [r"\.php"],                              "header_patterns": {"X-Powered-By": r"PHP"}},
    {"name": "Node.js",       "category": "language",  "patterns": [],                                      "header_patterns": {"X-Powered-By": r"Express|Node"}},
    {"name": "Cloudflare",    "category": "cdn",       "patterns": [],                                      "header_patterns": {"Server": r"cloudflare", "CF-Ray": r".+"}},
    {"name": "AWS CloudFront","category": "cdn",       "patterns": [],                                      "header_patterns": {"Via": r"CloudFront"}},
    {"name": "Vercel",        "category": "cdn",       "patterns": [],                                      "header_patterns": {"X-Vercel-Id": r".+"}},
    {"name": "Netlify",       "category": "cdn",       "patterns": [],                                      "header_patterns": {"X-Nf-Request-Id": r".+"}},
    {"name": "Fastly",        "category": "cdn",       "patterns": [],                                      "header_patterns": {"Via": r"varnish"}},
    {"name": "Google Analytics","category": "analytics","patterns": [r"google-analytics\.com", r"gtag\(", r"_gaq\.push"]},
    {"name": "reCAPTCHA",     "category": "security",  "patterns": [r"recaptcha\.net", r"g-recaptcha"]},
    {"name": "Cloudflare Bot","category": "security",  "patterns": [r"cf_clearance", r"__cf_bm"]},
]


def detect_from_response(url: str, headers: Dict[str, str], body: str) -> List[Technology]:
    found = []
    body_sample = body[:10000]
    parsed = urllib.parse.urlparse(url)

    for rule in TECH_RULES:
        matched = False
        confidence = "medium"

        for header_name, pattern in rule.get("header_patterns", {}).items():
            hval = next((v for k, v in headers.items() if k.lower() == header_name.lower()), "")
            if hval and re.search(pattern, hval, re.I):
                matched = True
                confidence = "high"
                break

        if not matched:
            for pattern in rule.get("patterns", []):
                if re.search(pattern, body_sample, re.I):
                    matched = True
                    break

        if matched:
            found.append(Technology(
                host=parsed.netloc, url=url,
                name=rule["name"], category=rule["category"],
                confidence=confidence,
            ))
    return found


async def fingerprint_url(url: str) -> List[Technology]:
    loop = asyncio.get_event_loop()

    def _fetch():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = resp.read(20000).decode("utf-8", errors="ignore")
                return body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            return "", dict(e.headers) if e.headers else {}
        except Exception:
            return "", {}

    body, headers = await loop.run_in_executor(None, _fetch)
    return detect_from_response(url, headers, body)


async def run_tech_fingerprint(live_hosts: list, emit_progress=None, max_hosts: int = 20) -> List[Technology]:
    results = []
    semaphore = asyncio.Semaphore(10)
    seen: Set[str] = set()

    hosts = []
    for lh in live_hosts:
        url = lh.url if hasattr(lh, "url") else lh.get("url", "")
        status = lh.status_code if hasattr(lh, "status_code") else lh.get("status_code", 0)
        if url and 200 <= status < 400 and url not in seen:
            seen.add(url)
            hosts.append(url)
        if len(hosts) >= max_hosts:
            break

    async def fingerprint(url: str):
        async with semaphore:
            techs = await fingerprint_url(url)
            if techs and emit_progress:
                await emit_progress(f"Detected on {url}: {', '.join(t.name for t in techs)}")
            return techs

    tech_lists = await asyncio.gather(*[fingerprint(u) for u in hosts], return_exceptions=True)
    for tl in tech_lists:
        if isinstance(tl, list):
            results.extend(tl)

    deduped = {}
    for t in results:
        key = f"{t.host}:{t.name}"
        if key not in deduped:
            deduped[key] = t
    return list(deduped.values())
