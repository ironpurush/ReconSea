"""
ReconSea - Core Data Models
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid


def new_id() -> str:
    return str(uuid.uuid4())[:8]


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


@dataclass
class ScanConfig:
    target: str
    scan_id: str = field(default_factory=new_id)
    engagement_name: str = ""
    notes: str = ""
    modules: List[str] = field(default_factory=lambda: [
        "surface_discovery", "live_hosts", "tech_fingerprint",
        "path_discovery", "crawl", "parameters", "js_intelligence"
    ])
    created_at: str = field(default_factory=now_iso)
    status: str = "pending"


@dataclass
class Subdomain:
    host: str
    source: str
    ip: Optional[str] = None
    is_live: Optional[bool] = None
    timestamp: str = field(default_factory=now_iso)
    tags: List[str] = field(default_factory=list)


@dataclass
class LiveHost:
    url: str
    host: str
    status_code: int = 0
    title: str = ""
    content_length: int = 0
    technologies: List[str] = field(default_factory=list)
    scheme: str = "https"
    port: int = 443
    redirect_url: str = ""
    ip: str = ""
    server: str = ""
    timestamp: str = field(default_factory=now_iso)
    tags: List[str] = field(default_factory=list)


@dataclass
class DiscoveredPath:
    url: str
    path: str
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    interesting: bool = False
    severity: str = "info"
    reason: str = ""
    timestamp: str = field(default_factory=now_iso)
    tags: List[str] = field(default_factory=list)


@dataclass
class CrawledEndpoint:
    url: str
    source_url: str = ""
    endpoint_type: str = "page"
    method: str = "GET"
    forms: List[Dict] = field(default_factory=list)
    timestamp: str = field(default_factory=now_iso)
    tags: List[str] = field(default_factory=list)


@dataclass
class ParameterizedURL:
    url: str
    host: str
    parameters: List[str] = field(default_factory=list)
    source_url: str = ""
    method: str = "GET"
    timestamp: str = field(default_factory=now_iso)
    tags: List[str] = field(default_factory=list)


@dataclass
class Technology:
    host: str
    url: str
    name: str
    category: str = "unknown"
    version: str = ""
    confidence: str = "medium"
    timestamp: str = field(default_factory=now_iso)


@dataclass
class JSFile:
    url: str
    host: str
    size: int = 0
    timestamp: str = field(default_factory=now_iso)


@dataclass
class SecretFinding:
    url: str
    host: str
    finding_type: str = "unknown"
    pattern: str = ""
    evidence: str = ""
    confidence: str = "low"
    severity: str = "info"
    line_number: int = 0
    timestamp: str = field(default_factory=now_iso)
    tags: List[str] = field(default_factory=list)


@dataclass
class ScanError:
    module: str
    message: str
    timestamp: str = field(default_factory=now_iso)
    recoverable: bool = True


@dataclass
class ScanResult:
    config: ScanConfig
    subdomains: List[Subdomain] = field(default_factory=list)
    live_hosts: List[LiveHost] = field(default_factory=list)
    paths: List[DiscoveredPath] = field(default_factory=list)
    crawled_endpoints: List[CrawledEndpoint] = field(default_factory=list)
    parameters: List[ParameterizedURL] = field(default_factory=list)
    technologies: List[Technology] = field(default_factory=list)
    js_files: List[JSFile] = field(default_factory=list)
    secret_findings: List[SecretFinding] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def stats(self) -> dict:
        return {
            "subdomains": len(self.subdomains),
            "live_hosts": len(self.live_hosts),
            "paths": len(self.paths),
            "crawled_endpoints": len(self.crawled_endpoints),
            "parameters": len(self.parameters),
            "technologies": len(self.technologies),
            "js_files": len(self.js_files),
            "secret_findings": len(self.secret_findings),
            "errors": len(self.errors),
            "interesting_paths": len([p for p in self.paths if p.interesting]),
            "high_severity_secrets": len([s for s in self.secret_findings if s.severity in ("high", "critical")]),
            "live_vs_dead": {
                "2xx": len([h for h in self.live_hosts if 200 <= h.status_code < 300]),
                "3xx": len([h for h in self.live_hosts if 300 <= h.status_code < 400]),
                "4xx": len([h for h in self.live_hosts if 400 <= h.status_code < 500]),
                "5xx": len([h for h in self.live_hosts if 500 <= h.status_code < 600]),
            }
        }


@dataclass
class ProgressEvent:
    scan_id: str
    event_type: str
    module: str = ""
    message: str = ""
    data: Optional[Dict] = None
    progress_pct: int = 0
    timestamp: str = field(default_factory=now_iso)

    def to_sse(self) -> str:
        import json
        payload = {
            "scan_id": self.scan_id,
            "event_type": self.event_type,
            "module": self.module,
            "message": self.message,
            "data": self.data,
            "progress_pct": self.progress_pct,
            "timestamp": self.timestamp,
        }
        return f"data: {json.dumps(payload)}\n\n"
