"""
ReconSea - Filesystem Storage Service
Uses absolute paths so it works correctly on any host (Render, Railway, local)
"""
import json
from pathlib import Path
from typing import Optional, List, Dict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SCANS_DIR = BASE_DIR / "storage" / "scans"
REPORTS_DIR = BASE_DIR / "storage" / "reports"
TMP_DIR = BASE_DIR / "storage" / "tmp"

for _d in [SCANS_DIR, REPORTS_DIR, TMP_DIR]:
    _d.mkdir(parents=True, exist_ok=True)


def save_scan(result) -> None:
    path = SCANS_DIR / f"{result.config.scan_id}.json"
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)


def load_scan(scan_id: str) -> Optional[Dict]:
    path = SCANS_DIR / f"{scan_id}.json"
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def list_scans() -> List[Dict]:
    scans = []
    for p in sorted(SCANS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            with open(p) as f:
                data = json.load(f)
            cfg = data.get("config", {})
            scans.append({
                "scan_id": cfg.get("scan_id", p.stem),
                "target": cfg.get("target", "unknown"),
                "engagement_name": cfg.get("engagement_name", ""),
                "status": cfg.get("status", "unknown"),
                "created_at": cfg.get("created_at", ""),
                "completed_at": data.get("completed_at"),
                "duration_seconds": data.get("duration_seconds", 0),
                "subdomains": len(data.get("subdomains", [])),
                "live_hosts": len(data.get("live_hosts", [])),
                "secrets": len(data.get("secret_findings", [])),
                "modules": cfg.get("modules", []),
            })
        except Exception:
            continue
    return scans


def delete_scan(scan_id: str) -> bool:
    deleted = False
    for path in [
        SCANS_DIR / f"{scan_id}.json",
        REPORTS_DIR / f"{scan_id}.html",
        REPORTS_DIR / f"{scan_id}.json",
        REPORTS_DIR / f"{scan_id}.csv",
    ]:
        if path.exists():
            path.unlink()
            deleted = True
    return deleted


def report_exists(scan_id: str, fmt: str) -> bool:
    return (REPORTS_DIR / f"{scan_id}.{fmt}").exists()


def get_report_path(scan_id: str, fmt: str) -> Path:
    return REPORTS_DIR / f"{scan_id}.{fmt}"


def save_report(scan_id: str, fmt: str, content: str) -> Path:
    path = REPORTS_DIR / f"{scan_id}.{fmt}"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path
