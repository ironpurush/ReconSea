"""
ReconSea - Report API Routes
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from app.services.storage import get_report_path, report_exists, load_scan
from app.reporting.report_generator import generate_all_reports
from app.core.models import (
    ScanResult, ScanConfig, Subdomain, LiveHost, DiscoveredPath,
    CrawledEndpoint, ParameterizedURL, Technology, JSFile, SecretFinding, ScanError
)

router = APIRouter()


def dict_to_scan_result(data: dict) -> ScanResult:
    cfg_data = data.get("config", {})
    cfg = ScanConfig(
        target=cfg_data.get("target", ""),
        scan_id=cfg_data.get("scan_id", ""),
        engagement_name=cfg_data.get("engagement_name", ""),
        notes=cfg_data.get("notes", ""),
        modules=cfg_data.get("modules", []),
        created_at=cfg_data.get("created_at", ""),
        status=cfg_data.get("status", "completed"),
    )

    def make(cls, lst):
        result = []
        for item in lst:
            try:
                result.append(cls(**{k: v for k, v in item.items() if k in cls.__dataclass_fields__}))
            except Exception:
                pass
        return result

    return ScanResult(
        config=cfg,
        subdomains=make(Subdomain, data.get("subdomains", [])),
        live_hosts=make(LiveHost, data.get("live_hosts", [])),
        paths=make(DiscoveredPath, data.get("paths", [])),
        crawled_endpoints=make(CrawledEndpoint, data.get("crawled_endpoints", [])),
        parameters=make(ParameterizedURL, data.get("parameters", [])),
        technologies=make(Technology, data.get("technologies", [])),
        js_files=make(JSFile, data.get("js_files", [])),
        secret_findings=make(SecretFinding, data.get("secret_findings", [])),
        errors=make(ScanError, data.get("errors", [])),
        started_at=data.get("started_at"),
        completed_at=data.get("completed_at"),
        duration_seconds=data.get("duration_seconds", 0),
    )


@router.get("/report/{scan_id}/{fmt}")
async def download_report(scan_id: str, fmt: str):
    if fmt not in ("html", "json", "csv"):
        raise HTTPException(status_code=400, detail="Format must be html, json, or csv")

    if not report_exists(scan_id, fmt):
        data = load_scan(scan_id)
        if not data:
            raise HTTPException(status_code=404, detail="Scan not found")
        result = dict_to_scan_result(data)
        generate_all_reports(result)

    path = get_report_path(scan_id, fmt)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    media_types = {"html": "text/html", "json": "application/json", "csv": "text/csv"}
    filenames = {"html": f"reconsea_{scan_id}.html", "json": f"reconsea_{scan_id}.json", "csv": f"reconsea_{scan_id}.csv"}

    return FileResponse(path=str(path), media_type=media_types[fmt], filename=filenames[fmt])


@router.post("/report/{scan_id}/regenerate")
async def regenerate_reports(scan_id: str):
    data = load_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = dict_to_scan_result(data)
    generate_all_reports(result)
    return {"status": "ok", "scan_id": scan_id}
