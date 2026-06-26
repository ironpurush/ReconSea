"""
ReconSea - Scan API Routes
"""
import asyncio
import re
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional

from app.core.models import ScanConfig
from app.core.job_manager import job_manager
from app.services.scan_engine import run_scan

router = APIRouter()

VALID_DOMAIN_RE = re.compile(
    r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

ALL_MODULES = [
    "surface_discovery", "live_hosts", "tech_fingerprint",
    "path_discovery", "crawl", "parameters", "js_intelligence"
]


class StartScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None
    engagement_name: Optional[str] = ""
    notes: Optional[str] = ""


def validate_target(target: str) -> str:
    target = target.strip().lower()
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0].strip()
    target = target.split(':')[0].strip()
    if not target:
        raise ValueError("Target cannot be empty")
    if len(target) > 253:
        raise ValueError("Target domain too long")
    if not VALID_DOMAIN_RE.match(target):
        raise ValueError(f"Invalid domain format: '{target}'. Use format: example.com or *.example.com")
    return target


@router.post("/scan/start")
async def start_scan(req: StartScanRequest, background_tasks: BackgroundTasks):
    try:
        target = validate_target(req.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    modules = req.modules if req.modules else ALL_MODULES
    modules = [m for m in modules if m in ALL_MODULES]
    if not modules:
        raise HTTPException(status_code=400, detail="No valid modules selected")

    config = ScanConfig(
        target=target,
        modules=modules,
        engagement_name=req.engagement_name or "",
        notes=req.notes or "",
    )

    job = job_manager.create_job(config)

    async def _run():
        await run_scan(job)

    task = asyncio.create_task(_run())
    job.task = task

    return {"scan_id": config.scan_id, "target": target, "modules": modules, "status": "started"}


@router.get("/scan/{scan_id}/progress")
async def scan_progress_stream(scan_id: str):
    job = job_manager.get_job(scan_id)
    if not job:
        from app.services.storage import load_scan
        data = load_scan(scan_id)
        if data:
            import json
            async def completed_stream():
                payload = json.dumps({"event_type": "scan_complete", "message": "Scan already completed", "progress_pct": 100})
                yield f"data: {payload}\n\n"
            return StreamingResponse(completed_stream(), media_type="text/event-stream")
        raise HTTPException(status_code=404, detail="Scan not found")

    return StreamingResponse(
        job.event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    job = job_manager.get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    job_manager.stop_job(scan_id)
    return {"status": "stopping", "scan_id": scan_id}


@router.get("/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    job = job_manager.get_job(scan_id)
    if job:
        return {"scan_id": scan_id, "status": job.config.status, "target": job.config.target}

    from app.services.storage import load_scan
    data = load_scan(scan_id)
    if data:
        return {
            "scan_id": scan_id,
            "status": data.get("config", {}).get("status", "completed"),
            "target": data.get("config", {}).get("target", ""),
        }
    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/scan/{scan_id}/results")
async def scan_results(scan_id: str):
    from app.services.storage import load_scan
    data = load_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan results not found")
    return data


@router.get("/scan/{scan_id}/stats")
async def scan_stats(scan_id: str):
    from app.services.storage import load_scan
    data = load_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "subdomains": len(data.get("subdomains", [])),
        "live_hosts": len(data.get("live_hosts", [])),
        "paths": len(data.get("paths", [])),
        "parameters": len(data.get("parameters", [])),
        "technologies": len(data.get("technologies", [])),
        "js_files": len(data.get("js_files", [])),
        "secret_findings": len(data.get("secret_findings", [])),
        "crawled_endpoints": len(data.get("crawled_endpoints", [])),
        "errors": len(data.get("errors", [])),
        "target": data.get("config", {}).get("target", ""),
        "status": data.get("config", {}).get("status", ""),
        "duration_seconds": data.get("duration_seconds", 0),
    }
