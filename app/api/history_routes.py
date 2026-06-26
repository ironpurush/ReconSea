"""
ReconSea - History Routes
"""
from fastapi import APIRouter, HTTPException
from app.services.storage import list_scans, delete_scan

router = APIRouter()


@router.get("/history")
async def get_history():
    return {"scans": list_scans()}


@router.delete("/scan/{scan_id}")
async def delete_scan_data(scan_id: str):
    if not delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted", "scan_id": scan_id}
