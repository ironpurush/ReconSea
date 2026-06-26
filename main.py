"""
ReconSea - Navigate the Attack Surface
Created by Sagar Jondhale aka IronPurush
"""
import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

# Always ensure storage dirs exist before anything else
BASE_DIR = Path(__file__).resolve().parent
for d in ["storage/scans", "storage/reports", "storage/tmp"]:
    (BASE_DIR / d).mkdir(parents=True, exist_ok=True)

from app.api import scan_routes, report_routes, history_routes

app = FastAPI(
    title="ReconSea",
    description="Navigate the Attack Surface",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.mount(
    "/storage/reports",
    StaticFiles(directory=str(BASE_DIR / "storage" / "reports"), html=False),
    name="reports",
)

# API routers
app.include_router(scan_routes.router, prefix="/api")
app.include_router(report_routes.router, prefix="/api")
app.include_router(history_routes.router, prefix="/api")

# Templates
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_view(request: Request, scan_id: str):
    return templates.TemplateResponse("scan.html", {"request": request, "scan_id": scan_id})


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})


@app.get("/report/{scan_id}")
async def report_redirect(scan_id: str):
    return RedirectResponse(url=f"/api/report/{scan_id}/html")


@app.get("/health")
async def health():
    return {"status": "ok", "app": "ReconSea"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
