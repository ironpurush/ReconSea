"""
ReconSea - Scan Orchestration Engine
"""
import asyncio
import time
from app.core.models import ScanResult, ProgressEvent, ScanError, now_iso
from app.core.job_manager import ScanJob
from app.recon.surface_discovery import run_surface_discovery
from app.recon.live_hosts import run_live_hosts
from app.recon.path_discovery import run_path_discovery
from app.recon.crawler import run_crawler
from app.recon.parameters import run_parameter_discovery
from app.recon.tech_fingerprint import run_tech_fingerprint
from app.recon.js_intelligence import run_js_intelligence
from app.services.storage import save_scan
from app.reporting.report_generator import generate_all_reports

MODULE_WEIGHTS = {
    "surface_discovery": 20,
    "live_hosts":        15,
    "tech_fingerprint":  10,
    "path_discovery":    15,
    "crawl":             15,
    "parameters":        10,
    "js_intelligence":   15,
}
TOTAL_WEIGHT = sum(MODULE_WEIGHTS.values())


async def run_scan(job: ScanJob):
    config = job.config
    result = ScanResult(config=config)
    result.started_at = now_iso()
    start_time = time.time()
    config.status = "running"
    progress_so_far = 0

    async def emit(event_type, module, message, data=None, pct=None):
        if job.stopped:
            return
        p = pct if pct is not None else progress_so_far
        await job.emit(ProgressEvent(
            scan_id=config.scan_id, event_type=event_type,
            module=module, message=message, data=data, progress_pct=p,
        ))

    async def run_module(name, coro):
        nonlocal progress_so_far
        if job.stopped or name not in config.modules:
            return None
        await emit("module_start", name, f"Starting {name.replace('_', ' ').title()}...")
        try:
            data = await coro
            weight = MODULE_WEIGHTS.get(name, 10)
            progress_so_far = min(95, progress_so_far + (weight * 100 // TOTAL_WEIGHT))
            await emit("module_complete", name, f"✓ {name.replace('_', ' ').title()} complete", pct=progress_so_far)
            return data
        except asyncio.CancelledError:
            raise
        except Exception as e:
            result.errors.append(ScanError(module=name, message=str(e)))
            await emit("module_error", name, f"✗ {name} failed: {str(e)[:200]}")
            return None

    try:
        await emit("log", "orchestrator", f"ReconSea scan started: {config.target}")
        await emit("log", "orchestrator", f"Modules: {', '.join(config.modules)}")

        # ── Surface Discovery
        async def _emit(msg):
            await emit("log", "surface_discovery", msg)

        subdomains = await run_module("surface_discovery",
            run_surface_discovery(config.target, _emit))
        if subdomains:
            result.subdomains = subdomains
            await emit("finding", "surface_discovery", f"Found {len(subdomains)} subdomains", {"count": len(subdomains)})

        # Use discovered hosts or base target
        hosts_for_probing = result.subdomains or []
        if not hosts_for_probing:
            from app.core.models import Subdomain
            hosts_for_probing = [Subdomain(host=config.target, source="base-target")]

        # ── Live Hosts
        async def _emit(msg):
            await emit("log", "live_hosts", msg)

        live_hosts = await run_module("live_hosts",
            run_live_hosts(hosts_for_probing, _emit))
        if live_hosts:
            result.live_hosts = live_hosts
            await emit("finding", "live_hosts", f"Found {len(live_hosts)} live web services", {"count": len(live_hosts)})

        # ── Tech Fingerprint
        async def _emit(msg):
            await emit("log", "tech_fingerprint", msg)

        techs = await run_module("tech_fingerprint",
            run_tech_fingerprint(result.live_hosts, _emit))
        if techs:
            result.technologies = techs
            tech_names = list(set(t.name for t in techs))[:8]
            await emit("finding", "tech_fingerprint", f"Identified: {', '.join(tech_names)}", {"count": len(techs)})

        # ── Path Discovery
        async def _emit(msg):
            await emit("log", "path_discovery", msg)

        paths = await run_module("path_discovery",
            run_path_discovery(result.live_hosts, _emit))
        if paths:
            result.paths = paths
            interesting = [p for p in paths if p.interesting]
            await emit("finding", "path_discovery", f"Found {len(paths)} paths ({len(interesting)} interesting)", {"count": len(paths), "interesting": len(interesting)})

        # ── Crawl
        async def _emit(msg):
            await emit("log", "crawl", msg)

        endpoints = await run_module("crawl",
            run_crawler(result.live_hosts, _emit))
        if endpoints:
            result.crawled_endpoints = endpoints
            await emit("finding", "crawl", f"Crawled {len(endpoints)} endpoints", {"count": len(endpoints)})

        # ── Parameters
        async def _emit(msg):
            await emit("log", "parameters", msg)

        params = await run_module("parameters",
            run_parameter_discovery(result.crawled_endpoints, result.live_hosts, _emit))
        if params:
            result.parameters = params
            await emit("finding", "parameters", f"Found {len(params)} parameterized endpoints", {"count": len(params)})

        # ── JS Intelligence
        async def _emit(msg):
            await emit("log", "js_intelligence", msg)

        js_result = await run_module("js_intelligence",
            run_js_intelligence(result.live_hosts, result.crawled_endpoints, _emit))
        if js_result:
            result.js_files, result.secret_findings = js_result
            await emit("finding", "js_intelligence",
                f"Analyzed {len(result.js_files)} JS files, {len(result.secret_findings)} findings",
                {"js_files": len(result.js_files), "secrets": len(result.secret_findings)})

        # ── Finalize
        result.completed_at = now_iso()
        result.duration_seconds = round(time.time() - start_time, 2)
        config.status = "completed"
        await emit("log", "orchestrator", f"Scan completed in {result.duration_seconds}s")
        save_scan(result)
        await emit("log", "orchestrator", "Generating reports...")
        generate_all_reports(result)
        job.result = result
        await emit("scan_complete", "orchestrator", f"Scan complete: {config.target}", data=result.stats, pct=100)

    except asyncio.CancelledError:
        result.completed_at = now_iso()
        result.duration_seconds = round(time.time() - start_time, 2)
        config.status = "stopped"
        save_scan(result)
        await emit("scan_complete", "orchestrator", "Scan stopped by user", pct=progress_so_far)

    except Exception as e:
        config.status = "failed"
        result.errors.append(ScanError(module="orchestrator", message=str(e), recoverable=False))
        result.completed_at = now_iso()
        result.duration_seconds = round(time.time() - start_time, 2)
        save_scan(result)
        await emit("scan_complete", "orchestrator", f"Scan failed: {str(e)[:200]}", pct=progress_so_far)
