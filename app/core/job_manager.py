"""
ReconSea - Scan Job Manager
"""
import asyncio
from typing import Dict, Optional, AsyncGenerator
from app.core.models import ScanConfig, ScanResult, ProgressEvent


class ScanJob:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.result: Optional[ScanResult] = None
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.task: Optional[asyncio.Task] = None
        self.stopped = False

    async def emit(self, event: ProgressEvent):
        await self.event_queue.put(event)

    async def event_stream(self) -> AsyncGenerator[str, None]:
        while True:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=30.0)
                yield event.to_sse()
                if event.event_type == "scan_complete":
                    break
            except asyncio.TimeoutError:
                yield 'data: {"event_type":"heartbeat"}\n\n'


class JobManager:
    def __init__(self):
        self._jobs: Dict[str, ScanJob] = {}

    def create_job(self, config: ScanConfig) -> ScanJob:
        job = ScanJob(config)
        self._jobs[config.scan_id] = job
        return job

    def get_job(self, scan_id: str) -> Optional[ScanJob]:
        return self._jobs.get(scan_id)

    def stop_job(self, scan_id: str):
        job = self._jobs.get(scan_id)
        if job:
            job.stopped = True
            if job.task and not job.task.done():
                job.task.cancel()

    def remove_job(self, scan_id: str):
        self._jobs.pop(scan_id, None)


job_manager = JobManager()
