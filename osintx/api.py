"""FastAPI app: REST + SSE live stream + static UI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from osintx.config import Config
from osintx.engine import Engine
from osintx.models import ScanStatus
from osintx.providers import registry
from osintx.report import RENDERERS, render
from osintx.storage import Storage
from osintx.utils import make_target

WEB_DIR = Path(__file__).parent / "web"

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=320)
    type: str = "auto"
    categories: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)

def create_app(config: Config) -> FastAPI:
    app = FastAPI(title="OSINTX", version="1.0.0")
    storage = Storage(config.db_path)
    queues: dict[str, asyncio.Queue] = {}

    @app.get("/api/health")
    async def health() -> dict:
        return {"ok": True, "providers": len(registry.discover())}

    @app.get("/api/providers")
    async def providers() -> list[dict]:
        return [
            {
                "name": name,
                "category": cls.meta.category,
                "description": cls.meta.description,
                "targets": list(cls.meta.targets),
                "requires_key": cls.meta.requires_key,
            }
            for name, cls in sorted(registry.discover().items())
        ]

    @app.get("/api/scans")
    async def scans(limit: int = Query(30, ge=1, le=200)) -> list[dict]:
        return await storage.list_scans(limit)

    @app.get("/api/scans/{scan_id}")
    async def scan_detail(scan_id: str) -> dict:
        result = await storage.get_scan(scan_id)
        if result is None:
            raise HTTPException(404, "scan not found")
        return json.loads(render(result, "json"))

    @app.get("/api/scans/{scan_id}/export")
    async def scan_export(scan_id: str, fmt: str = "json") -> dict:
        result = await storage.get_scan(scan_id)
        if result is None:
            raise HTTPException(404, "scan not found")
        if fmt not in RENDERERS:
            raise HTTPException(400, "bad format")
        return {"format": fmt, "content": render(result, fmt)}

    @app.delete("/api/scans/{scan_id}")
    async def scan_delete(scan_id: str) -> dict:
        await storage.delete_scan(scan_id)
        return {"deleted": scan_id}

    @app.post("/api/scan")
    async def start_scan(payload: ScanRequest) -> dict:
        target = make_target(payload.target, payload.type)
        providers_list = registry.build(
            names=payload.providers or None,
            categories=payload.categories or None,
        )
        if not providers_list:
            raise HTTPException(400, "no providers matched")

        queue: asyncio.Queue = asyncio.Queue()
        scan_holder: dict = {}

        async def on_event(event: str, data: dict) -> None:
            await queue.put({"event": event, "data": data})

        engine = Engine(config, storage, providers_list, on_event=on_event)

        async def runner() -> None:
            result = await engine.run(target)
            scan_holder["id"] = result.id
            await queue.put({"event": "finished", "data": {"id": result.id}})

        task = asyncio.create_task(runner())
        scan_id = await _wait_for_id(queue, scan_holder, task)
        queues[scan_id] = queue
        return {"id": scan_id}

    @app.get("/api/stream/{scan_id}")
    async def stream(scan_id: str) -> StreamingResponse:
        queue = queues.get(scan_id)
        if queue is None:
            raise HTTPException(404, "no live stream for this scan")

        async def generator() -> AsyncIterator[bytes]:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=30)
                except asyncio.TimeoutError:
                    yield b": keepalive\n\n"
                    continue
                yield f"event: {item['event']}\ndata: {json.dumps(item['data'], default=str)}\n\n".encode()
                if item["event"] == "finished":
                    queues.pop(scan_id, None)
                    break

        return StreamingResponse(generator(), media_type="text/event-stream")

    if WEB_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

        @app.get("/")
        async def index() -> FileResponse:
            return FileResponse(WEB_DIR / "index.html")

    return app

async def _wait_for_id(queue: asyncio.Queue, holder: dict, task: asyncio.Task) -> str:
    """Wait until the engine emits scan_start so we can return the id."""
    while True:
        item = await queue.get()
        if item["event"] == "scan_start":
            return item["data"]["id"]
        if task.done() and "id" in holder:
            return holder["id"]
