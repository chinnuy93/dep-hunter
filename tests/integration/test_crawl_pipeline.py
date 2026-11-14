from __future__ import annotations

import asyncio
from pathlib import Path

from aiohttp import web

from dephunter.core.config import Settings
from dephunter.core.pipeline import ScanPipeline
from dephunter.core.scope import ScopeConfig, WebTarget
from dephunter.database.db import Database


async def _start_server(port_holder: dict) -> tuple[web.AppRunner, int]:
    app = web.Application()

    async def robots(request):
        return web.Response(text="User-agent: *\nAllow: /\n", content_type="text/plain")

    async def index(request):
        return web.Response(
            text='<html><body><a href="/package.json">manifest</a>'
            '<script src="/static/app.js"></script></body></html>',
            content_type="text/html",
        )

    async def manifest(request):
        return web.json_response(
            {
                "name": "demo-app",
                "dependencies": {
                    "@acme/internal-lib": "^1.0.0",
                    "left-pad": "1.0.0",
                },
            }
        )

    async def bundle(request):
        return web.Response(
            text='const a = require("@acme/from-bundle");',
            content_type="application/javascript",
        )

    app.router.add_get("/robots.txt", robots)
    app.router.add_get("/", index)
    app.router.add_get("/package.json", manifest)
    app.router.add_get("/static/app.js", bundle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    port_holder["port"] = port
    return runner, port


def test_pipeline_crawl_local_site(tmp_path: Path) -> None:
    async def scenario() -> None:
        holder: dict = {}
        runner, port = await _start_server(holder)
        try:
            settings = Settings(data_dir=tmp_path / "data", reports_dir=tmp_path / "reports")
            settings.ensure_dirs()
            scope = ScopeConfig(
                program="Local Test",
                authorization="Authorized local integration test",
                allow_private_hosts=True,
                web=[WebTarget(url=f"http://127.0.0.1:{port}/")],
            )
            scope.crawl.requests_per_second = 100
            scope.crawl.max_urls = 20
            db = Database(settings.db_path)
            events = []
            try:
                outcome = await ScanPipeline(
                    settings, scope, db, on_progress=events.append
                ).run(phases=["crawl"])
                assert outcome.status in {"COMPLETED", "PARTIAL"}
                assert outcome.elapsed_seconds >= 0
                assert "crawl" in outcome.phase_timings
                assert any(event.phase == "crawl" and event.done for event in events)
                assert any(event.phase == "crawl" and event.total >= 1 for event in events)
                dependencies = db.load_dependencies(outcome.scan_id)
                names = {dep.name for dep in dependencies}
                assert "@acme/internal-lib" in names
                assert "@acme/from-bundle" in names
                scan = db.get_scan(outcome.scan_id)
                assert scan["phase"] == "crawl"
                assert scan["status"] in {"COMPLETED", "PARTIAL"}
                assert scan["stats"]["runtime"]["progress_percent"] == 100
            finally:
                db.close()
        finally:
            await runner.cleanup()

    asyncio.run(scenario())
