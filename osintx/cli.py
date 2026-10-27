"""Typer CLI — scan, list, show, export, providers, serve."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from osintx import __version__
from osintx.cache import DiskCache
from osintx.config import Config
from osintx.engine import Engine
from osintx.models import ScanStatus, Severity
from osintx.providers import registry
from osintx.report import RENDERERS, render, write
from osintx.storage import Storage
from osintx.utils import human_seconds, make_target, truncate

app = typer.Typer(add_completion=False, help="OSINTX — integrated OSINT & leaked-data recon.")
console = Console()

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

def _config(ctx: typer.Context) -> Config:
    return ctx.obj["config"]

def _storage(config: Config) -> Storage:
    return Storage(config.db_path)

@app.callback()
def main(
    ctx: typer.Context,
    data_dir: Optional[Path] = typer.Option(None, "--data-dir", help="Override data directory."),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL."),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", min=1, max=64),
    rate: Optional[float] = typer.Option(None, "--rate", help="Global requests per second."),
    timeout: Optional[float] = typer.Option(None, "--timeout", help="Per-request timeout (s)."),
    insecure: bool = typer.Option(False, "--insecure", help="Skip TLS verification."),
    offline: bool = typer.Option(False, "--offline", help="No network calls."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    config = Config.from_env()
    if data_dir:
        config.data_dir = data_dir.expanduser()
        config.data_dir.mkdir(parents=True, exist_ok=True)
    if proxy:
        config.proxy = proxy
    if concurrency:
        config.concurrency = concurrency
    if rate:
        config.global_rate = rate
    if timeout:
        config.timeout = timeout
    if insecure:
        config.verify_tls = False
    if offline:
        config.offline = True
    if verbose:
        config.verbose = True
    ctx.obj = {"config": config}

@app.command()
def version() -> None:
    """Print version."""
    console.print(f"OSINTX [bold cyan]{__version__}[/]")

@app.command("providers")
def list_providers(
    category: Optional[str] = typer.Option(None, "--category", "-c"),
) -> None:
    """List available providers."""
    table = Table(title="Providers", show_lines=False)
    table.add_column("Name", style="cyan")
    table.add_column("Category")
    table.add_column("Targets")
    table.add_column("Key")
    table.add_column("Description")
    for name, cls in sorted(registry.discover().items()):
        meta = cls.meta
        if category and meta.category != category:
            continue
        table.add_row(
            name,
            meta.category,
            ", ".join(meta.targets),
            "yes" if meta.requires_key else "—",
            meta.description,
        )
    console.print(table)

@app.command()
def scan(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Email, phone, username or domain."),
    target_type: str = typer.Option("auto", "--type", "-t", help="auto|email|phone|username|domain|ip"),
    category: list[str] = typer.Option([], "--category", "-c", help="Restrict to categories."),
    provider: list[str] = typer.Option([], "--provider", "-p", help="Restrict to providers."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file."),
    fmt: str = typer.Option("json", "--format", "-f", help="json|csv|markdown|html"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    no_save: bool = typer.Option(False, "--no-save"),
) -> None:
    """Run a scan against a target."""
    config = _config(ctx)
    if fmt not in RENDERERS:
        raise typer.BadParameter(f"format must be one of {', '.join(RENDERERS)}")

    resolved = make_target(target, target_type)
    providers = registry.build(names=provider or None, categories=category or None)
    if not providers:
        console.print("[red]No providers matched the filters.[/]")
        raise typer.Exit(1)

    storage = _storage(config)
    cache = DiskCache(config.cache_dir, config.cache_ttl)

    def on_event(event: str, payload: dict) -> None:
        if quiet:
            return
        if event == "provider_start":
            console.print(f"[dim]→ {payload['provider']}[/]", end=" ")
        elif event == "provider_done":
            mark = "[green]✓[/]" if payload["ok"] else "[red]✗[/]"
            console.print(f"{mark} {payload['provider']} ({human_seconds(payload['elapsed'])})")
        elif event == "provider_skipped":
            console.print(f"[yellow]⊘ {payload['provider']} — {payload['reason']}[/]")
        elif event == "finding":
            style = SEVERITY_STYLE.get(Severity(payload["severity"]), "dim")
            console.print(
                f"  [{style}]{payload['severity'].upper():8}[/] "
                f"[bold]{payload['provider']}[/] {truncate(payload['title'], 90)}"
            )

    engine = Engine(config, storage, providers, on_event=on_event)

    async def run() -> None:
        result = await engine.run(resolved)
        if not no_save:
            await storage.save_findings(result.id, result.findings)
        if output:
            write(result, fmt, output)
            console.print(f"\n[green]Report written to[/] {output}")
        if not quiet:
            stats = result.stats()
            console.print(
                Panel(
                    Text.from_markup(
                        f"[bold]Scan complete[/] — {stats['total']} findings "
                        f"({stats['providers_failed']} providers failed)"
                    ),
                    border_style="cyan",
                )
            )
        if output is None and not quiet:
            console.print(render(result, "markdown"))

    asyncio.run(run())
    cache.clear()

@app.command("list")
def list_scans(
    ctx: typer.Context,
    limit: int = typer.Option(20, "--limit", "-n", min=1, max=200),
) -> None:
    """List recent scans."""
    storage = _storage(_config(ctx))

    async def run() -> list[dict]:
        return await storage.list_scans(limit)

    rows = asyncio.run(run())
    table = Table(title="Recent scans")
    table.add_column("ID", style="dim")
    table.add_column("Target")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Created")
    for row in rows:
        table.add_row(row["id"][:12], row["target"], row["target_type"], row["status"], row["created_at"])
    console.print(table)

@app.command()
def show(
    ctx: typer.Context,
    scan_id: str = typer.Argument(...),
    fmt: str = typer.Option("markdown", "--format", "-f"),
) -> None:
    """Show a stored scan."""
    storage = _storage(_config(ctx))

    async def run():
        return await storage.get_scan(scan_id)

    result = asyncio.run(run())
    if result is None:
        console.print("[red]Scan not found.[/]")
        raise typer.Exit(1)
    console.print(render(result, fmt))

@app.command()
def export(
    ctx: typer.Context,
    scan_id: str = typer.Argument(...),
    fmt: str = typer.Option("json", "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Export a stored scan."""
    config = _config(ctx)
    storage = _storage(config)

    async def run():
        return await storage.get_scan(scan_id)

    result = asyncio.run(run())
    if result is None:
        console.print("[red]Scan not found.[/]")
        raise typer.Exit(1)
    path = output or (config.export_dir / f"{scan_id}.{fmt}")
    write(result, fmt, path)
    console.print(f"[green]Written:[/] {path}")

@app.command()
def delete(ctx: typer.Context, scan_id: str = typer.Argument(...)) -> None:
    """Delete a stored scan."""
    storage = _storage(_config(ctx))

    async def run() -> None:
        await storage.delete_scan(scan_id)

    asyncio.run(run())
    console.print(f"[green]Deleted[/] {scan_id}")

@app.command()
def serve(
    ctx: typer.Context,
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """Start the web UI."""
    import uvicorn

    from osintx.api import create_app

    config = _config(ctx)
    application = create_app(config)
    uvicorn.run(application, host=host, port=port, reload=reload)

@app.command()
def config(ctx: typer.Context) -> None:
    """Print effective configuration (secrets masked)."""
    console.print_json(json.dumps(_config(ctx).redacted(), indent=2))

if __name__ == "__main__":
    app()
