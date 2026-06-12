"""Generate rich SVG screenshots for the netblind README."""

from __future__ import annotations

from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
from rich.panel import Panel
from rich.columns import Columns

OUT = Path(__file__).parent


def action_text(action: str) -> Text:
    color = {"allow": "bold green", "block": "bold red", "ask": "bold yellow"}.get(action, "white")
    return Text(action.upper(), style=color)


def save(console: Console, name: str) -> None:
    svg = console.export_svg(title=f"netblind — {name}")
    (OUT / f"{name}.svg").write_text(svg)
    print(f"  wrote {name}.svg")


# ── rules ─────────────────────────────────────────────────────────────────────

def make_rules() -> None:
    c = Console(record=True, width=72)
    c.print()
    c.print("[dim]$ netblind rules[/dim]")
    c.print()

    table = Table(title="Firewall Rules", box=box.ROUNDED)
    table.add_column("App", style="bold")
    table.add_column("Path", style="dim")
    table.add_column("Action", justify="center")

    rows = [
        ("bash",    "/usr/bin/bash",    "allow"),
        ("curl",    "/usr/bin/curl",    "allow"),
        ("discord", "/opt/discord/Discord", "block"),
        ("firefox", "/usr/lib/firefox/firefox", "allow"),
        ("git",     "/usr/bin/git",    "allow"),
        ("python3", "/usr/bin/python3", "ask"),
        ("spotify", "/opt/spotify/spotify", "block"),
        ("wget",    "/usr/bin/wget",    "allow"),
    ]
    for name, path, action in rows:
        table.add_row(name, path, action_text(action))
    c.print(table)
    save(c, "rules")


# ── list ──────────────────────────────────────────────────────────────────────

def make_list() -> None:
    c = Console(record=True, width=84)
    c.print()
    c.print("[dim]$ netblind list[/dim]")
    c.print()

    table = Table(title="Active Connections", box=box.ROUNDED, show_lines=False)
    table.add_column("App", style="bold")
    table.add_column("Src", style="cyan")
    table.add_column("Destination", style="cyan")
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Proto", style="dim")

    rows = [
        ("firefox",  "192.168.1.50", "142.250.185.78",  "443", "TCP"),
        ("firefox",  "192.168.1.50", "142.250.80.46",   "443", "TCP"),
        ("curl",     "192.168.1.50", "93.184.216.34",   "443", "TCP"),
        ("git",      "192.168.1.50", "140.82.121.4",    "443", "TCP"),
        ("discord",  "192.168.1.50", "162.159.136.234", "443", "TCP"),
        ("python3",  "192.168.1.50", "151.101.129.69",  "443", "TCP"),
    ]
    for row in rows:
        table.add_row(*row)
    c.print(table)
    save(c, "list")


# ── log ───────────────────────────────────────────────────────────────────────

def make_log() -> None:
    c = Console(record=True, width=96)
    c.print()
    c.print("[dim]$ netblind log[/dim]")
    c.print()

    table = Table(title="Traffic Log (last 10)", box=box.ROUNDED)
    table.add_column("Time", style="dim")
    table.add_column("App", style="bold")
    table.add_column("Destination")
    table.add_column("Port", justify="right")
    table.add_column("Proto", style="dim")
    table.add_column("Action", justify="center")

    rows = [
        ("2026-06-12 14:01:05", "firefox",  "142.250.185.78",  "443", "TCP", "allow"),
        ("2026-06-12 14:01:07", "firefox",  "142.250.80.46",   "443", "TCP", "allow"),
        ("2026-06-12 14:01:32", "curl",     "93.184.216.34",   "443", "TCP", "allow"),
        ("2026-06-12 14:02:11", "spotify",  "35.186.224.47",   "443", "TCP", "block"),
        ("2026-06-12 14:02:15", "git",      "140.82.121.4",    "443", "TCP", "allow"),
        ("2026-06-12 14:02:44", "discord",  "162.159.136.234", "443", "TCP", "block"),
        ("2026-06-12 14:03:00", "python3",  "151.101.129.69",  "443", "TCP", "ask"),
        ("2026-06-12 14:03:01", "wget",     "151.101.129.69",  "443", "TCP", "allow"),
        ("2026-06-12 14:03:55", "spotify",  "35.186.225.22",   "443", "TCP", "block"),
        ("2026-06-12 14:04:11", "firefox",  "216.58.206.14",   "443", "TCP", "allow"),
    ]
    for ts, app, dst, port, proto, action in rows:
        table.add_row(ts, app, dst, port, proto, action_text(action))
    c.print(table)
    save(c, "log")


# ── stats ─────────────────────────────────────────────────────────────────────

def make_stats() -> None:
    c = Console(record=True, width=50)
    c.print()
    c.print("[dim]$ netblind stats[/dim]")
    c.print()

    table = Table(title="netblind Statistics", box=box.ROUNDED, show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Total connections today", "1 247")
    table.add_row("[green]Allowed today[/green]",  "[green]1 058[/green]")
    table.add_row("[red]Blocked today[/red]",      "[red]189[/red]")
    table.add_row("Apps with rules", "8")
    c.print(table)
    save(c, "stats")


# ── status + allow/block ──────────────────────────────────────────────────────

def make_status() -> None:
    c = Console(record=True, width=64)
    c.print()
    c.print("[dim]$ netblind status[/dim]")
    c.print("[green]●[/green] netblind daemon running (v1.0.0)")
    c.print()
    c.print("[dim]$ netblind block discord[/dim]")
    c.print("[red]✗[/red] Blocked: [bold]/opt/discord/Discord[/bold]")
    c.print()
    c.print("[dim]$ netblind allow curl[/dim]")
    c.print("[green]✓[/green] Allowed: [bold]/usr/bin/curl[/bold]")
    c.print()
    c.print("[dim]$ netblind delete python3[/dim]")
    c.print("[dim]Deleted rule for:[/dim] [bold]/usr/bin/python3[/bold]")
    c.print()
    save(c, "status_commands")


if __name__ == "__main__":
    print("Generating screenshots...")
    make_rules()
    make_list()
    make_log()
    make_stats()
    make_status()
    print("Done.")
