"""netblind CLI — per-application outbound firewall control."""

from __future__ import annotations

import argparse
import sys
from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.text import Text
except ImportError:
    print("rich is required: pip install rich", file=sys.stderr)
    sys.exit(1)

from clients.shared.rpc import NetblindRPC, DaemonNotRunning, PermissionDenied, RPCError

VERSION = "1.0.0"
GITHUB_URL = "https://github.com/dilates"

console = Console()
err_console = Console(stderr=True)


def action_color(action: str) -> str:
    """Map an action string to a rich color name."""
    return {"allow": "green", "block": "red", "ask": "yellow"}.get(action, "white")


def action_text(action: str) -> Text:
    """Render an action as a rich Text with color."""
    color = action_color(action)
    return Text(action.upper(), style=f"bold {color}")


def daemon_error(exc: Exception) -> None:
    """Print a friendly daemon-not-running error and exit."""
    err_console.print(f"[bold red]Error:[/bold red] {exc}")
    sys.exit(1)


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_list(rpc: NetblindRPC, _args: argparse.Namespace) -> None:
    """Show currently active outbound connections."""
    conns = rpc.get_connections()
    if not conns:
        console.print("[dim]No active connections.[/dim]")
        return

    table = Table(title="Active Connections", box=box.ROUNDED, show_lines=False)
    table.add_column("App", style="bold")
    table.add_column("Src", style="cyan")
    table.add_column("Destination", style="cyan")
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Proto", style="dim")

    for conn in conns:
        table.add_row(
            conn.get("app_name", "?"),
            conn.get("src_ip", "?"),
            conn.get("dst_ip", "?"),
            str(conn.get("dst_port", "?")),
            conn.get("proto", "?").upper(),
        )
    console.print(table)


def cmd_rules(rpc: NetblindRPC, _args: argparse.Namespace) -> None:
    """Show all persistent rules."""
    rules = rpc.get_rules()
    if not rules:
        console.print("[dim]No rules configured.[/dim]")
        return

    table = Table(title="Firewall Rules", box=box.ROUNDED)
    table.add_column("App", style="bold")
    table.add_column("Path", style="dim")
    table.add_column("Action", justify="center")

    for r in sorted(rules, key=lambda x: x.get("app_name", "")):
        table.add_row(
            r.get("app_name", "?"),
            r.get("app_path", "?"),
            action_text(r.get("action", "ask")),
        )
    console.print(table)


def _resolve_app_path(rpc: NetblindRPC, identifier: str) -> str:
    """Resolve a name or path to an exact app_path in the rules list."""
    rules = rpc.get_rules()
    # Exact path match first
    for r in rules:
        if r.get("app_path") == identifier:
            return identifier
    # Name match
    matches = [r for r in rules if r.get("app_name", "").lower() == identifier.lower()]
    if len(matches) == 1:
        return matches[0]["app_path"]
    if len(matches) > 1:
        console.print(f"[yellow]Ambiguous name '{identifier}'. Specify full path:[/yellow]")
        for m in matches:
            console.print(f"  {m['app_path']}")
        sys.exit(1)
    # If not found in rules, assume the identifier is a direct path
    return identifier


def cmd_allow(rpc: NetblindRPC, args: argparse.Namespace) -> None:
    """Set a rule to allow for an application."""
    path = _resolve_app_path(rpc, args.app)
    rpc.set_rule(path, "allow")
    console.print(f"[green]✓[/green] Allowed: [bold]{path}[/bold]")


def cmd_block(rpc: NetblindRPC, args: argparse.Namespace) -> None:
    """Set a rule to block for an application."""
    path = _resolve_app_path(rpc, args.app)
    rpc.set_rule(path, "block")
    console.print(f"[red]✗[/red] Blocked: [bold]{path}[/bold]")


def cmd_delete(rpc: NetblindRPC, args: argparse.Namespace) -> None:
    """Delete a rule for an application."""
    path = _resolve_app_path(rpc, args.app)
    rpc.delete_rule(path)
    console.print(f"[dim]Deleted rule for:[/dim] [bold]{path}[/bold]")


def cmd_log(rpc: NetblindRPC, args: argparse.Namespace) -> None:
    """Show recent traffic log."""
    entries = rpc.get_log(limit=args.limit)
    if not entries:
        console.print("[dim]No log entries.[/dim]")
        return

    table = Table(title=f"Traffic Log (last {len(entries)})", box=box.ROUNDED)
    table.add_column("Time", style="dim")
    table.add_column("App", style="bold")
    table.add_column("Destination")
    table.add_column("Port", justify="right")
    table.add_column("Proto", style="dim")
    table.add_column("Action", justify="center")

    for e in entries:
        table.add_row(
            str(e.get("ts", ""))[:19],
            e.get("app_name", "?"),
            e.get("dst_ip", "?"),
            str(e.get("dst_port", "?")),
            e.get("proto", "?").upper(),
            action_text(e.get("action", "?")),
        )
    console.print(table)


def cmd_stats(rpc: NetblindRPC, _args: argparse.Namespace) -> None:
    """Show summary statistics."""
    stats = rpc.get_stats()
    table = Table(title="netblind Statistics", box=box.ROUNDED, show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Total connections today", str(stats.get("total_connections", 0)))
    table.add_row("[green]Allowed today[/green]", str(stats.get("allowed_today", 0)))
    table.add_row("[red]Blocked today[/red]", str(stats.get("blocked_today", 0)))
    table.add_row("Apps with rules", str(stats.get("apps_count", 0)))
    console.print(table)


def cmd_status(rpc: NetblindRPC, _args: argparse.Namespace) -> None:
    """Check if the daemon is running."""
    result = rpc.ping()
    version = result.get("version", "?")
    console.print(f"[green]●[/green] netblind daemon running (v{version})")


# ── main ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="netblind",
        description="Per-application outbound firewall for Linux",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"netblind v{VERSION}\nPer-app outbound firewall for Linux\n{GITHUB_URL}",
    )
    parser.add_argument(
        "--socket", default="/run/netblind.sock",
        help="Unix socket path (default: /run/netblind.sock)",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    sub.add_parser("list", help="List active connections")
    sub.add_parser("rules", help="Show all persistent rules")
    sub.add_parser("stats", help="Show summary statistics")
    sub.add_parser("status", help="Check if daemon is running")

    allow_p = sub.add_parser("allow", help="Set rule to allow an app")
    allow_p.add_argument("app", help="App path or name")

    block_p = sub.add_parser("block", help="Set rule to block an app")
    block_p.add_argument("app", help="App path or name")

    delete_p = sub.add_parser("delete", help="Remove a rule")
    delete_p.add_argument("app", help="App path or name")

    log_p = sub.add_parser("log", help="Show recent traffic log")
    log_p.add_argument("--limit", type=int, default=50, metavar="N", help="Number of entries (default 50)")

    return parser


COMMANDS: dict[str, Any] = {
    "list": cmd_list,
    "rules": cmd_rules,
    "allow": cmd_allow,
    "block": cmd_block,
    "delete": cmd_delete,
    "log": cmd_log,
    "stats": cmd_stats,
    "status": cmd_status,
}


def main() -> None:
    """Entry point for the netblind CLI."""
    parser = build_parser()
    args = parser.parse_args()

    rpc = NetblindRPC(socket_path=args.socket)

    try:
        rpc.connect()

        try:
            COMMANDS[args.command](rpc, args)
        finally:
            rpc.disconnect()

    except DaemonNotRunning as exc:
        daemon_error(exc)
    except PermissionDenied as exc:
        daemon_error(exc)
    except RPCError as exc:
        err_console.print(f"[bold red]RPC Error:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
