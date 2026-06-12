"""Generate a TUI screenshot with mocked data."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Label, ListItem, ListView, Static

OUT = Path(__file__).parent

CSS = """
Screen { background: $surface; }
#main-container { height: 1fr; }
#sidebar {
    width: 30;
    min-width: 20;
    background: $panel;
    border-right: tall $background;
    padding: 0 1;
}
#sidebar-title { text-style: bold; color: $text-muted; padding: 1 0 0 0; }
#app-list { height: 1fr; }
#right-pane { width: 1fr; padding: 0 1; }
#pane-title { text-style: bold; color: $text-muted; padding: 1 0 0 0; }
#conn-table { height: 1fr; }
#stats-bar { height: 1; background: $boost; padding: 0 1; color: $text-muted; }
"""

MOCK_RULES = [
    {"app_path": "/usr/bin/curl",              "app_name": "curl",    "action": "allow"},
    {"app_path": "/usr/lib/firefox/firefox",   "app_name": "firefox", "action": "allow"},
    {"app_path": "/usr/bin/git",               "app_name": "git",     "action": "allow"},
    {"app_path": "/opt/discord/Discord",       "app_name": "discord", "action": "block"},
    {"app_path": "/opt/spotify/spotify",       "app_name": "spotify", "action": "block"},
    {"app_path": "/usr/bin/python3",           "app_name": "python3", "action": "ask"},
]

MOCK_CONNS = [
    {"app_path": "/usr/lib/firefox/firefox",  "app_name": "firefox", "dst_ip": "142.250.185.78",  "dst_port": 443, "proto": "tcp", "action": "allow", "ts": "2026-06-12T14:01:05Z"},
    {"app_path": "/usr/lib/firefox/firefox",  "app_name": "firefox", "dst_ip": "142.250.80.46",   "dst_port": 443, "proto": "tcp", "action": "allow", "ts": "2026-06-12T14:01:07Z"},
    {"app_path": "/usr/bin/curl",             "app_name": "curl",    "dst_ip": "93.184.216.34",   "dst_port": 443, "proto": "tcp", "action": "allow", "ts": "2026-06-12T14:01:32Z"},
    {"app_path": "/opt/spotify/spotify",      "app_name": "spotify", "dst_ip": "35.186.224.47",   "dst_port": 443, "proto": "tcp", "action": "block", "ts": "2026-06-12T14:02:11Z"},
    {"app_path": "/usr/bin/git",              "app_name": "git",     "dst_ip": "140.82.121.4",    "dst_port": 443, "proto": "tcp", "action": "allow", "ts": "2026-06-12T14:02:15Z"},
    {"app_path": "/opt/discord/Discord",      "app_name": "discord", "dst_ip": "162.159.136.234", "dst_port": 443, "proto": "tcp", "action": "block", "ts": "2026-06-12T14:02:44Z"},
    {"app_path": "/usr/bin/python3",          "app_name": "python3", "dst_ip": "151.101.129.69",  "dst_port": 443, "proto": "tcp", "action": "ask",   "ts": "2026-06-12T14:03:00Z"},
]

MOCK_STATS = {"allowed_today": 1058, "blocked_today": 189, "total_connections": 1247}


class MockAppListItem(ListItem):
    def __init__(self, app_path: str, app_name: str, action: str) -> None:
        color = {"allow": "green", "block": "red", "ask": "yellow"}.get(action, "white")
        super().__init__(Label(f"[bold]{app_name}[/bold] [{color}]{action.upper()}[/{color}]"))
        self.app_path = app_path


class MockTUI(App[None]):
    TITLE = "netblind"
    CSS = CSS
    BINDINGS = [
        Binding("a", "noop", "Allow"),
        Binding("b", "noop", "Block"),
        Binding("d", "noop", "Delete rule"),
        Binding("r", "noop", "Refresh"),
        Binding("q", "quit", "Quit"),
        Binding("?", "noop", "Help"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-container"):
            with Vertical(id="sidebar"):
                yield Label("Applications", id="sidebar-title")
                yield ListView(id="app-list")
            with Vertical(id="right-pane"):
                yield Label("Connections", id="pane-title")
                yield DataTable(id="conn-table", cursor_type="row")
        yield Static("", id="stats-bar")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#conn-table", DataTable)
        table.add_columns("Time", "App", "Destination", "Port", "Proto", "Action")

        app_list = self.query_one("#app-list", ListView)
        seen = {}
        for conn in MOCK_CONNS:
            path = conn["app_path"]
            if path not in seen:
                seen[path] = conn

        rules = {r["app_path"]: r for r in MOCK_RULES}
        for path, conn in sorted(seen.items(), key=lambda x: x[1].get("app_name", "")):
            rule = rules.get(path, {})
            action = rule.get("action", "ask")
            name = conn.get("app_name", path)
            await app_list.append(MockAppListItem(path, name, action))

        for conn in MOCK_CONNS:
            action = conn.get("action", "?")
            color = {"allow": "green", "block": "red", "ask": "yellow"}.get(action, "white")
            ts = str(conn.get("ts", ""))[:19].replace("T", " ").replace("Z", "")
            table.add_row(
                ts,
                conn.get("app_name", "?"),
                conn.get("dst_ip", "?"),
                str(conn.get("dst_port", "?")),
                conn.get("proto", "?").upper(),
                f"[{color}]{action.upper()}[/{color}]",
            )

        stats = MOCK_STATS
        self.query_one("#stats-bar", Static).update(
            f"[dim]Today:[/dim]  "
            f"[green]↑ {stats['allowed_today']} allowed[/green]  "
            f"[red]✗ {stats['blocked_today']} blocked[/red]  "
            f"[dim]({stats['total_connections']} total)[/dim]"
        )

        await self.save_screenshot()
        self.exit()

    async def save_screenshot(self) -> None:
        svg = self.export_screenshot()
        out_path = OUT / "tui.svg"
        out_path.write_text(svg)
        print(f"  wrote tui.svg")

    def action_noop(self) -> None:
        pass


if __name__ == "__main__":
    app = MockTUI()
    app.run()
