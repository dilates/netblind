"""netblind TUI — live per-app outbound firewall monitor."""

from __future__ import annotations

import asyncio
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    ListItem,
    ListView,
    Static,
)

from clients.shared.rpc import DaemonNotRunning, NetblindRPC, PermissionDenied, RPCError

REFRESH_INTERVAL = 2.0


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
#sidebar-title {
    text-style: bold;
    color: $text-muted;
    padding: 1 0 0 0;
}
#app-list { height: 1fr; }

#right-pane { width: 1fr; padding: 0 1; }
#pane-title { text-style: bold; color: $text-muted; padding: 1 0 0 0; }
#conn-table { height: 1fr; }

#stats-bar {
    height: 1;
    background: $boost;
    padding: 0 1;
    color: $text-muted;
}

DisconnectedModal { align: center middle; }
#modal-box {
    width: 52;
    height: 7;
    background: $panel;
    border: thick $primary;
    padding: 1 2;
    content-align: center middle;
}
"""


class DisconnectedModal(ModalScreen[None]):
    """Shown when the daemon connection is lost."""

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("Daemon disconnected — retrying…", id="modal-msg"),
            id="modal-box",
        )


class AppListItem(ListItem):
    """ListItem that carries app metadata."""

    def __init__(self, app_path: str, app_name: str, action: str) -> None:
        action_color = {"allow": "green", "block": "red", "ask": "yellow"}.get(action, "white")
        super().__init__(
            Label(f"[bold]{app_name}[/bold] [{action_color}]{action.upper()}[/{action_color}]")
        )
        self.app_path = app_path
        self.app_name = app_name
        self.action = action


class NetblindTUI(App[None]):
    """Live per-application outbound firewall monitor."""

    TITLE = "netblind"
    CSS = CSS
    BINDINGS = [
        Binding("a", "allow_selected", "Allow"),
        Binding("b", "block_selected", "Block"),
        Binding("d", "delete_selected", "Delete rule"),
        Binding("r", "refresh", "Refresh"),
        Binding("q", "quit", "Quit"),
        Binding("?", "help", "Help"),
    ]

    connected: reactive[bool] = reactive(True)
    selected_app: reactive[str | None] = reactive(None)

    def __init__(self) -> None:
        super().__init__()
        self._rpc = NetblindRPC()
        self._rules: dict[str, dict[str, Any]] = {}
        self._connections: list[dict[str, Any]] = []
        self._stats: dict[str, int] = {}
        self._modal_shown = False

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

    def on_mount(self) -> None:
        table = self.query_one("#conn-table", DataTable)
        table.add_columns("Time", "App", "Destination", "Port", "Proto", "Action")
        self.set_interval(REFRESH_INTERVAL, self._do_refresh)
        self.run_worker(self._do_refresh(), exclusive=True)

    # ── data refresh ──────────────────────────────────────────────────────────

    async def _do_refresh(self) -> None:
        try:
            rules, conns, stats = await asyncio.gather(
                asyncio.to_thread(self._rpc.get_rules),
                asyncio.to_thread(self._rpc.get_connections),
                asyncio.to_thread(self._rpc.get_stats),
            )
            self._rules = {r["app_path"]: r for r in rules}
            self._connections = conns
            self._stats = stats

            if not self.connected:
                self.connected = True
                if self._modal_shown:
                    self.pop_screen()
                    self._modal_shown = False

            await self._update_ui()

        except (DaemonNotRunning, PermissionDenied, RPCError, OSError):
            self.connected = False
            if not self._modal_shown:
                self._modal_shown = True
                await self.push_screen(DisconnectedModal())

    async def _update_ui(self) -> None:
        await self._refresh_sidebar()
        self._refresh_table()
        self._refresh_stats()

    async def _refresh_sidebar(self) -> None:
        app_list = self.query_one("#app-list", ListView)
        await app_list.clear()

        seen: dict[str, dict[str, Any]] = {}
        for conn in self._connections:
            path = conn.get("app_path", "")
            if path and path not in seen:
                seen[path] = conn

        for path, conn in sorted(seen.items(), key=lambda x: x[1].get("app_name", "")):
            rule = self._rules.get(path, {})
            action = rule.get("action", "ask")
            name = conn.get("app_name", path)
            await app_list.append(AppListItem(path, name, action))

    def _refresh_table(self) -> None:
        table = self.query_one("#conn-table", DataTable)
        table.clear()

        conns = self._connections
        if self.selected_app:
            conns = [c for c in conns if c.get("app_path") == self.selected_app]

        for conn in conns[-200:]:
            action = conn.get("action", "?")
            color = {"allow": "green", "block": "red", "ask": "yellow"}.get(action, "white")
            ts = conn.get("ts", "")
            if ts:
                ts = str(ts)[:19]
            table.add_row(
                ts,
                conn.get("app_name", "?"),
                conn.get("dst_ip", "?"),
                str(conn.get("dst_port", "?")),
                conn.get("proto", "?").upper(),
                f"[{color}]{action.upper()}[/{color}]",
            )

    def _refresh_stats(self) -> None:
        try:
            stats_bar = self.query_one("#stats-bar", Static)
        except NoMatches:
            return
        allowed = self._stats.get("allowed_today", 0)
        blocked = self._stats.get("blocked_today", 0)
        total = self._stats.get("total_connections", 0)
        stats_bar.update(
            f"[dim]Today:[/dim]  "
            f"[green]↑ {allowed} allowed[/green]  "
            f"[red]✗ {blocked} blocked[/red]  "
            f"[dim]({total} total)[/dim]"
        )

    # ── event handlers ────────────────────────────────────────────────────────

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, AppListItem):
            self.selected_app = item.app_path
            self._refresh_table()

    def _selected_app_info(self) -> tuple[str, str] | None:
        if not self.selected_app:
            self.notify("Select an app in the sidebar first.", severity="warning")
            return None
        rule = self._rules.get(self.selected_app, {})
        name = rule.get("app_name", self.selected_app)
        return self.selected_app, name

    # ── key actions ───────────────────────────────────────────────────────────

    def action_allow_selected(self) -> None:
        info = self._selected_app_info()
        if info:
            path, name = info
            self.run_worker(self._set_rule(path, "allow", name))

    def action_block_selected(self) -> None:
        info = self._selected_app_info()
        if info:
            path, name = info
            self.run_worker(self._set_rule(path, "block", name))

    def action_delete_selected(self) -> None:
        info = self._selected_app_info()
        if info:
            path, name = info
            self.run_worker(self._delete_rule(path, name))

    def action_refresh(self) -> None:
        self.run_worker(self._do_refresh(), exclusive=True)

    def action_help(self) -> None:
        self.notify(
            "a=Allow  b=Block  d=Delete  r=Refresh  q=Quit",
            title="Keyboard Shortcuts",
            timeout=5,
        )

    # ── worker helpers ────────────────────────────────────────────────────────

    async def _set_rule(self, app_path: str, action: str, name: str) -> None:
        try:
            await asyncio.to_thread(self._rpc.set_rule, app_path, action)
            self.notify(f"{action.capitalize()}ed: {name}", severity="information")
            await self._do_refresh()
        except (DaemonNotRunning, RPCError) as exc:
            self.notify(str(exc), severity="error")

    async def _delete_rule(self, app_path: str, name: str) -> None:
        try:
            await asyncio.to_thread(self._rpc.delete_rule, app_path)
            self.notify(f"Rule deleted: {name}", severity="information")
            await self._do_refresh()
        except (DaemonNotRunning, RPCError) as exc:
            self.notify(str(exc), severity="error")


def main() -> None:
    """Entry point for the netblind TUI."""
    NetblindTUI().run()


if __name__ == "__main__":
    main()
