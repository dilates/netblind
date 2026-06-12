"""netblind GTK4 GUI — professional per-app outbound firewall."""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any

try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("GLib", "2.0")
    gi.require_version("Gio", "2.0")
    gi.require_version("Gdk", "4.0")
    from gi.repository import Gtk, GLib, Gio, Gdk, Pango  # type: ignore[attr-defined]

    try:
        gi.require_version("Adw", "1")
        from gi.repository import Adw  # type: ignore[attr-defined]
        HAS_ADW = True
    except (ValueError, ImportError):
        HAS_ADW = False

    try:
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3  # type: ignore[attr-defined]
        HAS_INDICATOR = True
    except (ValueError, ImportError):
        HAS_INDICATOR = False

except ImportError as exc:
    print(f"GTK4/PyGObject not available: {exc}", file=sys.stderr)
    sys.exit(1)

from clients.shared.rpc import DaemonNotRunning, NetblindRPC, PermissionDenied, RPCError

VERSION = "1.0.0"
GITHUB_URL = "https://github.com/dilates"
REFRESH_MS = 2000


# ── CSS ───────────────────────────────────────────────────────────────────────

APP_CSS = """
.badge-allow {
    background: #1D9E75;
    color: #ffffff;
    border-radius: 9999px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: 600;
}
.badge-block {
    background: #E24B4A;
    color: #ffffff;
    border-radius: 9999px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: 600;
}
.badge-ask {
    background: #EF9F27;
    color: #ffffff;
    border-radius: 9999px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: 600;
}
.action-allow { color: #1D9E75; font-weight: 600; }
.action-block { color: #E24B4A; font-weight: 600; }
.action-ask   { color: #EF9F27; font-weight: 600; }
.monospace-label { font-family: monospace; }
.status-dot-ok  { color: #1D9E75; font-size: 16px; }
.status-dot-err { color: #E24B4A; font-size: 16px; }
.app-row { padding: 4px 8px; }
.app-name-label { font-weight: bold; }
.app-path-label { font-size: 11px; opacity: 0.6; }
"""


def _load_css() -> None:
    provider = Gtk.CssProvider()
    provider.load_from_string(APP_CSS)
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


def _make_badge(action: str) -> Gtk.Label:
    label = Gtk.Label(label=action.upper())
    label.add_css_class(f"badge-{action}")
    return label


# ── About Dialog ──────────────────────────────────────────────────────────────

def show_about(parent: Gtk.Window) -> None:
    if HAS_ADW:
        dialog = Adw.AboutWindow(transient_for=parent)
        dialog.set_application_name("netblind")
        dialog.set_version(VERSION)
        dialog.set_comments("Per-application outbound firewall for Linux")
        dialog.set_website(GITHUB_URL)
        dialog.set_license_type(Gtk.License.GPL_3_0)
        dialog.set_copyright("© 2025 dilates")
        dialog.set_developers(["dilates <https://github.com/dilates>"])
        dialog.present()
    else:
        dialog = Gtk.AboutDialog(transient_for=parent, modal=True)
        dialog.set_program_name("netblind")
        dialog.set_version(VERSION)
        dialog.set_comments("Per-application outbound firewall for Linux")
        dialog.set_website(GITHUB_URL)
        dialog.set_website_label("GitHub")
        dialog.set_license_type(Gtk.License.GPL_3_0)
        dialog.set_copyright("© 2025 dilates")
        dialog.set_authors(["dilates"])
        dialog.present()


# ── Preferences Dialog ────────────────────────────────────────────────────────

class PreferencesDialog(Gtk.Dialog):
    def __init__(self, parent: Gtk.Window) -> None:
        super().__init__(title="Preferences", transient_for=parent, modal=True)
        self.set_default_size(400, 340)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.connect("response", lambda d, _: d.destroy())

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(16)
        box.set_margin_bottom(16)
        box.set_margin_start(16)
        box.set_margin_end(16)
        self.get_content_area().append(box)

        # Default policy
        policy_label = Gtk.Label(label="<b>Default policy for unknown apps</b>", use_markup=True)
        policy_label.set_halign(Gtk.Align.START)
        box.append(policy_label)

        policy_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.append(policy_box)
        ask_btn = Gtk.CheckButton(label="Ask")
        ask_btn.set_active(True)
        allow_btn = Gtk.CheckButton(label="Allow", group=ask_btn)
        block_btn = Gtk.CheckButton(label="Block", group=ask_btn)
        for btn in (ask_btn, allow_btn, block_btn):
            policy_box.append(btn)

        box.append(Gtk.Separator())

        # Toggles
        notif_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        notif_row.append(Gtk.Label(label="Show notifications"))
        notif_switch = Gtk.Switch()
        notif_switch.set_active(True)
        notif_switch.set_halign(Gtk.Align.END)
        notif_switch.set_hexpand(True)
        notif_row.append(notif_switch)
        box.append(notif_row)

        autostart_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        autostart_row.append(Gtk.Label(label="Auto-start with system"))
        autostart_switch = Gtk.Switch()
        autostart_switch.set_halign(Gtk.Align.END)
        autostart_switch.set_hexpand(True)
        autostart_row.append(autostart_switch)
        box.append(autostart_row)

        box.append(Gtk.Separator())

        # Log retention
        retention_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        retention_row.append(Gtk.Label(label="Log retention (days)"))
        retention_spin = Gtk.SpinButton()
        retention_spin.set_adjustment(Gtk.Adjustment(value=7, lower=1, upper=30, step_increment=1))
        retention_spin.set_halign(Gtk.Align.END)
        retention_spin.set_hexpand(True)
        retention_row.append(retention_spin)
        box.append(retention_row)

        # Socket path
        socket_row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        socket_row.append(Gtk.Label(label="Socket path (advanced)", xalign=0))
        socket_entry = Gtk.Entry()
        socket_entry.set_text("/run/netblind.sock")
        socket_row.append(socket_entry)
        box.append(socket_row)

        self.present()


# ── New Connection Dialog ─────────────────────────────────────────────────────

class NewConnectionDialog(Gtk.Dialog):
    """Alert popup shown when an unknown app is trying to connect."""

    def __init__(self, parent: Gtk.Window, app_name: str,
                 dst_ip: str, dst_port: int, proto: str) -> None:
        super().__init__(title="New connection", transient_for=parent, modal=True)
        self.set_default_size(380, 260)

        self._result: str = "ask"
        self._countdown = 30

        # Buttons
        self._block_btn = self.add_button("Block", Gtk.ResponseType.REJECT)
        self._block_btn.add_css_class("destructive-action")
        self._ask_btn = self.add_button("Ask later", Gtk.ResponseType.CANCEL)
        self._allow_btn = self.add_button("Allow", Gtk.ResponseType.ACCEPT)
        self._allow_btn.add_css_class("suggested-action")
        self.set_default_response(Gtk.ResponseType.CANCEL)

        self.connect("response", self._on_response)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(20)
        box.set_margin_bottom(12)
        box.set_margin_start(20)
        box.set_margin_end(20)
        self.get_content_area().append(box)

        # App name
        title_lbl = Gtk.Label()
        title_lbl.set_markup(f"<span size='large' weight='bold'>{GLib.markup_escape_text(app_name)}"
                             f" wants to connect</span>")
        title_lbl.set_wrap(True)
        title_lbl.set_halign(Gtk.Align.CENTER)
        box.append(title_lbl)

        # Details
        details_lbl = Gtk.Label()
        details_lbl.set_markup(
            f"Destination: <tt>{GLib.markup_escape_text(dst_ip)}:{dst_port}</tt>\n"
            f"Protocol: {proto.upper()}"
        )
        details_lbl.set_halign(Gtk.Align.CENTER)
        box.append(details_lbl)

        # Remember checkbox
        self._remember_check = Gtk.CheckButton(label="Remember this decision")
        self._remember_check.set_halign(Gtk.Align.CENTER)
        box.append(self._remember_check)

        # Countdown label
        self._countdown_lbl = Gtk.Label(label=f"Auto-closing in {self._countdown}s")
        self._countdown_lbl.add_css_class("dim-label")
        box.append(self._countdown_lbl)

        GLib.timeout_add(1000, self._tick)
        self.present()

    def _tick(self) -> bool:
        self._countdown -= 1
        self._countdown_lbl.set_text(f"Auto-closing in {self._countdown}s")
        if self._countdown <= 0:
            self._result = "ask"
            self.response(Gtk.ResponseType.CANCEL)
            return False
        return True

    def _on_response(self, _dialog: Gtk.Dialog, response: int) -> None:
        if response == Gtk.ResponseType.ACCEPT:
            self._result = "allow"
        elif response == Gtk.ResponseType.REJECT:
            self._result = "block"
        else:
            self._result = "ask"
        self.destroy()

    @property
    def decision(self) -> str:
        return self._result

    @property
    def remember(self) -> bool:
        return self._remember_check.get_active()


# ── App Row Widget ────────────────────────────────────────────────────────────

class AppRow(Gtk.ListBoxRow):
    """A row in the application sidebar."""

    def __init__(self, app_path: str, app_name: str, action: str) -> None:
        super().__init__()
        self.app_path = app_path
        self.app_name = app_name

        self.add_css_class("app-row")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        self.set_child(box)

        # Icon fallback — generic application icon
        icon = Gtk.Image.new_from_icon_name("application-x-executable")
        icon.set_pixel_size(32)
        box.append(icon)

        # Text column
        text_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_col.set_hexpand(True)
        box.append(text_col)

        name_lbl = Gtk.Label(label=app_name, xalign=0)
        name_lbl.add_css_class("app-name-label")
        text_col.append(name_lbl)

        path_lbl = Gtk.Label(label=app_path, xalign=0)
        path_lbl.add_css_class("app-path-label")
        path_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        text_col.append(path_lbl)

        # Badge
        badge = _make_badge(action)
        badge.set_valign(Gtk.Align.CENTER)
        box.append(badge)

        self._badge = badge

    def update_action(self, action: str) -> None:
        for css_class in ("badge-allow", "badge-block", "badge-ask"):
            self._badge.remove_css_class(css_class)
        self._badge.add_css_class(f"badge-{action}")
        self._badge.set_text(action.upper())


# ── Main Window ───────────────────────────────────────────────────────────────

class NetblindWindow(Gtk.ApplicationWindow):
    """Main application window."""

    def __init__(self, app: Gtk.Application) -> None:
        super().__init__(application=app, title="netblind")
        self.set_default_size(800, 560)
        self.set_size_request(700, 480)

        self._rpc = NetblindRPC()
        self._rules: dict[str, dict[str, Any]] = {}
        self._connections: list[dict[str, Any]] = []
        self._stats: dict[str, int] = {}
        self._selected_app: str | None = None
        self._daemon_ok = False
        self._app_rows: dict[str, AppRow] = {}

        self._build_ui()
        _load_css()

        # Start periodic refresh
        GLib.timeout_add(REFRESH_MS, self._schedule_refresh)
        self._schedule_refresh()

    def _build_ui(self) -> None:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_child(outer)

        # Header bar
        self._build_header(outer)

        # Main content pane
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_position(240)
        paned.set_vexpand(True)
        outer.append(paned)

        # Left panel
        left = self._build_left_panel()
        paned.set_start_child(left)
        paned.set_shrink_start_child(False)
        paned.set_resize_start_child(False)

        # Right panel
        right = self._build_right_panel()
        paned.set_end_child(right)
        paned.set_shrink_end_child(True)

        # Status bar
        self._status_bar = self._build_status_bar()
        outer.append(self._status_bar)

    def _build_header(self, parent: Gtk.Box) -> None:
        header = Gtk.HeaderBar()
        self.set_titlebar(header)

        # Search
        self._search_entry = Gtk.SearchEntry()
        self._search_entry.set_placeholder_text("Filter by app or IP…")
        self._search_entry.connect("search-changed", self._on_search_changed)
        header.set_title_widget(self._search_entry)

        # Hamburger menu
        menu_model = Gio.Menu()
        menu_model.append("Preferences", "win.preferences")
        menu_model.append("View Log", "win.view-log")
        menu_model.append("About", "win.about")
        menu_model.append("Quit", "app.quit")

        menu_btn = Gtk.MenuButton()
        menu_btn.set_icon_name("open-menu-symbolic")
        menu_btn.set_menu_model(menu_model)
        header.pack_end(menu_btn)

        # Wire actions
        for name, callback in [
            ("preferences", self._on_preferences),
            ("view-log", self._on_view_log),
            ("about", self._on_about),
        ]:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    def _build_left_panel(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_start(8)
        box.set_margin_end(4)
        box.set_margin_top(8)
        box.set_size_request(240, -1)

        lbl = Gtk.Label(label="Applications", xalign=0)
        lbl.set_markup("<b>Applications</b>")
        lbl.add_css_class("dim-label")
        box.append(lbl)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        box.append(scroll)

        self._app_list = Gtk.ListBox()
        self._app_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._app_list.connect("row-selected", self._on_app_selected)
        scroll.set_child(self._app_list)

        return box

    def _build_right_panel(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_start(4)
        box.set_margin_end(8)
        box.set_margin_top(8)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        box.append(scroll)

        self._conn_list = Gtk.ListBox()
        self._conn_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._conn_list.connect("row-activated", self._on_conn_row_activated)
        scroll.set_child(self._conn_list)

        # Column headers (fake, via a label bar)
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        header_box.set_margin_bottom(2)
        for text, expand in [("Time", False), ("App", True), ("Destination", True),
                               ("Port", False), ("Proto", False), ("Action", False)]:
            lbl = Gtk.Label(label=text, xalign=0)
            lbl.set_markup(f"<b><small>{text}</small></b>")
            lbl.set_hexpand(expand)
            lbl.set_margin_start(4)
            lbl.set_width_chars(8 if not expand else 12)
            header_box.append(lbl)
        box.prepend(header_box)

        return box

    def _build_status_bar(self) -> Gtk.Box:
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        bar.set_margin_start(12)
        bar.set_margin_end(12)
        bar.set_margin_top(4)
        bar.set_margin_bottom(6)

        self._status_dot = Gtk.Label(label="●")
        self._status_dot.add_css_class("status-dot-err")
        bar.append(self._status_dot)

        self._status_label = Gtk.Label(label="Daemon offline")
        bar.append(self._status_label)

        spacer = Gtk.Label()
        spacer.set_hexpand(True)
        bar.append(spacer)

        self._stats_label = Gtk.Label(label="")
        bar.append(self._stats_label)

        return bar

    # ── refresh logic ─────────────────────────────────────────────────────────

    def _schedule_refresh(self) -> bool:
        t = threading.Thread(target=self._fetch_data, daemon=True)
        t.start()
        return True  # keep timer alive

    def _fetch_data(self) -> None:
        try:
            rules = self._rpc.get_rules()
            conns = self._rpc.get_connections()
            stats = self._rpc.get_stats()
            GLib.idle_add(self._apply_data, rules, conns, stats, True)
        except (DaemonNotRunning, PermissionDenied, RPCError, OSError):
            GLib.idle_add(self._apply_data, [], [], {}, False)

    def _apply_data(self, rules: list, conns: list, stats: dict, ok: bool) -> bool:
        self._daemon_ok = ok
        self._rules = {r["app_path"]: r for r in rules}
        self._connections = conns
        self._stats = stats
        self._update_status_bar()
        self._update_app_list()
        self._update_conn_list()
        return False

    def _update_status_bar(self) -> None:
        if self._daemon_ok:
            self._status_dot.set_text("●")
            for c in ("status-dot-ok", "status-dot-err"):
                self._status_dot.remove_css_class(c)
            self._status_dot.add_css_class("status-dot-ok")
            self._status_label.set_text("Daemon connected")
        else:
            self._status_dot.set_text("●")
            for c in ("status-dot-ok", "status-dot-err"):
                self._status_dot.remove_css_class(c)
            self._status_dot.add_css_class("status-dot-err")
            self._status_label.set_text("Daemon offline")

        allowed = self._stats.get("allowed_today", 0)
        blocked = self._stats.get("blocked_today", 0)
        self._stats_label.set_markup(
            f"<span color='#1D9E75'>↑ {allowed} allowed</span>  "
            f"<span color='#E24B4A'>✗ {blocked} blocked</span>  today"
        )

    def _update_app_list(self) -> None:
        search_text = self._search_entry.get_text().lower()

        seen: dict[str, dict[str, Any]] = {}
        for conn in self._connections:
            path = conn.get("app_path", "")
            if path and path not in seen:
                seen[path] = conn

        # Add/update rows
        for path, conn in seen.items():
            rule = self._rules.get(path, {})
            action = rule.get("action", "ask")
            name = conn.get("app_name", path)

            if path in self._app_rows:
                self._app_rows[path].update_action(action)
            else:
                row = AppRow(path, name, action)
                self._app_rows[path] = row
                self._app_list.append(row)

            # Apply search filter
            row = self._app_rows[path]
            visible = (not search_text or
                       search_text in name.lower() or
                       search_text in path.lower())
            row.set_visible(visible)

        # Right-click context menu via gesture
        for path, row in self._app_rows.items():
            if not hasattr(row, "_has_gesture"):
                gesture = Gtk.GestureClick()
                gesture.set_button(3)
                gesture.connect("pressed", self._on_app_row_right_click, row)
                row.add_controller(gesture)
                row._has_gesture = True  # type: ignore[attr-defined]

    def _update_conn_list(self) -> None:
        search_text = self._search_entry.get_text().lower()

        # Remove all existing rows
        while True:
            child = self._conn_list.get_first_child()
            if child is None:
                break
            self._conn_list.remove(child)

        conns = self._connections
        if self._selected_app:
            conns = [c for c in conns if c.get("app_path") == self._selected_app]
        if search_text:
            conns = [c for c in conns if (
                search_text in c.get("app_name", "").lower() or
                search_text in c.get("dst_ip", "").lower()
            )]

        for conn in conns[-200:]:
            row = self._make_conn_row(conn)
            self._conn_list.append(row)

    def _make_conn_row(self, conn: dict[str, Any]) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row._conn_data = conn  # type: ignore[attr-defined]

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        box.set_margin_top(2)
        box.set_margin_bottom(2)
        box.set_margin_start(4)
        box.set_margin_end(4)
        row.set_child(box)

        action = conn.get("action", "ask")
        color = {"allow": "#1D9E75", "block": "#E24B4A", "ask": "#EF9F27"}.get(action, "#888")

        def add_lbl(text: str, expand: bool = False, mono: bool = False) -> Gtk.Label:
            lbl = Gtk.Label(label=str(text), xalign=0)
            if expand:
                lbl.set_hexpand(True)
            if mono:
                lbl.add_css_class("monospace-label")
            lbl.set_ellipsize(Pango.EllipsizeMode.END)
            box.append(lbl)
            return lbl

        ts = str(conn.get("ts", ""))[:19]
        add_lbl(ts, mono=True)
        add_lbl(conn.get("app_name", "?"), expand=True)
        add_lbl(conn.get("dst_ip", "?"), expand=True, mono=True)
        add_lbl(str(conn.get("dst_port", "?")), mono=True)
        add_lbl(conn.get("proto", "?").upper())

        action_lbl = Gtk.Label(label=action.upper(), xalign=0)
        action_lbl.set_markup(f"<span color='{color}' weight='bold'>{action.upper()}</span>")
        box.append(action_lbl)

        return row

    # ── event handlers ────────────────────────────────────────────────────────

    def _on_app_selected(self, _listbox: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is None:
            self._selected_app = None
        else:
            self._selected_app = getattr(row, "app_path", None)
        self._update_conn_list()

    def _on_conn_row_activated(self, _listbox: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        conn = getattr(row, "_conn_data", None)
        if conn is None:
            return
        self._show_conn_detail_popover(row, conn)

    def _show_conn_detail_popover(self, widget: Gtk.Widget, conn: dict[str, Any]) -> None:
        popover = Gtk.Popover()
        popover.set_parent(widget)
        popover.set_autohide(True)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)

        fields = [
            ("App", conn.get("app_name", "?")),
            ("Path", conn.get("app_path", "?")),
            ("Source", f"{conn.get('src_ip', '?')}:{conn.get('src_port', '?')}"),
            ("Destination", f"{conn.get('dst_ip', '?')}:{conn.get('dst_port', '?')}"),
            ("Protocol", conn.get("proto", "?").upper()),
            ("Action", conn.get("action", "?").upper()),
            ("Time", str(conn.get("ts", "?"))[:19]),
        ]

        for key, val in fields:
            row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            key_lbl = Gtk.Label(label=f"{key}:", xalign=0)
            key_lbl.set_markup(f"<b>{key}:</b>")
            key_lbl.set_width_chars(12)
            val_lbl = Gtk.Label(label=val, xalign=0)
            val_lbl.set_selectable(True)
            row_box.append(key_lbl)
            row_box.append(val_lbl)
            box.append(row_box)

        popover.set_child(box)
        popover.popup()

    def _on_app_row_right_click(self, _gesture: Gtk.GestureClick, _n: int,
                                  _x: float, _y: float, row: AppRow) -> None:
        menu = Gtk.Popover()
        menu.set_parent(row)
        menu.set_autohide(True)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        box.set_margin_start(4)
        box.set_margin_end(4)

        for label, action in [("Allow", "allow"), ("Block", "block"), ("Delete rule", None)]:
            btn = Gtk.Button(label=label)
            btn.add_css_class("flat")
            btn.connect("clicked", self._on_context_action, row, action, menu)
            box.append(btn)

        menu.set_child(box)
        menu.popup()

    def _on_context_action(self, _btn: Gtk.Button, row: AppRow,
                            action: str | None, popover: Gtk.Popover) -> None:
        popover.popdown()
        if action is None:
            self._do_delete_rule(row.app_path)
        else:
            self._do_set_rule(row.app_path, action)

    def _on_search_changed(self, _entry: Gtk.SearchEntry) -> None:
        self._update_app_list()
        self._update_conn_list()

    def _on_about(self, _action: Gio.SimpleAction, _param: Any) -> None:
        show_about(self)

    def _on_preferences(self, _action: Gio.SimpleAction, _param: Any) -> None:
        PreferencesDialog(self)

    def _on_view_log(self, _action: Gio.SimpleAction, _param: Any) -> None:
        self._selected_app = None
        self._update_conn_list()

    # ── rule actions ──────────────────────────────────────────────────────────

    def _do_set_rule(self, app_path: str, action: str) -> None:
        def worker() -> None:
            try:
                self._rpc.set_rule(app_path, action)
                GLib.idle_add(self._schedule_refresh)
            except (DaemonNotRunning, RPCError) as exc:
                GLib.idle_add(self._show_error, str(exc))

        threading.Thread(target=worker, daemon=True).start()

    def _do_delete_rule(self, app_path: str) -> None:
        def worker() -> None:
            try:
                self._rpc.delete_rule(app_path)
                GLib.idle_add(self._schedule_refresh)
            except (DaemonNotRunning, RPCError) as exc:
                GLib.idle_add(self._show_error, str(exc))

        threading.Thread(target=worker, daemon=True).start()

    def _show_error(self, message: str) -> bool:
        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text="Error",
        )
        dialog.set_secondary_text(message)
        dialog.connect("response", lambda d, _: d.destroy())
        dialog.present()
        return False


# ── System Tray ───────────────────────────────────────────────────────────────

class Tray:
    """System tray icon with menu."""

    def __init__(self, app: "NetblindApp") -> None:
        self._app = app
        if HAS_INDICATOR:
            self._setup_indicator()
        else:
            pass  # StatusIcon deprecated in GTK4 — skip silently

    def _setup_indicator(self) -> None:
        # AppIndicator3 requires GTK3 which can't be loaded alongside GTK4.
        # This path is only reached if a future GTK4-native indicator library
        # is available. Current systems fall through to HAS_INDICATOR=False.
        pass

    def set_state(self, state: str) -> None:
        pass  # no-op until a GTK4-compatible tray library is available


# ── Application ───────────────────────────────────────────────────────────────

class NetblindApp(Gtk.Application):
    """GTK4 application wrapper."""

    def __init__(self) -> None:
        super().__init__(
            application_id="io.github.dilates.netblind",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self._window: NetblindWindow | None = None
        self._tray: Tray | None = None

        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self.quit())
        self.add_action(quit_action)

    def do_activate(self) -> None:
        if self._window is None:
            if HAS_ADW:
                Adw.init()
            self._window = NetblindWindow(self)
            self._tray = Tray(self)
        self._window.present()

    def show_window(self) -> None:
        if self._window:
            self._window.present()


def main() -> None:
    """Entry point for the netblind GUI."""
    app = NetblindApp()
    sys.exit(app.run(sys.argv))


if __name__ == "__main__":
    main()
