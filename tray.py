"""AutoNetGuard – system-tray icon and menu (Windows).

Architecture
------------
The tray runs on the **main thread** (required by pystray / Win32).
The guardian loop runs on a **background daemon thread**.

A shared ``AppState`` object is the single source of truth; both threads
read/write it through thread-safe primitives.

Public entry point
------------------
    from tray import run_tray
    run_tray()          # blocks until the user clicks "退出"
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable

from PIL import Image, ImageDraw
import pystray

from autostart import disable_autostart, enable_autostart, is_autostart_enabled


# ---------------------------------------------------------------------------
# Shared application state
# ---------------------------------------------------------------------------

class NetStatus(Enum):
    UNKNOWN = auto()
    ONLINE = auto()
    OFFLINE = auto()
    LOGGING_IN = auto()


@dataclass
class AppState:
    """Thread-safe container for runtime status shared between tray and guardian."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    _status: NetStatus = NetStatus.UNKNOWN
    _last_login_time: str = "—"
    _disconnect_count: int = 0

    # Called by the tray whenever it needs to refresh the menu / tooltip
    on_status_change: Callable[[], None] | None = field(default=None, repr=False)

    # ---- status ----
    @property
    def status(self) -> NetStatus:
        with self._lock:
            return self._status

    @status.setter
    def status(self, value: NetStatus) -> None:
        with self._lock:
            changed = self._status != value
            self._status = value
        if changed and self.on_status_change:
            self.on_status_change()

    # ---- last_login_time ----
    @property
    def last_login_time(self) -> str:
        with self._lock:
            return self._last_login_time

    @last_login_time.setter
    def last_login_time(self, value: str) -> None:
        with self._lock:
            self._last_login_time = value
        if self.on_status_change:
            self.on_status_change()

    # ---- disconnect_count ----
    @property
    def disconnect_count(self) -> int:
        with self._lock:
            return self._disconnect_count

    def increment_disconnect(self) -> None:
        with self._lock:
            self._disconnect_count += 1
        if self.on_status_change:
            self.on_status_change()

    # ---- summary ----
    def summary(self) -> str:
        with self._lock:
            status_text = {
                NetStatus.UNKNOWN: "检测中…",
                NetStatus.ONLINE: "✅ 已联网",
                NetStatus.OFFLINE: "❌ 未联网",
                NetStatus.LOGGING_IN: "🔄 登录中…",
            }.get(self._status, "未知")
            return (
                f"AutoNetGuard\n"
                f"状态: {status_text}\n"
                f"上次登录: {self._last_login_time}\n"
                f"断线次数: {self._disconnect_count}"
            )


# ---------------------------------------------------------------------------
# Icon image generation (no external image files needed)
# ---------------------------------------------------------------------------

_ICON_SIZE = 64


def _make_icon(status: NetStatus) -> Image.Image:
    """Draw a simple coloured circle icon for the given network status."""
    color_map = {
        NetStatus.ONLINE: "#22c55e",      # green
        NetStatus.OFFLINE: "#ef4444",     # red
        NetStatus.LOGGING_IN: "#f59e0b",  # amber
        NetStatus.UNKNOWN: "#6b7280",     # grey
    }
    bg_color = color_map.get(status, "#6b7280")

    img = Image.new("RGBA", (_ICON_SIZE, _ICON_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = 4
    draw.ellipse(
        [margin, margin, _ICON_SIZE - margin, _ICON_SIZE - margin],
        fill=bg_color,
    )
    # Small white "G" letter hint
    draw.ellipse(
        [_ICON_SIZE // 4, _ICON_SIZE // 4,
         _ICON_SIZE * 3 // 4, _ICON_SIZE * 3 // 4],
        fill="white",
    )
    return img


# ---------------------------------------------------------------------------
# Tray controller
# ---------------------------------------------------------------------------

class TrayController:
    """Manages the pystray icon lifecycle."""

    def __init__(self, state: AppState, stop_event: threading.Event) -> None:
        self._state = state
        self._stop_event = stop_event
        self._icon: pystray.Icon | None = None

        # Wire state changes → icon update
        state.on_status_change = self._refresh_icon

    # ---- menu actions -------------------------------------------------------

    def _on_login_now(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:  # noqa: ARG002
        """Trigger an immediate login attempt (signals guardian thread)."""
        # We signal by temporarily setting status to OFFLINE so the guardian
        # loop picks it up on the next wake.  The guardian itself will update
        # the status back.
        self._state.status = NetStatus.OFFLINE

    def _on_toggle_autostart(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:  # noqa: ARG002
        if is_autostart_enabled():
            disable_autostart()
        else:
            enable_autostart()
        # Rebuild menu to reflect new state
        if self._icon:
            self._icon.menu = self._build_menu()
            self._icon.update_menu()

    def _on_quit(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:  # noqa: ARG002
        self._stop_event.set()
        icon.stop()

    # ---- menu builder -------------------------------------------------------

    def _build_menu(self) -> pystray.Menu:
        autostart_label = (
            "✔ 开机自启动" if is_autostart_enabled() else "  开机自启动"
        )
        # pystray calls text callables as text(item), so we wrap summary()
        # in a lambda that accepts and discards the extra argument.
        summary_text = lambda item: self._state.summary()  # noqa: E731
        return pystray.Menu(
            pystray.MenuItem(summary_text, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("立即重新登录", self._on_login_now),
            pystray.MenuItem(autostart_label, self._on_toggle_autostart),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出 AutoNetGuard", self._on_quit),
        )

    # ---- icon refresh -------------------------------------------------------

    def _refresh_icon(self) -> None:
        if self._icon is None:
            return
        self._icon.icon = _make_icon(self._state.status)
        self._icon.title = self._state.summary()
        self._icon.menu = self._build_menu()
        self._icon.update_menu()

    # ---- run (blocks main thread) ------------------------------------------

    def run(self) -> None:
        self._icon = pystray.Icon(
            name="AutoNetGuard",
            icon=_make_icon(NetStatus.UNKNOWN),
            title="AutoNetGuard – 检测中…",
            menu=self._build_menu(),
        )
        self._icon.run()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_tray(
    guardian_target: Callable[[AppState, threading.Event], None],
) -> None:
    """Start the guardian thread then run the tray on the main thread.

    Parameters
    ----------
    guardian_target:
        Callable that accepts ``(state, stop_event)`` and implements the
        network-monitoring loop.  It will be run on a daemon thread.
    """
    stop_event = threading.Event()
    state = AppState()

    # Start guardian as a background daemon thread
    guardian_thread = threading.Thread(
        target=guardian_target,
        args=(state, stop_event),
        name="guardian",
        daemon=True,
    )
    guardian_thread.start()

    # Run tray on main thread (blocks until user clicks "退出")
    tray = TrayController(state=state, stop_event=stop_event)
    tray.run()

    # Tray has exited – signal guardian to stop and wait briefly
    stop_event.set()
    guardian_thread.join(timeout=5)
