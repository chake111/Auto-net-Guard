"""AutoNetGuard – system-tray icon and menu.

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


def _get_notify_message(old: NetStatus, new: NetStatus) -> tuple[str, str] | None:
    """Return a ``(title, message)`` pair for a noteworthy status transition.

    Returns ``None`` for transitions that do not warrant a desktop notification.
    """
    if old == NetStatus.ONLINE and new == NetStatus.LOGGING_IN:
        return ("AutoNetGuard", "检测到断网，准备重新登录")
    if old == NetStatus.ONLINE and new == NetStatus.OFFLINE:
        return ("AutoNetGuard", "检测到断网，网络已离线")
    if old == NetStatus.LOGGING_IN and new == NetStatus.ONLINE:
        return ("AutoNetGuard", "重新认证成功，网络已恢复")
    if old == NetStatus.OFFLINE and new == NetStatus.ONLINE:
        return ("AutoNetGuard", "网络已恢复")
    if old == NetStatus.LOGGING_IN and new == NetStatus.OFFLINE:
        return ("AutoNetGuard", "多次尝试登录失败，请检查账号或网关")
    return None


@dataclass
class AppState:
    """Thread-safe container for runtime status shared between tray and guardian."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    _status: NetStatus = NetStatus.UNKNOWN
    _last_login_time: str = "—"
    _disconnect_count: int = 0

    # Called by the tray whenever it needs to refresh the menu / tooltip
    on_status_change: Callable[[], None] | None = field(default=None, repr=False)

    # Called when a noteworthy status transition occurs; args are (title, message).
    # Executed on whatever thread changes the status – must be non-blocking.
    on_notify: Callable[[str, str], None] | None = field(default=None, repr=False)

    # GUI 保存配置后设置此事件，通知后台可以感知配置变更（如记录日志、刷新菜单）
    config_changed: threading.Event = field(
        default_factory=threading.Event, repr=False
    )

    # 设置此事件可唤醒守护线程的定时等待，使其立即进入下一轮检测循环。
    # 切换 Profile 后由托盘菜单处理器设置，以触发即时重连。
    wakeup_event: threading.Event = field(
        default_factory=threading.Event, repr=False
    )

    def wake_guardian(self) -> None:
        """Wake the guardian thread without forcing a config reload."""
        self.wakeup_event.set()

    def request_config_reload(self) -> None:
        """Wake the guardian thread and ask it to reload configuration."""
        self.config_changed.set()
        self.wakeup_event.set()

    # ---- status ----
    @property
    def status(self) -> NetStatus:
        with self._lock:
            return self._status

    @status.setter
    def status(self, value: NetStatus) -> None:
        with self._lock:
            changed = self._status != value
            old_status = self._status
            self._status = value
        if changed:
            if self.on_status_change:
                self.on_status_change()
            if self.on_notify:
                notification = _get_notify_message(old_status, value)
                if notification:
                    title, message = notification
                    self.on_notify(title, message)

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

    def _status_text(self) -> str:
        return {
            NetStatus.UNKNOWN: "检测中…",
            NetStatus.ONLINE: "已联网",
            NetStatus.OFFLINE: "未联网",
            NetStatus.LOGGING_IN: "登录中…",
        }.get(self._status, "未知")

    # ---- summary ----
    def summary(self) -> str:
        with self._lock:
            status_text = self._status_text()
            return (
                f"AutoNetGuard\n"
                f"状态: {status_text}\n"
                f"上次登录: {self._last_login_time}\n"
                f"断线次数: {self._disconnect_count}"
            )

    def tooltip(self) -> str:
        """Return a compact, single-line tooltip for the tray icon."""
        import config as _cfg  # noqa: PLC0415

        with self._lock:
            profile = _cfg.get_active_profile() or "默认"
            return (
                f"AutoNetGuard | 状态: {self._status_text()}"
                f" | 订阅: {profile} | 断线: {self._disconnect_count} 次"
            )


# ---------------------------------------------------------------------------
# Icon image generation (no external image files needed)
# ---------------------------------------------------------------------------

_ICON_SIZE = 64


def _draw_geometric_glyph(
    draw: ImageDraw.ImageDraw,
    status: NetStatus,
    accent: str,
) -> None:
    """Draw an abstract geometric glyph for the given status."""
    center = _ICON_SIZE // 2
    orbit_r = 28

    # Neutral orbit ring.
    draw.ellipse(
        [
            center - orbit_r,
            center - orbit_r,
            center + orbit_r,
            center + orbit_r,
        ],
        outline="#0f172a",
        width=4,
    )

    segment_map = {
        NetStatus.ONLINE: (302, 352),
        NetStatus.OFFLINE: (32, 82),
        NetStatus.LOGGING_IN: (122, 172),
        NetStatus.UNKNOWN: (212, 262),
    }
    start, end = segment_map.get(status, (212, 262))
    draw.arc(
        [
            center - orbit_r,
            center - orbit_r,
            center + orbit_r,
            center + orbit_r,
        ],
        start=start,
        end=end,
        fill=accent,
        width=7,
    )

    # Center diamond creates the geometric focus.
    half = 14
    draw.polygon(
        [
            (center, center - half),
            (center + half, center),
            (center, center + half),
            (center - half, center),
        ],
        fill="#0f172a",
    )
    cut = 5
    draw.ellipse(
        [
            center - cut,
            center - cut,
            center + cut,
            center + cut,
        ],
        fill="#f8fafc",
    )

    node_map = {
        NetStatus.ONLINE: (58, 6),
        NetStatus.OFFLINE: (58, 58),
        NetStatus.LOGGING_IN: (6, 58),
        NetStatus.UNKNOWN: (6, 6),
    }
    node_x, node_y = node_map.get(status, (19, 19))
    draw.line([(center, center), (node_x, node_y)], fill="#64748b", width=4)
    node_half = 5
    draw.rectangle(
        [
            node_x - node_half,
            node_y - node_half,
            node_x + node_half,
            node_y + node_half,
        ],
        fill=accent,
    )


def _make_icon(status: NetStatus) -> Image.Image:
    """Draw an abstract geometric icon for the given network status."""
    color_map = {
        NetStatus.ONLINE: "#16a34a",      # green
        NetStatus.OFFLINE: "#dc2626",     # red
        NetStatus.LOGGING_IN: "#d97706",  # amber
        NetStatus.UNKNOWN: "#475569",     # slate
    }
    accent = color_map.get(status, "#6b7280")

    img = Image.new("RGBA", (_ICON_SIZE, _ICON_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Light circular base keeps the glyph visible on both bright and dark taskbars.
    margin = 0
    draw.ellipse(
        [margin, margin, _ICON_SIZE - margin, _ICON_SIZE - margin],
        fill="#f8fafc",
        outline="#cbd5e1",
        width=1,
    )

    _draw_geometric_glyph(draw, status, accent)

    return img


# ---------------------------------------------------------------------------
# Tray controller
# ---------------------------------------------------------------------------

class TrayController:
    """Manages the pystray icon lifecycle."""

    def __init__(
        self,
        state: AppState,
        stop_event: threading.Event,
        on_settings_open: Callable[[], None] | None = None,
    ) -> None:
        self._state = state
        self._stop_event = stop_event
        # 打开设置窗口的回调（由 run_tray 注入，防止多进程/多线程重入）
        self._on_settings_open = on_settings_open
        self._icon: pystray.Icon | None = None
        self._notification_lock = threading.Lock()
        self._last_notification_monotonic: float = 0.0

        # Wire state changes → icon update
        state.on_status_change = self._refresh_icon
        # Wire status transitions → desktop notification
        state.on_notify = self._send_notification

    # ---- menu actions -------------------------------------------------------

    def _on_login_now(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:  # noqa: ARG002
        """Trigger an immediate login attempt (signals guardian thread)."""
        self._state.status = NetStatus.LOGGING_IN
        self._state.wake_guardian()

    def _on_open_settings(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:  # noqa: ARG002
        """打开图形化配置窗口。

        通过注入的回调在独立守护线程中运行 tkinter 窗口，
        确保不阻塞 pystray 主线程的事件循环。
        """
        if self._on_settings_open:
            self._on_settings_open()

    def _on_toggle_autostart(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:  # noqa: ARG002
        if is_autostart_enabled():
            disable_autostart()
        else:
            enable_autostart()
        self._refresh_menu()

    def _on_quit(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:  # noqa: ARG002
        self._stop_event.set()
        icon.stop()

    # ---- profile switching --------------------------------------------------

    def _on_switch_profile(self, name: str) -> None:
        """Switch the active network profile and trigger an immediate reconnect.

        Steps:
        1. Persist the new ``active_profile`` value to ``config.ini`` and
           reload all module globals (via :func:`config.switch_profile`).
        2. Signal the guardian thread that configuration has changed.
        3. Wake the guardian thread from its inter-check sleep so that it
           applies the new profile and attempts reconnection without waiting
           for the full ``CHECK_INTERVAL_SECONDS`` timeout.
        4. Refresh the tray menu so the active-profile tick mark updates.
        """
        import config as _cfg  # noqa: PLC0415

        _cfg.switch_profile(name)
        self._state.request_config_reload()
        # Rebuild menu immediately so the ✔ mark reflects the new profile
        self._refresh_menu()

    def _build_profile_submenu(self) -> pystray.Menu:
        """Build the dynamic "切换网络环境" submenu from configured profiles."""
        import config as _cfg  # noqa: PLC0415

        profiles = _cfg.list_profiles()
        active = _cfg.get_active_profile()

        if not profiles:
            return pystray.Menu(
                pystray.MenuItem("（请在 config.ini 中配置 profile）", None, enabled=False),
            )

        def _make_handler(profile_name: str):
            def _handler(icon: pystray.Icon, item: pystray.MenuItem) -> None:  # noqa: ARG001
                self._on_switch_profile(profile_name)
            return _handler

        items = [
            pystray.MenuItem(
                f"✔ {name}" if name == active else f"  {name}",
                _make_handler(name),
            )
            for name in profiles
        ]
        return pystray.Menu(*items)

    # ---- notifications ------------------------------------------------------

    def _send_notification(self, title: str, message: str) -> None:
        """Send a desktop notification if notifications are enabled.

        This method is called from the background guardian thread via the
        ``AppState.on_notify`` callback.  It must be non-blocking.

        ``pystray``'s ``icon.notify()`` is thread-safe and posts the
        notification asynchronously, so calling it here is safe.

        ``config`` is imported lazily inside this method so that changes made
        via the GUI settings window (which call ``config.save_config()`` /
        ``config.reload_config()``) are reflected immediately without a
        restart – the same hot-reload strategy used in ``guardian_target``.
        """
        import config as _cfg  # noqa: PLC0415

        if not _cfg.ENABLE_NOTIFICATIONS:
            return
        if self._icon is None:
            return
        try:
            now = time.monotonic()
            with self._notification_lock:
                if now - self._last_notification_monotonic < _cfg.STATUS_NOTIFICATION_COOLDOWN_SECONDS:
                    return
                self._last_notification_monotonic = now
            self._icon.notify(message, title)
        except Exception:  # pylint: disable=broad-except  # noqa: BLE001
            # Notification delivery is best-effort; never crash the guardian loop.
            pass

    def _refresh_menu(self) -> None:
        if self._icon is None:
            return
        self._icon.menu = self._build_menu()
        self._icon.update_menu()

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
            pystray.MenuItem("切换网络环境", self._build_profile_submenu()),
            pystray.MenuItem("设置 (Settings)", self._on_open_settings),
            pystray.MenuItem(autostart_label, self._on_toggle_autostart),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出 AutoNetGuard", self._on_quit),
        )

    # ---- icon refresh -------------------------------------------------------

    def _refresh_icon(self) -> None:
        if self._icon is None:
            return
        self._icon.icon = _make_icon(self._state.status)
        self._icon.title = self._state.tooltip()

    # ---- run (blocks main thread) ------------------------------------------

    def run(self) -> None:
        self._icon = pystray.Icon(
            name="AutoNetGuard",
            icon=_make_icon(NetStatus.UNKNOWN),
            title=self._state.tooltip(),
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

    # ------------------------------------------------------------------
    # 非阻塞打开设置窗口
    # ------------------------------------------------------------------
    # 用锁防止同时打开多个设置窗口（pystray 回调可能在短时间内多次触发）
    _settings_lock = threading.Lock()

    def _open_settings_in_thread() -> None:
        """在独立守护线程中运行 tkinter 配置窗口。

        关键并发约束：
        - pystray 在主线程的事件循环中调用此函数，必须立刻返回。
        - tkinter 的 mainloop() 是阻塞调用，只能在独立线程中运行。
        - 使用 _settings_lock 保证同时只有一个设置窗口存在。
        """
        if not _settings_lock.acquire(blocking=False):
            # 设置窗口已在运行，忽略重复点击
            return

        def _gui_thread_target() -> None:
            try:
                from gui_config import ConfigWindow  # noqa: PLC0415

                # on_saved 回调：保存成功后唤醒 guardian，
                # 让它尽快重新加载配置并进入下一轮检测。
                ConfigWindow(on_saved=lambda: state.request_config_reload()).run()
            finally:
                _settings_lock.release()

        threading.Thread(
            target=_gui_thread_target,
            name="gui_settings",
            daemon=True,  # 主进程退出时自动销毁，不阻碍程序关闭
        ).start()

    # Run tray on main thread (blocks until user clicks "退出")
    tray = TrayController(
        state=state,
        stop_event=stop_event,
        on_settings_open=_open_settings_in_thread,
    )
    tray.run()

    # Tray has exited – signal guardian to stop and wait briefly
    stop_event.set()
    guardian_thread.join(timeout=5)
