"""AutoNetGuard 图形化配置界面 (tkinter).

并发安全说明
-----------
``pystray`` 已占用主线程的事件循环，因此本模块的 tkinter 窗口**必须**在独立的
守护线程中运行，绝不能在 pystray 的回调内直接调用 ``mainloop()``。

调用方式（见 ``tray.py``）::

    import threading
    t = threading.Thread(target=ConfigWindow(on_saved=cb).run, daemon=True)
    t.start()

也可作为独立脚本运行，用于调试界面::

    python gui_config.py
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox
from typing import Callable


class ConfigWindow:
    """基于 tkinter 的设置窗口。

    Parameters
    ----------
    on_saved:
        保存成功后在 GUI 线程内调用的回调（可为 ``None``）。
        ``tray.py`` 传入 ``lambda: state.config_changed.set()`` 以通知
        主进程配置已变更。
    """

    def __init__(self, on_saved: Callable[[], None] | None = None) -> None:
        self._on_saved = on_saved
        self._root: tk.Tk | None = None

        # 表单变量（在 run() 内初始化，避免在非 GUI 线程创建 tk 对象）
        self._var_account: tk.StringVar
        self._var_password: tk.StringVar
        self._var_gateway: tk.StringVar
        self._var_login_url: tk.StringVar
        self._var_interval: tk.StringVar

    # ------------------------------------------------------------------ #
    # 公开入口                                                              #
    # ------------------------------------------------------------------ #

    def run(self) -> None:
        """在当前线程运行 tkinter 事件循环（阻塞至窗口关闭）。

        必须从专用守护线程调用，不得在 pystray 回调内直接调用。
        """
        self._root = tk.Tk()
        self._root.title("AutoNetGuard 设置")
        self._root.resizable(False, False)
        # 窗口启动时置顶，防止被其他窗口遮盖
        self._root.attributes("-topmost", True)
        self._root.after(200, lambda: self._root.attributes("-topmost", False))  # type: ignore[union-attr]

        self._init_vars()
        self._build_ui()
        self._load_config()

        self._root.mainloop()

    # ------------------------------------------------------------------ #
    # 内部：初始化 StringVar                                                #
    # ------------------------------------------------------------------ #

    def _init_vars(self) -> None:
        """在 Tk 实例创建后初始化 StringVar（必须在同一线程内）。"""
        self._var_account = tk.StringVar()
        self._var_password = tk.StringVar()
        self._var_gateway = tk.StringVar()
        self._var_login_url = tk.StringVar()
        self._var_interval = tk.StringVar()

    # ------------------------------------------------------------------ #
    # 内部：UI 布局                                                         #
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        root = self._root
        assert root is not None

        pad = {"padx": 10, "pady": 6}
        label_opts = {"anchor": "e", "width": 22}

        # ── 账号 ────────────────────────────────────────────────────────
        tk.Label(root, text="账号 (user_account):", **label_opts).grid(
            row=0, column=0, sticky="e", **pad
        )
        tk.Entry(root, textvariable=self._var_account, width=38).grid(
            row=0, column=1, **pad
        )

        # ── 密码（遮罩显示）────────────────────────────────────────────
        tk.Label(root, text="密码 (user_password):", **label_opts).grid(
            row=1, column=0, sticky="e", **pad
        )
        tk.Entry(root, textvariable=self._var_password, show="*", width=38).grid(
            row=1, column=1, **pad
        )

        # ── 网关 IP ──────────────────────────────────────────────────────
        tk.Label(root, text="网关 IP (gateway_ip):", **label_opts).grid(
            row=2, column=0, sticky="e", **pad
        )
        tk.Entry(root, textvariable=self._var_gateway, width=38).grid(
            row=2, column=1, **pad
        )

        # ── 登录 URL ─────────────────────────────────────────────────────
        tk.Label(root, text="登录 URL (login_url):", **label_opts).grid(
            row=3, column=0, sticky="e", **pad
        )
        tk.Entry(root, textvariable=self._var_login_url, width=38).grid(
            row=3, column=1, **pad
        )

        # ── 检测间隔 ─────────────────────────────────────────────────────
        tk.Label(root, text="检测间隔（秒）:", **label_opts).grid(
            row=4, column=0, sticky="e", **pad
        )
        tk.Entry(root, textvariable=self._var_interval, width=10).grid(
            row=4, column=1, sticky="w", **pad
        )

        # ── 按钮区域 ─────────────────────────────────────────────────────
        btn_frame = tk.Frame(root)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=12)

        tk.Button(
            btn_frame,
            text="保存并应用",
            command=self._on_save,
            width=14,
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame,
            text="取消",
            command=root.destroy,
            width=8,
        ).pack(side="left", padx=6)

    # ------------------------------------------------------------------ #
    # 内部：读取配置                                                         #
    # ------------------------------------------------------------------ #

    def _load_config(self) -> None:
        """从 config 模块读取当前值并填充表单。

        使用 ``import config`` 而非 ``from config import X`` 以确保始终读到
        最新的模块全局变量（包括 ``save_config`` / ``reload_config`` 更新后的值）。
        """
        import config as _cfg  # noqa: PLC0415  (延迟导入，确保在 GUI 线程内)

        self._var_account.set(_cfg.USER_ACCOUNT)
        self._var_password.set(_cfg.USER_PASSWORD)
        self._var_gateway.set(_cfg.GATEWAY_IP)
        self._var_login_url.set(_cfg.LOGIN_URL)
        self._var_interval.set(str(_cfg.CHECK_INTERVAL_SECONDS))

    # ------------------------------------------------------------------ #
    # 内部：保存逻辑                                                         #
    # ------------------------------------------------------------------ #

    def _on_save(self) -> None:
        """校验表单并调用 config.save_config() 持久化配置。

        save_config() 会同时更新 config 模块的全局变量，guardian 线程下次
        循环时通过 ``import config as _cfg; _cfg.X`` 自动读到新值，无需重启。
        """
        root = self._root
        assert root is not None

        account = self._var_account.get().strip()
        password = self._var_password.get()
        gateway = self._var_gateway.get().strip()
        login_url = self._var_login_url.get().strip()
        interval_str = self._var_interval.get().strip()

        # ── 基本校验 ────────────────────────────────────────────────────
        if not account or not password or not gateway:
            messagebox.showerror(
                "输入错误",
                "账号、密码和网关 IP 不能为空。",
                parent=root,
            )
            return

        if not login_url.startswith("http"):
            messagebox.showerror(
                "输入错误",
                "登录 URL 必须以 http 开头。",
                parent=root,
            )
            return

        try:
            interval = int(interval_str)
            if interval <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "输入错误",
                "检测间隔必须为正整数（秒）。",
                parent=root,
            )
            return

        # ── 写入配置（含加密）────────────────────────────────────────────
        try:
            import config as _cfg  # noqa: PLC0415

            _cfg.save_config(
                user_account=account,
                user_password=password,
                gateway_ip=gateway,
                login_url=login_url,
                check_interval_seconds=interval,
            )
        except Exception as exc:  # pylint: disable=broad-except
            messagebox.showerror("保存失败", str(exc), parent=root)
            return

        messagebox.showinfo(
            "已保存",
            "配置已保存并已加密。\n守护进程将在下次检测循环时自动使用新配置。",
            parent=root,
        )

        # 通知调用方（tray.py）配置已变更
        if self._on_saved:
            self._on_saved()

        root.destroy()


# ---------------------------------------------------------------------------
# 独立运行入口（调试用）
# ---------------------------------------------------------------------------

def main() -> None:
    """以独立进程运行配置界面（调试或命令行直接调用时使用）。"""
    window = ConfigWindow()
    window.run()


if __name__ == "__main__":
    main()
