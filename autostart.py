"""AutoNetGuard – cross-platform startup helper.

Provides three public functions:
  enable_autostart()      – register the app to start at login
  disable_autostart()     – remove the startup registration
  is_autostart_enabled()  – check whether startup is registered

Supported platforms
-------------------
* Windows  – HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (registry)
* macOS    – ~/Library/LaunchAgents/com.autonetguard.plist (LaunchAgent)
* Linux    – ~/.config/autostart/AutoNetGuard.desktop (XDG autostart)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "AutoNetGuard"


def _exe_path() -> str:
    """Return the absolute path of the running executable or script."""
    if getattr(sys, "frozen", False):
        # PyInstaller bundle
        return str(Path(sys.executable).resolve())
    # Running as a plain Python script – point to the script itself
    return str(Path(__file__).resolve().parent / "guardian.py")


def _launch_command() -> str:
    """Return the shell command used to launch the app.

    In frozen (bundled) mode the executable is invoked directly.  In script
    mode the current Python interpreter is prepended so the command is
    immediately runnable from a shell.
    """
    if getattr(sys, "frozen", False):
        return _exe_path()
    interpreter = sys.executable
    script = str(Path(__file__).resolve().parent / "guardian.py")
    return f'"{interpreter}" "{script}"'


# ---------------------------------------------------------------------------
# Windows – HKCU registry Run key
# ---------------------------------------------------------------------------

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

try:
    import winreg
    _WINREG_AVAILABLE = True
except ImportError:  # pragma: no cover
    _WINREG_AVAILABLE = False


def _win_enable() -> bool:
    if not _WINREG_AVAILABLE:
        return False
    exe = _exe_path()
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, exe)
    return True


def _win_disable() -> bool:
    if not _WINREG_AVAILABLE:
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, APP_NAME)
        return True
    except FileNotFoundError:
        return False


def _win_is_enabled() -> bool:
    if not _WINREG_AVAILABLE:
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_READ
        ) as key:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
            return value == _exe_path()
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# macOS – LaunchAgent plist
# ---------------------------------------------------------------------------

def _macos_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / "com.autonetguard.plist"


def _macos_plist_content() -> str:
    exe = _exe_path()
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
        ' "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        "<dict>\n"
        "    <key>Label</key>\n"
        "    <string>com.autonetguard</string>\n"
        "    <key>ProgramArguments</key>\n"
        "    <array>\n"
        f"        <string>{exe}</string>\n"
        "    </array>\n"
        "    <key>RunAtLoad</key>\n"
        "    <true/>\n"
        "    <key>KeepAlive</key>\n"
        "    <false/>\n"
        "</dict>\n"
        "</plist>\n"
    )


def _macos_enable() -> bool:
    plist = _macos_plist_path()
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_text(_macos_plist_content(), encoding="utf-8")
    return True


def _macos_disable() -> bool:
    plist = _macos_plist_path()
    if plist.exists():
        plist.unlink()
        return True
    return False


def _macos_is_enabled() -> bool:
    plist = _macos_plist_path()
    if not plist.exists():
        return False
    # Verify that the plist refers to the current executable path
    return _exe_path() in plist.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Linux – XDG autostart .desktop file
# ---------------------------------------------------------------------------

def _linux_desktop_path() -> Path:
    xdg_config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return xdg_config / "autostart" / f"{APP_NAME}.desktop"


def _linux_desktop_content() -> str:
    cmd = _launch_command()
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        f"Exec={cmd}\n"
        "Hidden=false\n"
        "NoDisplay=false\n"
        "X-GNOME-Autostart-enabled=true\n"
        "Comment=Auto re-authenticate campus network\n"
    )


def _linux_enable() -> bool:
    desktop = _linux_desktop_path()
    desktop.parent.mkdir(parents=True, exist_ok=True)
    desktop.write_text(_linux_desktop_content(), encoding="utf-8")
    return True


def _linux_disable() -> bool:
    desktop = _linux_desktop_path()
    if desktop.exists():
        desktop.unlink()
        return True
    return False


def _linux_is_enabled() -> bool:
    return _linux_desktop_path().exists()


# ---------------------------------------------------------------------------
# Public API – dispatch to the correct platform implementation
# ---------------------------------------------------------------------------

def enable_autostart() -> bool:
    """Register AutoNetGuard to start at login.

    Returns True on success, False if the operation could not be completed.
    """
    if sys.platform == "win32":
        return _win_enable()
    if sys.platform == "darwin":
        return _macos_enable()
    return _linux_enable()


def disable_autostart() -> bool:
    """Remove AutoNetGuard from the login startup list.

    Returns True if the entry was removed, False if it did not exist.
    """
    if sys.platform == "win32":
        return _win_disable()
    if sys.platform == "darwin":
        return _macos_disable()
    return _linux_disable()


def is_autostart_enabled() -> bool:
    """Return True if AutoNetGuard is registered to start at login."""
    if sys.platform == "win32":
        return _win_is_enabled()
    if sys.platform == "darwin":
        return _macos_is_enabled()
    return _linux_is_enabled()
